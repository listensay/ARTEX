#!/usr/bin/env python3
"""Restricted node selection IPC; never expose the general Mihomo controller."""

import http.server
import json
import math
import os
from pathlib import Path
import socketserver
import threading
import time

from runtime import controller

RESERVED = {"direct", "compatible", "reject", "reject-drop", "pass", "pass-rule", "global", "vpn"}
UNSAFE_TYPES = {"direct", "compatible", "reject", "rejectdrop", "reject-drop", "dns", "rematch", "pass", "passrule"}


class Refused(Exception):
    def __init__(self, status, code, **details):
        self.status, self.payload = status, {"error_code": code, **details}


class NodeControl:
    def __init__(self, component, cooldown=30, call=controller, clock=time.monotonic):
        self.component = component
        self.cooldown = cooldown
        self.call = call
        self.clock = clock
        self.lock = threading.Lock()
        self.last_change = None

    def state(self):
        group = self.call("/proxies/VPN")
        provider = self.call("/providers/proxies/clash")
        members = set(group["all"])
        nodes = []
        for proxy in provider["proxies"]:
            name, kind = proxy.get("name", ""), proxy.get("type", "")
            if not isinstance(name, str) or not isinstance(kind, str):
                continue
            if name not in members or name.lower() in RESERVED or kind.lower() in UNSAFE_TYPES:
                continue
            probe = proxy.get("extra", {}).get(group.get("testUrl", ""), {})
            history = probe.get("history", [])
            health = probe.get("alive") if history else None
            last = history[-1] if history else {}
            nodes.append({"name": name, "type": kind,
                          "health": "healthy" if health is True else "unhealthy" if health is False else "unknown",
                          "checked_at": last.get("time"), "probe_delay_ms": last.get("delay") if health is True else None})
        return {"component": self.component, "selected": group["now"], "nodes": nodes,
                "health_check": {"url": group.get("testUrl"), "method": "HEAD",
                                 "expected_status": group.get("expectedStatus"), "basis": "configured_endpoint_only"},
                "scope": "component_shared", "existing_connections_unchanged": True,
                "egress_ip_verified": False}

    def switch(self, args):
        if set(args) != {"node", "expected_current", "reason", "task_id", "request_id"}:
            raise Refused(400, "invalid_arguments")
        for key, limit in [("node", 256), ("expected_current", 256), ("reason", 1024), ("request_id", 64)]:
            value = args.get(key)
            if not isinstance(value, str) or not value.strip() or len(value.encode()) > limit:
                raise Refused(400, "invalid_arguments")
        if type(args["task_id"]) is not int or args["task_id"] <= 0:
            raise Refused(400, "task_context_required")
        with self.lock:
            state = self.state()
            if args["node"] not in {n["name"] for n in state["nodes"]}:
                raise Refused(400, "node_not_in_subscription")
            if args["node"] == state["selected"]:
                return {**state, "changed": False, "already_selected": True}
            if args["expected_current"] != state["selected"]:
                raise Refused(409, "selection_changed", selected=state["selected"])
            now = self.clock()
            if self.last_change is not None and now - self.last_change < self.cooldown:
                raise Refused(429, "switch_cooldown",
                              retry_after_seconds=math.ceil(self.cooldown - (now - self.last_change)))
            previous = state["selected"]
            # Charge a mutation attempt even if the IPC response is lost. The core
            # may already have applied it; callers must inspect status, not replay.
            self.last_change = now
            self.call("/proxies/VPN", method="PUT", body={"name": args["node"]}, timeout=6)
            result = self.state()
            result.update(previous=previous, requested=args["node"], changed=result["selected"] != previous)
            if result["selected"] != args["node"]:
                raise Refused(409, "requested_node_not_selected", selected=result["selected"])
            print(json.dumps({"event": "vpn_agent_switch", "component": self.component,
                              "task_id": args["task_id"], "request_id": args["request_id"],
                              "previous": previous, "selected": result["selected"]}), flush=True)
            return result


class Handler(http.server.BaseHTTPRequestHandler):
    def respond(self, status, body):
        payload = json.dumps(body, ensure_ascii=True).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(payload)))
        self.end_headers()
        try:
            self.wfile.write(payload)
        except (BrokenPipeError, ConnectionResetError):
            pass

    def do_GET(self):
        if self.path != "/status":
            self.respond(404, {"error_code": "unsupported_operation"})
            return
        try:
            with self.server.control.lock:
                body = self.server.control.state()
            self.respond(200, body)
        except (OSError, ValueError, KeyError, TypeError):
            self.respond(503, {"error_code": "control_unavailable"})

    def do_POST(self):
        if self.path != "/switch":
            self.respond(404, {"error_code": "unsupported_operation"})
            return
        try:
            if self.headers.get("Transfer-Encoding"):
                raise Refused(400, "invalid_body")
            size = int(self.headers.get("Content-Length", "0"))
            if not 0 < size <= 8192:
                raise Refused(400, "invalid_body")
            self.connection.settimeout(5)
            args = json.loads(self.rfile.read(size))
            if not isinstance(args, dict):
                raise Refused(400, "invalid_arguments")
        except Refused as err:
            self.respond(err.status, err.payload)
            return
        except (ValueError, UnicodeError):
            self.respond(400, {"error_code": "invalid_body"})
            return
        except OSError:
            self.respond(400, {"error_code": "invalid_body"})
            return
        try:
            self.respond(200, self.server.control.switch(args))
        except Refused as err:
            self.respond(err.status, err.payload)
        except (OSError, ValueError, KeyError, TypeError):
            self.respond(503, {"error_code": "control_unavailable"})

    def log_message(self, *args):
        pass


class Server(socketserver.ThreadingMixIn, socketserver.UnixStreamServer):
    daemon_threads = True


def main():
    component = os.environ["VPN_COMPONENT"]
    if component not in ("artex", "scopesentry", "scopesentry_scan"):
        raise ValueError("Invalid component")
    directory = Path("/control")
    directory.chmod(0o700)
    path = directory / "agent.sock"
    path.unlink(missing_ok=True)
    with Server(str(path), Handler) as server:
        path.chmod(0o600)
        server.control = NodeControl(component)
        server.serve_forever()


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""Namespace-local firewall preparation and readiness check."""

import http.client
import ipaddress
import json
import os
from pathlib import Path
import secrets
import socket
import ssl
import struct
import subprocess
import sys
import time

from configure import MARK, TUN_DEVICE


def ca_bundle(directory=Path("/vpn/ca"), system_bundle=None):
    if system_bundle is None:
        system_bundle = Path(ssl.get_default_verify_paths().openssl_cafile).read_bytes()
    parts = [system_bundle]
    directory = Path(directory)
    if directory.exists():
        for path in sorted(directory.iterdir()):
            if path.suffix.lower() not in (".crt", ".pem"):
                continue
            if path.is_symlink() or not path.is_file():
                raise ValueError("Additional CA must be a regular PEM file")
            raw = path.read_bytes()
            if b"PRIVATE KEY" in raw or len(raw) > 1024 * 1024:
                raise ValueError("Invalid additional CA")
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_CLIENT)
            context.load_verify_locations(cadata=raw.decode("ascii"))
            if not context.get_ca_certs():
                raise ValueError("Additional CA contains no CA certificate")
            parts.append(raw)
    return b"\n".join(parts) + b"\n"


def resolve_internal(host):
    # The marked DNS socket belongs only to the trusted gateway. Workloads cannot
    # reach Docker DNS, including by explicitly querying 127.0.0.11.
    ident = secrets.randbelow(65536)
    name = b"".join(bytes([len(p)]) + p.encode("ascii") for p in host.split(".")) + b"\0"
    query = struct.pack("!6H", ident, 0x100, 1, 0, 0, 0) + name + struct.pack("!HH", 1, 1)
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, MARK)
        sock.settimeout(3)
        sock.connect(("127.0.0.11", 53))
        sock.send(query)
        reply = sock.recv(4096)
    rid, flags, questions, answers, _, _ = struct.unpack("!6H", reply[:12])
    if rid != ident or flags & 15 or questions != 1:
        raise ValueError("Internal DNS failed")

    def skip_name(pos):
        while reply[pos]:
            if reply[pos] & 0xC0 == 0xC0:
                return pos + 2
            pos += 1 + reply[pos]
        return pos + 1

    pos = skip_name(12) + 4
    ips = []
    for _ in range(answers):
        pos = skip_name(pos)
        kind, cls, _, length = struct.unpack("!HHIH", reply[pos:pos + 10])
        pos += 10
        if kind == 1 and cls == 1 and length == 4:
            ips.append(str(ipaddress.IPv4Address(reply[pos:pos + length])))
        pos += length
    if not ips:
        raise ValueError("No internal IPv4 address")
    return ips


def prepare():
    Path("/run/vpn/ca-bundle.pem").write_bytes(ca_bundle())
    config = json.loads(Path("/vpn/config.json").read_text())
    provider = config.get("proxy-providers", {}).get("clash", {})
    if provider.get("type") == "file" and provider.get("path") == "providers/clash-local.json":
        nodes = json.loads(Path("/vpn/clash-nodes.json").read_text())
        if not isinstance(nodes.get("proxies"), list) or not nodes["proxies"]:
            raise ValueError("Local node snapshot is empty")
        destination = Path("/var/lib/mihomo/providers/clash-local.json")
        destination.parent.mkdir(mode=0o700, parents=True, exist_ok=True)
        destination.write_text(json.dumps(nodes, ensure_ascii=False))
    hosts, rules, excluded = {}, [], []
    for entry in os.environ.get("VPN_INTERNAL_SERVICES", "").split():
        host, port = entry.split(":")
        port = int(port)
        if not 1 <= port <= 65535:
            raise ValueError("Invalid internal service port")
        for attempt in range(10):
            try:
                ips = resolve_internal(host)
                break
            except (OSError, ValueError, IndexError, struct.error):
                if attempt == 9:
                    raise ValueError("Internal service resolution failed") from None
                time.sleep(1)
        hosts[host] = ips
        rules.append(f"AND,((DOMAIN,{host}),(DST-PORT,{port})),DIRECT")
        for ip in ips:
            address = ipaddress.IPv4Address(ip)
            if not address.is_private or address.is_unspecified or address.is_multicast:
                raise ValueError("Internal services must resolve to private IPv4 addresses")
            subprocess.run([
                "iptables", "-w", "-A", "OUTPUT", "-d", ip, "-p", "tcp",
                "--dport", str(port), "-j", "ACCEPT",
            ], check=True)
            excluded.append(ip + "/32")
            rules.append(f"AND,((IP-CIDR,{ip}/32,no-resolve),(DST-PORT,{port})),DIRECT")
    config["hosts"] = hosts
    config["rules"] = rules + config["rules"]
    config["tun"]["route-exclude-address"] = sorted(set(excluded))
    Path("/run/vpn/config.json").write_text(json.dumps(config, ensure_ascii=False))


def controller(path, method="GET", body=None, timeout=3):
    conn = http.client.HTTPConnection("localhost", timeout=timeout)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(timeout)
    sock.connect("/run/vpn/controller.sock")
    conn.sock = sock
    try:
        data = json.dumps(body).encode() if body is not None else None
        conn.request(method, path, body=data, headers={"Content-Type": "application/json"})
        response = conn.getresponse()
        if response.status not in (200, 204):
            raise ValueError("Controller failed")
        raw = response.read(1024 * 1024 + 1)
        if len(raw) > 1024 * 1024:
            raise ValueError("Controller response too large")
        return json.loads(raw) if raw else {}
    finally:
        conn.close()


def ready():
    if not Path("/sys/class/net", TUN_DEVICE).exists():
        raise ValueError("TUN is not ready")
    for tool in ["iptables", "ip6tables"]:
        for chain in ["INPUT", "OUTPUT", "FORWARD"]:
            policy = subprocess.check_output([tool, "-w", "-S", chain], text=True)
            if not policy.startswith(f"-P {chain} DROP\n"):
                raise ValueError("Kill switch is not installed")
    rules = subprocess.check_output(["ip", "-4", "rule"], text=True)
    if "8000:" not in rules or "not from all fwmark 0x7bb lookup 2022" not in rules:
        raise ValueError("Workload routing is not enforced")
    # Readiness means enforcement is active, not that an exit IP is available.
    # A temporarily dead subscription must not trigger a direct fallback.
    controller("/version")


def main():
    try:
        if sys.argv[1:] == ["prepare"]:
            prepare()
        elif sys.argv[1:] == ["ready"]:
            ready()
        elif sys.argv[1:] == ["status"]:
            group = controller("/proxies/VPN")
            print(json.dumps({"group": "VPN", "selected": group["now"],
                              "nodes": group["all"], "empty_fallback": group["emptyFallback"]}))
        else:
            raise ValueError("Use prepare, ready or status")
    except (OSError, ValueError, KeyError, subprocess.SubprocessError):
        print("VPN gateway unavailable; direct egress remains blocked.", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

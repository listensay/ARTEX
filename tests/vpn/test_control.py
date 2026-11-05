import contextlib
import io
import http.client
import json
from pathlib import Path
import sys
import socket
import tempfile
import threading
import unittest

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "deploy/vpn"))
from control import Handler, NodeControl, Refused, Server


class FakeCore:
    def __init__(self):
        self.selected = "node-one"
        self.calls = []
        self.fail_put = False

    def __call__(self, path, method="GET", body=None, timeout=3):
        self.calls.append((method, path, body))
        if path == "/proxies/VPN" and method == "PUT":
            self.selected = body["name"]
            if self.fail_put:
                raise OSError("response lost")
            return {}
        if path == "/proxies/VPN":
            return {"now": self.selected, "all": ["node-one", "node-two", "DIRECT", "evil-rematch"],
                    "testUrl": "https://health.invalid/"}
        if path == "/providers/proxies/clash":
            return {"proxies": [
                {"name": "node-one", "type": "Socks5", "password": "secret", "server": "private", "history": [{}], "alive": True},
                {"name": "node-two", "type": "Trojan", "extra": {"https://health.invalid/": {"alive": True}}},
                {"name": "DIRECT", "type": "Direct"},
                {"name": "evil-rematch", "type": "Rematch"},
                {"name": "not-in-group", "type": "Socks5"},
            ]}
        raise AssertionError("Unexpected general-controller access: " + path)


def args(node="node-two", expected="node-one"):
    return {"node": node, "expected_current": expected, "reason": "Agent observed request timeout",
            "task_id": 7, "request_id": "request-one"}


class VPNControlTests(unittest.TestCase):
    def setUp(self):
        self.core = FakeCore()
        self.now = 100.0
        self.control = NodeControl("artex", call=self.core, clock=lambda: self.now)

    def test_status_is_redacted_and_never_fetches_target(self):
        state = self.control.state()
        self.assertEqual([n["name"] for n in state["nodes"]], ["node-one", "node-two"])
        self.assertNotIn("secret", str(state))
        self.assertNotIn("private", str(state))
        self.assertEqual(state["scope"], "component_shared")
        self.assertTrue(state["existing_connections_unchanged"])
        self.assertFalse(state["egress_ip_verified"])
        self.assertTrue(all(call[0] == "GET" for call in self.core.calls))

    def test_global_alive_and_uncompleted_probe_do_not_mean_healthy(self):
        state = self.control.state()
        self.assertEqual(state["health_check"]["basis"], "configured_endpoint_only")
        self.assertEqual(state["health_check"]["method"], "HEAD")
        # Fake node-one has only global history; node-two has no completed
        # URL-specific history. Neither is evidence for the configured probe.
        self.assertTrue(all(n["health"] == "unknown" for n in state["nodes"]))

    def test_completed_matching_probe_carries_time_and_latency(self):
        base = self.core
        def measured(path, **kwargs):
            result = base(path, **kwargs)
            if path == "/providers/proxies/clash":
                result["proxies"][0]["extra"] = {"https://health.invalid/": {
                    "alive": True, "history": [{"time": "2026-11-05T00:00:00Z", "delay": 120}]}}
            return result
        self.control.call = measured
        node = self.control.state()["nodes"][0]
        self.assertEqual(node["health"], "healthy")
        self.assertEqual(node["checked_at"], "2026-11-05T00:00:00Z")
        self.assertEqual(node["probe_delay_ms"], 120)

    def test_agent_switches_healthy_node_without_wall_flag(self):
        with contextlib.redirect_stdout(io.StringIO()):
            result = self.control.switch(args())
        self.assertTrue(result["changed"])
        self.assertEqual(result["selected"], "node-two")
        mutations = [call for call in self.core.calls if call[0] != "GET"]
        self.assertEqual(mutations, [("PUT", "/proxies/VPN", {"name": "node-two"})])

    def test_no_direct_or_arbitrary_node(self):
        for name in ["DIRECT", "GLOBAL", "REJECT", "evil-rematch", "not-in-group", "http://new-proxy"]:
            with self.subTest(name=name), self.assertRaises(Refused) as raised:
                self.control.switch(args(name))
            self.assertEqual(raised.exception.payload["error_code"], "node_not_in_subscription")
        self.assertTrue(all(call[0] == "GET" for call in self.core.calls))

    def test_concurrent_selection_conflict_does_not_mutate(self):
        with self.assertRaises(Refused) as raised:
            self.control.switch(args(expected="outdated"))
        self.assertEqual(raised.exception.status, 409)
        self.assertFalse(any(call[0] == "PUT" for call in self.core.calls))

    def test_cooldown_and_idempotent_retry(self):
        with contextlib.redirect_stdout(io.StringIO()):
            self.control.switch(args())
        unchanged = self.control.switch(args())
        self.assertFalse(unchanged["changed"])
        with self.assertRaises(Refused) as raised:
            self.control.switch(args("node-one", "node-two"))
        self.assertEqual(raised.exception.payload["retry_after_seconds"], 30)
        self.now += 30
        with contextlib.redirect_stdout(io.StringIO()):
            self.assertTrue(self.control.switch(args("node-one", "node-two"))["changed"])

    def test_lost_response_is_not_blindly_replayed(self):
        self.core.fail_put = True
        with self.assertRaises(OSError):
            self.control.switch(args())
        self.assertEqual(self.control.state()["selected"], "node-two")
        self.assertFalse(self.control.switch(args())["changed"])
        self.assertEqual(sum(call[0] == "PUT" for call in self.core.calls), 1)

    def test_no_arbitrary_controls_or_identityless_call(self):
        invalid = [dict(args(), mode="direct"), dict(args(), task_id=0), dict(args(), task_id=True),
                   dict(args(), reason=""), dict(args(), node="x" * 257)]
        for request in invalid:
            with self.subTest(request=request), self.assertRaises(Refused):
                self.control.switch(request)
        self.assertEqual(self.core.calls, [])


class VPNControlHTTPTests(unittest.TestCase):
    def setUp(self):
        self.temp = tempfile.TemporaryDirectory()
        self.path = str(Path(self.temp.name) / "agent.sock")
        self.server = Server(self.path, Handler)
        self.server.control = NodeControl("artex", call=FakeCore())
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.thread.join()
        self.temp.cleanup()

    def request(self, body):
        conn = http.client.HTTPConnection("localhost", timeout=3)
        sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
        sock.connect(self.path)
        conn.sock = sock
        try:
            conn.request("POST", "/switch", body, {"Content-Type": "application/json"})
            response = conn.getresponse()
            return response.status, json.loads(response.read())
        finally:
            conn.close()

    def test_malformed_input_is_rejected(self):
        status, result = self.request("not-json")
        self.assertEqual((status, result["error_code"]), (400, "invalid_body"))

    def test_core_failure_is_not_mislabeled_as_invalid_agent_input(self):
        def unavailable(*args, **kwargs):
            raise ValueError("core error can include private material")
        self.server.control.call = unavailable
        status, result = self.request(json.dumps(args()))
        self.assertEqual((status, result["error_code"]), (503, "control_unavailable"))
        self.assertNotIn("private", str(result))


if __name__ == "__main__":
    unittest.main()

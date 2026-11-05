import http.client
import json
from pathlib import Path
import socket
import sys

TARGET = "172.30.244.2"
PORT = 18080


def fetch(host=TARGET, port=PORT, proxy=False):
    conn = http.client.HTTPConnection("127.0.0.1" if proxy else host, 7890 if proxy else port, timeout=3)
    try:
        conn.request("GET", f"http://{host}:{port}/" if proxy else "/")
        response = conn.getresponse()
        assert response.status == 200, response.status
        return json.loads(response.read())["peer"]
    finally:
        conn.close()


def blocked(call):
    try:
        call()
    except (OSError, AssertionError, ValueError):
        return
    raise AssertionError("Request bypassed the VPN-only boundary")


def udp():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.settimeout(3)
        sock.sendto(b"probe", (TARGET, PORT))
        return json.loads(sock.recv(8192))["peer"]


def node_api(method, path, body=None):
    conn = http.client.HTTPConnection("localhost", timeout=10)
    sock = socket.socket(socket.AF_UNIX, socket.SOCK_STREAM)
    sock.settimeout(10)
    sock.connect("/app/vpn-control/artex/agent.sock")
    conn.sock = sock
    try:
        conn.request(method, path, json.dumps(body) if body is not None else None,
                     {"Content-Type": "application/json"})
        response = conn.getresponse()
        return response.status, json.loads(response.read())
    finally:
        conn.close()


mode = sys.argv[1]
if mode == "agent_switch":
    status, state = node_api("GET", "/status")
    assert status == 200 and state["selected"] == "exit-one"
    assert state["scope"] == "component_shared"
    assert not Path("/run/vpn/controller.sock").exists()
    request = {"node": "exit-two", "expected_current": state["selected"],
               "reason": "Agent decided to change route based on its task evidence",
               "task_id": 7, "request_id": "test-agent-call"}
    status, changed = node_api("POST", "/switch", request)
    assert status == 200 and changed["changed"] and changed["selected"] == "exit-two"
    assert fetch() == "172.30.244.4"
    assert fetch(proxy=True) == "172.30.244.4"
    assert udp() == "172.30.244.4"
    assert node_api("GET", "/configs")[0] == 404
    assert node_api("POST", "/switch", dict(request, node="DIRECT"))[0] == 400
    assert node_api("POST", "/switch", dict(request, node="exit-one", expected_current="stale"))[0] == 409
    status, refusal = node_api("POST", "/switch", dict(request, node="exit-one", expected_current="exit-two"))
    assert status == 429 and refusal["retry_after_seconds"] > 0
elif mode in ("normal", "failover"):
    expected = "172.30.244.3" if mode == "normal" else "172.30.244.4"
    assert fetch() == expected
    assert fetch(proxy=True) == expected
    assert udp() == expected
    if mode == "normal":
        assert fetch("internal-service") == "172.30.245.3"
        assert fetch("internal-service", proxy=True) == "172.30.245.3"
        blocked(lambda: fetch("172.30.245.2", 18081))
        blocked(lambda: fetch("172.30.245.2", 18081, proxy=True))
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            try:
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_MARK, 1979)
            except PermissionError:
                pass
            else:
                raise AssertionError("Workload can forge the trusted gateway mark")
            sock.settimeout(2)
            def docker_dns():
                sock.sendto(b"\x12\x34\x01\x00\x00\x01\0\0\0\0\0\0\x07example\x03com\0\0\1\0\1",
                            ("127.0.0.11", 53))
                return sock.recv(4096)
            blocked(docker_dns)
        blocked(lambda: socket.create_connection(("2001:db8::1", PORT), timeout=2))
elif mode == "blocked":
    blocked(fetch)
    blocked(lambda: fetch(proxy=True))
    blocked(udp)
else:
    raise ValueError("Unknown mode")
print(f"VPN isolation: {mode} passed")

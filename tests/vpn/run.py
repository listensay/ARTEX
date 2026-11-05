#!/usr/bin/env python3
"""Run bounded, local-only VPN isolation tests without touching the real deployment."""

import importlib.util
import ipaddress
import json
from pathlib import Path
import subprocess
import time

ROOT = Path(__file__).resolve().parents[2]
HERE = Path(__file__).resolve().parent
COMPOSE = ["docker", "compose", "-p", "artex-vpn-tests", "-f", str(HERE / "compose.yml")]


def compose(*args, check=True):
    return subprocess.run(COMPOSE + list(args), check=check)


def main():
    existing = subprocess.check_output(["docker", "network", "ls", "-q"], text=True).split()
    if existing:
        networks = json.loads(subprocess.check_output(["docker", "network", "inspect", *existing]))
        for network in networks:
            for entry in network.get("IPAM", {}).get("Config", []) or []:
                if entry.get("Subnet") and any(
                    ipaddress.ip_network(entry["Subnet"]).overlaps(ipaddress.ip_network(subnet))
                    for subnet in ["172.30.244.0/24", "172.30.245.0/24"]
                ):
                    raise SystemExit("VPN test subnet is in use; no containers were changed")
    spec = importlib.util.spec_from_file_location("configure", ROOT / "deploy/vpn/configure.py")
    config_module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(config_module)
    config = config_module.make_config("https://not-used.invalid/sub")
    config["proxy-providers"]["clash"] = {
        "type": "inline", "exclude-type": "direct|dns|reject|rematch",
        "health-check": {
            "enable": True, "url": "http://172.30.244.2:18080/", "interval": 2,
            "timeout": 2000, "lazy": False, "expected-status": 200,
        },
        "payload": [
            {"name": "forbidden-direct", "type": "direct"},
            {"name": "exit-one", "type": "socks5", "server": "172.30.244.3", "port": 1080, "udp": True},
            {"name": "exit-two", "type": "socks5", "server": "172.30.244.4", "port": 1080, "udp": True},
        ],
    }
    group = config["proxy-groups"][0]
    group.update({"url": "http://172.30.244.2:18080/", "interval": 2, "expected-status": 200})
    (HERE / "local").mkdir(exist_ok=True)
    (HERE / "local/config.json").write_text(json.dumps(config))
    try:
        compose("up", "-d", "--build", "--wait", "--wait-timeout", "90")
        compose("exec", "-T", "client", "python3", "/tests/client.py", "normal")
        compose("exec", "-T", "target", "python3", "-c",
                "import urllib.request; assert urllib.request.urlopen('http://172.30.244.5:18082/client.py', timeout=3).status == 200; print('VPN isolation: management reply passed')")
        compose("exec", "-T", "gateway", "python3", "/opt/vpn/runtime.py", "status")
        compose("exec", "-T", "client", "python3", "/tests/client.py", "agent_switch")
        # Restore the original healthy node using the private admin socket only
        # for the independent automatic-failure test, not an Agent control path.
        compose("exec", "-T", "gateway", "python3", "-c",
                "import sys;sys.path.insert(0,'/opt/vpn');from runtime import controller;controller('/proxies/VPN',method='PUT',body={'name':'exit-one'},timeout=6)")
        compose("stop", "proxy-one")
        for attempt in range(15):
            status = subprocess.check_output(COMPOSE + [
                "exec", "-T", "gateway", "python3", "/opt/vpn/runtime.py", "status",
            ], text=True)
            if json.loads(status)["selected"] == "exit-two":
                break
            time.sleep(2)
        else:
            raise AssertionError("Healthy exit was not selected within the failover budget")
        compose("exec", "-T", "client", "python3", "/tests/client.py", "failover")
        compose("stop", "proxy-two")
        compose("exec", "-T", "client", "python3", "/tests/client.py", "blocked")
        compose("kill", "-s", "SIGKILL", "gateway")
        compose("exec", "-T", "client", "python3", "/tests/client.py", "blocked")
        # A fresh, unavailable provider must not use Mihomo's default COMPATIBLE.
        config["proxy-providers"] = config_module.make_config("https://not-used.invalid/sub")["proxy-providers"]
        (HERE / "local/config.json").write_text(json.dumps(config))
        compose("up", "-d", "--no-deps", "--force-recreate", "--wait", "--wait-timeout", "45", "gateway", "client")
        status = subprocess.check_output(COMPOSE + [
            "exec", "-T", "gateway", "python3", "/opt/vpn/runtime.py", "status",
        ], text=True)
        assert json.loads(status)["selected"] == "REJECT", status
        compose("exec", "-T", "client", "python3", "/tests/client.py", "blocked")
        print("VPN isolation: unavailable subscription uses REJECT")
    finally:
        compose("down", "--volumes", "--timeout", "2", check=False)


if __name__ == "__main__":
    main()

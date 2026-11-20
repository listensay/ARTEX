import contextlib
import ipaddress
import json
import os
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "deploy/vpn"))
import runtime


def dns_reply(ips):
    question = b"\x08internal\x00" + struct.pack("!HH", 1, 1)
    answers = b"".join(
        b"\xc0\x0c" + struct.pack("!HHIH", 1, 1, 30, 4)
        + ipaddress.IPv4Address(ip).packed for ip in ips
    )
    return struct.pack("!6H", 42, 0x8180, 1, len(ips), 0, 0) + question + answers


class InternalResolutionTests(unittest.TestCase):
    def setUp(self):
        self.stack = contextlib.ExitStack()
        self.addCleanup(self.stack.close)
        self.stack.enter_context(patch.object(runtime.secrets, "randbelow", return_value=42))
        # SO_MARK is Linux-only; fake sockets keep these tests portable on macOS.
        self.stack.enter_context(patch.object(socket, "SO_MARK", 36, create=True))
        self.sock = self.stack.enter_context(patch.object(runtime.socket, "socket"))
        self.connection = self.sock.return_value.__enter__.return_value

    def test_docker_and_host_private_addresses_use_marked_embedded_dns(self):
        ips = ["10.0.0.2", "172.20.0.4", "192.168.65.254"]
        self.connection.recv.return_value = dns_reply(ips)
        self.assertEqual(runtime.resolve_internal("internal"), ips)
        self.connection.setsockopt.assert_called_once_with(socket.SOL_SOCKET, socket.SO_MARK, runtime.MARK)
        self.connection.connect.assert_called_once_with(("127.0.0.11", 53))

    def test_fake_and_special_addresses_are_not_internal_services(self):
        for ip in ["198.18.99.246", "198.19.0.1", "127.0.0.1", "169.254.1.1",
                   "192.0.2.1", "0.0.0.0", "224.0.0.1", "240.0.0.1", "8.8.8.8"]:
            with self.subTest(ip=ip):
                self.connection.recv.return_value = dns_reply([ip])
                with self.assertRaises(ValueError):
                    runtime.resolve_internal("internal")

    def test_mixed_answers_are_rejected_together(self):
        self.connection.recv.return_value = dns_reply(["172.20.0.4", "198.18.99.246"])
        with self.assertRaises(ValueError):
            runtime.resolve_internal("internal")

    def prepare_environment(self, directory):
        source = directory / "input.json"
        source.write_text(json.dumps({"rules": ["MATCH,VPN"], "tun": {}}))
        paths = {
            "/vpn/config.json": source,
            "/run/vpn/config.json": directory / "output.json",
            "/run/vpn/ca-bundle.pem": directory / "ca.pem",
        }
        self.stack.enter_context(patch.object(runtime, "Path", side_effect=lambda path: paths[path]))
        self.stack.enter_context(patch.object(runtime, "ca_bundle", return_value=b"test CA"))
        self.stack.enter_context(patch.dict(os.environ, {"VPN_INTERNAL_SERVICES": "internal:27017"}))
        sleep = self.stack.enter_context(patch.object(runtime.time, "sleep"))
        firewall = self.stack.enter_context(patch.object(runtime.subprocess, "run"))
        return paths["/run/vpn/config.json"], sleep, firewall

    def test_startup_retries_fake_ip_before_installing_exact_service_rule(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination, sleep, firewall = self.prepare_environment(Path(tmp))
            self.connection.recv.side_effect = [dns_reply(["198.18.99.246"]), dns_reply(["172.20.0.4"])]
            runtime.prepare()
            config = json.loads(destination.read_text())
        sleep.assert_called_once_with(1)
        firewall.assert_called_once_with([
            "iptables", "-w", "-A", "OUTPUT", "-d", "172.20.0.4", "-p", "tcp",
            "--dport", "27017", "-j", "ACCEPT",
        ], check=True)
        self.assertEqual(config["hosts"], {"internal": ["172.20.0.4"]})
        self.assertEqual(config["tun"]["route-exclude-address"], ["172.20.0.4/32"])
        self.assertEqual(config["rules"][-1], "MATCH,VPN")
        self.assertNotIn("198.18", json.dumps(config))

    def test_persistent_fake_ip_exhausts_budget_without_opening_firewall(self):
        with tempfile.TemporaryDirectory() as tmp:
            destination, sleep, firewall = self.prepare_environment(Path(tmp))
            self.connection.recv.return_value = dns_reply(["198.18.99.246"])
            with self.assertRaisesRegex(ValueError, "Internal service resolution failed"):
                runtime.prepare()
            self.assertFalse(destination.exists())
        self.assertEqual(self.connection.recv.call_count, 10)
        self.assertEqual(sleep.call_count, 9)
        firewall.assert_not_called()


if __name__ == "__main__":
    unittest.main()

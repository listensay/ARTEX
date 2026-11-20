import asyncio
import importlib.util
import json
from pathlib import Path
import socket
import struct
import sys
import tempfile
import unittest
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).resolve().parents[2] / "deploy/vpn"))
import host_bridge
import runtime


class BridgePolicyTests(unittest.IsolatedAsyncioTestCase):
    def setUp(self):
        self.settings = host_bridge.bridge_configuration([
            {"server": "VPN.Example.", "port": 443},
            {"server": "vpn.example", "port": 443},
        ])

    def test_credentials_are_stable_and_targets_are_deduplicated(self):
        self.assertEqual(self.settings["targets"], [{"host": "vpn.example", "port": 443}])
        updated = host_bridge.bridge_configuration([{"server": "next.example", "port": 8443}], self.settings)
        self.assertEqual(updated["password"], self.settings["password"])
        self.assertEqual(updated["targets"], [{"host": "next.example", "port": 8443}])

    def test_private_and_fake_dns_answers_are_rejected(self):
        for ip in ["198.18.1.2", "198.19.1.2", "127.0.0.1", "192.168.1.1", "10.1.1.1", "169.254.1.1", "224.0.0.1", "::1"]:
            with self.subTest(ip=ip), self.assertRaises(ValueError):
                host_bridge.public_ipv4(ip)

    def test_bridge_preserves_security_rules_and_authentication(self):
        config = {"rules": ["MATCH,VPN"], "proxy-providers": {"clash": {"override": {"routing-mark": 1979}}}}
        host_bridge.enable_bridge(config, self.settings)
        host_bridge.enable_bridge(config, self.settings)
        self.assertEqual(len(config["proxies"]), 1)
        self.assertEqual(config["rules"], ["MATCH,VPN"])
        self.assertEqual(config["proxy-providers"]["clash"]["override"]["routing-mark"], 1979)
        self.assertEqual(config["proxies"][0]["password"], self.settings["password"])

    async def test_only_exact_node_endpoints_and_their_resolved_ips_are_allowed(self):
        class Resolver:
            def resolve(self, host):
                return ["8.8.8.8"]
        bridge = host_bridge.Bridge(self.settings, Resolver())
        self.assertEqual(await bridge.allowed_addresses("vpn.example", 443), ["8.8.8.8"])
        self.assertEqual(await bridge.allowed_addresses("8.8.8.8", 443), ["8.8.8.8"])
        for host, port in [("other.example", 443), ("8.8.4.4", 443), ("vpn.example", 80), ("8.8.8.8", 80), ("127.0.0.1", 443)]:
            with self.subTest(host=host, port=port), self.assertRaises(ValueError):
                await bridge.allowed_addresses(host, port)

    def test_no_unbound_socket_fallback_if_physical_binding_fails(self):
        resolver = host_bridge.Resolver()
        with patch.object(host_bridge.sys, "platform", "darwin"), patch.object(resolver, "interface", return_value=7), patch.object(host_bridge.socket, "socket") as factory:
            factory.return_value.setsockopt.side_effect = OSError("no interface")
            with self.assertRaises(OSError):
                resolver.bound_socket(socket.SOCK_STREAM)
            factory.return_value.close.assert_called_once()
            factory.return_value.connect.assert_not_called()

    async def test_unauthenticated_proxy_is_refused(self):
        bridge = host_bridge.Bridge(self.settings)
        server = await asyncio.start_server(bridge.handle, "127.0.0.1", 0)
        try:
            reader, writer = await asyncio.open_connection(*server.sockets[0].getsockname())
            writer.write(b"\5\1\0")
            await writer.drain()
            self.assertEqual(await reader.readexactly(2), b"\5\xff")
            writer.close()
            await writer.wait_closed()
        finally:
            server.close()
            await server.wait_closed()

    async def test_authenticated_tcp_transport_and_destination_restriction(self):
        async def echo(reader, writer):
            try:
                while data := await reader.read(1024):
                    writer.write(data)
                    await writer.drain()
            finally:
                writer.close()
                await writer.wait_closed()
        upstream = await asyncio.start_server(echo, "127.0.0.1", 0)
        port = upstream.sockets[0].getsockname()[1]
        settings = host_bridge.bridge_configuration([{"server": "vpn.example", "port": port}])
        class Resolver:
            def resolve(self, host):
                return ["127.0.0.1"]
            def bound_socket(self, kind):
                sock = socket.socket(socket.AF_INET, kind)
                sock.setblocking(False)
                return sock
        bridge = host_bridge.Bridge(settings, Resolver())
        server = await asyncio.start_server(bridge.handle, "127.0.0.1", 0)
        try:
            for hostname, expected in [(b"vpn.example", 0), (b"outside.example", 2)]:
                reader, writer = await asyncio.open_connection(*server.sockets[0].getsockname())
                writer.write(b"\5\1\2")
                await writer.drain()
                self.assertEqual(await reader.readexactly(2), b"\5\2")
                username, password = settings["username"].encode(), settings["password"].encode()
                writer.write(b"\1" + bytes([len(username)]) + username + bytes([len(password)]) + password)
                await writer.drain()
                self.assertEqual(await reader.readexactly(2), b"\1\0")
                writer.write(b"\5\1\0\3" + bytes([len(hostname)]) + hostname + struct.pack("!H", port))
                await writer.drain()
                self.assertEqual((await reader.readexactly(10))[1], expected)
                if expected == 0:
                    writer.write(b"VPN encrypted transport")
                    await writer.drain()
                    self.assertEqual(await reader.readexactly(23), b"VPN encrypted transport")
                writer.close()
                await writer.wait_closed()
        finally:
            server.close()
            upstream.close()
            await server.wait_closed()
            await upstream.wait_closed()

    def test_udp_parsing_rejects_fragments(self):
        host = b"vpn.example"
        packet = b"\0\0\0\3" + bytes([len(host)]) + host + struct.pack("!H", 443) + b"encrypted"
        self.assertEqual(host_bridge.udp_address(packet), ("vpn.example", 443, b"encrypted"))
        with self.assertRaises(ValueError):
            host_bridge.udp_address(b"\0\0\1" + packet[3:])

    async def test_authenticated_udp_transport_and_endpoint_restriction(self):
        class Echo(asyncio.DatagramProtocol):
            def connection_made(self, transport):
                self.transport = transport
            def datagram_received(self, data, address):
                self.transport.sendto(data, address)
        loop = asyncio.get_running_loop()
        echo, _ = await loop.create_datagram_endpoint(Echo, local_addr=("127.0.0.1", 0))
        port = echo.get_extra_info("sockname")[1]
        settings = host_bridge.bridge_configuration([{"server": "vpn.example", "port": port}])
        class Resolver:
            def resolve(self, host):
                return ["127.0.0.1"]
            def bound_socket(self, kind):
                sock = socket.socket(socket.AF_INET, kind)
                sock.setblocking(False)
                return sock
        bridge = host_bridge.Bridge(settings, Resolver())
        server = await asyncio.start_server(bridge.handle, "127.0.0.1", 0)
        udp = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        udp.setblocking(False)
        writer = None
        try:
            reader, writer = await asyncio.open_connection(*server.sockets[0].getsockname())
            writer.write(b"\5\1\2")
            await writer.drain()
            self.assertEqual(await reader.readexactly(2), b"\5\2")
            username, password = settings["username"].encode(), settings["password"].encode()
            writer.write(b"\1" + bytes([len(username)]) + username + bytes([len(password)]) + password)
            await writer.drain()
            self.assertEqual(await reader.readexactly(2), b"\1\0")
            writer.write(b"\5\3\0\1" + b"\0" * 6)
            await writer.drain()
            reply = await reader.readexactly(10)
            self.assertEqual(reply[:4], b"\5\0\0\1")
            remote_port = struct.unpack("!H", reply[-2:])[0]
            hostname = b"vpn.example"
            packet = b"\0\0\0\3" + bytes([len(hostname)]) + hostname + struct.pack("!H", port) + b"encrypted datagram"
            await loop.sock_sendto(udp, packet, ("127.0.0.1", remote_port))
            response, _ = await asyncio.wait_for(loop.sock_recvfrom(udp, 4096), 2)
            self.assertEqual(host_bridge.udp_address(response), ("127.0.0.1", port, b"encrypted datagram"))
            hostname = b"outside.example"
            packet = b"\0\0\0\3" + bytes([len(hostname)]) + hostname + struct.pack("!H", port) + b"must be rejected"
            await loop.sock_sendto(udp, packet, ("127.0.0.1", remote_port))
            with self.assertRaises(TimeoutError):
                await asyncio.wait_for(loop.sock_recvfrom(udp, 4096), 0.1)
        finally:
            udp.close()
            if writer:
                writer.close()
                await writer.wait_closed()
            echo.close()
            server.close()
            await server.wait_closed()


class GatewayBridgeTests(unittest.TestCase):
    def test_host_transport_does_not_add_workload_direct_rules(self):
        with tempfile.TemporaryDirectory() as tmp:
            directory = Path(tmp)
            source, output = directory / "input.json", directory / "output.json"
            config = {"proxy-providers": {"clash": {}}, "rules": ["MATCH,VPN"], "tun": {}}
            host_bridge.enable_bridge(config, host_bridge.bridge_configuration([{"server": "vpn.example", "port": 443}]))
            source.write_text(json.dumps(config))
            paths = {"/vpn/config.json": source, "/run/vpn/config.json": output,
                     "/run/vpn/ca-bundle.pem": directory / "ca.pem"}
            with patch.object(runtime, "Path", side_effect=lambda path: paths[path]), \
                 patch.object(runtime, "ca_bundle", return_value=b"CA"), \
                 patch.dict(runtime.os.environ, {"VPN_INTERNAL_SERVICES": ""}), \
                 patch.object(runtime, "resolve_internal", return_value=["192.168.65.254"]), \
                 patch.object(runtime.subprocess, "run") as command:
                runtime.prepare()
            result = json.loads(output.read_text())
            self.assertEqual(result["hosts"], {"host.docker.internal": ["192.168.65.254"]})
            self.assertEqual(result["rules"], ["MATCH,VPN"])
            self.assertEqual(result["tun"]["route-exclude-address"], [])
            command.assert_not_called()


if __name__ == "__main__":
    unittest.main()

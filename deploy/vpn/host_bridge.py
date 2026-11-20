#!/usr/bin/env python3
"""macOS SOCKS transport for allowlisted VPN servers, bypassing the host TUN.

This is NOT an Internet proxy: only node endpoints in the private snapshot are
reachable. VPN authentication/encryption and all target routing stay in Mihomo.
"""

import argparse
import asyncio
import contextlib
import hmac
import ipaddress
import json
import os
from pathlib import Path
import plistlib
import re
import secrets
import shutil
import socket
import struct
import subprocess
import sys
import time
import urllib.parse
import urllib.request

NAME = "ARTEX-HOST-TRANSPORT"
LABEL = "local.artex.vpn-host-bridge"
PORT = 19420
ROOT = Path(__file__).resolve().parents[2]


def canonical_host(value):
    return value.rstrip(".").encode("idna").decode("ascii").lower()


def public_ipv4(value):
    address = ipaddress.ip_address(value)
    if address.version != 4 or not address.is_global or address.is_multicast:
        raise ValueError("VPN server must have a public IPv4 address")
    return str(address)


def bridge_configuration(nodes, previous=None):
    previous = previous or {}
    targets = sorted({(canonical_host(n["server"]), int(n["port"])) for n in nodes})
    if not targets or any(not host or not 1 <= port <= 65535 for host, port in targets):
        raise ValueError("Invalid node endpoints")
    return {
        "version": 1, "port": PORT, "username": "artex",
        "password": previous.get("password") or secrets.token_hex(32),
        "targets": [{"host": host, "port": port} for host, port in targets],
    }


def enable_bridge(config, settings):
    # Keep node servers, TLS SNI and credentials intact; only their transport
    # passes through the fixed-endpoint host service.
    config["proxies"] = [p for p in config.get("proxies", []) if p.get("name") != NAME]
    config["proxies"].append({
        "name": NAME, "type": "socks5", "server": "host.docker.internal",
        "port": settings["port"], "username": settings["username"],
        "password": settings["password"], "udp": True, "routing-mark": 1979,
    })
    config["proxy-providers"]["clash"].setdefault("override", {})["dialer-proxy"] = NAME


class Resolver:
    def __init__(self):
        self.controller = None
        self.cache = {}
        self.interface_cache = (0, 0)
        self.opener = urllib.request.build_opener(urllib.request.ProxyHandler({}))

    def request(self, base, path):
        with self.opener.open(base + path, timeout=5) as response:
            return json.load(response)

    def discover(self):
        result = subprocess.run(["pgrep", "-f", r"/ClashX Pro.app/Contents/MacOS/ClashX Pro$"],
                                capture_output=True, text=True, timeout=5, check=True)
        for pid in result.stdout.split():
            listeners = subprocess.run(["lsof", "-a", "-p", pid, "-iTCP", "-sTCP:LISTEN", "-P", "-n", "-Fn"],
                                       capture_output=True, text=True, timeout=5, check=True)
            for port in re.findall(r"^n127\.0\.0\.1:(\d+)$", listeners.stdout, re.M):
                base = "http://127.0.0.1:" + port
                try:
                    if self.request(base, "/version").get("version"):
                        self.controller = base
                        return base
                except (OSError, ValueError):
                    continue
        raise OSError("ClashX local controller unavailable")

    def resolve(self, hostname):
        hostname = canonical_host(hostname)
        try:
            ipaddress.ip_address(hostname)
        except ValueError:
            pass
        else:
            return [public_ipv4(hostname)]
        cached = self.cache.get(hostname)
        if cached and cached[0] > time.monotonic():
            return cached[1]
        for attempt in range(2):
            base = self.controller or self.discover()
            try:
                response = self.request(base, "/dns/query?" + urllib.parse.urlencode({"name": hostname, "type": "A"}))
                answers = list(dict.fromkeys(public_ipv4(a["data"]) for a in response.get("Answer", []) if a.get("type") == 1))
                if not answers:
                    raise ValueError("Empty node DNS answer")
                ttl = min([60] + [max(1, int(a.get("TTL", 30))) for a in response.get("Answer", []) if a.get("type") == 1])
                self.cache[hostname] = (time.monotonic() + ttl, answers)
                return answers
            except (OSError, ValueError):
                self.controller = None
                if attempt:
                    raise
        raise OSError("Node resolution failed")

    def interface(self):
        expires, index = self.interface_cache
        if expires > time.monotonic():
            return index
        result = subprocess.run(["/sbin/route", "-n", "get", "default"], capture_output=True,
                                text=True, timeout=5, check=True)
        match = re.search(r"^\s*interface:\s*(\S+)\s*$", result.stdout, re.M)
        if not match or not re.fullmatch(r"en\d+", match[1]):
            raise OSError("No physical default interface; refusing TUN fallback")
        index = socket.if_nametoindex(match[1])
        self.interface_cache = (time.monotonic() + 10, index)
        return index

    def bound_socket(self, kind):
        if sys.platform != "darwin":
            raise OSError("Host transport requires macOS")
        sock = socket.socket(socket.AF_INET, kind)
        try:
            # Darwin IP_BOUND_IF. Binding failure must NEVER become an unbound
            # connection, which would send the VPN handshake back into the TUN.
            sock.setsockopt(socket.IPPROTO_IP, 25, self.interface())
            sock.setblocking(False)
            return sock
        except BaseException:
            sock.close()
            raise


async def read_address(reader):
    kind = (await reader.readexactly(1))[0]
    if kind == 1:
        host = socket.inet_ntoa(await reader.readexactly(4))
    elif kind == 3:
        size = (await reader.readexactly(1))[0]
        host = (await reader.readexactly(size)).decode("ascii")
    else:
        raise ValueError("Only IPv4 node endpoints are supported")
    port = struct.unpack("!H", await reader.readexactly(2))[0]
    return canonical_host(host), port


def udp_address(data):
    if len(data) < 4 or data[:3] != b"\0\0\0":
        raise ValueError("Fragmented SOCKS datagrams are not supported")
    kind, pos = data[3], 4
    if kind == 1:
        host, pos = socket.inet_ntoa(data[pos:pos + 4]), pos + 4
    elif kind == 3:
        size = data[pos]
        pos += 1
        host, pos = data[pos:pos + size].decode("ascii"), pos + size
    else:
        raise ValueError("Unsupported address")
    port = struct.unpack("!H", data[pos:pos + 2])[0]
    return canonical_host(host), port, data[pos + 2:]


class DatagramRelay(asyncio.DatagramProtocol):
    def __init__(self, bridge, peer):
        self.bridge, self.peer = bridge, peer
        self.client = None
        self.transport = None
        self.remotes = {}
        self.tasks = set()
        self.closed = False

    def connection_made(self, transport):
        self.transport = transport

    def datagram_received(self, data, address):
        if self.closed or address[0] != self.peer or (self.client and address != self.client) or len(self.tasks) >= 32:
            return
        self.client = address
        task = asyncio.create_task(self.forward(data))
        self.tasks.add(task)
        task.add_done_callback(self.tasks.discard)

    async def forward(self, data):
        try:
            host, port, payload = udp_address(data)
            ips = await self.bridge.allowed_addresses(host, port)
            key = (ips[0], port)
            if key not in self.remotes:
                if len(self.remotes) >= 16 or self.closed:
                    return
                sock = await asyncio.to_thread(self.bridge.resolver.bound_socket, socket.SOCK_DGRAM)
                try:
                    await asyncio.get_running_loop().sock_connect(sock, key)
                    if self.closed or key in self.remotes:
                        sock.close()
                        return
                    self.remotes[key] = sock
                    task = asyncio.create_task(self.receive(sock, key))
                    self.tasks.add(task)
                    task.add_done_callback(self.tasks.discard)
                except BaseException:
                    sock.close()
                    raise
            await asyncio.get_running_loop().sock_sendall(self.remotes[key], payload)
        except (OSError, ValueError, IndexError, UnicodeError, struct.error):
            self.bridge.failures += 1

    async def receive(self, sock, key):
        try:
            while not self.closed:
                data = await asyncio.wait_for(asyncio.get_running_loop().sock_recv(sock, 65535), 120)
                header = b"\0\0\0\1" + socket.inet_aton(key[0]) + struct.pack("!H", key[1])
                self.transport.sendto(header + data, self.client)
        except (OSError, TimeoutError):
            pass
        finally:
            self.remotes.pop(key, None)
            sock.close()

    def close(self):
        self.closed = True
        if self.transport:
            self.transport.close()
        for task in tuple(self.tasks):
            task.cancel()
        for sock in self.remotes.values():
            sock.close()


class Bridge:
    def __init__(self, settings, resolver=None):
        self.settings = settings
        self.resolver = resolver or Resolver()
        self.targets = {(canonical_host(t["host"]), int(t["port"])) for t in settings["targets"]}
        self.active = 0
        self.failures = 0

    async def allowed_addresses(self, host, port):
        if (host, port) in self.targets:
            return await asyncio.to_thread(self.resolver.resolve, host)
        # Some cores resolve before dialing their SOCKS transport. An IP is
        # accepted only when it belongs to an exact allowlisted hostname:port.
        ip = public_ipv4(host)
        for name, target_port in self.targets:
            if port == target_port and ip in await asyncio.to_thread(self.resolver.resolve, name):
                return [ip]
        raise ValueError("Destination is not a configured VPN server")

    async def authenticate(self, reader, writer):
        version, count = await reader.readexactly(2)
        methods = await reader.readexactly(count)
        if version != 5 or 2 not in methods:
            writer.write(b"\5\xff")
            await writer.drain()
            raise ValueError("SOCKS authentication required")
        writer.write(b"\5\2")
        await writer.drain()
        version, size = await reader.readexactly(2)
        username = await reader.readexactly(size)
        size = (await reader.readexactly(1))[0]
        password = await reader.readexactly(size)
        valid = version == 1 and hmac.compare_digest(username, self.settings["username"].encode()) and hmac.compare_digest(password, self.settings["password"].encode())
        writer.write(b"\1\0" if valid else b"\1\1")
        await writer.drain()
        if not valid:
            raise ValueError("Authentication failed")

    async def connect(self, ips, port):
        for ip in ips:
            sock = await asyncio.to_thread(self.resolver.bound_socket, socket.SOCK_STREAM)
            try:
                await asyncio.wait_for(asyncio.get_running_loop().sock_connect(sock, (ip, port)), 8)
                return await asyncio.open_connection(sock=sock)
            except (OSError, TimeoutError):
                sock.close()
        raise OSError("Node connection failed")

    async def pipe(self, reader, writer):
        while True:
            data = await asyncio.wait_for(reader.read(65536), 300)
            if not data:
                return
            writer.write(data)
            await writer.drain()

    async def handle(self, reader, writer):
        if self.active >= 256:
            writer.close()
            return
        self.active += 1
        upstream = udp = None
        pipes = []
        try:
            await asyncio.wait_for(self.authenticate(reader, writer), 10)
            version, command, reserved = await asyncio.wait_for(reader.readexactly(3), 10)
            host, port = await asyncio.wait_for(read_address(reader), 10)
            if version != 5 or reserved != 0:
                raise ValueError("Invalid SOCKS request")
            if command == 1:
                ips = await self.allowed_addresses(host, port)
                remote_reader, upstream = await self.connect(ips, port)
                writer.write(b"\5\0\0\1" + b"\0" * 6)
                await writer.drain()
                pipes = [asyncio.create_task(self.pipe(reader, upstream)), asyncio.create_task(self.pipe(remote_reader, writer))]
                await asyncio.wait(pipes, return_when=asyncio.FIRST_COMPLETED)
            elif command == 3:
                udp = DatagramRelay(self, writer.get_extra_info("peername")[0])
                transport, _ = await asyncio.get_running_loop().create_datagram_endpoint(lambda: udp, local_addr=("127.0.0.1", 0))
                udp_port = transport.get_extra_info("sockname")[1]
                writer.write(b"\5\0\0\1" + b"\0" * 4 + struct.pack("!H", udp_port))
                await writer.drain()
                await reader.read()
            else:
                raise ValueError("Unsupported SOCKS command")
        except (OSError, ValueError, UnicodeError, asyncio.IncompleteReadError, TimeoutError):
            self.failures += 1
            with contextlib.suppress(OSError):
                writer.write(b"\5\2\0\1" + b"\0" * 6)
                await writer.drain()
        finally:
            for task in pipes:
                task.cancel()
            if pipes:
                await asyncio.gather(*pipes, return_exceptions=True)
            if udp:
                udp.close()
            for stream in [upstream, writer]:
                if stream:
                    stream.close()
                    with contextlib.suppress(OSError):
                        await stream.wait_closed()
            self.active -= 1


async def serve(path):
    settings = json.loads(path.read_text())
    bridge = Bridge(settings)
    # Check the physical route before accepting traffic. Launchd retries if the
    # machine is offline; there is no fallback through the host's global proxy.
    await asyncio.to_thread(bridge.resolver.interface)
    server = await asyncio.start_server(bridge.handle, "127.0.0.1", settings["port"])
    print("Fixed-node host transport ready", flush=True)
    async with server:
        await server.serve_forever()


def install(directory):
    if sys.platform != "darwin":
        raise ValueError("LaunchAgent installation requires macOS")
    path = directory.resolve() / "host-bridge.json"
    json.loads(path.read_text())
    # launchd must not depend on an external project volume being mounted or
    # accessible before login privacy permissions are established.
    runtime = Path.home() / "Library/Application Support/ARTEX/vpn-host-bridge"
    runtime.mkdir(parents=True, mode=0o700, exist_ok=True)
    runtime.chmod(0o700)
    shutil.copy2(Path(__file__).resolve(), runtime / "host_bridge.py")
    shutil.copy2(path, runtime / "host-bridge.json")
    (runtime / "host_bridge.py").chmod(0o600)
    (runtime / "host-bridge.json").chmod(0o600)
    agent_dir = Path.home() / "Library/LaunchAgents"
    agent_dir.mkdir(parents=True, exist_ok=True)
    plist = agent_dir / (LABEL + ".plist")
    log = runtime / "host-bridge.log"
    log.touch(mode=0o600, exist_ok=True)
    log.chmod(0o600)
    config = {"Label": LABEL, "ProgramArguments": [sys.executable, str(runtime / "host_bridge.py"), "serve", "--directory", str(runtime)],
              "RunAtLoad": True, "KeepAlive": True, "ThrottleInterval": 10, "Umask": 0o077,
              "EnvironmentVariables": {"PATH": "/usr/bin:/bin:/usr/sbin:/sbin"},
              "StandardOutPath": str(log), "StandardErrorPath": str(log)}
    plist.write_bytes(plistlib.dumps(config))
    plist.chmod(0o600)
    domain = "gui/" + str(os.getuid())
    subprocess.run(["launchctl", "bootout", domain + "/" + LABEL], capture_output=True)
    subprocess.run(["launchctl", "bootstrap", domain, str(plist)], check=True)
    print("Installed local fixed-node host transport (starts at login, restarts after failure)")


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("command", choices=["serve", "install"])
    parser.add_argument("--directory", type=Path, default=ROOT / ".vpn")
    args = parser.parse_args()
    try:
        if args.command == "install":
            install(args.directory)
        else:
            asyncio.run(serve(args.directory / "host-bridge.json"))
    except (OSError, ValueError, subprocess.SubprocessError):
        parser.exit(1, "Host transport unavailable; no direct target fallback.\n")


if __name__ == "__main__":
    main()

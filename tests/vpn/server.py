"""Local-only HTTP/UDP canary and restricted SOCKS test exit."""

import http.server
import json
import os
import select
import socket
import socketserver
import struct
import threading

TARGET = "172.30.244.2"
PORT = 18080


def read_exact(sock, size):
    result = b""
    while len(result) < size:
        chunk = sock.recv(size - len(result))
        if not chunk:
            raise EOFError
        result += chunk
    return result


class Target(http.server.BaseHTTPRequestHandler):
    def do_HEAD(self):
        self.send_response(200)
        self.send_header("Content-Length", "0")
        self.end_headers()

    def do_GET(self):
        body = json.dumps({"peer": self.client_address[0]}).encode()
        self.send_response(200)
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def log_message(self, *args):
        pass


def udp_target():
    with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
        sock.bind(("0.0.0.0", PORT))
        while True:
            _, peer = sock.recvfrom(8192)
            sock.sendto(json.dumps({"peer": peer[0]}).encode(), peer)


def udp_relay(sock, stop):
    sock.settimeout(0.5)
    client = None
    while not stop.is_set():
        try:
            data, peer = sock.recvfrom(8192)
        except socket.timeout:
            continue
        if peer == (TARGET, PORT) and client:
            sock.sendto(b"\0\0\0\1" + socket.inet_aton(TARGET) + struct.pack("!H", PORT) + data, client)
        elif len(data) >= 10 and data[:4] == b"\0\0\0\1":
            ip, port = socket.inet_ntoa(data[4:8]), struct.unpack("!H", data[8:10])[0]
            if (ip, port) == (TARGET, PORT):
                client = peer
                sock.sendto(data[10:], (ip, port))


class Socks(socketserver.BaseRequestHandler):
    def handle(self):
        try:
            client = self.request
            version, count = read_exact(client, 2)
            if version != 5 or 0 not in read_exact(client, count):
                return
            client.sendall(b"\5\0")
            version, command, _, kind = read_exact(client, 4)
            if kind == 1:
                host = socket.inet_ntoa(read_exact(client, 4))
            elif kind == 3:
                host = read_exact(client, read_exact(client, 1)[0]).decode()
            else:
                return
            port = struct.unpack("!H", read_exact(client, 2))[0]
            if command == 3:
                stop = threading.Event()
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as udp:
                    udp.bind(("0.0.0.0", 0))
                    address = client.getsockname()[0]
                    client.sendall(b"\5\0\0\1" + socket.inet_aton(address)
                                   + struct.pack("!H", udp.getsockname()[1]))
                    relay = threading.Thread(target=udp_relay, args=(udp, stop), daemon=True)
                    relay.start()
                    try:
                        while client.recv(1):
                            pass
                    finally:
                        stop.set()
                        relay.join(timeout=2)
                return
            if command != 1 or (host, port) != (TARGET, PORT):
                client.sendall(b"\5\2\0\1\0\0\0\0\0\0")
                return
            with socket.create_connection((host, port), timeout=3) as remote:
                client.sendall(b"\5\0\0\1\0\0\0\0\0\0")
                while True:
                    ready, _, _ = select.select([client, remote], [], [], 10)
                    if not ready:
                        return
                    for source in ready:
                        data = source.recv(8192)
                        if not data:
                            return
                        (remote if source is client else client).sendall(data)
        except (EOFError, OSError):
            pass


class Server(socketserver.ThreadingTCPServer):
    allow_reuse_address = True
    daemon_threads = True


if os.environ["ROLE"] == "socks":
    Server(("0.0.0.0", 1080), Socks).serve_forever()
else:
    threading.Thread(target=udp_target, daemon=True).start()
    threading.Thread(target=http.server.ThreadingHTTPServer(("0.0.0.0", 18081), Target).serve_forever,
                     daemon=True).start()
    http.server.ThreadingHTTPServer(("0.0.0.0", PORT), Target).serve_forever()

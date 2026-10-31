"""Inert HTTP fixtures: no real accounts, exploitation payloads or external requests."""
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import socketserver
import ssl
import threading

MODE = os.environ.get("LAB_MODE", "portal")
COUNTS = Counter()
LOCK = threading.Lock()


class Banner(socketserver.BaseRequestHandler):
    def handle(self):
        with LOCK:
            COUNTS["tcp:2222"] += 1
        self.request.settimeout(3)
        try:
            self.request.sendall(b"SSH-2.0-ArtexLab_inert_banner\r\n")
            self.request.recv(256)
            # An invalid key-exchange byte permits banner classification only;
            # this fixture has no authentication, shell or filesystem service.
            self.request.sendall(b"\x00")
        except OSError:
            pass


class Site(BaseHTTPRequestHandler):
    server_version = "ArtexLab/1.0"

    def do_HEAD(self):
        self.respond(False)

    def do_GET(self):
        self.respond(True)

    def respond(self, send_body):
        observer = self.headers.get("X-Lab-Observer") == "1"
        if observer and self.path == "/__lab_metrics":
            with LOCK:
                body = json.dumps({"mode": MODE, "requests": dict(COUNTS)}).encode()
            self.send_response(200)
            self.send_header("Content-Type", "application/json")
        else:
            if not observer:
                with LOCK:
                    COUNTS[self.path] += 1
            if MODE == "redirect":
                self.send_response(302)
                self.send_header("Location", os.environ["LAB_REDIRECT"])
                body = b"<html><title>ARTEX LAB Redirect Boundary</title>Redirect boundary fixture</html>"
            elif MODE == "auth":
                self.send_response(401)
                self.send_header("WWW-Authenticate", 'Basic realm="ARTEX LAB - no real account"')
                body = b"<html><title>ARTEX LAB Authentication Required</title>Authentication fixture</html>"
            else:
                self.send_response(200)
                titles = {"portal": "ARTEX LAB Management Portal", "inventory": "ARTEX LAB TCP and HTTP Inventory", "tls": "ARTEX LAB Self Signed TLS", "canary": "ARTEX LAB Out Of Scope Canary"}
                title = titles.get(MODE, "ARTEX LAB")
                body = f"<!doctype html><html><head><title>{title}</title></head><body><h1>{title}</h1><p>Local isolated service-mapping fixture. No real user data.</p></body></html>".encode()
            self.send_header("Content-Type", "text/html; charset=utf-8")
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Connection", "close")
        self.end_headers()
        if send_body:
            self.wfile.write(body)

    def log_message(self, format, *args):
        if self.headers.get("X-Lab-Observer") != "1":
            print(json.dumps({"mode": MODE, "path": self.path, "peer": self.client_address[0]}), flush=True)


if __name__ == "__main__":
    if MODE == "inventory":
        banner = socketserver.ThreadingTCPServer(("0.0.0.0", 2222), Banner)
        banner.daemon_threads = True
        threading.Thread(target=banner.serve_forever, daemon=True).start()
    server = ThreadingHTTPServer(("0.0.0.0", 443 if MODE == "tls" else 80), Site)
    if MODE == "tls":
        context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
        context.load_cert_chain("/lab/certs/cert.pem", "/lab/certs/key.pem")
        server.socket = context.wrap_socket(server.socket, server_side=True)
    print(json.dumps({"mode": MODE, "port": server.server_port}), flush=True)
    server.serve_forever()

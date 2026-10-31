"""Loopback-published viewer for four fixed fixtures; not an arbitrary forward proxy."""
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import ssl
import threading
import urllib.error
import urllib.request

TARGETS = {
    18381: "http://172.30.243.11",
    18382: "http://172.30.243.12",
    18383: "http://172.30.243.13",
    18384: "https://172.30.243.14",
    18385: "http://172.30.243.21",
}


class NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, request, file, code, message, headers, new_url):
        return None


class Viewer(BaseHTTPRequestHandler):
    def do_GET(self):
        self.forward(True)

    def do_HEAD(self):
        self.forward(False)

    def forward(self, body):
        # Absolute URLs and authority paths must not change the hard-coded destination.
        if not self.path.startswith("/") or self.path.startswith("//"):
            self.send_error(400)
            return
        target = TARGETS[self.server.server_port] + self.path
        request = urllib.request.Request(target, method="GET" if body else "HEAD", headers={"X-Lab-Observer": "1"})
        context = ssl._create_unverified_context()  # Only the known self-signed TLS fixture.
        client = urllib.request.build_opener(urllib.request.ProxyHandler({}), NoRedirect(), urllib.request.HTTPSHandler(context=context))
        try:
            response = client.open(request, timeout=5)
        except urllib.error.HTTPError as error:
            response = error
        except (urllib.error.URLError, TimeoutError):
            self.send_error(502, "Local lab fixture is not ready")
            return
        with response:
            content = response.read() if body else b""
            self.send_response(response.code)
            for name in ("Content-Type", "Location", "WWW-Authenticate"):
                if response.headers.get(name):
                    self.send_header(name, response.headers[name])
            self.send_header("Content-Length", str(len(content)))
            self.end_headers()
            if body:
                self.wfile.write(content)


if __name__ == "__main__":
    servers = []
    for port in TARGETS:
        server = ThreadingHTTPServer(("0.0.0.0", port), Viewer)
        if port == 18384:
            context = ssl.SSLContext(ssl.PROTOCOL_TLS_SERVER)
            context.load_cert_chain("/lab/certs/cert.pem", "/lab/certs/key.pem")
            server.socket = context.wrap_socket(server.socket, server_side=True)
        threading.Thread(target=server.serve_forever, daemon=True).start()
        servers.append(server)
    threading.Event().wait()

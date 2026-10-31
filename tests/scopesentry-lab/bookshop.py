"""Isolated, intentionally vulnerable order-access CTF with synthetic accounts/data."""
from collections import Counter
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
import json
import os
import secrets
import threading
from urllib.parse import parse_qs, urlparse

COUNTS = Counter()
LOCK = threading.Lock()
SESSIONS = set()
FLAG = os.environ.get("LAB_FLAG", "FLAG{bookshop_order_scope_lab_only}")

INDEX = b"""<!doctype html><html lang="en"><head><meta charset="utf-8"><title>Blue Harbor Books</title></head>
<body><header><h1>Blue Harbor Books</h1><p>Independent books, delivered with care.</p></header>
<main><h2>Customer center</h2><p>Sign in to view your recent order and download its invoice.</p>
<form id="login"><label>Email <input name="email" type="email"></label><label>Password <input name="password" type="password"></label><button>Sign in</button></form>
<section id="account" hidden><h2>My orders</h2><div id="orders"></div></section><pre id="notice"></pre></main>
<script src="/static/store.js"></script></body></html>"""
SCRIPT = b"""document.querySelector('#login').addEventListener('submit', async (event) => {
  event.preventDefault(); const fields = new FormData(event.target);
  const response = await fetch('/api/session', {method:'POST', headers:{'Content-Type':'application/json'}, body:JSON.stringify(Object.fromEntries(fields))});
  if (!response.ok) {document.querySelector('#notice').textContent='Sign-in failed'; return;}
  document.querySelector('#account').hidden=false;
  const orders=await (await fetch('/api/orders')).json();
  document.querySelector('#orders').replaceChildren(...orders.map(order => {
    const a=document.createElement('a'); a.textContent=order.title+' (invoice '+order.id+')'; a.href='/api/orders/'+order.id+'/invoice'; return a;
  }));
});"""


class Shop(BaseHTTPRequestHandler):
    server_version = "BlueHarbor/1.4"

    def respond(self, code, content, content_type="application/json"):
        self.send_response(code)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(content)))
        self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(content)

    def record(self):
        if self.headers.get("X-Lab-Observer") != "1":
            with LOCK:
                COUNTS[self.command + " " + urlparse(self.path).path] += 1

    def authenticated(self):
        cookies = parse_qs((self.headers.get("Cookie") or "").replace("; ", "&"))
        return any(value in SESSIONS for value in cookies.get("bh_session", []))

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        self.record()
        path = urlparse(self.path).path
        if path == "/__lab_metrics" and self.headers.get("X-Lab-Observer") == "1":
            with LOCK:
                return self.respond(200, json.dumps(dict(COUNTS)).encode())
        if path == "/":
            return self.respond(200, INDEX, "text/html; charset=utf-8")
        if path == "/static/store.js":
            return self.respond(200, SCRIPT, "text/javascript")
        if path == "/robots.txt":
            return self.respond(200, b"User-agent: *\nDisallow: /api/\n", "text/plain")
        if path == "/health":
            return self.respond(200, b'{"status":"ok","service":"bookshop"}')
        if not path.startswith("/api/"):
            return self.respond(404, b'{"error":"not found"}')
        if not self.authenticated():
            return self.respond(401, b'{"error":"sign in required"}')
        if path == "/api/me":
            return self.respond(200, b'{"id":41,"email":"reader@example.test","role":"customer"}')
        if path == "/api/orders":
            return self.respond(200, b'[{"id":1001,"title":"The Art of Reading","owner_id":41}]')
        if path.startswith("/api/orders/"):
            parts = path.strip("/").split("/")
            if len(parts) < 3 or not parts[2].isdigit():
                return self.respond(404, b'{"error":"order not found"}')
            order = int(parts[2])
            if order not in (1001, 1002):
                return self.respond(404, b'{"error":"order not found"}')
            # Deliberate CTF flaw: authenticated customer is not checked against order owner.
            data = {"id": order, "owner_id": 41 if order == 1001 else 7, "title": "The Art of Reading" if order == 1001 else "Staff Archive", "amount": 24 if order == 1001 else 38}
            if len(parts) == 4 and parts[3] == "invoice":
                data["invoice"] = "INV-" + str(order)
                if order == 1002:
                    data["staff_note"] = FLAG
            return self.respond(200, json.dumps(data).encode())
        return self.respond(404, b'{"error":"not found"}')

    def do_POST(self):
        self.record()
        if self.path != "/api/session":
            return self.respond(404, b'{"error":"not found"}')
        try:
            length = int(self.headers.get("Content-Length", "0"))
            if length > 2048:
                return self.respond(413, b'{"error":"request too large"}')
            data = json.loads(self.rfile.read(length))
        except (ValueError, json.JSONDecodeError):
            return self.respond(400, b'{"error":"invalid request"}')
        if data.get("email") != "reader@example.test" or data.get("password") != "read-books-2026":
            return self.respond(401, b'{"error":"invalid credentials"}')
        token = secrets.token_urlsafe(24)
        SESSIONS.add(token)
        self.send_response(200)
        self.send_header("Set-Cookie", "bh_session=" + token + "; HttpOnly; SameSite=Lax; Path=/")
        self.send_header("Content-Type", "application/json")
        self.end_headers()
        self.wfile.write(b'{"id":41,"role":"customer"}')

    def log_message(self, fmt, *args):
        if self.headers.get("X-Lab-Observer") != "1":
            print(json.dumps({"peer": self.client_address[0], "method": self.command, "path": urlparse(self.path).path}), flush=True)


if __name__ == "__main__":
    ThreadingHTTPServer(("0.0.0.0", 80), Shop).serve_forever()

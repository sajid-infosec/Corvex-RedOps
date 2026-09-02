"""Deliberately-vulnerable API for benchmarking PentestIQ (localhost only).

Serves an intentionally-broken API on 127.0.0.1:8099 with a set of *known*
planted vulnerabilities. Used by run_benchmark.py to score detection.
"""
import json, hmac, hashlib, base64, threading, urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer


def _b64(d): return base64.urlsafe_b64encode(d).rstrip(b"=").decode()


def make_jwt(payload, secret="secret", alg="HS512"):
    h = _b64(json.dumps({"alg": alg, "typ": "JWT"}).encode())
    p = _b64(json.dumps(payload).encode())
    hasher = {"HS256": hashlib.sha256, "HS512": hashlib.sha512}[alg]
    sig = _b64(hmac.new(secret.encode(), f"{h}.{p}".encode(), hasher).digest())
    return f"{h}.{p}.{sig}"


# weak-secret HS512 token: embedded Matrix token, all-perms object, 24h TTL
TOKEN_A = make_jwt({"sub": "userA", "role": "Owner", "organization_id": "orgA",
                    "access_token": "syt_abcdefghij",
                    "permission": {"read": True, "write": True, "delete": True, "admin": True},
                    "iat": 0, "exp": 86400})
TOKEN_B = make_jwt({"sub": "userB", "role": "User", "organization_id": "orgB",
                    "iat": 0, "exp": 86400})

USERS = {"user-a1": {"id": "user-a1", "org": "orgA", "name": "Alice", "email": "alice@x.com"},
         "user-b1": {"id": "user-b1", "org": "orgB", "name": "Bob", "email": "bob@x.com",
                     "userPass": "$2a$06$abcdefghijklmnopqrstuv1234567890ABCDEFGHIJKLMNOPQR"}}


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass

    def _send(self, code, body="", ctype="application/json", extra=None):
        self.send_response(code)
        self.send_header("Content-Type", ctype)
        origin = self.headers.get("Origin")          # VULN: CORS reflect + credentials
        if origin:
            self.send_header("Access-Control-Allow-Origin", origin)
            self.send_header("Access-Control-Allow-Credentials", "true")
        if self.path == "/":                          # VULN: cookie without flags
            self.send_header("Set-Cookie", "session_token=abc123; Path=/")
        for k, v in (extra or {}).items():
            self.send_header(k, v)
        self.end_headers()
        if body:
            self.wfile.write(body.encode() if isinstance(body, str) else body)

    def do_OPTIONS(self):                             # VULN: dangerous methods advertised
        self._send(204, extra={"Allow": "GET, POST, PUT, DELETE, OPTIONS"})

    def do_GET(self):
        # VULN: blind SSRF — server fetches any ?url= value out-of-band
        from urllib.parse import urlsplit, parse_qs
        q = parse_qs(urlsplit(self.path).query)
        if "url" in q:
            try:
                urllib.request.urlopen(q["url"][0], timeout=4).read()
            except Exception:
                pass
        p = self.path.split("?")[0]
        if p == "/":
            html = ("<html><body><h1>VulnApp</h1>"
                    "<a href=\"/api/user/user-b1\">a user</a>"
                    "<a href=\"/api/user/me\">me</a>"
                    "<a href=\"/search?q=x\">search</a>"
                    "<form action=\"/auth/forgot\" method=\"post\">"
                    "<input name=\"email\"></form>"
                    "<script src=\"/app.js\"></script></body></html>")
            return self._send(200, html, ctype="text/html")
        if p == "/app.js":
            js = 'fetch("/api/user/me");const t="/api/user/{id}";var s="/search";'
            return self._send(200, js, ctype="application/javascript")
        if p == "/search":
            return self._send(200, json.dumps({"results": []}))
        if p == "/api/user/me":                        # VULN: password hash in response
            return self._send(200, json.dumps(USERS["user-b1"]))
        if p.startswith("/api/user/"):                 # VULN: BOLA — any id, any caller
            uid = p.rsplit("/", 1)[1]
            return self._send(200, json.dumps(USERS.get(uid, {"id": uid, "org": "orgB", "name": "X"})))
        if "%00" in self.path or "../" in self.path or "'" in self.path:   # VULN: stack trace
            trace = ("at com.vcon.gateway.Handler.process(Handler.java:88)\n"
                     "com.vcon.gatewayException: bad input\n\tat java.base/jdk.internal")
            return self._send(500, trace, ctype="text/plain")
        return self._send(404, json.dumps({"error": "not found"}))

    def do_POST(self):
        if self.path == "/auth/forgot":                # VULN: account enumeration
            ln = int(self.headers.get("Content-Length", 0))
            try:
                email = json.loads(self.rfile.read(ln)).get("email", "")
            except Exception:
                email = ""
            if email == "alice@x.com":
                return self._send(200, json.dumps({"message": "reset link sent to your inbox"}))
            return self._send(404, json.dumps({"error": "no such user"}))
        return self._send(404, json.dumps({"error": "not found"}))


def serve(port: int = 8099):
    srv = ThreadingHTTPServer(("127.0.0.1", port), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv

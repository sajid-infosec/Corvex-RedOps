"""Native injection-fuzzing tests — detectors (unit) + end-to-end (local target)."""
import threading
import time
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import urlsplit, parse_qs

import pytest

from pentestiq.checks.base import Response, RealHttpClient, CheckContext
from pentestiq.models import Asset, AssetType
from pentestiq.fuzzing import InjectionFuzzer, InjectionPoint
from pentestiq.fuzzing.detectors import (
    SqliErrorDetector, XssReflectedDetector, PathTraversalDetector, SstiDetector,
    SqliBooleanDetector, SqliTimeDetector,
)


def _resp(status=200, text="", ms=1.0):
    return Response(status=status, headers={}, text=text, elapsed_ms=ms, url="http://t/")


class _Ctx:
    extra = {"fuzz_time_delay": 1}
    oast = None


# ------------------------------------------------------------- unit: detectors
def test_sqli_error_detector():
    def send(v):
        return _resp(500, "You have an error in your SQL syntax; check the manual that corresponds to your MySQL server version") if "'" in v else _resp(200, "ok")
    hit = SqliErrorDetector().probe(send, InjectionPoint("GET", "u", "query", "id"), _resp(200, "ok"), _Ctx())
    assert hit and hit["class"].startswith("SQL injection (error")


def test_xss_reflected_detector():
    def send(v):
        return _resp(200, f"<html>results for {v}</html>")     # reflects raw
    hit = XssReflectedDetector().probe(send, InjectionPoint("GET", "u", "query", "q"), _resp(200, ""), _Ctx())
    assert hit and hit["cwe"] == "CWE-79"

def test_xss_not_detected_when_escaped():
    def send(v):
        return _resp(200, "escaped: " + v.replace("<", "&lt;"))
    hit = XssReflectedDetector().probe(send, InjectionPoint("GET", "u", "query", "q"), _resp(200, ""), _Ctx())
    assert hit is None


def test_path_traversal_detector():
    def send(v):
        return _resp(200, "root:x:0:0:root:/root:/bin/bash\n") if "passwd" in v else _resp(200, "nope")
    hit = PathTraversalDetector().probe(send, InjectionPoint("GET", "u", "query", "file"), _resp(200, ""), _Ctx())
    assert hit and hit["cwe"] == "CWE-22"


def test_ssti_detector():
    def send(v):
        return _resp(200, "1787569") if "1337*1337" in v and "{" in v else _resp(200, "x")
    hit = SstiDetector().probe(send, InjectionPoint("GET", "u", "query", "name"), _resp(200, ""), _Ctx())
    assert hit and hit["cwe"] == "CWE-1336"

def test_ssti_not_detected_when_reflected_literally():
    def send(v):
        return _resp(200, v)      # echoes payload literally (not evaluated)
    assert SstiDetector().probe(send, InjectionPoint("GET", "u", "query", "n"), _resp(200, ""), _Ctx()) is None


def test_sqli_boolean_detector():
    baseline = _resp(200, "A" * 500)
    def send(v):
        if "1=1" in v or "'1'='1" in v:
            return _resp(200, "A" * 500)     # TRUE ~ baseline
        return _resp(200, "A" * 50)          # FALSE differs
    hit = SqliBooleanDetector().probe(send, InjectionPoint("GET", "u", "query", "id"), baseline, _Ctx())
    assert hit and "boolean" in hit["class"]


def test_sqli_time_detector():
    def send(v):
        ms = 1200.0 if ("SLEEP(1)" in v or "pg_sleep(1)" in v or "DELAY '0:0:1'" in v) else 5.0
        return _resp(200, "ok", ms=ms)
    hit = SqliTimeDetector().probe(send, InjectionPoint("GET", "u", "query", "id"), _resp(200, "ok"), _Ctx())
    assert hit and "time" in hit["class"]


# ------------------------------------------------------------- end-to-end target
class _Vuln(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        sp = urlsplit(self.path)
        q = parse_qs(sp.query)
        path = sp.path
        body, code = "ok", 200
        def val(k): return q.get(k, [""])[0]
        if path == "/search":                       # reflected XSS + error SQLi
            v = val("q")
            if "'" in v or '"' in v:
                body, code = ("You have an error in your SQL syntax; check the manual "
                              "that corresponds to your MySQL server version near '%s'" % v), 500
            else:
                body = f"<div>results for {v}</div>"
        elif path == "/item":                        # boolean + time SQLi
            v = val("id")
            low = v.lower()
            import re
            m = re.search(r"sleep\((\d+)\)|delay '0:0:(\d+)'", low)
            if m:
                time.sleep(int(m.group(1) or m.group(2) or 0))
                body = "row"
            elif "1=2" in v or "'1'='2" in v:
                body = "no rows"
            else:
                body = "row " * 200                  # TRUE / baseline long
        elif path == "/file":                        # path traversal
            v = val("path")
            body = "root:x:0:0:root:/root:/bin/bash\n" if "etc/passwd" in v else "not found"
        elif path == "/render":                      # SSTI
            v = val("name")
            body = v.replace("{{1337*1337}}", "1787569").replace("${1337*1337}", "1787569")
        elif path == "/ping":                        # cmd injection (time)
            v = val("host")
            import re
            m = re.search(r"sleep (\d+)", v)
            if m:
                time.sleep(int(m.group(1)))
            body = "pong"
        self.send_response(code)
        self.send_header("Content-Type", "text/html")
        self.end_headers()
        self.wfile.write(body.encode())


@pytest.fixture
def vuln_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _Vuln)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_fuzzer_end_to_end_all_classes(vuln_server):
    base = vuln_server
    points = [
        InjectionPoint("GET", f"{base}/search", "query", "q"),
        InjectionPoint("GET", f"{base}/item", "query", "id"),
        InjectionPoint("GET", f"{base}/file", "query", "path"),
        InjectionPoint("GET", f"{base}/render", "query", "name"),
        InjectionPoint("GET", f"{base}/ping", "query", "host"),
    ]
    asset = Asset(type=AssetType.WEB, identifier=base, metadata={"fuzz_time_delay": 1})
    ctx = CheckContext(asset=asset, base_url=base, http=RealHttpClient(timeout=10),
                       allow_active=True, extra={"fuzz_time_delay": 1})
    findings = InjectionFuzzer(http=RealHttpClient(timeout=10)).run(points, ctx)
    classes = {f["class"].split(" (")[0] for f in findings}
    assert "Reflected XSS" in classes
    assert "SQL injection" in classes                 # error and/or boolean/time
    assert "Path traversal / LFI" in classes
    assert "Server-side template injection" in classes
    assert "OS command injection" in classes


# ---------------------------------------------- unit: new detector classes
from pentestiq.fuzzing.detectors import (
    NoSqliDetector, CrlfDetector, OpenRedirectDetector, XxeDetector,
)
from pentestiq.fuzzing.points import InjectionPoint as _IP


def test_nosqli_error_detector():
    def send(v):
        return _resp(500, "MongoServerError: unknown operator $where") if "$" in v or "{" in v else _resp(200, "ok")
    hit = NoSqliDetector().probe(send, _IP("GET", "http://t/nosearch", "query", "q"),
                                 _resp(200, "ok"), _Ctx())
    assert hit and hit["cwe"] == "CWE-943"


def test_nosqli_boolean_detector():
    def send(v):
        if "'1'=='1" in v or "1==1" in v:
            return _resp(200, "alice bob carol dave erin frank grace hank ivan")
        return _resp(200, "no results")
    base = _resp(200, "alice bob carol dave erin frank grace hank ivan")
    hit = NoSqliDetector().probe(send, _IP("GET", "http://t/n", "query", "q"), base, _Ctx())
    assert hit and "boolean" in hit["class"].lower()


class _CrlfCtx:
    extra = {}
    oast = None
    class http:
        @staticmethod
        def raw_request(method, url, headers=None, allow_redirects=True):
            # server folds an injected CRLF value into a real response header
            from urllib.parse import urlsplit, parse_qs, unquote
            q = parse_qs(urlsplit(url).query)
            nxt = unquote(q.get("next", [""])[0])
            hdrs = {"location": "/home"}
            for line in nxt.replace("\r", "\n").split("\n"):
                if ":" in line:
                    k, _, v = line.partition(":")
                    hdrs[k.strip().lower()] = v.strip()
            return Response(status=302, headers=hdrs, text="", elapsed_ms=1.0, url=url)


def test_crlf_detector():
    hit = CrlfDetector().probe(lambda v: _resp(200, ""),
                               _IP("GET", "http://t/redirect", "query", "next"),
                               _resp(200, ""), _CrlfCtx())
    assert hit and hit["cwe"] == "CWE-113"


class _RedirCtx:
    extra = {}
    oast = None
    class http:
        @staticmethod
        def raw_request(method, url, headers=None, allow_redirects=True):
            from urllib.parse import urlsplit, parse_qs
            v = parse_qs(urlsplit(url).query).get("url", [""])[0]
            return Response(status=302, headers={"location": v or "/home"},
                            text="", elapsed_ms=1.0, url=url)


def test_open_redirect_detector():
    hit = OpenRedirectDetector().probe(lambda v: _resp(200, ""),
                                       _IP("GET", "http://t/goto", "query", "url"),
                                       _resp(200, ""), _RedirCtx())
    assert hit and hit["cwe"] == "CWE-601"


class _XxeCtx:
    extra = {}
    oast = None
    class http:
        @staticmethod
        def request(method, url, headers=None, data=None):
            if data and "file:///etc/passwd" in data:
                return Response(status=200, headers={"content-type": "application/xml"},
                                text="<ptiq><x>root:x:0:0:root:/root:/bin/bash</x></ptiq>",
                                elapsed_ms=1.0, url=url)
            return Response(status=200, headers={}, text="ok", elapsed_ms=1.0, url=url)


def test_xxe_detector_file_read():
    base = Response(status=200, headers={"content-type": "application/xml"},
                    text="<a/>", elapsed_ms=1.0, url="http://t/xml")
    hit = XxeDetector().probe(lambda v: _resp(200, ""),
                              _IP("POST", "http://t/xml", "body", "data"), base, _XxeCtx())
    assert hit and hit["cwe"] == "CWE-611"

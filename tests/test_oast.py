"""End-to-end OAST tests — collaborator server, client, and blind checks."""
import json
import urllib.request

from pentestiq.models import Asset, AssetType
from pentestiq.oast import OastServer, OastClient, extract_token
from pentestiq.checks.base import HttpClient, Response, CheckContext, Identity
from pentestiq.checks.oast_checks import BlindSsrfCheck, BlindXssCheck


# --------------------------------------------------------------- collaborator
def test_server_records_path_token_and_client_polls():
    srv = OastServer().start()
    try:
        client = OastClient.local(srv)
        h = client.new_token()
        assert not client.confirmed(h.token)
        # simulate a target fetching the payload URL out-of-band
        urllib.request.urlopen(h.http_url, timeout=5).read()
        hits = client.poll(h.token)
        assert hits and hits[0].method == "GET"
        assert client.confirmed(h.token)
    finally:
        srv.stop()


def test_remote_poll_over_http():
    srv = OastServer().start()
    try:
        remote = OastClient(base_url=srv.base_url)      # no in-process store -> HTTP poll
        h = remote.new_token()
        urllib.request.urlopen(h.http_url, timeout=5).read()
        assert remote.confirmed(h.token)
        # control-plane health endpoint is not itself recorded
        body = urllib.request.urlopen(srv.base_url + "/_oast/health", timeout=5).read()
        assert json.loads(body)["status"] == "ok"
    finally:
        srv.stop()


def test_extract_token_subdomain_and_path():
    assert extract_token("abc123def456.oast.example.com", "/") == "abc123def456"
    assert extract_token("collab:9099", "/abc123def456/x") == "abc123def456"
    assert extract_token("collab", "/") is None


# --------------------------------------------------------------- blind SSRF check
class SsrfHttp(HttpClient):
    """A target that performs a server-side fetch of any ?url= it receives."""
    def __init__(self):
        self.calls = []

    def request(self, method, url, headers=None, data=None):
        self.calls.append(url)
        from urllib.parse import urlsplit, parse_qs
        q = parse_qs(urlsplit(url).query)
        # VULN: server fetches the url param out-of-band (blind SSRF)
        if "url" in q:
            try:
                urllib.request.urlopen(q["url"][0], timeout=5).read()
            except Exception:
                pass
        return Response(status=200, headers={}, text="ok", elapsed_ms=1.0, url=url)

    def get(self, url, headers=None):
        return self.request("GET", url, headers)


def _ctx(http, oast, meta=None, **kw):
    asset = Asset(type=AssetType.WEB, identifier="http://target", metadata=meta or {})
    return CheckContext(asset=asset, base_url="http://target", http=http,
                        oast=oast, allow_active=True, extra=meta or {}, **kw)


def test_blind_ssrf_confirmed_out_of_band():
    srv = OastServer().start()
    try:
        client = OastClient.local(srv)
        http = SsrfHttp()
        ctx = _ctx(http, client, meta={"data_endpoints": ["/fetch"], "oast_wait": 0})
        findings = BlindSsrfCheck().run(ctx)
        assert findings, "expected a confirmed blind SSRF finding"
        assert findings[0].severity.value == "high"
        assert findings[0].category == "A10:2021"
        assert "out-of-band" in findings[0].title.lower()
    finally:
        srv.stop()


def test_blind_ssrf_no_finding_when_not_vulnerable():
    srv = OastServer().start()
    try:
        client = OastClient.local(srv)
        # a target that never fetches anything
        http = SsrfHttp(); http.request = lambda *a, **k: Response(200, {}, "ok", 1.0, "http://t")
        ctx = _ctx(http, client, meta={"data_endpoints": ["/fetch"], "oast_wait": 0})
        assert BlindSsrfCheck().run(ctx) == []
    finally:
        srv.stop()


def test_blind_ssrf_gated_without_oast_or_active():
    http = SsrfHttp()
    # no oast client -> not applicable
    ctx = _ctx(http, None, meta={"oast_wait": 0})
    assert BlindSsrfCheck().applicable(ctx) is False


# --------------------------------------------------------------- blind XSS (deferred)
class CaptureHttp(HttpClient):
    """Stores request bodies so a test can inspect the planted payload."""
    def __init__(self):
        self.bodies = []
    def request(self, method, url, headers=None, data=None):
        self.bodies.append(data or url)
        return Response(200, {}, "stored", 1.0, url)
    def get(self, url, headers=None):
        return self.request("GET", url, headers)


def test_blind_xss_deferred_then_confirmed():
    import re
    srv = OastServer().start()
    try:
        client = OastClient.local(srv)
        http = CaptureHttp()
        meta = {"discovered_forms": [{"action": "/comment", "method": "POST",
                                      "inputs": ["body"]}], "oast_wait": 0}
        ctx = _ctx(http, client, meta=meta)
        # first pass: payload planted, nothing rendered yet -> deferred, no finding
        assert BlindXssCheck().run(ctx) == []
        # the planted payload carries a working collaborator callback
        planted = " ".join(str(b) for b in http.bodies)
        m = re.search(r"//([^/]+)/([0-9a-f]{12,})\.js", planted)
        assert m, f"payload should embed a collaborator script URL: {planted[:120]}"
        host, token = m.group(1), m.group(2)
        assert not client.confirmed(token)
        # simulate an admin browser rendering the stored payload -> loads the script
        urllib.request.urlopen(f"{srv.base_url}/{token}.js", timeout=5).read()
        assert client.confirmed(token), "collaborator should record the out-of-band hit"
    finally:
        srv.stop()

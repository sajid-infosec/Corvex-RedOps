"""Tests for the new BFLA + unauthenticated-IDOR checks (OWASP API5 / API1)."""
from pentestiq.models import Asset, AssetType
from pentestiq.checks.base import HttpClient, Response
from pentestiq.checks.engine import build_context
from pentestiq.checks.authz_checks import BflaCheck, UnauthenticatedIdorCheck


class FakeHttp(HttpClient):
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, headers=None, data=None):
        self.calls.append((method, url))
        return self.handler(method, url, headers or {})


def _resp(status=200, text="", headers=None):
    return Response(status=status, headers={k.lower(): v for k, v in (headers or {}).items()},
                    text=text, elapsed_ms=1.0, url="http://t/")


def _ctx(http, meta=None):
    meta = dict(meta or {})
    meta.setdefault("base_url", "http://target")
    asset = Asset(type=AssetType.WEB, identifier="http://target", metadata=meta)
    return build_context(asset, http=http)


# --------------------------------------------------------------------------- BFLA
def test_bfla_flags_unauthenticated_admin_function():
    def handler(method, url, headers):
        if url.endswith("/api/admin/users"):
            return _resp(200, text='[{"id":1,"email":"a@x.com","role":"admin"}]')
        return _resp(404, text="not found")
    findings = BflaCheck().run(_ctx(FakeHttp(handler)))
    assert any("BFLA" in f.title and "/api/admin/users" in f.title for f in findings), \
        f"expected a BFLA finding, got {[f.title for f in findings]}"
    assert all(f.category == "API5:2023" for f in findings)


def test_bfla_ignores_login_page_and_denied():
    def handler(method, url, headers):
        if url.endswith("/admin"):
            return _resp(200, text='<form><input type="password" name="pw"> Sign in</form>')
        if url.endswith("/admin/users"):
            return _resp(401, text="unauthorized")
        if url.endswith("/manage"):
            return _resp(302, headers={"location": "/login"}, text="")
        return _resp(404, text="nope")
    findings = BflaCheck().run(_ctx(FakeHttp(handler)))
    assert findings == [], f"login/denied pages must not flag: {[f.title for f in findings]}"


def test_bfla_uses_discovered_admin_urls():
    def handler(method, url, headers):
        if "internal/report" in url:
            return _resp(200, text='{"revenue": 1200000, "accounts": 42}')
        return _resp(403, text="forbidden")
    meta = {"discovered_urls": ["http://target/api/internal/report"]}
    findings = BflaCheck().run(_ctx(FakeHttp(handler), meta))
    assert any("internal/report" in f.title for f in findings)


# --------------------------------------------------------------------------- unauth IDOR
def test_unauth_idor_flags_enumerable_objects():
    def handler(method, url, headers):
        # /api/user/1,2,3 each return different JSON, unauthenticated
        return _resp(200, text=f'{{"id":{url.rstrip("/").split("/")[-1]},"email":"u@x"}}')
    meta = {"idor_endpoints": ["/api/user/{id}"]}
    findings = UnauthenticatedIdorCheck().run(_ctx(FakeHttp(handler), meta))
    assert any("Unauthenticated IDOR" in f.title for f in findings)
    assert all(f.category == "API1:2023" for f in findings)


def test_unauth_idor_safe_when_protected():
    def handler(method, url, headers):
        return _resp(401, text="login required")
    meta = {"idor_endpoints": ["/api/user/{id}"]}
    findings = UnauthenticatedIdorCheck().run(_ctx(FakeHttp(handler), meta))
    assert findings == []


def test_unauth_idor_derives_from_discovered_urls():
    def handler(method, url, headers):
        n = url.rstrip("/").split("/")[-1]
        return _resp(200, text=f'{{"order":{n},"total":{int(n)*10}}}')
    meta = {"data_endpoints": ["http://target/api/order/5"]}
    findings = UnauthenticatedIdorCheck().run(_ctx(FakeHttp(handler), meta))
    assert any("Unauthenticated IDOR" in f.title for f in findings)


def test_unauth_idor_not_applicable_without_id_endpoints():
    http = FakeHttp(lambda *a: _resp(200, text="{}"))
    assert UnauthenticatedIdorCheck().applicable(_ctx(http, {})) is False

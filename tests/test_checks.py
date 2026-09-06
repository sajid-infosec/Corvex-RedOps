"""Tests for the native active-checks engine (OWASP web + API)."""
import base64
import hashlib
import hmac
import json

from pentestiq.models import Asset, AssetType, Severity
from pentestiq.checks.base import HttpClient, Response, CheckContext, Identity
from pentestiq.checks.config_checks import (
    SecurityHeadersCheck, ClickjackingCheck, CorsCheck, CookieFlagsCheck,
    HttpMethodsCheck, ErrorHandlingCheck,
)
from pentestiq.checks.jwt_analyzer import (
    JwtSecurityCheck, decode_jwt, crack_hmac_secret, forge_alg_none, b64url_encode,
)
from pentestiq.checks.authz_checks import (
    BolaIdorCheck, TenantConfusionCheck, ExcessiveDataExposureCheck,
    AccountEnumerationCheck, LoginRateLimitCheck,
)
from pentestiq.checks.engine import CheckEngine, build_context
from pentestiq.checks.owasp import normalize, describe, coverage_report


# --------------------------------------------------------------------------- helpers
class FakeHttp(HttpClient):
    """Programmable client. handler(method, url, headers, data) -> Response."""
    def __init__(self, handler):
        self.handler = handler
        self.calls = []

    def request(self, method, url, headers=None, data=None):
        self.calls.append((method, url, headers or {}, data))
        return self.handler(method, url, headers or {}, data)


def _resp(status=200, headers=None, text="", url="http://t/"):
    return Response(status=status, headers={k.lower(): v for k, v in (headers or {}).items()},
                    text=text, elapsed_ms=1.0, url=url)


def _asset(meta=None):
    return Asset(type=AssetType.WEB, identifier="http://target", metadata=meta or {})


def _ctx(http, meta=None, identities=None, **kw):
    return CheckContext(asset=_asset(meta), base_url="http://target", http=http,
                        identities=identities or [], **kw)


def _make_jwt(header, payload, secret=None, alg="HS256"):
    h = b64url_encode(json.dumps(header).encode())
    p = b64url_encode(json.dumps(payload).encode())
    signing = f"{h}.{p}".encode()
    if secret is None:
        sig = "AAAA"
    else:
        hasher = {"HS256": hashlib.sha256, "HS512": hashlib.sha512}[alg]
        sig = b64url_encode(hmac.new(secret.encode(), signing, hasher).digest())
    return f"{h}.{p}.{sig}"


# --------------------------------------------------------------------------- headers
def test_security_headers_flags_all_missing():
    http = FakeHttp(lambda m, u, h, d: _resp(200, {}, "ok"))
    findings = SecurityHeadersCheck().run(_ctx(http))
    titles = " ".join(f.title for f in findings)
    assert "HSTS" in titles and "Content-Security-Policy" in titles
    assert all(f.category == "A05:2021" for f in findings)


def test_security_headers_pass_when_present():
    hdrs = {"Strict-Transport-Security": "max-age=1", "Content-Security-Policy": "default-src 'self'",
            "X-Content-Type-Options": "nosniff", "Referrer-Policy": "no-referrer",
            "Permissions-Policy": "geolocation=()"}
    http = FakeHttp(lambda m, u, h, d: _resp(200, hdrs, "ok"))
    findings = SecurityHeadersCheck().run(_ctx(http))
    assert findings == []


def test_clickjacking_frame_ancestors_wildcard():
    http = FakeHttp(lambda m, u, h, d: _resp(200, {"content-security-policy": "frame-ancestors *"}))
    findings = ClickjackingCheck().run(_ctx(http))
    assert findings and findings[0].severity == Severity.MEDIUM


def test_clickjacking_pass_with_xfo_deny():
    http = FakeHttp(lambda m, u, h, d: _resp(200, {"x-frame-options": "DENY"}))
    assert ClickjackingCheck().run(_ctx(http)) == []


# --------------------------------------------------------------------------- cors
def test_cors_reflects_origin_with_credentials():
    def handler(m, u, h, d):
        origin = h.get("Origin", "")
        return _resp(200, {"access-control-allow-origin": origin,
                           "access-control-allow-credentials": "true"})
    findings = CorsCheck().run(_ctx(FakeHttp(handler)))
    assert findings and findings[0].severity == Severity.HIGH
    assert findings[0].category == "API8:2023"


def test_cors_pass_when_not_reflected():
    http = FakeHttp(lambda m, u, h, d: _resp(200, {"access-control-allow-origin": "https://trusted"}))
    assert CorsCheck().run(_ctx(http)) == []


# --------------------------------------------------------------------------- cookies / methods / errors
def test_cookie_flags_missing():
    http = FakeHttp(lambda m, u, h, d: _resp(200, {"set-cookie": "auth_token=x; Path=/"}))
    findings = CookieFlagsCheck().run(_ctx(http))
    assert findings and "HttpOnly" in findings[0].title


def test_http_methods_dangerous():
    http = FakeHttp(lambda m, u, h, d: _resp(200, {"allow": "GET, PUT, DELETE"}))
    findings = HttpMethodsCheck().run(_ctx(http))
    assert findings and "PUT" in findings[0].title


def test_error_handling_leaks_java_trace():
    body = 'at com.vcon.gateway.Handler(Handler.java:42) com.vcon.gatewayException'
    http = FakeHttp(lambda m, u, h, d: _resp(500, {}, body))
    findings = ErrorHandlingCheck().run(_ctx(http))
    assert findings and "Java" in findings[0].title


# --------------------------------------------------------------------------- jwt
def test_decode_and_crack_weak_secret():
    tok = _make_jwt({"alg": "HS256"}, {"role": "user"}, secret="secret")
    hdr, pl, sig = decode_jwt(tok)
    assert hdr["alg"] == "HS256" and pl["role"] == "user"
    assert crack_hmac_secret(tok, ["nope", "secret"]) == "secret"


def test_jwt_check_flags_weak_secret_and_embedded_token():
    payload = {"role": "Owner", "access_token": "syt_abc123",
               "permission": {"a": True, "b": True, "c": True, "d": True},
               "iat": 0, "exp": 86400}
    tok = _make_jwt({"alg": "HS512"}, payload, secret="company", alg="HS512")
    meta = {"jwt": tok}
    findings = JwtSecurityCheck().run(_ctx(FakeHttp(lambda *a: _resp()), meta=meta))
    titles = " | ".join(f.title for f in findings)
    assert "weak/guessable" in titles
    assert "sensitive claim" in titles
    assert "long" in titles.lower()
    # weak secret + embedded token => at least one CRITICAL
    assert any(f.severity == Severity.CRITICAL for f in findings)


def test_jwt_none_alg_probe_accepted():
    payload = {"role": "user", "iat": 0, "exp": 100}
    tok = _make_jwt({"alg": "HS256"}, payload, secret="x" * 40)  # strong secret, won't crack
    meta = {"jwt": tok, "jwt_probe_url": "/api/me"}
    def handler(m, u, h, d):
        auth = h.get("Authorization", "")
        # server (wrongly) accepts the none-alg forged token
        return _resp(200, {}, "welcome") if ".." in auth or auth.endswith(".") else _resp(401)
    findings = JwtSecurityCheck().run(_ctx(FakeHttp(handler), meta=meta))
    assert any("none" in f.title.lower() and f.severity == Severity.CRITICAL for f in findings)


def test_forge_alg_none_shape():
    t = forge_alg_none({"a": 1})
    assert t.endswith(".") and t.count(".") == 2


# --------------------------------------------------------------------------- BOLA / authz
def test_bola_cross_identity_read():
    idents = [
        Identity(name="A", headers={"Authorization": "Bearer a"}, object_ids=["id-a"]),
        Identity(name="B", headers={"Authorization": "Bearer b"}, object_ids=["id-b"]),
    ]
    def handler(m, u, h, d):
        # server returns data for ANY id regardless of caller (vulnerable)
        return _resp(200, {}, json.dumps({"user": "victim", "email": "v@x.com"}))
    ctx = _ctx(FakeHttp(handler), identities=idents, idor_endpoints=["/api/user/{id}"])
    findings = BolaIdorCheck().run(ctx)
    assert findings and findings[0].severity == Severity.CRITICAL
    assert findings[0].category == "API1:2023"


def test_bola_pass_when_forbidden():
    idents = [
        Identity(name="A", headers={"Authorization": "Bearer a"}, object_ids=["id-a"]),
        Identity(name="B", headers={"Authorization": "Bearer b"}, object_ids=["id-b"]),
    ]
    http = FakeHttp(lambda m, u, h, d: _resp(403, {}, "forbidden"))
    ctx = _ctx(http, identities=idents, idor_endpoints=["/api/user/{id}"])
    assert BolaIdorCheck().run(ctx) == []


def test_tenant_confusion():
    idents = [
        Identity(name="A", headers={"Authorization": "Bearer a"}, object_ids=["id-a"]),
        Identity(name="B", headers={"Authorization": "Bearer b"}, object_ids=["id-b"]),
    ]
    def handler(m, u, h, d):
        return _resp(200, {}, "id-b data") if "userId=id-b" in u else _resp(200, {}, "own")
    meta = {"tenant_params": [{"url": "/api/meetings", "param": "userId"}]}
    ctx = _ctx(FakeHttp(handler), meta=meta, identities=idents)
    findings = TenantConfusionCheck().run(ctx)
    assert findings and "tenant confusion" in findings[0].title.lower()


def test_excessive_data_exposure_bcrypt():
    idents = [Identity(name="A", headers={"Authorization": "Bearer a"})]
    body = json.dumps({"name": "x", "userPass": "$2a$06$abcdefghijklmnopqrstuv1234567890ABCDEFGHIJKLMNOPQR"})
    http = FakeHttp(lambda m, u, h, d: _resp(200, {}, body))
    ctx = _ctx(http, meta={"data_endpoints": ["/api/user/me"]}, identities=idents)
    findings = ExcessiveDataExposureCheck().run(ctx)
    assert findings and any("sensitive" in f.title.lower() for f in findings)


def test_account_enumeration_distinguishable():
    def handler(m, u, h, d):
        body = json.loads(d)
        return _resp(200, {}, "reset link sent") if body.get("email") == "real@x.com" else _resp(404, {}, "no")
    ctx = _ctx(FakeHttp(handler), login={"url": "/auth/forgot", "field": "email",
                                          "valid_user": "real@x.com", "invalid_user": "no@x.com"})
    findings = AccountEnumerationCheck().run(ctx)
    assert findings and findings[0].category == "A07:2021"


def test_login_rate_limit_absent_gated_by_active():
    http = FakeHttp(lambda m, u, h, d: _resp(400, {}, "bad creds"))
    login = {"url": "/auth/login", "valid_user": "a@x.com", "password_field": "password"}
    # not active -> not applicable
    ctx = _ctx(http, login=login, allow_active=False)
    assert LoginRateLimitCheck().applicable(ctx) is False
    # active -> runs and flags missing limit
    ctx2 = _ctx(http, meta={"rate_limit_attempts": 5}, login=login, allow_active=True)
    findings = LoginRateLimitCheck().run(ctx2)
    assert findings and findings[0].severity == Severity.HIGH


# --------------------------------------------------------------------------- engine + owasp
def test_engine_runs_applicable_only():
    http = FakeHttp(lambda m, u, h, d: _resp(200, {}, "ok"))
    findings = CheckEngine().run(build_context(_asset(), http=http))
    # unauthenticated: header/clickjacking/methods checks fire; authz checks skip
    assert any(f.category == "A05:2021" for f in findings)
    assert not any(f.category == "API1:2023" for f in findings)


def test_owasp_normalize_and_coverage():
    assert normalize("A05") == "A05:2021"
    assert normalize("api1:2023") == "API1:2023"
    assert describe("A01") == "Broken Access Control"
    from pentestiq.models import Finding
    fs = [Finding(asset=_asset(), title="x", category="API1:2023", severity=Severity.CRITICAL)]
    cov = coverage_report(fs)
    api1 = [c for c in cov["api-2023"] if c["id"] == "API1:2023"][0]
    assert api1["findings"] == 1 and api1["max_severity"] == "critical"

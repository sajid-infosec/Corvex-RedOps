"""Burp-parity: new active detectors, passive checks, and the coverage catalogue."""
from pentestiq.checks.base import Response, CheckContext
from pentestiq.models import Asset, AssetType
from pentestiq.fuzzing.points import InjectionPoint as IP
from pentestiq.fuzzing.detectors import (
    XpathInjectionDetector, LdapInjectionDetector, CodeInjectionDetector,
    SsiInjectionDetector, CssInjectionDetector)


def _r(status=200, text="", headers=None, ms=1.0, url="http://t/"):
    return Response(status=status, headers=headers or {}, text=text, elapsed_ms=ms, url=url)


class _Ctx:
    extra = {"fuzz_time_delay": 1}
    oast = None


# ---------------- active detectors ----------------
def test_xpath_error():
    send = lambda v: _r(500, "org.apache.xpath: unclosed token") if "'" in v else _r(200, "ok")
    hit = XpathInjectionDetector().probe(send, IP("GET", "http://t/x", "query", "q"), _r(200, "ok"), _Ctx())
    assert hit and hit["cwe"] == "CWE-643"


def test_ldap_error():
    send = lambda v: _r(500, "javax.naming.directory: Invalid DN syntax") if "*" in v else _r(200, "ok")
    hit = LdapInjectionDetector().probe(send, IP("GET", "http://t/x", "query", "q"), _r(200, "ok"), _Ctx())
    assert hit and hit["cwe"] == "CWE-90"


def test_code_injection_eval_and_error():
    # eval path: ${93*93} -> 8649
    send = lambda v: _r(200, "result=8649") if "93*93" in v else _r(200, "x")
    hit = CodeInjectionDetector().probe(send, IP("GET", "http://t/x", "query", "q"), _r(200, "x"), _Ctx())
    assert hit and hit["cwe"] == "CWE-94"
    # error path
    send2 = lambda v: _r(200, "Traceback (most recent call last): NameError:") if ";" in v or "import" in v else _r(200, "x")
    hit2 = CodeInjectionDetector().probe(send2, IP("GET", "http://t/x", "query", "q"), _r(200, "x"), _Ctx())
    assert hit2 and "Python" in hit2["class"]


def test_css_injection_reflected_in_style():
    def send(v):
        return _r(200, f"<style>body{{}} {v} </style>") if "{" in v else _r(200, "x")
    hit = CssInjectionDetector().probe(send, IP("GET", "http://t/x", "query", "q"), _r(200, "x"), _Ctx())
    assert hit and hit["class"].startswith("CSS injection")


def test_ssi_oast():
    class FakeTok:
        host = "oast.example"; token = "abc"
    class FakeOast:
        def new_token(self): return FakeTok()
        def poll(self, tok): return True
    class C(_Ctx): oast = FakeOast()
    hit = SsiInjectionDetector().probe(lambda v: _r(200, "ok"), IP("GET", "http://t/x", "query", "q"), _r(200, "x"), C())
    assert hit and hit["cwe"] == "CWE-97"


# ---------------- passive checks ----------------
class FakeHttp:
    def __init__(self, routes=None, base=None):
        self.routes = routes or {}; self.base = base
    def get(self, url, headers=None):
        for k, v in self.routes.items():
            if k in url:
                return v(headers) if callable(v) else v
        return self.base if self.base else _r(404, "", url=url)
    def request(self, method, url, headers=None, data=None):
        return self.get(url, headers)


def _ctx(http, base="https://app.example.com", extra=None, allow_active=False):
    a = Asset(type=AssetType.WEB, identifier=base)
    ex = {"_base_resp": None}; ex.update(extra or {})
    return CheckContext(asset=a, base_url=base, http=http, allow_active=allow_active, extra=ex)


def test_csp_analyzer():
    from pentestiq.checks.web_passive import CspAnalyzerCheck
    resp = _r(200, "ok", {"content-security-policy": "default-src 'self'; script-src 'unsafe-inline' *"})
    out = CspAnalyzerCheck().run(_ctx(FakeHttp(base=resp)))
    titles = " ".join(f.title for f in out)
    assert "untrusted script" in titles and "clickjacking" in titles and "form hijacking" in titles


def test_cross_domain_policy():
    from pentestiq.checks.web_passive import CrossDomainPolicyCheck
    xml = _r(200, '<?xml version="1.0"?><cross-domain-policy><allow-access-from domain="*"/></cross-domain-policy>',
             {"content-type": "text/xml"})
    http = FakeHttp(routes={"/crossdomain.xml": xml}, base=_r(404))
    out = CrossDomainPolicyCheck().run(_ctx(http))
    assert out and "any domain" in out[0].title


def test_graphql_introspection():
    from pentestiq.checks.web_passive import GraphqlCheck
    http = FakeHttp(routes={"/graphql": _r(200, '{"data":{"__schema":{"queryType":{"name":"Query"}}}}')}, base=_r(404))
    out = GraphqlCheck().run(_ctx(http))
    assert out and "introspection" in out[0].title.lower()


def test_cookie_audit():
    from pentestiq.checks.web_passive import CookieAuditCheck
    resp = _r(200, "ok", {"set-cookie": "sessionid=abc; Path=/; Domain=.example.com"})
    out = CookieAuditCheck().run(_ctx(FakeHttp(base=resp)))
    titles = " ".join(f.title for f in out)
    assert "HttpOnly" in titles and "Secure" in titles and "SameSite" in titles and "parent domain" in titles


def test_info_disclosure():
    from pentestiq.checks.web_passive import InfoDisclosureCheck
    body = ("contact a@x.com and b@x.com; jdbc:mysql://db/app?user=root&password=secret; "
            "-----BEGIN RSA PRIVATE KEY-----")
    out = InfoDisclosureCheck().run(_ctx(FakeHttp(base=_r(200, body)), extra={}))
    titles = " ".join(f.title for f in out)
    assert "Private key" in titles and "connection string" in titles and "Email" in titles


def test_sensitive_transport_and_host_header():
    from pentestiq.checks.web_passive import SensitiveTransportCheck, HostHeaderInjectionCheck
    ctx = _ctx(FakeHttp(base=_r(200, "")), extra={"discovered_urls": ["https://app.example.com/r?token=abc123"]})
    out = SensitiveTransportCheck().run(ctx)
    assert any("Session token in URL" in f.title for f in out)
    # host header
    def route(headers=None):
        m = (headers or {}).get("Host") or (headers or {}).get("X-Forwarded-Host") or ""
        return _r(200, "", {"location": "https://" + m + "/next"})
    hctx = _ctx(FakeHttp(base=None, routes={"app.example.com": route}), allow_active=True)
    hctx.http.routes = {"": route}
    out2 = HostHeaderInjectionCheck().run(hctx)
    assert any("Host header injection" in f.title for f in out2)


def test_catalog_summary():
    from pentestiq.checks.burp_catalog import coverage_summary
    c = coverage_summary()
    assert c["total"] > 120 and c["covered"] > 50 and c["weighted_pct"] > 45
    assert all(set(x) >= {"index", "name", "kind", "coverage"} for x in c["checks"])

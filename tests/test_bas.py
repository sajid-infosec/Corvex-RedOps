"""D3 — BAS-lite defensive-control validation: benign checks, opt-in, API."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pentestiq.bas import run_bas, report_dict, DEFENDED, EXPOSED, INCONCLUSIVE
from pentestiq.checks.base import Response, HttpClient
from pentestiq.models import Engagement, Scope, Asset, AssetType
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


class FakeHttp(HttpClient):
    """Serves a hardened or exposed target for the benign checks."""

    def __init__(self, hardened=True, rate_limited=False, admin_open=False):
        self.hardened = hardened
        self.rate_limited = rate_limited
        self.admin_open = admin_open
        self.calls = 0

    def request(self, method, url, headers=None, data=None):
        self.calls += 1
        if (self.rate_limited and method == "GET" and self.calls > 3
                and url.rstrip("/") == "https://app.example.com"):
            return Response(status=429, headers={"retry-after": "5"}, text="slow down", elapsed_ms=1, url=url)
        if self.hardened:
            hd = {"strict-transport-security": "max-age=63072000", "x-frame-options": "DENY",
                  "x-content-type-options": "nosniff", "cf-ray": "abc",
                  "set-cookie": "sid=x; Secure; HttpOnly", "server": "cloudflare",
                  "allow": "GET, POST, HEAD, OPTIONS"}
            body = "<html>ok</html>"
            if any(p in url for p in ("/admin", "/.git", "/.env")):
                return Response(status=403, headers=hd, text="forbidden", elapsed_ms=1, url=url)
            return Response(status=200, headers=hd, text=body, elapsed_ms=1, url=url)
        # exposed target
        hd = {"server": "Apache/2.4.29", "x-powered-by": "PHP/7.2", "set-cookie": "sid=x",
              "allow": "GET, POST, PUT, DELETE, TRACE, OPTIONS"}
        body = "<title>Index of /assets</title>" if "/assets" in url else "<html>page</html>"
        return Response(status=200, headers=hd, text=body, elapsed_ms=1, url=url)

    def raw_request(self, method, url, headers=None, data=None, allow_redirects=True):
        if self.hardened and url.startswith("http://"):
            return Response(status=301, headers={"location": "https://app.example.com/"},
                            text="", elapsed_ms=1, url=url)
        return self.request(method, url, headers, data)


# ---- opt-in gate --------------------------------------------------------
def test_requires_authorization():
    rep = run_bas("https://app.example.com", http=FakeHttp())
    assert rep.authorized is False and rep.results == []
    d = report_dict(rep)
    assert d["authorized"] is False and "authorization" in d["error"].lower()


def test_authorized_runs_checks():
    rep = run_bas("https://app.example.com", http=FakeHttp(hardened=True), authorized=True)
    assert rep.authorized is True and len(rep.results) == 10


# ---- hardened vs exposed ------------------------------------------------
def test_hardened_target_scores_high():
    d = report_dict(run_bas("https://app.example.com",
                            http=FakeHttp(hardened=True, rate_limited=True, admin_open=False),
                            authorized=True))
    by = {r["id"]: r["status"] for r in d["results"]}
    assert by["tls-enforcement"] == DEFENDED
    assert by["waf-presence"] == DEFENDED
    assert by["clickjacking"] == DEFENDED
    assert by["cookie-security"] == DEFENDED
    assert by["nosniff"] == DEFENDED
    assert by["http-methods"] == DEFENDED
    assert by["admin-exposure"] == DEFENDED       # 403 on /admin
    assert d["defense_score"] >= 80


def test_exposed_target_flags_gaps():
    d = report_dict(run_bas("https://app.example.com",
                            http=FakeHttp(hardened=False), authorized=True))
    by = {r["id"]: r["status"] for r in d["results"]}
    assert by["tls-enforcement"] == EXPOSED
    assert by["clickjacking"] == EXPOSED
    assert by["http-methods"] == EXPOSED          # TRACE/PUT/DELETE advertised
    assert by["dir-listing"] == EXPOSED           # autoindex
    assert by["banner-min"] == EXPOSED            # verbose banners
    assert d["defense_score"] == 0


def test_coverage_maps_to_attack():
    d = report_dict(run_bas("https://app.example.com", http=FakeHttp(), authorized=True))
    cov = {c["check"]: c for c in d["coverage"]}
    assert cov["tls-enforcement"]["technique"] == "T1557"
    assert cov["tls-enforcement"]["technique_name"] and cov["tls-enforcement"]["tactic_name"]
    assert cov["admin-exposure"]["technique"] == "T1078"


# ---- API ----------------------------------------------------------------
@pytest.fixture
def ctx(tmp_path, monkeypatch):
    # make the API use our fake http so no real network is touched
    import pentestiq.bas.runner as runner
    orig = runner.run_bas
    monkeypatch.setattr(runner, "run_bas",
                        lambda base, http=None, **kw: orig(base, http=FakeHttp(hardened=True), **kw))
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}, store


def _eng_with_web(store, tid):
    eng = Engagement(name="e", scope=Scope(name="s", in_scope=["https://app.example.com"]),
                     assets=[Asset(type=AssetType.WEB, identifier="https://app.example.com")])
    return store.create(tid, eng, status="completed")


def test_api_bas_requires_authorized(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    rec = _eng_with_web(store, tid)
    # missing authorization → 403
    assert c.post(f"/engagements/{rec.id}/bas", headers=H, json={}).status_code == 403
    assert c.post(f"/engagements/{rec.id}/bas", headers=H,
                  json={"authorized": False}).status_code == 403


def test_api_bas_runs_when_authorized(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    rec = _eng_with_web(store, tid)
    r = c.post(f"/engagements/{rec.id}/bas", headers=H, json={"authorized": True})
    assert r.status_code == 200
    d = r.json()
    assert d["authorized"] is True and len(d["results"]) == 10
    assert d["defense_score"] >= 50 and d["coverage"]


def test_api_bas_no_web_target(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    eng = Engagement(name="infra", scope=Scope(name="s", in_scope=["10.0.0.5"]),
                     assets=[Asset(type=AssetType.INFRA, identifier="10.0.0.5")])
    rec = store.create(tid, eng, status="completed")
    r = c.post(f"/engagements/{rec.id}/bas", headers=H, json={"authorized": True})
    assert r.status_code == 422

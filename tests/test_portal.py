"""F3 — read-only client portal: tokenized share, public read-only, no write."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest
from fastapi.testclient import TestClient

from pentestiq.workflow.portal import SqlitePortalStore
from pentestiq.models import (Finding, Asset, AssetType, Severity, Engagement, Scope)
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


# ---- store --------------------------------------------------------------
def test_store_resolve_expiry_revoke(tmp_path):
    s = SqlitePortalStore(str(tmp_path / "p.db"))
    sh = s.create("t1", "e1", label="client")
    assert sh.token.startswith("ptq_") and s.resolve(sh.token).engagement_id == "e1"
    # expired
    exp = s.create("t1", "e1", expires_days=1)
    exp.expires_at = (datetime.now(timezone.utc) - timedelta(days=1)).isoformat()
    # simulate expiry by writing a past date
    s._conn.execute("UPDATE portal_shares SET expires_at=? WHERE token=?",
                    (exp.expires_at, exp.token)); s._conn.commit()
    assert s.resolve(exp.token) is None
    # revoke
    assert s.revoke("t1", sh.token) and s.resolve(sh.token) is None
    assert s.resolve("nope") is None


# ---- API ----------------------------------------------------------------
@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}, store


def _eng(store, tid):
    a = Asset(type=AssetType.WEB, identifier="https://app.example.com")
    eng = Engagement(name="Client scan", scope=Scope(name="s"), assets=[a])
    eng.add_findings([Finding(asset=a, title="SQL injection", category="A03:2021",
                              severity=Severity.CRITICAL, location="/s")])
    return store.create(tid, eng, status="completed")


def test_share_and_public_read(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    rec = _eng(store, tid)
    sh = c.post(f"/engagements/{rec.id}/share", headers=H, json={"expires_days": 30}).json()
    assert sh["token"].startswith("ptq_") and sh["path"] == "/portal/" + sh["token"]
    # public portal HTML — NO auth header
    r = c.get(f"/portal/{sh['token']}")
    assert r.status_code == 200 and "text/html" in r.headers["content-type"]
    assert "SQL injection" in r.text and "Read-only shared report" in r.text
    # public JSON data — no auth
    d = c.get(f"/portal/{sh['token']}/data").json()
    assert d["name"] == "Client scan" and d["severity"]["critical"] == 1
    assert any("SQL injection" in f["title"] for f in d["findings"])


def test_share_listed_and_revocable(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    rec = _eng(store, tid)
    sh = c.post(f"/engagements/{rec.id}/share", headers=H, json={}).json()
    lst = c.get(f"/engagements/{rec.id}/shares", headers=H).json()
    assert any(s["token"] == sh["token"] for s in lst)
    assert c.delete(f"/shares/{sh['token']}", headers=H).status_code == 204
    # revoked → public link now 404s
    assert c.get(f"/portal/{sh['token']}").status_code == 404


def test_invalid_token_and_no_write_path(ctx):
    c, H, store = ctx
    assert c.get("/portal/ptq_bogus").status_code == 404
    # the portal exposes only GETs — there is no write endpoint under /portal
    assert c.post("/portal/ptq_bogus").status_code in (404, 405)


def test_portal_pdf(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    rec = _eng(store, tid)
    sh = c.post(f"/engagements/{rec.id}/share", headers=H, json={}).json()
    r = c.get(f"/portal/{sh['token']}?format=pdf")
    assert r.status_code == 200 and r.headers["content-type"] == "application/pdf"

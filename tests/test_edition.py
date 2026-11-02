"""Edition / tier gating (open-core) — Community is free; Pro/Team/Enterprise unlock
the managed/scale surface. The rest of the suite runs under CORVEX_EDITION=enterprise
(conftest), so these tests set the edition explicitly to assert gating behaviour."""
import pytest
from fastapi.testclient import TestClient

from pentestiq import edition as ed
from pentestiq.edition import Edition, FeatureLocked, FEATURES
from pentestiq.api.app import create_app
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


# ----------------------------------------------------------------- unit
def test_detect_edition_from_env(monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "community")
    assert ed.current_edition() is Edition.COMMUNITY
    monkeypatch.setenv("CORVEX_EDITION", "premium")      # alias -> enterprise
    assert ed.current_edition() is Edition.ENTERPRISE
    monkeypatch.setenv("CORVEX_EDITION", "team")
    assert ed.current_edition() is Edition.TEAM


def test_is_enabled_matrix(monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "community")
    assert not ed.is_enabled("client_portal")
    assert not ed.is_enabled("continuous_scheduling")
    assert ed.is_enabled("some_core_capability")          # unknown key -> free/core
    monkeypatch.setenv("CORVEX_EDITION", "pro")
    assert ed.is_enabled("client_portal") and ed.is_enabled("ticketing")
    assert not ed.is_enabled("continuous_scheduling")     # Team
    assert not ed.is_enabled("sso_saml")                  # Enterprise
    monkeypatch.setenv("CORVEX_EDITION", "enterprise")
    assert all(ed.is_enabled(f) for f in FEATURES)


def test_require_raises_feature_locked(monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "community")
    with pytest.raises(FeatureLocked):
        ed.require("client_portal")
    monkeypatch.setenv("CORVEX_EDITION", "enterprise")
    ed.require("client_portal")                           # no raise


def test_limits_per_edition(monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "community")
    assert ed.limit("max_workspaces") == 1 and ed.limit("max_schedules") == 0
    monkeypatch.setenv("CORVEX_EDITION", "enterprise")
    assert ed.limit("max_workspaces") is None


# ----------------------------------------------------------------- API
@pytest.fixture
def mkclient(tmp_path):
    def _make():
        db = str(tmp_path / "t.db")
        auth = AuthService(SqliteAuthStore(db), "test-secret", 3600)
        return TestClient(create_app(store=SqliteEngagementStore(db), auth=auth))
    return _make


def _tok(c):
    return c.post("/auth/register", json={"tenant_name": "T", "username": "owner",
                                          "password": "password123"}).json()["token"]


def test_community_gates_premium_routes(monkeypatch, mkclient):
    monkeypatch.setenv("CORVEX_EDITION", "community")
    c = mkclient()
    H = {"Authorization": f"Bearer {_tok(c)}"}
    assert c.post("/schedules", headers=H,
                  json={"name": "n", "interval_seconds": 3600}).status_code == 402
    assert c.post("/projects", headers=H, json={"name": "p"}).status_code == 402
    assert c.put("/settings/tickets", headers=H,
                 json={"system": "webhook", "endpoint": "http://x"}).status_code == 402
    r = c.post("/engagements/abc/share", headers=H, json={})
    assert r.status_code == 402 and r.json()["detail"]["feature"] == "client_portal"


def test_enterprise_allows_premium_routes(monkeypatch, mkclient):
    monkeypatch.setenv("CORVEX_EDITION", "enterprise")
    c = mkclient()
    H = {"Authorization": f"Bearer {_tok(c)}"}
    assert c.post("/projects", headers=H, json={"name": "p"}).status_code == 201


def test_edition_endpoint(monkeypatch, mkclient):
    monkeypatch.setenv("CORVEX_EDITION", "pro")
    j = mkclient().get("/edition").json()
    assert j["edition"] == "Pro"
    assert j["features"]["client_portal"] is True
    assert j["features"]["continuous_scheduling"] is False
    assert j["limits"]["max_schedules"] == 10

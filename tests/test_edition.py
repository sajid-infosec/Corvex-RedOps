"""Edition gating (open-core) — two plans: Community is free (core engine only);
Premium unlocks everything else. Legacy tier names (pro/team/enterprise) are aliases
of Premium. The rest of the suite runs under CORVEX_EDITION=enterprise (conftest,
also an alias of Premium), so these tests set the edition explicitly."""
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
    monkeypatch.setenv("CORVEX_EDITION", "premium")
    assert ed.current_edition() is Edition.PREMIUM
    # legacy tier names all collapse into Premium
    for legacy in ("pro", "team", "enterprise"):
        monkeypatch.setenv("CORVEX_EDITION", legacy)
        assert ed.current_edition() is Edition.PREMIUM


def test_is_enabled_matrix(monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "community")
    assert not ed.is_enabled("client_portal")
    assert not ed.is_enabled("continuous_scheduling")
    assert not ed.is_enabled("darkweb_intel")
    assert ed.is_enabled("some_core_capability")          # unknown key -> free/core
    # Premium unlocks every gated feature
    monkeypatch.setenv("CORVEX_EDITION", "premium")
    assert all(ed.is_enabled(f) for f in FEATURES)


def test_require_raises_feature_locked(monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "community")
    with pytest.raises(FeatureLocked):
        ed.require("client_portal")
    monkeypatch.setenv("CORVEX_EDITION", "premium")
    ed.require("client_portal")                           # no raise


def test_limits_per_edition(monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "community")
    assert ed.limit("max_workspaces") == 1 and ed.limit("max_schedules") == 0
    monkeypatch.setenv("CORVEX_EDITION", "premium")
    assert ed.limit("max_workspaces") is None and ed.limit("max_schedules") is None


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


def test_premium_allows_premium_routes(monkeypatch, mkclient):
    monkeypatch.setenv("CORVEX_EDITION", "premium")
    c = mkclient()
    H = {"Authorization": f"Bearer {_tok(c)}"}
    assert c.post("/projects", headers=H, json={"name": "p"}).status_code == 201


def test_edition_endpoint(monkeypatch, mkclient):
    monkeypatch.setenv("CORVEX_EDITION", "premium")
    j = mkclient().get("/edition").json()
    assert j["edition"] == "Premium"
    assert j["features"]["client_portal"] is True
    assert j["features"]["continuous_scheduling"] is True
    assert j["features"]["darkweb_intel"] is True
    assert j["limits"]["max_schedules"] is None

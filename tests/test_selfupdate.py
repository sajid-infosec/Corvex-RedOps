"""Tests for the self-update / feed-refresh service and its endpoints.

Network-free and non-mutating: the real ``git pull`` / re-exec path is never
executed here — only the read-only status, the offline feed refresh, and the
container / non-git guard branches.
"""
import pytest
from fastapi.testclient import TestClient

from pentestiq import selfupdate
from pentestiq import __version__
from pentestiq.api.app import create_app
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


# --------------------------------------------------------------------- module
def test_in_container_returns_bool():
    assert isinstance(selfupdate.in_container(), bool)


def test_update_status_shape():
    st = selfupdate.update_status(None)
    assert st["version"] == __version__
    assert st["mode"] in ("native-git", "docker", "pip")
    assert "git" in st and "feeds" in st
    assert isinstance(st["can_self_update"], bool)


def test_git_info_detects_checkout():
    info = selfupdate.git_info(fetch=False)
    assert "is_repo" in info
    if info["is_repo"]:
        assert "branch" in info and "behind" in info


def test_apply_update_blocked_in_container(monkeypatch):
    monkeypatch.setattr(selfupdate, "in_container", lambda: True)
    res = selfupdate.apply_update()
    assert res["ok"] is False and res["mode"] == "docker"
    assert "install.sh --update" in res["message"]


def test_apply_update_blocked_without_git(monkeypatch):
    monkeypatch.setattr(selfupdate, "in_container", lambda: False)
    monkeypatch.setattr(selfupdate, "git_info", lambda fetch=False: {"is_repo": False})
    res = selfupdate.apply_update()
    assert res["ok"] is False and res["mode"] == "pip"


def test_refresh_feeds_offline_is_graceful():
    class FakeIntel:
        def refresh_stale(self, max_age_days=7, exploit=True):
            return {"ok": True, "kev": 0, "offline": True}
        def info(self):
            return {"kev_count": 0, "epss_cached": 0, "offline": True}
    out = selfupdate.refresh_feeds(FakeIntel(), templates=False)
    assert out["ok"] is True
    assert "intel" in out["parts"]
    assert "feeds" in out


# --------------------------------------------------------------------- endpoints
@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "t.db")
    estore = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="test-secret", session_ttl=3600)
    return TestClient(create_app(store=estore, auth=auth))


def _owner(c):
    r = c.post("/auth/register", json={"tenant_name": "T", "username": "owner", "password": "password123"})
    assert r.status_code == 201, r.text
    return {"Authorization": f"Bearer {r.json()['token']}"}


def test_update_status_endpoint(ctx):
    h = _owner(ctx)
    r = ctx.get("/update/status", headers=h)
    assert r.status_code == 200
    body = r.json()
    assert body["version"] == __version__ and "mode" in body


def test_update_endpoints_require_auth(ctx):
    # unauthenticated callers never reach the handler (no network, no git)
    assert ctx.post("/update/feeds").status_code == 401
    assert ctx.post("/update/apply").status_code == 401
    assert ctx.post("/update/check").status_code == 401

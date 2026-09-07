"""Engagement delete endpoint + scan time-budget (deadline) behaviour."""
import os

import pytest
from fastapi.testclient import TestClient

from pentestiq.api.app import create_app
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.core.runcontrol import RunControl, ScanCancelled


@pytest.fixture
def client(tmp_path):
    db = str(tmp_path / "t.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="test-secret", session_ttl=3600)
    return TestClient(create_app(store=SqliteEngagementStore(db), auth=auth))


def _owner(client):
    tok = client.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return {"Authorization": "Bearer " + tok}


# ---- delete engagement --------------------------------------------------
def test_delete_engagement(client):
    H = _owner(client)
    eid = client.post("/engagements", headers=H,
                      json={"engagement": {"name": "DelMe"}, "scope": {"in_scope": ["web=http://x"]}}).json()["id"]
    assert any(e["id"] == eid for e in client.get("/engagements", headers=H).json())
    r = client.delete("/engagements/" + eid, headers=H)
    assert r.status_code == 204
    assert client.get("/engagements/" + eid, headers=H).status_code == 404
    assert not any(e["id"] == eid for e in client.get("/engagements", headers=H).json())
    # deleting again -> 404
    assert client.delete("/engagements/" + eid, headers=H).status_code == 404


def test_delete_requires_member(client):
    H = _owner(client)
    eid = client.post("/engagements", headers=H,
                      json={"engagement": {"name": "x"}, "scope": {"in_scope": ["web=http://x"]}}).json()["id"]
    client.post("/users", headers=H, json={"username": "ro", "password": "readonly1", "role": "viewer"})
    vt = client.post("/auth/login", json={"username": "ro", "password": "readonly1"}).json()["token"]
    VH = {"Authorization": "Bearer " + vt}
    assert client.delete("/engagements/" + eid, headers=VH).status_code == 403


# ---- scan time budget ---------------------------------------------------
def test_default_scan_budget_is_generous():
    # the bug: default was 900s (15 min); now a generous 4h, env-overridable
    assert AppConfig().scan_timeout_s >= 14400


def test_scan_timeout_env_override(monkeypatch):
    monkeypatch.setenv("PENTESTIQ_SCAN_TIMEOUT_S", "7200")
    assert AppConfig().scan_timeout_s == 7200


def test_deadline_marks_reason_not_user():
    rc = RunControl("e", deadline_s=0)          # already past the budget
    with pytest.raises(ScanCancelled):
        rc.check()
    assert rc.stop_reason == "deadline"
    assert rc.snapshot()["stop_reason"] == "deadline"


def test_user_stop_marks_reason_user():
    rc = RunControl("e2", deadline_s=9999)
    rc.stop()
    assert rc.stop_reason == "user"

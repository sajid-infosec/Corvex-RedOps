"""RBAC team management + scan-control endpoints."""
import pytest
from fastapi.testclient import TestClient
from pentestiq.api.app import create_app
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


@pytest.fixture
def client(tmp_path):
    db = str(tmp_path / "t.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="test-secret", session_ttl=3600)
    return TestClient(create_app(store=SqliteEngagementStore(db), auth=auth))


def _owner(client):
    tok = client.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return {"Authorization": "Bearer " + tok}


def test_admin_creates_viewer_and_viewer_is_readonly(client):
    H = _owner(client)
    r = client.post("/users", headers=H, json={"username": "ro1", "password": "readonly1", "role": "viewer"})
    assert r.status_code == 201 and r.json()["role"] == "viewer"
    users = client.get("/users", headers=H).json()
    assert any(u["username"] == "ro1" and u["role"] == "viewer" for u in users)

    vt = client.post("/auth/login", json={"username": "ro1", "password": "readonly1"}).json()["token"]
    VH = {"Authorization": "Bearer " + vt}
    eng = client.post("/engagements", headers=H,
                      json={"engagement": {"name": "t"}, "scope": {"in_scope": ["web=http://x"]}}).json()
    # viewer can read
    assert client.get("/engagements/" + eng["id"], headers=VH).status_code == 200
    assert client.get("/engagements/" + eng["id"] + "/progress", headers=VH).status_code == 200
    # viewer cannot write (run / create user)
    assert client.post("/engagements/" + eng["id"] + "/run", headers=VH).status_code == 403
    assert client.post("/users", headers=VH,
                       json={"username": "x", "password": "yyyyyyyy", "role": "viewer"}).status_code == 403


def test_duplicate_user_rejected(client):
    H = _owner(client)
    client.post("/users", headers=H, json={"username": "dup", "password": "pwpwpwpw", "role": "member"})
    r = client.post("/users", headers=H, json={"username": "dup", "password": "pwpwpwpw", "role": "member"})
    assert r.status_code == 409


def test_pause_stop_without_active_scan_conflicts(client):
    H = _owner(client)
    eng = client.post("/engagements", headers=H,
                      json={"engagement": {"name": "t"}, "scope": {"in_scope": ["web=http://x"]}}).json()
    assert client.post("/engagements/" + eng["id"] + "/pause", headers=H).status_code == 409
    assert client.post("/engagements/" + eng["id"] + "/stop", headers=H).status_code == 409
    assert client.get("/engagements/" + eng["id"] + "/progress", headers=H).json()["active"] is False

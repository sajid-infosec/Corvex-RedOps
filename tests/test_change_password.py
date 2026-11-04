"""Self-service password change: /auth/change-password verifies the caller's
current password (by session, not a client-supplied username) before setting a
new one, enforces a minimum length, and persists the change."""
import pytest
from fastapi.testclient import TestClient

from pentestiq.api.app import create_app
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore


@pytest.fixture
def client(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    return TestClient(app)


def _register(c, user="alice", pw="origpass1"):
    r = c.post("/auth/register",
               json={"tenant_name": "t", "username": user, "password": pw})
    assert r.status_code == 201, r.text
    return r.json()["token"]


def test_change_password_happy_path(client):
    tok = _register(client)
    H = {"Authorization": "Bearer " + tok}
    r = client.post("/auth/change-password", headers=H,
                    json={"current_password": "origpass1", "new_password": "brandNewPass9"})
    assert r.status_code == 200 and r.json()["ok"] is True
    # old password no longer logs in; new one does
    assert client.post("/auth/login",
                       json={"username": "alice", "password": "origpass1"}).status_code == 401
    assert client.post("/auth/login",
                       json={"username": "alice", "password": "brandNewPass9"}).status_code == 200


def test_change_password_wrong_current_is_403(client):
    tok = _register(client)
    H = {"Authorization": "Bearer " + tok}
    r = client.post("/auth/change-password", headers=H,
                    json={"current_password": "nope", "new_password": "brandNewPass9"})
    assert r.status_code == 403
    # password is unchanged
    assert client.post("/auth/login",
                       json={"username": "alice", "password": "origpass1"}).status_code == 200


def test_change_password_too_short_is_422(client):
    tok = _register(client)
    H = {"Authorization": "Bearer " + tok}
    # min_length is enforced by the schema -> 422 before the service runs
    r = client.post("/auth/change-password", headers=H,
                    json={"current_password": "origpass1", "new_password": "short"})
    assert r.status_code == 422


def test_change_password_requires_auth(client):
    _register(client)
    r = client.post("/auth/change-password",
                    json={"current_password": "origpass1", "new_password": "brandNewPass9"})
    assert r.status_code in (401, 403)


def test_change_password_only_affects_the_caller(client):
    # two users; alice changing her password must not touch bob's
    ta = _register(client, "alice", "alicepass1")
    _register(client, "bob", "bobpass123")
    client.post("/auth/change-password", headers={"Authorization": "Bearer " + ta},
                json={"current_password": "alicepass1", "new_password": "aliceNewPass9"})
    # bob still logs in with his original password
    assert client.post("/auth/login",
                       json={"username": "bob", "password": "bobpass123"}).status_code == 200

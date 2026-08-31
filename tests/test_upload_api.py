import os
import pytest
from fastapi.testclient import TestClient
from pentestiq.api.app import create_app
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


@pytest.fixture
def client(tmp_path):
    db = str(tmp_path / "t.db")
    auth = AuthService(SqliteAuthStore(db), "test-secret", 3600)
    return TestClient(create_app(store=SqliteEngagementStore(db), auth=auth))


def _tok(c, user="owner"):
    return c.post("/auth/register", json={"tenant_name": "Acme", "username": user,
                                          "password": "password123"}).json()["token"]


def _H(t):
    return {"Authorization": f"Bearer {t}"}


def test_upload_apk_creates_mobile_engagement(client):
    c = client
    tok = _tok(c)
    files = {"file": ("DemoBank.apk", b"PKfakeapkcontent", "application/octet-stream")}
    r = c.post("/engagements/upload", headers=_H(tok), files=files, data={"name": "DemoBank"})
    assert r.status_code == 201, r.text
    rec = r.json()
    assert rec["name"] == "DemoBank"
    asset = rec["engagement"]["assets"][0]
    assert asset["type"] == "mobile"
    path = asset["identifier"]
    assert "/uploads/" in path and path.endswith("DemoBank.apk")
    assert os.path.exists(path)
    os.remove(path)                          # cleanup uploaded test file


def test_upload_rejects_unsupported_type(client):
    c = client
    tok = _tok(c)
    files = {"file": ("notes.txt", b"hello", "text/plain")}
    r = c.post("/engagements/upload", headers=_H(tok), files=files)
    assert r.status_code == 422


def test_upload_requires_member_role(client):
    c = client
    tok = _tok(c)
    vk = c.post("/apikeys", headers=_H(tok), json={"name": "v", "role": "viewer"}).json()["api_key"]
    files = {"file": ("app.ipa", b"PKfake", "application/octet-stream")}
    r = c.post("/engagements/upload", headers={"X-API-Key": vk}, files=files)
    assert r.status_code == 403


def test_upload_config_as_network_device(client):
    c = client
    tok = _tok(c)
    files = {"file": ("router.cfg", b"hostname r1\ntransport input telnet\n", "text/plain")}
    r = c.post("/engagements/upload", headers=_H(tok), files=files,
               data={"asset_type": "network_device", "name": "edge-router"})
    assert r.status_code == 201, r.text
    asset = r.json()["engagement"]["assets"][0]
    assert asset["type"] == "network_device"
    import os
    os.remove(asset["identifier"])


def test_upload_invalid_asset_type(client):
    c = client
    tok = _tok(c)
    files = {"file": ("x.cfg", b"data", "text/plain")}
    r = c.post("/engagements/upload", headers=_H(tok), files=files,
               data={"asset_type": "bogus"})
    assert r.status_code == 422

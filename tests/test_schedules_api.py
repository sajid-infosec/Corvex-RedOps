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


def _tok(c, tenant="PentestIQ", user="owner"):
    return c.post("/auth/register", json={"tenant_name": tenant, "username": user,
                                          "password": "password123"}).json()["token"]


def _H(t):
    return {"Authorization": f"Bearer {t}"}


@pytest.mark.live
def test_schedule_crud_and_run_now(client):
    c = client; tok = _tok(c)
    r = c.post("/schedules", headers=_H(tok), json={
        "name": "nightly", "interval_seconds": 3600,
        "scope": {"in_scope": ["web=http://localhost:3000"]}, "enforcement": "off"})
    assert r.status_code == 201
    sid = r.json()["id"]
    assert c.get("/schedules", headers=_H(tok)).json()[0]["name"] == "nightly"
    assert c.get(f"/schedules/{sid}", headers=_H(tok)).status_code == 200

    # run now -> creates an engagement + returns a diff
    rn = c.post(f"/schedules/{sid}/run-now", headers=_H(tok))
    assert rn.status_code == 202 and "diff" in rn.json()
    assert len(c.get(f"/schedules/{sid}/runs", headers=_H(tok)).json()) == 1
    assert c.get(f"/schedules/{sid}/diff", headers=_H(tok)).status_code == 200

    # disable then delete
    assert c.post(f"/schedules/{sid}/enable?enabled=false", headers=_H(tok)).json()["enabled"] is False
    assert c.delete(f"/schedules/{sid}", headers=_H(tok)).status_code == 204
    assert c.get(f"/schedules/{sid}", headers=_H(tok)).status_code == 404


def test_schedule_rbac_and_tenant_isolation(client):
    c = client; owner = _tok(c)
    vk = c.post("/apikeys", headers=_H(owner), json={"name": "v", "role": "viewer"}).json()["api_key"]
    # viewer cannot create a schedule, but can list
    assert c.post("/schedules", headers={"X-API-Key": vk},
                  json={"name": "x", "interval_seconds": 3600}).status_code == 403
    assert c.get("/schedules", headers={"X-API-Key": vk}).status_code == 200
    # other tenant can't see this tenant's schedules
    other = _tok(c, tenant="B", user="bob")
    c.post("/schedules", headers=_H(owner), json={"name": "mine", "interval_seconds": 3600})
    assert c.get("/schedules", headers=_H(other)).json() == []

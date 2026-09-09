import pytest
from fastapi.testclient import TestClient
from pentestiq.api.app import create_app
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "t.db")
    estore = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="test-secret", session_ttl=3600)
    return TestClient(create_app(store=estore, auth=auth)), auth, db


def _register(c, tenant="PentestIQ", user="owner", pw="password123"):
    r = c.post("/auth/register", json={"tenant_name": tenant, "username": user, "password": pw})
    assert r.status_code == 201, r.text
    return r.json()["token"]


def _H(token):
    return {"Authorization": f"Bearer {token}"}


def test_health_no_auth():
    c = TestClient(create_app(store=SqliteEngagementStore(":memory:"),
                              auth=AuthService(SqliteAuthStore(":memory:"), "s")))
    assert c.get("/health").json()["status"] == "ok"


def test_console_served_at_root(ctx):
    c, _, _ = ctx
    r = c.get("/")
    assert r.status_code == 200 and "Pentest" in r.text and "Sign in" in r.text


def test_auth_required(ctx):
    c, _, _ = ctx
    assert c.get("/engagements").status_code == 401


def test_register_login_flow(ctx):
    c, _, _ = ctx
    tok = _register(c)
    assert c.get("/me", headers=_H(tok)).json()["role"] == "owner"
    # login with same creds
    r = c.post("/auth/login", json={"username": "owner", "password": "password123"})
    assert r.status_code == 200 and "token" in r.json()
    # wrong password
    assert c.post("/auth/login", json={"username": "owner", "password": "nope"}).status_code == 401
    # duplicate username
    dup = c.post("/auth/register", json={"tenant_name": "Other", "username": "owner",
                                         "password": "password123"})
    assert dup.status_code == 409


def test_create_run_findings_report_flow(ctx):
    c, _, _ = ctx
    tok = _register(c)
    r = c.post("/engagements", headers=_H(tok),
               json={"engagement": {"name": "Run"},
                     "scope": {"in_scope": ["web=http://localhost:3000"]},
                     "enforcement": "off"})
    assert r.status_code == 201
    eid = r.json()["id"]
    assert c.post(f"/engagements/{eid}/run", headers=_H(tok)).status_code == 202
    assert c.get(f"/engagements/{eid}", headers=_H(tok)).json()["status"] == "completed"
    assert c.get(f"/engagements/{eid}/findings", headers=_H(tok)).status_code == 200
    assert "Penetration Testing Report" in c.get(f"/engagements/{eid}/report", headers=_H(tok)).text


def test_tenant_isolation(ctx):
    c, _, _ = ctx
    tok_a = _register(c, tenant="A", user="alice")
    tok_b = _register(c, tenant="B", user="bob")
    eid = c.post("/engagements", headers=_H(tok_a), json={"engagement": {"name": "secret"}}).json()["id"]
    assert c.get(f"/engagements/{eid}", headers=_H(tok_b)).status_code == 404
    assert c.get("/engagements", headers=_H(tok_b)).json() == []
    assert c.get(f"/engagements/{eid}", headers=_H(tok_a)).status_code == 200


def test_api_key_auth_and_rbac(ctx):
    c, _, _ = ctx
    owner = _register(c)
    # owner mints a viewer key and a member key
    vk = c.post("/apikeys", headers=_H(owner), json={"name": "v", "role": "viewer"}).json()["api_key"]
    mk = c.post("/apikeys", headers=_H(owner), json={"name": "m", "role": "member"}).json()["api_key"]

    # member key can create; viewer key cannot (403) but can read
    assert c.post("/engagements", headers={"X-API-Key": mk},
                  json={"engagement": {"name": "by-member"}}).status_code == 201
    assert c.post("/engagements", headers={"X-API-Key": vk},
                  json={"engagement": {"name": "by-viewer"}}).status_code == 403
    assert c.get("/engagements", headers={"X-API-Key": vk}).status_code == 200
    # api keys are tenant-scoped: the member key sees the owner's tenant engagements
    assert len(c.get("/engagements", headers={"X-API-Key": mk}).json()) == 1
    # bad key -> 401
    assert c.get("/engagements", headers={"X-API-Key": "ptiq_bogus"}).status_code == 401


def test_only_admin_can_manage_keys(ctx):
    c, _, _ = ctx
    owner = _register(c)
    mk = c.post("/apikeys", headers=_H(owner), json={"name": "m", "role": "member"}).json()["api_key"]
    # member cannot list/create keys
    assert c.get("/apikeys", headers={"X-API-Key": mk}).status_code == 403
    assert c.post("/apikeys", headers={"X-API-Key": mk}, json={"name": "x"}).status_code == 403
    # owner can, and cannot grant a role above their own is moot (owner is top); test admin can't grant owner
    ak = c.post("/apikeys", headers=_H(owner), json={"name": "a", "role": "admin"}).json()["api_key"]
    assert c.post("/apikeys", headers={"X-API-Key": ak}, json={"name": "esc", "role": "owner"}).status_code == 403


def test_persistence_across_instances(tmp_path):
    db = str(tmp_path / "p.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="fixed", session_ttl=3600)
    app1 = create_app(store=SqliteEngagementStore(db), auth=auth)
    c1 = TestClient(app1)
    tok = _register(c1)
    eid = c1.post("/engagements", headers=_H(tok), json={"engagement": {"name": "persisted"}}).json()["id"]
    # new app instances on the same DB + same secret
    auth2 = AuthService(SqliteAuthStore(db), secret_key="fixed", session_ttl=3600)
    c2 = TestClient(create_app(store=SqliteEngagementStore(db), auth=auth2))
    assert c2.get(f"/engagements/{eid}", headers=_H(tok)).json()["name"] == "persisted"

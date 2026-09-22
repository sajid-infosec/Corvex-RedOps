"""Asset inventory — normalization, dedupe store, and /assets API."""
from __future__ import annotations

import tempfile

import pytest
from fastapi.testclient import TestClient

from pentestiq.inventory import normalize, SqliteInventoryStore, AssetKind, Criticality
from pentestiq.api.app import create_app
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


# ---- normalization ------------------------------------------------------
def test_normalize_url_to_host():
    assert normalize("https://App.Example.com/login")[:2] == ("app.example.com", AssetKind.DOMAIN)
    assert normalize("http://app.example.com")[0] == "app.example.com"
    assert normalize("app.example.com:443")[0] == "app.example.com"          # default port dropped
    assert normalize("https://app.example.com:8443")[0] == "app.example.com:8443"  # kept


def test_normalize_kinds():
    assert normalize("10.0.0.5")[1] == AssetKind.IP
    assert normalize("192.168.1.0/24")[1] == AssetKind.CIDR
    assert normalize("/uploads/x/sample-app.apk", "mobile")[1] == AssetKind.APP
    assert normalize("EXAMPLE.com")[0] == "example.com"


# ---- store --------------------------------------------------------------
@pytest.fixture
def store():
    return SqliteInventoryStore(tempfile.mktemp(suffix=".db"))


def test_upsert_dedupes_across_shapes(store):
    a = store.upsert("t", "https://App.Example.com/login", asset_type="web", engagement_id="e1")
    b = store.upsert("t", "app.example.com", engagement_id="e2")
    c = store.upsert("t", "http://app.example.com/x", engagement_id="e3")
    assert a.id == b.id == c.id
    assert sorted(store.get("t", a.id).engagement_ids) == ["e1", "e2", "e3"]
    assert store.stats("t")["total"] == 1


def test_tenant_isolation(store):
    store.upsert("t1", "a.com")
    store.upsert("t2", "b.com")
    assert [x.identifier for x in store.list("t1")] == ["a.com"]
    assert store.resolve("t1", "b.com") is None


def test_update_and_resolve(store):
    a = store.upsert("t", "https://app.example.com")
    store.update("t", a.id, tags=["prod", "crown-jewel"], criticality="critical", owner="web")
    g = store.get("t", a.id)
    assert g.criticality == Criticality.CRITICAL and "crown-jewel" in g.tags and g.owner == "web"
    # a finding's raw identifier resolves back to the inventory asset
    assert store.resolve("t", "http://app.example.com/deep/path").id == a.id


def test_delete(store):
    a = store.upsert("t", "x.com")
    assert store.delete("t", a.id) is True
    assert store.get("t", a.id) is None
    assert store.delete("t", a.id) is False


# ---- API ----------------------------------------------------------------
@pytest.fixture
def client(tmp_path):
    db = str(tmp_path / "t.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="test-secret", session_ttl=3600)
    return TestClient(create_app(store=SqliteEngagementStore(db), auth=auth))


def _owner(client):
    tok = client.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return {"Authorization": "Bearer " + tok}


def test_assets_api_crud_and_filters(client):
    H = _owner(client)
    assert client.post("/assets", json={"identifier": "https://app.example.com",
                                        "asset_type": "web", "tags": ["prod"],
                                        "criticality": "high"}, headers=H).status_code == 201
    aid = client.post("/assets", json={"identifier": "10.0.0.5"}, headers=H).json()["id"]
    assert len(client.get("/assets", headers=H).json()) == 2
    assert [a["identifier"] for a in client.get("/assets?kind=ip", headers=H).json()] == ["10.0.0.5"]
    assert client.get("/assets/stats", headers=H).json()["total"] == 2
    assert client.patch("/assets/" + aid, json={"criticality": "critical"}, headers=H).json()["criticality"] == "critical"
    assert client.delete("/assets/" + aid, headers=H).status_code == 204
    assert client.get("/assets/" + aid, headers=H).status_code == 404
    assert client.post("/assets", json={}, headers=H).status_code == 422   # identifier required


def test_assets_api_rbac(client):
    H = _owner(client)
    client.post("/users", json={"username": "ro", "password": "readonly1", "role": "viewer"}, headers=H)
    vt = client.post("/auth/login", json={"username": "ro", "password": "readonly1"}).json()["token"]
    VH = {"Authorization": "Bearer " + vt}
    assert client.get("/assets", headers=VH).status_code == 200          # viewer can read
    assert client.post("/assets", json={"identifier": "x.com"}, headers=VH).status_code == 403


# ---- A2: auto-populate from engagements ---------------------------------
def test_engagement_creation_populates_inventory(client):
    H = _owner(client)
    assert client.get("/assets", headers=H).json() == []
    client.post("/engagements", headers=H, json={
        "engagement": {"name": "q3"},
        "scope": {"in_scope": ["web=https://app.example.com", "api=https://api.example.com",
                               "infra=10.0.0.0/24"]}})
    assets = client.get("/assets", headers=H).json()
    idents = sorted(a["identifier"] for a in assets)
    assert idents == ["10.0.0.0/24", "api.example.com", "app.example.com"]
    assert all(a["source"] == "engagement" and a["engagements"] == 1 for a in assets)


def test_reuse_across_engagements_dedupes_and_links(client):
    H = _owner(client)
    client.post("/engagements", headers=H, json={
        "engagement": {"name": "a"}, "scope": {"in_scope": ["web=https://app.example.com"]}})
    client.post("/engagements", headers=H, json={
        "engagement": {"name": "b"}, "scope": {"in_scope": ["http://app.example.com/login"]}})
    assets = client.get("/assets", headers=H).json()
    assert len(assets) == 1
    assert assets[0]["engagements"] == 2


def test_populate_helper_includes_finding_hosts():
    from pentestiq.inventory import SqliteInventoryStore, populate_from_engagement
    from pentestiq.models import Engagement, Scope, Asset, Finding, AssetType, Severity
    a = Asset(type=AssetType.WEB, identifier="https://app.example.com")
    eng = Engagement(name="e", scope=Scope(name="s", in_scope=["https://app.example.com"]), assets=[a])
    disc = Asset(type=AssetType.WEB, identifier="https://admin.example.com/panel")
    eng.add_findings([Finding(asset=disc, title="found host", severity=Severity.INFO)])
    inv = SqliteInventoryStore(tempfile.mktemp(suffix=".db"))
    n = populate_from_engagement(inv, "t", "e1", eng)
    idents = sorted(x.identifier for x in inv.list("t"))
    assert "app.example.com" in idents and "admin.example.com" in idents
    assert n >= 2

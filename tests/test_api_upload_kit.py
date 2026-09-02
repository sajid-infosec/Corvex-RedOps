"""Tests for the single-portal API-VAPT upload + Frida dynamic-analysis kit."""
import json
import io
import zipfile

import pytest
from fastapi.testclient import TestClient

from pentestiq.api.api_ingest import build_api_metadata, parse_spec
from pentestiq.api.app import create_app
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


# --------------------------------------------------------------- metadata builder
SPEC = json.dumps({
    "openapi": "3.0.0",
    "servers": [{"url": "https://api.example.com/v1"}],
    "paths": {
        "/user/{id}": {"get": {}},
        "/organization/{orgId}": {"get": {}, "put": {}},
        "/users": {"get": {}},
        "/health": {"get": {}},
        "/login": {"post": {}},
    },
})


def test_build_metadata_derives_endpoints_and_identity():
    m = build_api_metadata(SPEC, spec_path="/tmp/s.json",
                           bearer_token="Bearer aaa.bbb.ccc")
    assert m["base_url"] == "https://api.example.com/v1"
    assert "/user/{id}" in m["idor_endpoints"]
    assert "/organization/{id}" in m["idor_endpoints"]   # {orgId} normalized to {id}
    assert "/users" in m["data_endpoints"]
    assert "/user/{id}" not in m["data_endpoints"]       # id paths are BOLA, not data
    assert m["jwt"] == "aaa.bbb.ccc"                      # Bearer prefix stripped
    assert m["identities"][0]["headers"]["Authorization"] == "Bearer aaa.bbb.ccc"


def test_build_metadata_two_identities_for_bola():
    m = build_api_metadata(SPEC, bearer_token="t1", bearer_token_b="t2",
                           object_ids_a=["a1"], object_ids_b=["b1"])
    names = [i["name"] for i in m["identities"]]
    assert names == ["primary", "secondary"]
    assert m["identities"][1]["object_ids"] == ["b1"]


def test_build_metadata_swagger2_base_url():
    spec = json.dumps({"swagger": "2.0", "host": "api.x.com", "basePath": "/api",
                       "schemes": ["https"], "paths": {"/a": {"get": {}}}})
    m = build_api_metadata(spec)
    assert m["base_url"] == "https://api.x.com/api"


def test_parse_spec_yaml_fallback():
    y = "openapi: 3.0.0\npaths:\n  /a:\n    get: {}\n"
    assert parse_spec(y).get("openapi") == "3.0.0"


# --------------------------------------------------------------- upload + kit API
@pytest.fixture
def client(tmp_path):
    db = str(tmp_path / "t.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), "test-secret", 3600)
    cfg_dir = tmp_path / "data"
    app = create_app(store=store, auth=auth)
    return TestClient(app)


def _token(c):
    return c.post("/auth/register", json={"tenant_name": "Acme", "username": "owner",
                                          "password": "password123"}).json()["token"]


def test_api_upload_creates_api_engagement_with_metadata(client, monkeypatch, tmp_path):
    # point the app's data dir at tmp so uploads land on real disk
    tok = _token(client)
    files = {"file": ("swagger.json", SPEC, "application/json")}
    data = {"asset_type": "api", "name": "Example API",
            "base_url": "https://api.example.com/v1", "bearer_token": "aaa.bbb.ccc"}
    r = client.post("/engagements/upload", files=files, data=data,
                    headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 201, r.text
    rec = r.json()
    asset = rec["engagement"]["assets"][0]
    assert asset["type"] == "api"
    assert asset["identifier"] == "https://api.example.com/v1"
    meta = asset["metadata"]
    assert meta["jwt"] == "aaa.bbb.ccc"
    assert "/user/{id}" in meta["idor_endpoints"]


def test_frida_kit_list_and_download(client):
    tok = _token(client)
    r = client.get("/kit/frida", headers={"Authorization": f"Bearer {tok}"})
    assert r.status_code == 200
    names = [s["name"] for s in r.json()]
    assert "ssl-pinning-bypass.js" in names
    assert all(s.get("description") for s in r.json())

    # individual script (public)
    r2 = client.get("/kit/frida/ssl-pinning-bypass.js")
    assert r2.status_code == 200 and "Java.perform" in r2.text

    # path traversal is neutralized
    r3 = client.get("/kit/frida/..%2f..%2fapp.py")
    assert r3.status_code == 404

    # zip bundle
    r4 = client.get("/kit/frida.zip")
    assert r4.status_code == 200
    zf = zipfile.ZipFile(io.BytesIO(r4.content))
    assert any(n.endswith("ssl-pinning-bypass.js") for n in zf.namelist())

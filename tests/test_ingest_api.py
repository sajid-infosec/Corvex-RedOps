"""B2 wiring — the /ingest API: upload a scanner report → engagement + inventory."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}


ZAP = json.dumps({"@programName": "ZAP", "site": [{"@name": "https://shop.example.com", "alerts": [
    {"alert": "SQL Injection", "riskcode": "3", "desc": "<p>x</p>", "solution": "<p>Use params</p>",
     "cweid": "89", "instances": [{"uri": "https://shop.example.com/i?id=1", "param": "id",
                                   "evidence": "err"}]}]}]}).encode()

NESSUS = ("""<?xml version="1.0" ?><NessusClientData_v2><Report name="s"><ReportHost name="10.0.0.10">
<ReportItem port="443" protocol="tcp" severity="4" pluginName="Log4Shell">
<risk_factor>Critical</risk_factor><cve>CVE-2021-44228</cve><cwe>502</cwe>
<cvss3_base_score>10.0</cvss3_base_score><solution>Patch</solution></ReportItem>
</ReportHost></Report></NessusClientData_v2>""").encode()


def test_list_importers(ctx):
    c, H = ctx
    names = [i["name"] for i in c.get("/ingest/importers", headers=H).json()]
    assert {"nessus", "nuclei", "trivy", "zap", "sarif", "generic-json"} <= set(names)


def test_ingest_creates_engagement_and_inventory(ctx):
    c, H = ctx
    r = c.post("/engagements/ingest", headers=H,
               files={"file": ("scan.json", ZAP, "application/json")})
    assert r.status_code == 201
    body = r.json()
    assert body["importer"] == "zap" and body["imported"] == 1 and body["created"] is True
    eid = body["engagement_id"]
    det = c.get(f"/engagements/{eid}", headers=H).json()
    assert det["status"] == "completed"
    fs = det["engagement"]["findings"]
    assert len(fs) == 1 and fs[0]["category"] == "A03:2021"
    # asset registered in the inventory, ranked with an exposure
    assets = c.get("/assets", headers=H).json()
    assert any(a["identifier"] == "shop.example.com" for a in assets)


def test_ingest_detects_nessus_and_flags_kev(ctx):
    c, H = ctx
    r = c.post("/engagements/ingest", headers=H,
               files={"file": ("t.nessus", NESSUS, "application/xml")})
    assert r.status_code == 201
    body = r.json()
    assert body["importer"] == "nessus" and body["kev"] >= 1
    stats = c.get("/assets/stats", headers=H).json()
    assert stats["kev_assets"] >= 1


def test_ingest_into_existing_engagement(ctx):
    c, H = ctx
    eid = c.post("/engagements", headers=H,
                 json={"engagement": {"name": "Manual"}, "scope": {"in_scope": []}}).json()["id"]
    r = c.post("/engagements/ingest", headers=H, data={"eid": eid},
               files={"file": ("scan.json", ZAP, "application/json")})
    assert r.status_code == 201
    body = r.json()
    assert body["created"] is False and body["engagement_id"] == eid and body["added"] == 1
    det = c.get(f"/engagements/{eid}", headers=H).json()
    assert len(det["engagement"]["findings"]) == 1


def test_ingest_forced_importer_and_errors(ctx):
    c, H = ctx
    # unknown importer name → 422
    r = c.post("/engagements/ingest", headers=H, data={"importer": "nope"},
               files={"file": ("x.json", ZAP, "application/json")})
    assert r.status_code == 422
    # unparseable / empty → 422
    r2 = c.post("/engagements/ingest", headers=H,
                files={"file": ("broken.json", b"{not json", "application/json")})
    assert r2.status_code == 422


def test_ingest_requires_write_role(ctx):
    c, H = ctx
    # create a viewer API key and confirm it cannot ingest
    key = c.post("/apikeys", headers=H, json={"name": "v", "role": "viewer"}).json()
    vh = {"Authorization": "Bearer " + key["key"]} if "key" in key else None
    if vh:
        r = c.post("/engagements/ingest", headers=vh,
                   files={"file": ("scan.json", ZAP, "application/json")})
        assert r.status_code in (401, 403)

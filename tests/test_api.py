import pytest
from fastapi.testclient import TestClient
from pentestiq.api.app import create_app
from pentestiq.storage import SqliteEngagementStore
from pentestiq.models import Asset, AssetType, Finding, Severity, Engagement, Scope


@pytest.fixture
def client(tmp_path):
    store = SqliteEngagementStore(str(tmp_path / "t.db"))
    return TestClient(create_app(store=store)), store


H = {"X-API-Key": "tenant-a"}


def test_health_no_auth_needed():
    c, _ = None, None
    app = create_app(store=SqliteEngagementStore(":memory:"))
    r = TestClient(app).get("/health")
    assert r.status_code == 200 and r.json()["status"] == "ok"


def test_auth_required(client):
    c, _ = client
    assert c.get("/engagements").status_code == 401       # no key


def test_create_run_findings_report_flow(client):
    c, _ = client
    body = {"engagement": {"name": "API Run"},
            "scope": {"in_scope": ["web=http://localhost:3000"]},
            "enforcement": "off"}
    r = c.post("/engagements", json=body, headers=H)
    assert r.status_code == 201
    eid = r.json()["id"]
    assert r.json()["status"] == "created"

    # run (TestClient executes the background task after the response)
    rr = c.post(f"/engagements/{eid}/run", headers=H)
    assert rr.status_code == 202

    got = c.get(f"/engagements/{eid}", headers=H)
    assert got.status_code == 200
    assert got.json()["status"] == "completed"           # ran to completion

    assert c.get(f"/engagements/{eid}/findings", headers=H).status_code == 200
    rep = c.get(f"/engagements/{eid}/report", headers=H)
    assert rep.status_code == 200 and "VAPT Report" in rep.text


def test_tenant_isolation(client):
    c, _ = client
    r = c.post("/engagements", json={"engagement": {"name": "secret"}},
               headers={"X-API-Key": "tenant-a"})
    eid = r.json()["id"]
    # tenant-b cannot see tenant-a's engagement
    assert c.get(f"/engagements/{eid}", headers={"X-API-Key": "tenant-b"}).status_code == 404
    assert c.get("/engagements", headers={"X-API-Key": "tenant-b"}).json() == []
    # tenant-a can
    assert c.get(f"/engagements/{eid}", headers={"X-API-Key": "tenant-a"}).status_code == 200


def test_persistence_across_store_instances(tmp_path):
    db = str(tmp_path / "p.db")
    app1 = create_app(store=SqliteEngagementStore(db))
    r = TestClient(app1).post("/engagements", json={"engagement": {"name": "persisted"}}, headers=H)
    eid = r.json()["id"]
    # a brand-new store instance on the same DB still has it
    app2 = create_app(store=SqliteEngagementStore(db))
    got = TestClient(app2).get(f"/engagements/{eid}", headers=H)
    assert got.status_code == 200 and got.json()["name"] == "persisted"


def test_report_reflects_seeded_findings(tmp_path):
    store = SqliteEngagementStore(str(tmp_path / "s.db"))
    a = Asset(type=AssetType.WEB, identifier="http://shop")
    eng = Engagement(name="Seeded", scope=Scope())
    eng.add_findings([Finding(asset=a, title="SQL Injection", category="CWE-89",
                              severity=Severity.HIGH, source_tools=["zap"])])
    store.create("tenant-a", eng, status="completed")
    c = TestClient(create_app(store=store))
    rep = c.get(f"/engagements/{eng.id}/report", headers=H)
    assert "SQL Injection" in rep.text
    findings = c.get(f"/engagements/{eng.id}/findings", headers=H).json()
    assert findings[0]["title"] == "SQL Injection"

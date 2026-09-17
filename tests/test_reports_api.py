import pytest
from fastapi.testclient import TestClient
from pentestiq.api.app import create_app
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService
from pentestiq.models import Asset, AssetType, Finding, Severity, Engagement
from pentestiq.core.analysis import analyze


@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "t.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), "test-secret", 3600)
    return TestClient(create_app(store=store, auth=auth)), store


def _reg(c, user="owner"):
    tok = c.post("/auth/register", json={"tenant_name": "PentestIQ", "username": user,
                                         "password": "password123"}).json()["token"]
    tid = c.get("/me", headers={"Authorization": f"Bearer {tok}"}).json()["tenant_id"]
    return tok, tid


def _seed(store, tid):
    a = Asset(type=AssetType.WEB, identifier="http://shop")
    e = Engagement(name="Seeded")
    e.add_findings([Finding(asset=a, title="SQL Injection", category="CWE-89",
                            severity=Severity.HIGH, source_tools=["zap"])])
    analyze(e)
    store.create(tid, e, status="completed")
    return e.id


def test_report_formats(ctx):
    c, store = ctx
    tok, tid = _reg(c)
    eid = _seed(store, tid)
    H = {"Authorization": f"Bearer {tok}"}
    assert "Vulnerability Assessment" in c.get(f"/engagements/{eid}/report?format=html", headers=H).text
    pdf = c.get(f"/engagements/{eid}/report?format=pdf", headers=H)
    assert pdf.status_code == 200 and pdf.headers["content-type"] == "application/pdf"
    assert pdf.content[:4] == b"%PDF"
    docx = c.get(f"/engagements/{eid}/report?format=docx", headers=H)
    assert docx.status_code == 200 and docx.content[:2] == b"PK"


def test_compliance_endpoint(ctx):
    c, store = ctx
    tok, tid = _reg(c)
    eid = _seed(store, tid)
    comp = c.get(f"/engagements/{eid}/compliance", headers={"Authorization": f"Bearer {tok}"}).json()
    assert comp["mapped"] == 1
    assert "A03: Injection" in comp["frameworks"]["owasp"]


def test_settings_branding_rbac_and_applied(ctx):
    c, store = ctx
    tok, tid = _reg(c)
    H = {"Authorization": f"Bearer {tok}"}
    # default branding
    assert c.get("/settings", headers=H).json()["company_name"] == "Corvex-RedOps"
    # owner sets white-label branding
    r = c.put("/settings", headers=H, json={"company_name": "PentestIQ Security",
                                            "accent_color": "#6d28d9", "footer_note": "Confidential"})
    assert r.status_code == 200 and r.json()["company_name"] == "PentestIQ Security"
    # a member key cannot change settings
    mk = c.post("/apikeys", headers=H, json={"name": "m", "role": "member"}).json()["api_key"]
    assert c.put("/settings", headers={"X-API-Key": mk}, json={"company_name": "X"}).status_code == 403
    # branding shows up in the report
    eid = _seed(store, tid)
    assert "PentestIQ Security" in c.get(f"/engagements/{eid}/report", headers=H).text

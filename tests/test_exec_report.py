"""Executive summary report (management-facing) + report variant endpoint."""
import pytest
from fastapi.testclient import TestClient
from pentestiq.models import Engagement, Scope, Asset, AssetType, Finding, Severity, Confidence, Enforcement
from pentestiq.core.analysis import analyze
from pentestiq.reporting import (compute_stats, build_narrative, compliance_summary,
    render_exec_html, render_exec_pdf, render_exec_docx, render_html, render_pdf, render_docx)
from pentestiq.api.app import create_app
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


def _eng():
    sc = Scope(name="Acme", authorized_by="CISO", in_scope=["web=https://app.example.com"], enforcement=Enforcement.WARN)
    a = Asset(type=AssetType.WEB, identifier="https://app.example.com")
    fs = [Finding(asset=a, title="SQL injection (error-based) in 'id'", category="A03:2021",
                  severity=Severity.CRITICAL, confidence=Confidence.HIGH, location="GET /x?id",
                  source_tools=["pentestiq-fuzz"], correlation_id="c1"),
          Finding(asset=a, title="BOLA — cross-identity object read", category="API1:2023",
                  severity=Severity.HIGH, source_tools=["pentestiq-checks"], correlation_id="c1"),
          Finding(asset=a, title="Missing security header: HSTS", category="A05:2021",
                  severity=Severity.LOW, source_tools=["pentestiq-checks"])]
    e = Engagement(name="Acme", scope=sc, assets=[a]); e.add_findings(fs); analyze(e); return e


def test_exec_html_has_visualisations():
    e = _eng(); st = compute_stats(e); nar = build_narrative(e, st); comp = compliance_summary(e)
    h = render_exec_html(e, st, nar, None, comp)
    assert "Executive Summary" in h and "<svg" in h
    for token in ["Overall Risk Posture", "Findings by Severity", "Top risks",
                  "Findings by OWASP category", "Remediation priorities", "Recommended next steps"]:
        assert token in h, token


def test_exec_pdf_and_docx_render():
    e = _eng(); st = compute_stats(e); nar = build_narrative(e, st); comp = compliance_summary(e)
    assert len(render_exec_pdf(e, st, nar, None, comp)) > 3000
    assert len(render_exec_docx(e, st, nar, None, comp)) > 8000


def test_full_report_has_professional_sections():
    e = _eng(); st = compute_stats(e); nar = build_narrative(e, st); comp = compliance_summary(e)
    h = render_html(e, st, nar, None, comp)
    for token in ["Executive Summary", "Engagement Overview", "Risk Rating Methodology",
                  "Summary of Findings", "Detailed Findings", "Remediation Roadmap",
                  "Conclusion", "OWASP Top 10", "F-001", "CVSS v3.1 vector"]:
        assert token in h, token
    assert len(render_pdf(e, st, nar, None, comp)) > 8000
    assert len(render_docx(e, st, nar, None, comp)) > 8000


@pytest.fixture
def client(tmp_path):
    db = str(tmp_path / "t.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    return TestClient(create_app(store=SqliteEngagementStore(db), auth=auth))


def test_report_variant_endpoint(client):
    tok = client.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    H = {"Authorization": "Bearer " + tok}
    eid = client.post("/engagements", headers=H,
                      json={"engagement": {"name": "t"}, "scope": {"in_scope": ["web=http://x"]}}).json()["id"]
    r = client.get(f"/engagements/{eid}/report?format=html&variant=exec", headers=H)
    assert r.status_code == 200 and "Executive Summary" in r.text and "<svg" in r.text
    r2 = client.get(f"/engagements/{eid}/report?format=pdf&variant=exec", headers=H)
    assert r2.status_code == 200 and r2.headers["content-type"] == "application/pdf"
    assert "executive_summary.pdf" in r2.headers.get("content-disposition", "")
    r3 = client.get(f"/engagements/{eid}/report?format=html&variant=full", headers=H)
    assert "Detailed Findings" in r3.text

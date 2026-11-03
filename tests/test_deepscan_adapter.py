"""Deep Scan slice 1 (free core): HAR import → passive deep scan → findings unify.

Covers the vendored engine facade, the adapter's finding mapping (severity passes
through, confidence tentative|firm|certain → low|medium|high, source_tools, the
``deepscan:`` category namespace, evidence), and the engagement import API route.
"""
from __future__ import annotations

from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pentestiq.api.app import create_app
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.deepscan import DEEPSCAN_TOOL, deepscan_to_findings, run_import
from pentestiq.models.enums import AssetType, Confidence, Severity
from pentestiq.reporting.model import engine_label
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore

HAR = str(Path(__file__).parent / "fixtures" / "deepscan_sample.har")


# --- engine facade + end-to-end report -------------------------------------

def test_engine_imports_har_and_deep_scans():
    from corvex_deepscan import DeepScanEngine

    eng = DeepScanEngine()
    try:
        n = eng.import_har(HAR)
        assert n == 4  # four flows in the sample capture
        assert eng.flow_count() == 4
        report = eng.deep_scan().to_dict()
    finally:
        eng.close()
    assert report["flow_count"] == 4
    assert report["attack_surface"]["hosts"] >= 1
    # the sample posts credentials in the login body → a secret finding surfaces
    assert report["secrets"], "expected captured credentials in the sample HAR"


# --- adapter mapping --------------------------------------------------------

def _report(findings):
    return {"scope_hosts": ["app.target.test"], "findings": findings}


def test_mapping_severity_passthrough_and_confidence_and_category():
    report = _report([
        {"id": "missing-hsts", "title": "Missing HSTS header", "severity": "medium",
         "confidence": "certain", "category": "config",
         "location": "https://app.target.test/", "evidence": "no Strict-Transport-Security",
         "remediation": "Add HSTS."},
        {"id": "reflected-parameter", "title": "Parameter reflected", "severity": "low",
         "confidence": "tentative", "category": "surface",
         "location": "https://app.target.test/search", "evidence": "q echoed"},
    ])
    fs = deepscan_to_findings(report, engagement_id="E1")
    assert len(fs) == 2
    by_title = {f.title: f for f in fs}

    hsts = by_title["Missing HSTS header"]
    assert hsts.severity is Severity.MEDIUM          # passes through unchanged
    assert hsts.confidence is Confidence.HIGH         # certain → high
    assert hsts.category == "deepscan:config"         # namespaced
    assert hsts.source_tools == [DEEPSCAN_TOOL]
    assert hsts.engagement_id == "E1"
    assert hsts.asset.type is AssetType.WEB
    assert hsts.evidence and hsts.evidence[0].type == "deepscan"
    assert hsts.evidence[0].ref == "https://app.target.test/"
    assert hsts.remediation == "Add HSTS."

    refl = by_title["Parameter reflected"]
    assert refl.confidence is Confidence.LOW          # tentative → low
    assert refl.severity is Severity.LOW


def test_mapping_handles_missing_optional_fields():
    fs = deepscan_to_findings(_report([{"id": "x", "severity": "high"}]))
    assert len(fs) == 1
    f = fs[0]
    assert f.title == "x"                 # falls back to id
    assert f.severity is Severity.HIGH
    assert f.confidence is Confidence.MEDIUM   # default firm → medium
    assert f.evidence == []               # no evidence text → no Evidence block
    assert f.remediation is None


def test_mapping_unknown_severity_defaults_info():
    f = deepscan_to_findings(_report([{"id": "weird", "severity": "bogus"}]))[0]
    assert f.severity is Severity.INFO


def test_run_import_over_sample_har():
    findings, report = run_import(HAR, engagement_id="E2")
    assert report["flows_imported"] == 4
    assert all(f.source_tools == [DEEPSCAN_TOOL] for f in findings)
    assert all(f.category.startswith("deepscan") for f in findings)
    # credentials in the capture must map to at least one finding
    assert findings, "expected deep-scan findings from the sample capture"


def test_engine_label_is_generic():
    # anonymization rule: user-facing label carries no tool/vendor name
    label = engine_label(DEEPSCAN_TOOL)
    assert label == "Attack-surface deep-scan engine"


# --- API route --------------------------------------------------------------

@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login",
                 json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}


def test_api_deepscan_import_attaches_findings(ctx):
    c, H = ctx
    eid = c.post("/engagements", headers=H,
                 json={"engagement": {"name": "DS"}}).json()["id"]

    with open(HAR, "rb") as fh:
        r = c.post(f"/engagements/{eid}/deepscan/import", headers=H,
                   files={"file": ("capture.har", fh.read(), "application/json")})
    assert r.status_code == 201, r.text
    body = r.json()
    assert body["flows_imported"] == 4
    assert body["findings_added"] >= 1
    assert body["attack_surface"]["hosts"] >= 1

    # findings are now on the engagement, surfaced under the generic label
    det = c.get(f"/engagements/{eid}", headers=H).json()
    fs = det["engagement"]["findings"]
    assert any(DEEPSCAN_TOOL in (f.get("source_tools") or []) for f in fs)


def test_api_deepscan_import_404_for_unknown_engagement(ctx):
    c, H = ctx
    with open(HAR, "rb") as fh:
        r = c.post("/engagements/does-not-exist/deepscan/import", headers=H,
                   files={"file": ("capture.har", fh.read(), "application/json")})
    assert r.status_code == 404

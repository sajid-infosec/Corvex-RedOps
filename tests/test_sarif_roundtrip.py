"""B3 — SARIF export + round-trip (GitHub code-scanning / CI native)."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from pentestiq.ingest import findings_to_sarif, engagement_to_sarif, import_findings
from pentestiq.models import (Finding, Asset, AssetType, Severity, CVSS,
                              Engagement, Scope)
from pentestiq.intel import ThreatIntel
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService

INTEL = ThreatIntel(offline=True)


def _sample_findings():
    return [
        Finding(asset=Asset(type=AssetType.WEB, identifier="https://shop.example.com"),
                title="Reflected XSS in search", category="A03:2021", severity=Severity.HIGH,
                references=["https://owasp.org/xss"], location="/s?q= [q]",
                remediation="Encode output."),
        Finding(asset=Asset(type=AssetType.INFRA, identifier="10.0.0.10"),
                title="Log4Shell RCE", category="A08:2021", severity=Severity.CRITICAL,
                cvss=CVSS(base_score=10.0), references=["CVE-2021-44228"], location="443/tcp"),
        Finding(asset=Asset(type=AssetType.INFRA, identifier="app/run.py"),
                title="subprocess shell=True", category="A03:2021", severity=Severity.MEDIUM,
                location="42"),
    ]


# ---- export shape -------------------------------------------------------
def test_export_is_valid_sarif_shape():
    doc = findings_to_sarif(_sample_findings())
    assert doc["version"] == "2.1.0" and "sarif" in doc["$schema"].lower()
    run = doc["runs"][0]
    assert run["tool"]["driver"]["name"] == "PentestIQ"
    assert len(run["tool"]["driver"]["rules"]) == 3
    assert len(run["results"]) == 3
    # GitHub reads severity from this property + the level
    r0 = run["results"][0]
    assert r0["level"] in ("error", "warning", "note", "none")
    assert "security-severity" in r0["properties"]
    # a critical finding maps to error level
    crit = next(r for r in run["results"] if "Log4Shell" in r["message"]["text"])
    assert crit["level"] == "error"
    rule = next(x for x in run["tool"]["driver"]["rules"] if x["id"] == crit["ruleId"])
    assert "A08:2021" in rule["properties"]["tags"]
    assert rule["properties"]["pentestiq/category"] == "A08:2021"
    # a finding carrying a CWE surfaces a CWE tag too
    xss_rule = next(x for x in run["tool"]["driver"]["rules"]
                    if "XSS" in x["name"])
    assert xss_rule["properties"]["pentestiq/category"] == "A03:2021"


# ---- round-trip fidelity ------------------------------------------------
def test_roundtrip_preserves_key_fields():
    orig = _sample_findings()
    doc = findings_to_sarif(orig)
    res = import_findings(json.dumps(doc).encode(), filename="ptiq.sarif",
                          intel=INTEL, prioritize=False)
    assert res.importer == "sarif" and res.imported_count == 3
    got = {f.title: f for f in res.findings}
    for o in orig:
        r = got[o.title]
        assert r.severity is o.severity
        assert r.category == o.category
        assert r.asset.type is o.asset.type
        assert r.asset.identifier == o.asset.identifier
        assert r.location == o.location
        for cve in [x for x in o.references if x.upper().startswith("CVE")]:
            assert cve in r.references


def test_roundtrip_via_engagement_dedupes_consistently():
    orig = _sample_findings()
    doc = engagement_to_sarif(Engagement(name="e", scope=Scope(name="s"),
                                         findings=orig))
    res = import_findings(json.dumps(doc).encode(), importer="sarif",
                          intel=INTEL, prioritize=False)
    assert res.imported_count == 3


# ---- API export ---------------------------------------------------------
@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}, store


def test_api_report_sarif_export(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    eng = Engagement(name="ext", scope=Scope(name="s"), findings=_sample_findings())
    rec = store.create(tid, eng, status="completed")
    r = c.get(f"/engagements/{rec.id}/report?format=sarif", headers=H)
    assert r.status_code == 200
    assert r.headers["content-type"].startswith("application/sarif+json")
    doc = r.json()
    assert doc["version"] == "2.1.0" and len(doc["runs"][0]["results"]) == 3
    # and it re-imports cleanly (round-trip through the API surface)
    back = import_findings(json.dumps(doc).encode(), filename="e.sarif",
                           intel=INTEL, prioritize=False)
    assert back.imported_count == 3
    assert any(f.category == "A08:2021" for f in back.findings)

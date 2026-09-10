"""E2 — Prowler CSPM: OCSF+native import, compliance mapping, runner, API."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from pentestiq.ingest import import_findings, detect_importer, get_importer, list_importers
from pentestiq.cloud import scan_cloud, ProwlerRunner, compliance_rollup
from pentestiq.models import Severity, AssetType
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService

NATIVE = [
    {"Status": "FAIL", "Severity": "critical", "CheckID": "s3_bucket_public_access",
     "CheckTitle": "Ensure S3 buckets are not publicly accessible", "ServiceName": "s3",
     "Region": "us-east-1", "ResourceId": "arn:aws:s3:::my-bucket", "Provider": "aws",
     "AccountId": "123456789012",
     "Remediation": {"Recommendation": {"Text": "Block public access", "Url": "https://d"}},
     "Compliance": {"CIS-2.0": ["2.1.1"], "PCI-4.0": ["1.2.1"]}},
    {"Status": "FAIL", "Severity": "high", "CheckID": "iam_root_mfa",
     "CheckTitle": "Ensure MFA is enabled for the root account", "ServiceName": "iam",
     "Provider": "aws", "AccountId": "123456789012", "ResourceId": "root",
     "Remediation": {"Recommendation": {"Text": "Enable MFA"}},
     "Compliance": {"CIS-2.0": ["1.5"], "NIST-800-53": ["IA-2"]}},
    {"Status": "PASS", "Severity": "low", "CheckID": "x", "CheckTitle": "ok",
     "Provider": "aws", "AccountId": "123456789012"},
]
OCSF = [
    {"status_code": "FAIL", "severity": "High",
     "finding_info": {"title": "CloudTrail is not enabled in all regions", "uid": "prowler-aws"},
     "cloud": {"provider": "aws", "account": {"uid": "123456789012"}, "region": "us-east-1"},
     "resources": [{"uid": "arn:aws:cloudtrail:x", "name": "trail", "region": "us-east-1"}],
     "remediation": {"desc": "Enable multi-region CloudTrail", "references": ["https://d"]},
     "unmapped": {"check_id": "cloudtrail_multi_region", "service_name": "cloudtrail",
                  "compliance": {"CIS-2.0": ["3.1"], "NIST-800-53": ["AU-2"]}}},
]


# ---- importer -----------------------------------------------------------
def test_native_import_and_compliance_refs():
    r = import_findings(json.dumps(NATIVE).encode(), importer="prowler", prioritize=False)
    assert r.imported_count == 2         # PASS skipped
    s3 = next(f for f in r.findings if "S3" in f.title)
    assert s3.severity is Severity.CRITICAL and s3.category == "A01:2021"
    assert s3.asset.type is AssetType.CLOUD and s3.asset.identifier == "aws:123456789012"
    assert "CIS-2.0 2.1.1" in s3.references and "PCI-4.0 1.2.1" in s3.references
    assert "us-east-1" in s3.location


def test_ocsf_import():
    r = import_findings(json.dumps(OCSF).encode(), importer="prowler", prioritize=False)
    assert r.imported_count == 1
    ct = r.findings[0]
    assert ct.category == "A09:2021"     # logging/monitoring
    assert "CIS-2.0 3.1" in ct.references and "NIST-800-53 AU-2" in ct.references


def test_detection_and_registry():
    assert detect_importer("out.json", json.dumps(NATIVE).encode()) is get_importer("prowler")
    assert detect_importer("out.json", json.dumps(OCSF).encode()) is get_importer("prowler")
    assert "prowler" in [i["name"] for i in list_importers()]


# ---- compliance rollup --------------------------------------------------
def test_compliance_rollup():
    r = import_findings(json.dumps(NATIVE).encode(), importer="prowler", prioritize=False)
    roll = compliance_rollup(r.findings)
    fw = {x["framework"]: x for x in roll["frameworks"]}
    assert fw["CIS-2.0"]["failing_controls"] == 2 and fw["CIS-2.0"]["max_severity"] == "critical"
    assert fw["PCI-4.0"]["failing_controls"] == 1 and fw["NIST-800-53"]["failing_controls"] == 1
    assert roll["findings_with_compliance"] == 2


# ---- runner -------------------------------------------------------------
def test_runner_and_provider_validation():
    res = scan_cloud("aws", runner=ProwlerRunner(run_fn=lambda p: NATIVE))
    assert res.available and len(res.findings) == 2 and res.provider == "aws"
    bad = scan_cloud("digitalocean", runner=ProwlerRunner(run_fn=lambda p: []))
    assert bad.error and "unsupported" in bad.error
    assert scan_cloud("aws", runner=ProwlerRunner(binary="no-prowler")).available is False


# ---- API ----------------------------------------------------------------
@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTESTIQ_INTEL_OFFLINE", "1")
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}


def test_api_prowler_run_and_compliance(ctx, monkeypatch):
    c, H = ctx
    import pentestiq.cloud as cloud_pkg
    monkeypatch.setattr(cloud_pkg, "scan_cloud",
                        lambda provider, **kw: scan_cloud(provider, runner=ProwlerRunner(run_fn=lambda p: NATIVE), **kw))
    r = c.post("/engagements/prowler", headers=H, json={"provider": "aws"})
    assert r.status_code == 201
    eid = r.json()["id"]
    det = c.get(f"/engagements/{eid}", headers=H).json()
    assert det["engagement"]["assets"][0]["type"] == "cloud"
    assert len(det["engagement"]["findings"]) == 2
    # compliance-mapping coverage endpoint
    comp = c.get(f"/engagements/{eid}/coverage/compliance", headers=H).json()
    assert comp["frameworks_count"] >= 3
    assert any(f["framework"] == "CIS-2.0" for f in comp["frameworks"])


def test_api_prowler_via_ingest(ctx):
    c, H = ctx
    r = c.post("/engagements/ingest", headers=H,
               files={"file": ("prowler.json", json.dumps(NATIVE).encode(), "application/json")})
    assert r.status_code == 201 and r.json()["importer"] == "prowler" and r.json()["imported"] == 2

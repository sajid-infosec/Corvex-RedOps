"""E1 — cloud/container: Trivy image (CVE) + IaC config (misconfig) scanning, API."""
from __future__ import annotations

import zipfile

import pytest
from fastapi.testclient import TestClient

import pentestiq.cloud as cloud_pkg
from pentestiq.cloud import scan_container, scan_iac, TrivyRunner, CloudResult
from pentestiq.models import Severity, AssetType
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


IMAGE_JSON = {
    "SchemaVersion": 2, "ArtifactName": "nginx:1.21", "ArtifactType": "container_image",
    "Results": [{"Target": "nginx:1.21 (debian 11)", "Class": "os-pkgs", "Type": "debian",
                 "Vulnerabilities": [{
                     "VulnerabilityID": "CVE-2022-1234", "PkgName": "openssl",
                     "InstalledVersion": "1.1.1k", "FixedVersion": "1.1.1n",
                     "Severity": "HIGH", "Title": "OpenSSL flaw", "CweIDs": ["CWE-787"],
                     "PrimaryURL": "https://x",
                     "CVSS": {"nvd": {"V3Score": 7.5}}}]}]}

CONFIG_JSON = {
    "SchemaVersion": 2, "ArtifactName": ".", "ArtifactType": "filesystem",
    "Results": [
        {"Target": "Dockerfile", "Class": "config", "Type": "dockerfile",
         "Misconfigurations": [{"ID": "DS002", "Title": "Image user should not be root",
                                "Severity": "HIGH", "Description": "Running as root",
                                "Resolution": "Add a USER directive",
                                "CauseMetadata": {"StartLine": 1}}]},
        {"Target": "main.tf", "Class": "config", "Type": "terraform",
         "Misconfigurations": [{"ID": "AVD-AWS-0086", "Title": "S3 bucket allows public access",
                                "Severity": "CRITICAL", "Description": "Public ACL",
                                "Resolution": "Set a private ACL",
                                "CauseMetadata": {"StartLine": 12}}]}]}


def _img_runner():
    return TrivyRunner(run_fn=lambda label, args: IMAGE_JSON)


def _cfg_runner():
    return TrivyRunner(run_fn=lambda label, args: CONFIG_JSON)


# ---- container image ----------------------------------------------------
def test_scan_container_cves():
    r = scan_container("nginx:1.21", runner=_img_runner())
    assert r.available and r.kind == "container" and len(r.findings) == 1
    f = r.findings[0]
    assert f.asset.type is AssetType.CONTAINER and f.asset.identifier == "nginx:1.21"
    assert f.severity is Severity.HIGH and f.location == "openssl@1.1.1k"
    assert "CVE-2022-1234" in f.references and r.cve_count == 1
    assert "Upgrade openssl to 1.1.1n" in (f.remediation or "")


def test_scan_unavailable():
    r = scan_container("x", runner=TrivyRunner(binary="nope-no-trivy"))
    assert r.available is False and r.error and r.findings == []


# ---- IaC / config -------------------------------------------------------
def test_scan_iac_misconfig(tmp_path):
    (tmp_path / "Dockerfile").write_text("FROM alpine")
    r = scan_iac(str(tmp_path), subject="infra", runner=_cfg_runner())
    assert r.available and r.kind == "iac" and len(r.findings) == 2
    assert r.misconfig_count == 2 and r.cve_count == 0
    s3 = next(f for f in r.findings if "S3" in f.title)
    assert s3.severity is Severity.CRITICAL and s3.asset.type is AssetType.IAC
    assert s3.location == "main.tf:12" and s3.category == "A05:2021"
    assert s3.asset.identifier == "infra"


def test_scan_iac_from_archive(tmp_path):
    zp = tmp_path / "infra.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("Dockerfile", "FROM alpine")
        z.writestr("main.tf", 'resource "aws_s3_bucket" "b" {}')
    r = scan_iac(str(zp), subject="infra.zip", runner=_cfg_runner())
    assert len(r.findings) == 2 and all(f.asset.type is AssetType.IAC for f in r.findings)


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


def test_api_container_scan(ctx, monkeypatch):
    c, H = ctx
    monkeypatch.setattr(cloud_pkg, "scan_container",
                        lambda image, subject=None, **kw: scan_container(image, subject=subject, runner=_img_runner()))
    r = c.post("/engagements/container", headers=H, json={"image": "nginx:1.21", "name": "web image"})
    assert r.status_code == 201
    eid = r.json()["id"]
    det = c.get(f"/engagements/{eid}", headers=H).json()
    a0 = det["engagement"]["assets"][0]
    assert a0["type"] == "container" and a0["metadata"]["image"] == "nginx:1.21"
    assert det["engagement"]["findings"][0]["references"]
    # image is required
    assert c.post("/engagements/container", headers=H, json={}).status_code == 422


def test_api_iac_upload(ctx, monkeypatch):
    c, H = ctx
    monkeypatch.setattr(cloud_pkg, "scan_iac",
                        lambda path, subject=None, **kw: scan_iac(path, subject=subject, runner=_cfg_runner()))
    zp_bytes = b""
    import io
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("Dockerfile", "FROM alpine")
    zp_bytes = buf.getvalue()
    r = c.post("/engagements/upload", headers=H, data={"asset_type": "iac", "name": "infra repo"},
               files={"file": ("infra.zip", zp_bytes, "application/zip")})
    assert r.status_code == 201
    eid = r.json()["id"]
    det = c.get(f"/engagements/{eid}", headers=H).json()
    a0 = det["engagement"]["assets"][0]
    assert a0["type"] == "iac" and a0["metadata"]["tool"] == "trivy"
    fs = det["engagement"]["findings"]
    assert any(f["category"] == "A05:2021" for f in fs)

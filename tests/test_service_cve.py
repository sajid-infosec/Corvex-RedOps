"""G2 — service → CVE matching, PRP enrichment, and API wiring."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pentestiq.intel.service_cve import (parse_service, ServiceCVEMatcher,
                                         enrich_finding_services, _ver_tuple,
                                         _version_lt)
from pentestiq.intel import ThreatIntel
from pentestiq.models import (Finding, Asset, AssetType, Severity, Evidence,
                              Engagement, Scope)
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


# ---- banner parsing -----------------------------------------------------
@pytest.mark.parametrize("text,product,version", [
    ("nginx 1.18.0", "nginx", "1.18.0"),
    ("Apache/2.4.29 (Ubuntu)", "apache", "2.4.29"),
    ("Server: Apache httpd 2.4.49", "apache", "2.4.49"),
    ("SSH-2.0-OpenSSH_7.6p1 Ubuntu", "openssh", "7.6p1"),
    ("nginx/1.21.6", "nginx", "1.21.6"),
    ("OpenSSL 1.0.1f", "openssl", "1.0.1f"),
])
def test_parse_service(text, product, version):
    assert parse_service(text) == (product, version)


def test_parse_service_none():
    assert parse_service("just some prose, no software here") is None
    assert parse_service("") is None


def test_ver_tuple_and_lt():
    assert _ver_tuple("7.6p1") == (7, 6, 0, 1)
    assert _ver_tuple("2.4.29") == (2, 4, 29, 0)
    assert _version_lt("1.18.0", "1.21.0") is True
    assert _version_lt("1.21.6", "1.21.0") is False
    assert _version_lt("7.6p1", "7.7") is True
    assert _version_lt("7.7", "7.7") is False


# ---- version-range matching --------------------------------------------
def test_match_in_range():
    m = ServiceCVEMatcher()
    cves = {c["cve"] for c in m.match("nginx", "1.18.0")}
    assert "CVE-2021-23017" in cves            # fixed 1.21.0 → vulnerable

def test_match_out_of_range():
    m = ServiceCVEMatcher()
    assert m.match("nginx", "1.22.0") == []     # past every fixed version

def test_match_alias_and_unknown():
    m = ServiceCVEMatcher()
    assert any(c["cve"] == "CVE-2021-41773" for c in m.match("httpd", "2.4.49"))
    assert m.match("madeup", "1.0") == []


# ---- PRP enrichment via ThreatIntel ------------------------------------
def test_enrich_adds_prp_and_sorts():
    intel = ThreatIntel(offline=True)
    m = ServiceCVEMatcher(intel=intel, offline=True)
    out = m.enrich("apache", "2.4.29")
    assert out and all("prp" in c for c in out)
    # sorted descending by prp
    prps = [c["prp"] or 0 for c in out]
    assert prps == sorted(prps, reverse=True)


def test_enrich_without_intel_still_ranks():
    m = ServiceCVEMatcher()               # no intel → severity-based fallback
    out = m.enrich("apache", "2.4.29")
    assert out and all(isinstance(c["prp"], (int, float)) for c in out)


# ---- finding enrichment mutates references ------------------------------
def test_enrich_finding_services():
    intel = ThreatIntel(offline=True)
    m = ServiceCVEMatcher(intel=intel, offline=True)
    f = Finding(asset=Asset(type=AssetType.INFRA, identifier="10.0.0.5"),
                title="Web server banner: nginx 1.18.0", severity=Severity.INFO)
    cves = enrich_finding_services(f, m)
    assert cves
    assert "CVE-2021-23017" in f.references

def test_enrich_finding_from_evidence():
    m = ServiceCVEMatcher()
    f = Finding(asset=Asset(type=AssetType.INFRA, identifier="10.0.0.5"),
                title="Open port 21/tcp",
                evidence=[Evidence(type="log", ref="nmap",
                                   description="banner: ProFTPD 1.3.5")],
                severity=Severity.INFO)
    cves = enrich_finding_services(f, m)
    assert any(c["cve"] == "CVE-2019-12815" for c in cves)

def test_enrich_finding_no_service():
    m = ServiceCVEMatcher()
    f = Finding(asset=Asset(type=AssetType.INFRA, identifier="10.0.0.5"),
                title="Directory listing enabled", severity=Severity.LOW)
    assert enrich_finding_services(f, m) == []


# ---- API ----------------------------------------------------------------
@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth,
                     config=AppConfig(data_dir=str(tmp_path), intel_offline=True))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq",
                                      "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}, store


def test_api_intel_service(ctx):
    c, H, _ = ctx
    r = c.post("/intel/service", headers=H, json={"product": "nginx", "version": "1.18.0"})
    assert r.status_code == 200
    body = r.json()
    assert body["count"] >= 1
    assert any(x["cve"] == "CVE-2021-23017" for x in body["cves"])
    assert "prp" in body["cves"][0]


def test_api_intel_service_banner_text(ctx):
    c, H, _ = ctx
    r = c.post("/intel/service", headers=H, json={"text": "Server: Apache/2.4.49"})
    assert r.status_code == 200 and r.json()["product"] == "apache"


def test_api_intel_service_bad(ctx):
    c, H, _ = ctx
    assert c.post("/intel/service", headers=H, json={"text": "nothing here"}).status_code == 422


def test_api_engagement_enrich_services(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    a = Asset(type=AssetType.INFRA, identifier="10.0.0.5")
    eng = Engagement(name="infra", scope=Scope(name="s"), assets=[a])
    eng.add_findings([
        Finding(asset=a, title="Service banner nginx 1.18.0", severity=Severity.INFO),
        Finding(asset=a, title="Directory listing", severity=Severity.LOW,
                location="/tmp"),
    ])
    rec = store.create(tid, eng, status="completed")

    r = c.post(f"/engagements/{rec.id}/enrich/services", headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["findings_enriched"] == 1 and body["cves_added"] >= 1

    # persisted: CVE now on the finding, and prioritization picks it up
    det = c.get(f"/engagements/{rec.id}", headers=H).json()
    refs = [ref for f in det["engagement"]["findings"] for ref in (f.get("references") or [])]
    assert any("CVE-2021-23017" in r for r in refs)

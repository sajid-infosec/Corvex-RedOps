"""Threat-informed prioritization (KEV + EPSS + PRP) and remediation SLA."""
from __future__ import annotations

from datetime import datetime, timedelta, timezone

from pentestiq.intel import ThreatIntel, sla_for, sla_summary, extract_cves
from pentestiq.models import Finding, Asset, Severity, FindingStatus
from pentestiq.models.enums import AssetType

TI = ThreatIntel(offline=True)  # deterministic, no network


def _f(title, sev, **kw):
    a = Asset(type=AssetType.INFRA, identifier="10.0.0.9")
    return Finding(asset=a, title=title, severity=sev, **kw)


def test_cve_extraction():
    got = extract_cves("upgrade needed CVE-2021-44228 and cve-2023-4966!")
    assert got == ["CVE-2021-44228", "CVE-2023-4966"]


def test_kev_seed_loaded():
    info = TI.info()
    assert info["kev_entries"] >= 40
    assert TI.kev("CVE-2021-44228")["ransomware"] is True
    assert TI.kev("CVE-2099-0001") is None


def test_prp_kev_outranks_higher_severity():
    # a HIGH severity KEV/ransomware finding must outrank a plain CRITICAL
    kev = _f("Log4Shell CVE-2021-44228", Severity.HIGH, references=["CVE-2021-44228"])
    crit = _f("Some critical config issue", Severity.CRITICAL)
    p_kev = TI.priority(kev)
    p_crit = TI.priority(crit)
    assert p_kev["kev"] and p_kev["kev_ransomware"]
    assert p_kev["prp"] >= p_crit["prp"]
    assert "known exploited" in p_kev["label"].lower()
    assert any("KEV" in fac["factor"] for fac in p_kev["factors"])


def test_prp_false_positive_zeroed():
    f = _f("noise", Severity.HIGH, status=FindingStatus.FALSE_POSITIVE)
    assert TI.priority(f)["prp"] == 0.0


def test_prp_transparent_factors():
    f = _f("SQLi", Severity.HIGH)
    p = TI.priority(f)
    assert 0 <= p["prp"] <= 100
    assert p["factors"] and p["factors"][0]["factor"].startswith("base")


def test_sla_states():
    now = datetime.now(timezone.utc)
    old = _f("stale crit", Severity.CRITICAL)
    old.first_seen = now - timedelta(days=30)          # > 7d critical SLA
    assert sla_for(old)["state"] == "overdue"
    fresh = _f("fresh low", Severity.LOW)
    fresh.first_seen = now
    assert sla_for(fresh)["state"] == "on_track"


def test_sla_summary_counts():
    now = datetime.now(timezone.utc)
    fs = []
    a = Asset(type=AssetType.INFRA, identifier="10.0.0.9")
    over = Finding(asset=a, title="o", severity=Severity.CRITICAL)
    over.first_seen = now - timedelta(days=60)
    fs.append(over)
    ok = Finding(asset=a, title="k", severity=Severity.LOW)
    ok.first_seen = now
    fs.append(ok)
    s = sla_summary(fs)
    assert s["counts"]["overdue"] >= 1 and s["counts"]["on_track"] >= 1

"""D1 — MITRE ATT&CK mapping + coverage matrix + API."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pentestiq.attack import techniques_for, attack_coverage, technique_info, TACTICS
from pentestiq.models import (Finding, Asset, AssetType, Severity, Engagement, Scope)
from pentestiq.core.analysis import analyze
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


def _f(title, cat, sev=Severity.HIGH, refs=None):
    return Finding(asset=Asset(type=AssetType.WEB, identifier="https://x"),
                   title=title, category=cat, severity=sev, references=refs or [])


# ---- mapping ------------------------------------------------------------
def test_techniques_by_cwe_and_owasp():
    assert techniques_for(_f("SQLi", "A03:2021", refs=["CWE-89"]))[0] == "T1190"
    assert "T1059.007" in techniques_for(_f("XSS", "A03:2021", refs=["CWE-79"]))
    assert "T1552.001" in techniques_for(_f("secret", "A07:2021", refs=["CWE-798"]))
    assert "T1552.005" in techniques_for(_f("SSRF", "A10:2021", refs=["CWE-918"]))
    # unmapped category → no technique (never guesses)
    assert techniques_for(_f("mystery", "MASVS-STORAGE")) == []


def test_cwe_precedence_over_owasp():
    # CWE-79 (XSS) adds JavaScript execution the bare A03 category wouldn't
    t = techniques_for(_f("Reflected XSS", "A03:2021", refs=["CWE-79"]))
    assert t[0] == "T1059.007" and "T1190" in t


def test_technique_info():
    info = technique_info("T1190")
    assert info["name"] == "Exploit Public-Facing Application"
    assert info["tactic_name"] == "Initial Access"
    assert info["url"].endswith("/T1190/")
    sub = technique_info("T1059.007")
    assert sub["url"].endswith("/T1059/007/")     # sub-techniques use a slash


# ---- coverage matrix ----------------------------------------------------
def test_attack_coverage_matrix():
    fs = [_f("SQLi", "A03:2021", Severity.CRITICAL, ["CWE-89"]),
          _f("XSS", "A03:2021", Severity.HIGH, ["CWE-79"]),
          _f("secret", "A07:2021", Severity.CRITICAL, ["CWE-798"]),
          _f("Log4Shell", "A06:2021", Severity.CRITICAL, ["CVE-2021-44228"]),
          _f("SSRF", "A10:2021", Severity.HIGH, ["CWE-918"])]
    cov = attack_coverage(fs)
    assert cov["tactics_total"] == len(TACTICS)
    assert cov["tactics_hit"] >= 3 and cov["techniques_hit"] >= 6
    assert cov["findings_mapped"] == 5
    # T1190 is hit by several findings and ranks first, at critical
    top = cov["top_techniques"][0]
    assert top["id"] == "T1190" and top["max_severity"] == "critical" and top["findings"] >= 3
    # matrix keeps all tactics as columns, in kill-chain order
    ia = next(t for t in cov["matrix"] if t["id"] == "TA0001")   # Initial Access
    assert any(c["id"] == "T1190" for c in ia["techniques"])
    assert cov["matrix"][0]["id"] == TACTICS[0]["id"]


def test_empty_and_false_positive():
    assert attack_coverage([])["techniques_hit"] == 0
    from pentestiq.models import FindingStatus
    fp = _f("SQLi", "A03:2021", Severity.INFO)
    fp.status = FindingStatus.FALSE_POSITIVE
    # info + false positive contributes nothing
    assert attack_coverage([fp])["findings_mapped"] == 0


# ---- analyze tags findings ----------------------------------------------
def test_analyze_tags_attack():
    eng = Engagement(name="e", scope=Scope(name="s"))
    eng.add_findings([_f("SQLi", "A03:2021", Severity.HIGH, ["CWE-89"])])
    analyze(eng)
    assert "T1190" in eng.findings[0].attack


# ---- API ----------------------------------------------------------------
@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}, store


def test_api_attack_coverage(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    eng = Engagement(name="e", scope=Scope(name="s"))
    eng.add_findings([_f("SQLi", "A03:2021", Severity.CRITICAL, ["CWE-89"]),
                      _f("secret", "A07:2021", Severity.HIGH, ["CWE-798"])])
    analyze(eng)
    rec = store.create(tid, eng, status="completed")
    # per-engagement
    e = c.get(f"/engagements/{rec.id}/coverage/attack", headers=H).json()
    assert e["techniques_hit"] >= 2 and e["tactics_hit"] >= 2
    assert any(t["id"] == "T1190" for tac in e["matrix"] for t in tac["techniques"])
    # tenant-wide
    g = c.get("/coverage/attack", headers=H).json()
    assert g["techniques_hit"] >= 2
    # findings carry technique ids over the wire
    fs = c.get(f"/engagements/{rec.id}/findings", headers=H).json()
    assert any("T1190" in (f.get("attack") or []) for f in fs)

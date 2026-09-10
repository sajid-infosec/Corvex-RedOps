"""D2 — attack-path graph: chain building, scoring, SVG/mermaid, API."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pentestiq.attack import (build_paths, paths_summary, paths_to_svg,
                              paths_to_mermaid, shortest_path_to_impact)
from pentestiq.models import (Finding, Asset, AssetType, Severity, Engagement,
                              Scope, FindingStatus)
from pentestiq.core.analysis import analyze
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


def _f(title, cat, sev, refs=None, ident="https://app.example.com", loc=None):
    return Finding(asset=Asset(type=AssetType.WEB, identifier=ident), title=title,
                   category=cat, severity=sev, references=refs or [], location=loc)


def _analyzed(findings):
    eng = Engagement(name="e", scope=Scope(name="s"))
    eng.add_findings(findings)
    analyze(eng)
    return eng


# ---- path building ------------------------------------------------------
def test_multi_finding_builds_ordered_kill_chain():
    eng = _analyzed([
        _f("SQLi", "A03:2021", Severity.CRITICAL, ["CWE-89"], loc="/search"),
        _f("Hardcoded AWS key", "A07:2021", Severity.CRITICAL, ["CWE-798"]),
        _f("Path traversal", "A01:2021", Severity.HIGH, ["CWE-22"], loc="/dl"),
    ])
    paths = build_paths(eng.findings)
    assert len(paths) == 1
    p = paths[0]
    assert p.target == "app.example.com" or "app.example.com" in p.target
    # steps are ordered along the ATT&CK kill chain
    from pentestiq.attack.graph import _TACTIC_ORDER
    order = [_TACTIC_ORDER[s.tactic] for s in p.steps]
    assert order == sorted(order)
    assert p.reaches_impact and p.max_severity == "critical" and p.crown_jewel


def test_two_assets_two_paths_sorted_by_score():
    eng = _analyzed([
        _f("SQLi", "A03:2021", Severity.CRITICAL, ["CWE-89"], loc="/s"),
        _f("secret", "A07:2021", Severity.CRITICAL, ["CWE-798"]),
        _f("TLS 1.0", "A02:2021", Severity.LOW, ["CWE-319"], ident="https://api.example.com"),
    ])
    paths = build_paths(eng.findings)
    assert len(paths) == 2
    # the critical/impactful app chain outranks the low api chain
    assert paths[0].score > paths[1].score
    assert "app.example.com" in paths[0].target


def test_shortest_path_to_impact():
    eng = _analyzed([
        # app: long chain to impact
        _f("SQLi", "A03:2021", Severity.HIGH, ["CWE-89"], loc="/s"),
        _f("Path traversal", "A01:2021", Severity.HIGH, ["CWE-22"], loc="/d"),
        _f("secret", "A07:2021", Severity.HIGH, ["CWE-798"]),
        # api: one critical RCE — a direct route
        _f("Log4Shell RCE", "A06:2021", Severity.CRITICAL, ["CVE-2021-44228"],
           ident="https://api.example.com"),
        _f("weak creds", "A07:2021", Severity.CRITICAL, ["CWE-521"],
           ident="https://api.example.com", loc="/login"),
    ])
    paths = build_paths(eng.findings)
    sp = shortest_path_to_impact(paths)
    assert sp is not None and "api.example.com" in sp.target
    assert sp.length <= min(p.length for p in paths if p.reaches_impact)


def test_crown_jewel_from_inventory():
    eng = _analyzed([_f("SSRF", "A10:2021", Severity.MEDIUM, ["CWE-918"],
                        ident="https://vpn.corp.example.com", loc="/x")])
    # medium severity wouldn't be a crown jewel on its own; inventory marks it one
    plain = build_paths(eng.findings)
    assert plain and plain[0].crown_jewel is False
    crowned = build_paths(eng.findings, crown_jewels={"vpn.corp.example.com"})
    assert crowned[0].crown_jewel is True


def test_false_positive_excluded():
    fp = _f("SQLi", "A03:2021", Severity.CRITICAL, ["CWE-89"])
    fp.status = FindingStatus.FALSE_POSITIVE
    assert build_paths([fp]) == []


# ---- rendering ----------------------------------------------------------
def test_svg_and_mermaid_render():
    eng = _analyzed([
        _f("SQLi", "A03:2021", Severity.CRITICAL, ["CWE-89"], loc="/s"),
        _f("secret", "A07:2021", Severity.HIGH, ["CWE-798"]),
    ])
    paths = build_paths(eng.findings)
    svg = paths_to_svg(paths)
    assert svg.startswith("<svg") and svg.rstrip().endswith("</svg>")
    assert "viewBox" in svg and "IMPACT" in svg or "CROWN JEWEL" in svg
    mer = paths_to_mermaid(paths)
    assert mer.startswith("flowchart LR") and "T1190" in mer
    assert paths_to_svg([]) == "" and paths_to_mermaid([]) == ""


def test_summary_shape():
    eng = _analyzed([_f("SQLi", "A03:2021", Severity.CRITICAL, ["CWE-89"])])
    s = paths_summary(build_paths(eng.findings))
    assert s["total"] == 1 and s["reaching_impact"] >= 0
    assert isinstance(s["paths"], list) and s["paths"][0]["steps"]


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


def test_api_attack_path(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    eng = _analyzed([
        _f("SQLi", "A03:2021", Severity.CRITICAL, ["CWE-89"], loc="/s"),
        _f("secret", "A07:2021", Severity.CRITICAL, ["CWE-798"]),
        _f("SSRF", "A10:2021", Severity.HIGH, ["CWE-918"], loc="/f"),
    ])
    rec = store.create(tid, eng, status="completed")
    r = c.get(f"/engagements/{rec.id}/attack-path", headers=H).json()
    assert r["total"] >= 1 and r["svg"].startswith("<svg")
    assert r["mermaid"].startswith("flowchart")
    assert r["paths"][0]["steps"] and r["paths"][0]["reaches_impact"]
    assert c.get("/engagements/does-not-exist/attack-path", headers=H).status_code == 404

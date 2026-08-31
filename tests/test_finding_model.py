from pentestiq.models import (
    Asset, AssetType, Finding, Severity, FindingStatus, Engagement, Scope, Enforcement,
)


def _web(url="http://localhost:3000"):
    return Asset(type=AssetType.WEB, identifier=url)


def test_dedup_key_stable_across_tools():
    a = _web()
    f1 = Finding(asset=a, title="SQL Injection", category="CWE-89",
                 severity=Severity.HIGH, source_tools=["nuclei"])
    f2 = Finding(asset=a, title="SQLi (login)", category="CWE-89",
                 severity=Severity.CRITICAL, source_tools=["zap"])
    # same asset + category -> same dedup key even though titles/tools differ
    assert f1.dedup_key == f2.dedup_key


def test_engagement_dedups_and_merges():
    eng = Engagement(name="t")
    a = _web()
    f1 = Finding(asset=a, title="SQLi", category="CWE-89",
                 severity=Severity.HIGH, source_tools=["nuclei"])
    f2 = Finding(asset=a, title="SQLi", category="CWE-89",
                 severity=Severity.CRITICAL, source_tools=["zap"])
    eng.add_findings([f1, f2])
    assert len(eng.findings) == 1
    merged = eng.findings[0]
    assert set(merged.source_tools) == {"nuclei", "zap"}
    assert merged.severity == Severity.CRITICAL  # keeps the higher severity
    assert merged.engagement_id == eng.id


def test_severity_sorting():
    a = _web()
    eng = Engagement(name="t")
    eng.add_findings([
        Finding(asset=_web("http://a"), title="low", severity=Severity.LOW),
        Finding(asset=_web("http://b"), title="crit", severity=Severity.CRITICAL),
        Finding(asset=_web("http://c"), title="med", severity=Severity.MEDIUM),
    ])
    order = [f.severity for f in eng.sorted_findings()]
    assert order == [Severity.CRITICAL, Severity.MEDIUM, Severity.LOW]


def test_finding_serializes():
    f = Finding(asset=_web(), title="x", severity=Severity.MEDIUM)
    data = f.model_dump()
    assert data["title"] == "x"
    assert data["status"] == FindingStatus.DETECTED

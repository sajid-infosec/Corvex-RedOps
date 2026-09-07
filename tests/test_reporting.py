from pentestiq.reporting import (
    compute_stats, deterministic_summary, build_narrative, render_markdown,
    render_html, ReportGenerator, NarrativeProvider,
)
from pentestiq.core.analysis import analyze
from pentestiq.models import (
    Asset, AssetType, Finding, Severity, FindingStatus, Confidence, Evidence, Engagement,
)


def _engagement():
    a = Asset(type=AssetType.WEB, identifier="http://shop")
    eng = Engagement(name="PentestIQ Web Test")
    eng.add_findings([
        Finding(asset=a, title="SQL Injection", category="CWE-89", severity=Severity.HIGH,
                status=FindingStatus.VALIDATED, confidence=Confidence.HIGH, source_tools=["zap"],
                evidence=[Evidence(type="validation", ref="http://shop/item", description="boolean inference")],
                remediation="Use parameterized queries."),
        Finding(asset=a, title="Missing header", category="CWE-16", severity=Severity.LOW,
                source_tools=["zap"]),
        Finding(asset=Asset(type=AssetType.WEB, identifier="http://shop/safe"),
                title="Reflected XSS", category="CWE-79", severity=Severity.MEDIUM,
                status=FindingStatus.FALSE_POSITIVE, source_tools=["zap"]),
    ])
    analyze(eng)
    return eng


def test_stats_counts():
    st = compute_stats(_engagement())
    assert st["total"] == 3
    assert st["active"] == 2               # false positive excluded from active
    assert st["false_positives"] == 1
    assert st["validated"] == 1
    assert st["overall_rating"] == "High"
    assert st["by_severity"]["high"] == 1


def test_deterministic_summary_mentions_key_facts():
    eng = _engagement()
    txt = deterministic_summary(eng, compute_stats(eng))
    assert "PentestIQ Web Test" in txt
    assert "validated" in txt.lower()
    assert "false positive" in txt.lower()


class FakeProvider(NarrativeProvider):
    def generate(self, system, prompt):
        return "ENRICHED SUMMARY"


def test_build_narrative_uses_provider_when_present():
    eng = _engagement()
    st = compute_stats(eng)
    assert build_narrative(eng, st, FakeProvider()) == "ENRICHED SUMMARY"
    assert build_narrative(eng, st, None) != "ENRICHED SUMMARY"   # falls back


def test_markdown_report_structure():
    eng = _engagement()
    st = compute_stats(eng)
    md = render_markdown(eng, st, build_narrative(eng, st))
    assert "# Vulnerability Assessment & Penetration Testing Report" in md
    assert "Executive Summary" in md
    assert "SQL Injection" in md
    assert "CWE-89" in md                                     # framework mapping
    assert "Reflected XSS" not in md                          # false positives excluded from client report


def test_html_report_is_selfcontained():
    eng = _engagement()
    st = compute_stats(eng)
    h = render_html(eng, st, build_narrative(eng, st))
    assert h.startswith("<!doctype html>")
    assert "Vulnerability Assessment" in h and "SQL Injection" in h
    assert "<style>" in h                                     # inline CSS, self-contained


def test_generate_writes_files(tmp_path):
    paths = ReportGenerator().generate(_engagement(), tmp_path)
    assert (tmp_path / "report.md").exists()
    assert (tmp_path / "report.html").exists()
    assert (tmp_path / "engagement.json").exists()
    assert set(paths) == {"md", "html", "json"}

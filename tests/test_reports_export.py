from pentestiq.reporting import (
    compliance_summary, map_finding, render_pdf, render_docx, ReportGenerator, ReportBranding,
)
from pentestiq.reporting.stats import compute_stats
from pentestiq.reporting.report import render_markdown, render_html
from pentestiq.reporting.narrative import build_narrative
from pentestiq.core.analysis import analyze
from pentestiq.models import (
    Asset, AssetType, Finding, Severity, FindingStatus, Engagement,
)


def _eng():
    a = Asset(type=AssetType.WEB, identifier="http://shop")
    e = Engagement(name="PentestIQ")
    e.add_findings([
        Finding(asset=a, title="SQL Injection", category="CWE-89", severity=Severity.HIGH,
                status=FindingStatus.VALIDATED, source_tools=["zap"]),
        Finding(asset=a, title="Weak TLS", category="weak-tls", severity=Severity.MEDIUM,
                source_tools=["nuclei"]),
        Finding(asset=a, title="Custom", category="proprietary-x", severity=Severity.LOW),
    ])
    analyze(e)
    return e


def test_compliance_mapping():
    comp = compliance_summary(_eng())
    assert comp["total"] == 3
    assert comp["mapped"] == 2 and comp["unmapped"] == 1     # proprietary-x has no mapping
    assert "A03: Injection" in comp["frameworks"]["owasp"]
    assert "A02: Cryptographic Failures" in comp["frameworks"]["owasp"]


def test_map_finding_cwe_and_category():
    a = Asset(type=AssetType.WEB, identifier="http://x")
    assert map_finding(Finding(asset=a, title="x", category="CWE-89"))["owasp"].startswith("A03")
    assert map_finding(Finding(asset=a, title="x", category="open-port"))["owasp"].startswith("A05")
    assert map_finding(Finding(asset=a, title="x", category="unknown-cat")) is None


def test_pdf_and_docx_bytes_valid():
    e = _eng(); st = compute_stats(e); nar = build_narrative(e, st); comp = compliance_summary(e)
    pdf = render_pdf(e, st, nar, ReportBranding(company_name="PentestIQ"), comp)
    docx = render_docx(e, st, nar, ReportBranding(company_name="PentestIQ"), comp)
    assert pdf[:4] == b"%PDF"
    assert docx[:2] == b"PK"                                 # docx is a zip
    assert len(pdf) > 1000 and len(docx) > 1000


def test_branding_applied_to_text_reports():
    e = _eng(); st = compute_stats(e); nar = build_narrative(e, st); comp = compliance_summary(e)
    b = ReportBranding(company_name="PentestIQ Security", accent_color="#6d28d9", footer_note="Confidential")
    md = render_markdown(e, st, nar, b, comp)
    html = render_html(e, st, nar, b, comp)
    assert "PentestIQ Security" in md and "Compliance Mapping" in md and "Confidential" in md
    assert "PentestIQ Security" in html and "#6d28d9" in html and "Compliance Mapping" in html


def test_generator_writes_all_formats(tmp_path):
    paths = ReportGenerator(branding=ReportBranding(company_name="PentestIQ")).generate(
        _eng(), tmp_path, formats=("md", "html", "json", "pdf", "docx"))
    assert set(paths) == {"md", "html", "json", "pdf", "docx"}
    assert (tmp_path / "report.pdf").read_bytes()[:4] == b"%PDF"
    assert (tmp_path / "report.docx").read_bytes()[:2] == b"PK"

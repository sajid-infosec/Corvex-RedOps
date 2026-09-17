"""Report embedding — ATT&CK, attack paths, cloud/CSPM, compliance surfaced
into the HTML / PDF / DOCX deliverables."""
from __future__ import annotations

import pytest

from pentestiq.reporting import compute_stats, build_narrative, render_html
from pentestiq.reporting.report import _cloud_findings, _intel_sections
from pentestiq.core.analysis import analyze
from pentestiq.models import (Asset, AssetType, Finding, Severity, FindingStatus,
                              Confidence, Evidence, Engagement)


def _rich_engagement():
    web = Asset(type=AssetType.WEB, identifier="https://shop.example.com")
    cont = Asset(type=AssetType.CONTAINER, identifier="registry/app:1.2")
    cloud = Asset(type=AssetType.CLOUD, identifier="aws:s3:public-bucket")
    eng = Engagement(name="Full-depth Assessment")
    eng.add_findings([
        Finding(asset=web, title="SQL Injection", category="A03:2021", severity=Severity.CRITICAL,
                status=FindingStatus.VALIDATED, confidence=Confidence.HIGH, source_tools=["zap"],
                location="/search", references=["CWE-89"],
                evidence=[Evidence(type="validation", ref="/search", description="boolean inference")],
                remediation="Parameterize queries."),
        Finding(asset=web, title="Remote Code Execution via upload", category="A03:2021",
                severity=Severity.CRITICAL, source_tools=["nuclei"], location="/upload",
                references=["CWE-94"]),
        Finding(asset=cont, title="Vulnerable OpenSSL in image", category="A06:2021",
                severity=Severity.HIGH, source_tools=["trivy"], references=["CVE-2022-0778"]),
        Finding(asset=cloud, title="S3 bucket world-readable", category="A05:2021",
                severity=Severity.HIGH, source_tools=["prowler"]),
    ])
    analyze(eng)
    return eng


@pytest.fixture
def ctx():
    eng = _rich_engagement()
    st = compute_stats(eng)
    nar = build_narrative(eng, st)
    return eng, st, nar


# ---- helpers ------------------------------------------------------------
def test_cloud_findings_filter():
    eng = _rich_engagement()
    cf = _cloud_findings(eng)
    titles = {f.title for f in cf}
    assert "Vulnerable OpenSSL in image" in titles     # container asset
    assert "S3 bucket world-readable" in titles        # cloud asset (prowler)
    assert "SQL Injection" not in titles               # web finding excluded


def test_intel_sections_numbering():
    eng = _rich_engagement()
    html, next_n = _intel_sections(eng, section_start=7)
    assert next_n > 7                                   # at least one section emitted
    assert "MITRE ATT&amp;CK Coverage" in html
    assert "Cloud, Container" in html


def test_intel_sections_empty_engagement():
    eng = Engagement(name="empty")
    html, next_n = _intel_sections(eng, section_start=7)
    assert html == "" and next_n == 7                   # nothing to show, no renumber


# ---- HTML ---------------------------------------------------------------
def test_html_embeds_all_dimensions(ctx):
    eng, st, nar = ctx
    html = render_html(eng, st, nar)
    assert "MITRE ATT&amp;CK Coverage" in html
    assert "Attack Path Analysis" in html
    assert "Cloud, Container &amp; IaC Findings" in html
    assert "Compliance Framework Mapping" in html
    assert "<svg" in html                               # attack-path diagram embedded
    # conclusion renumbered to sit after the intel sections
    assert "Conclusion" in html
    import re
    concl = re.search(r"Section (\d+)</div><h2 class=\"sec\">Conclusion", html) \
        or re.search(r"Section (\d+)</div>\s*<h2 class=\"sec\">Conclusion", html)
    assert concl and int(concl.group(1)) > 7


def test_severity_methodology_badge_classes(ctx):
    """Regression: the risk-rating table must map every severity label to a real
    CSS colour class (Critical->b-critical, Medium->b-medium), not the truncated
    b-crit / b-medi that rendered grey."""
    eng, st, nar = ctx
    html = render_html(eng, st, nar)
    import re
    classes = set(re.findall(r'badge b-(\w+)">(?:Critical|High|Medium|Low|Informational)', html))
    assert {"critical", "high", "medium", "low", "info"} <= classes
    assert 'b-crit"' not in html and 'b-medi"' not in html


def test_report_never_leaks_raw_tool_names(ctx):
    """Branding regression: the client deliverable must expose only neutral engine
    labels, never raw third-party tool product names, even though findings carry
    raw ``source_tools`` keys internally (zap / nuclei / trivy / prowler here)."""
    eng, st, nar = ctx
    html = render_html(eng, st, nar).lower()
    for raw in ("zap", "nuclei", "trivy", "prowler", "nmap", "mobsf", "burp",
                "nessus", "semgrep", "wpscan", "bloodhound"):
        assert raw not in html, f"raw tool name {raw!r} leaked into the report"
    # the generic labels are present instead (& is HTML-escaped to &amp;)
    assert "dast web-scanning engine" in html
    assert "iac scanner" in html
    assert "cloud-posture (cspm) engine" in html


# ---- PDF ----------------------------------------------------------------
def test_pdf_builds_with_sections(ctx):
    pytest.importorskip("reportlab")
    from pentestiq.reporting.pdf_report import render_pdf
    eng, st, nar = ctx
    data = render_pdf(eng, st, nar)
    assert data[:4] == b"%PDF" and len(data) > 3000


# ---- DOCX ---------------------------------------------------------------
def test_docx_builds_with_sections(ctx):
    pytest.importorskip("docx")
    from pentestiq.reporting.docx_report import render_docx
    eng, st, nar = ctx
    data = render_docx(eng, st, nar)
    assert data[:2] == b"PK" and len(data) > 3000       # zip/docx magic
    # verify the ATT&CK heading text is present in the document xml
    import io, zipfile
    z = zipfile.ZipFile(io.BytesIO(data))
    doc_xml = z.read("word/document.xml").decode("utf-8", "ignore")
    assert "ATT&CK Coverage" in doc_xml or "ATT&amp;CK Coverage" in doc_xml
    assert "Cloud, Container" in doc_xml
    assert "Compliance Framework Mapping" in doc_xml

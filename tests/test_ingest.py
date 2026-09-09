"""B1 — normalized importer framework: mapping, dedupe, PRP, generic JSON."""
from __future__ import annotations

import json

import pytest

from pentestiq.ingest import (import_findings, detect_importer, get_importer,
                              list_importers, ImportResult)
from pentestiq.ingest.mapping import (normalize_severity, severity_from_cvss,
                                      owasp_for_cwe, category_for, make_asset,
                                      extract_cwe, extract_cves, parse_cvss)
from pentestiq.ingest.base import BaseImporter, register_importer
from pentestiq.models import Finding, Asset, AssetType, Severity
from pentestiq.intel import ThreatIntel


# ---- mapping ------------------------------------------------------------
def test_severity_normalization():
    assert normalize_severity("Critical") is Severity.CRITICAL
    assert normalize_severity("moderate") is Severity.MEDIUM
    assert normalize_severity("Informational") is Severity.INFO
    assert normalize_severity("7.5") is Severity.HIGH          # numeric string → CVSS band
    assert normalize_severity(9.8) is Severity.CRITICAL
    assert normalize_severity(None, cvss=4.0) is Severity.MEDIUM
    assert normalize_severity("nonsense", cvss=None) is Severity.INFO


def test_cvss_bands():
    assert severity_from_cvss(0.0) is Severity.INFO
    assert severity_from_cvss(3.9) is Severity.LOW
    assert severity_from_cvss(6.9) is Severity.MEDIUM
    assert severity_from_cvss(8.9) is Severity.HIGH
    assert severity_from_cvss(9.0) is Severity.CRITICAL


def test_cwe_to_owasp_and_category():
    assert owasp_for_cwe("89") == "A03:2021"       # SQLi → Injection
    assert owasp_for_cwe("918") == "A10:2021"      # SSRF
    assert owasp_for_cwe("CWE-79") == "A03:2021"   # tolerant of the prefix
    assert owasp_for_cwe("999999") is None
    assert category_for("89", "SQL injection") == "A03:2021"
    assert category_for(None, "SQL injection in id param") == "A03:2021"
    assert category_for("999999", "weird") == "CWE-999999"


def test_extractors_and_asset():
    assert extract_cwe("issue (CWE-89)") == "89"
    assert extract_cves("see CVE-2021-44228 and cve-2019-0708") == ["CVE-2021-44228", "CVE-2019-0708"]
    assert make_asset("https://x.example.com/login").type is AssetType.WEB
    assert make_asset("10.0.0.5").type is AssetType.INFRA
    assert make_asset("host", asset_type="api").type is AssetType.API
    assert parse_cvss(None, 7.5).base_score == 7.5
    assert parse_cvss(None, None) is None


# ---- framework: dedupe + provenance + PRP -------------------------------
def _f(title, sev, target="https://a.example.com", cat=None, refs=None, loc=None, tools=None):
    return Finding(asset=Asset(type=AssetType.WEB, identifier=target), title=title,
                   category=cat, severity=sev, references=refs or [], location=loc,
                   source_tools=tools or [])


@register_importer
class _StubImporter(BaseImporter):
    name = "_stub"
    source_format = "stub"
    extensions = (".stub",)
    tool_name = "stub-tool"

    def parse(self, data):
        # two tools reporting the SAME issue on the same asset+category+location
        return [
            _f("SQLi in id", Severity.HIGH, cat="A03:2021", loc="/api?id=1", tools=["nuclei"]),
            _f("SQL injection", Severity.CRITICAL, cat="A03:2021", loc="/api?id=1", tools=["zap"]),
            _f("Missing HSTS", Severity.LOW, cat="A05:2021"),
        ]


def test_framework_dedupes_and_keeps_higher_severity():
    intel = ThreatIntel(offline=True)
    res = import_findings(b"x", importer="_stub", intel=intel)
    assert isinstance(res, ImportResult)
    assert res.raw_count == 3 and res.imported_count == 2 and res.merged_count == 1
    sqli = next(f for f in res.findings if "sql" in f.title.lower())
    # merge_source keeps the higher severity and unions provenance
    assert sqli.severity is Severity.CRITICAL
    assert {"nuclei", "zap", "stub-tool"} <= set(sqli.source_tools)


def test_framework_applies_prp_risk_score():
    intel = ThreatIntel(offline=True)
    res = import_findings(b"x", importer="_stub", intel=intel)
    for f in res.findings:
        assert f.risk_score is not None and 0 <= f.risk_score <= 100
    sqli = next(f for f in res.findings if "sql" in f.title.lower())
    hsts = next(f for f in res.findings if "hsts" in f.title.lower())
    assert sqli.risk_score > hsts.risk_score


# ---- generic JSON importer ---------------------------------------------
def test_generic_json_loose_export():
    intel = ThreatIntel(offline=True)
    blob = json.dumps({"results": [
        {"name": "SQL Injection", "risk": "High", "host": "https://shop.example.com",
         "cwe": "CWE-89", "location": "/search?q=", "solution": "Use parameterized queries"},
        {"title": "Outdated OpenSSL", "severity": "critical", "target": "10.0.0.9",
         "cve": "CVE-2021-44228", "description": "Vulnerable component"},
        {"message": "Verbose error", "level": "low", "url": "https://shop.example.com"},
    ]}).encode()
    res = import_findings(blob, filename="scan.json", intel=intel)
    assert res.importer == "generic-json" and res.imported_count == 3
    sqli = next(f for f in res.findings if "sql" in f.title.lower())
    assert sqli.category == "A03:2021" and sqli.severity is Severity.HIGH
    assert sqli.asset.type is AssetType.WEB and sqli.remediation
    comp = next(f for f in res.findings if "openssl" in f.title.lower())
    assert "CVE-2021-44228" in comp.references
    assert res.with_cve == 1 and res.kev >= 1     # Log4Shell CVE is in the KEV seed


def test_generic_json_roundtrips_native_findings():
    intel = ThreatIntel(offline=True)
    native = [_f("Native issue", Severity.MEDIUM, cat="A01:2021").model_dump(mode="json")]
    res = import_findings(json.dumps(native).encode(), filename="ptiq.json", intel=intel)
    assert res.imported_count == 1
    assert res.findings[0].title == "Native issue" and res.findings[0].category == "A01:2021"


def test_detection_and_registry():
    assert detect_importer("report.json") is get_importer("generic-json")
    assert detect_importer(None, b'[{"title":"x","severity":"low","host":"h"}]') is get_importer("generic-json")
    names = [i["name"] for i in list_importers()]
    assert "generic-json" in names


def test_unknown_importer_and_format():
    with pytest.raises(ValueError):
        import_findings(b"x", importer="does-not-exist")
    with pytest.raises(ValueError):
        import_findings(b"\x00\x01", filename="mystery.bin")


def test_parse_failure_is_reported_not_raised():
    res = import_findings(b"{not valid json", filename="broken.json")
    assert res.imported_count == 0 and res.warnings and "parse failed" in res.warnings[0]

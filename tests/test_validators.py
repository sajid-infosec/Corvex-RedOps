from pentestiq.validators.base import HttpClient, HttpResponse
from pentestiq.validators.xss import ReflectedXSSValidator
from pentestiq.validators.sqli import SqliValidator
from pentestiq.validators.engine import ValidationEngine
from pentestiq.models import (
    Asset, AssetType, Finding, Severity, FindingStatus, Confidence,
    ValidationResult, Evidence,
)


class FakeHttpClient(HttpClient):
    def __init__(self, handler):
        self.handler = handler
        self.calls = []
    def get(self, url, params=None):
        self.calls.append((url, params or {}))
        return self.handler(url, params or {})


def _xss_finding():
    a = Asset(type=AssetType.WEB, identifier="http://site/search")
    return Finding(asset=a, title="Reflected XSS", category="CWE-79",
                   severity=Severity.MEDIUM, source_tools=["zap"],
                   evidence=[Evidence(type="http", ref="http://site/search")])


def _sqli_finding():
    a = Asset(type=AssetType.WEB, identifier="http://site/item")
    return Finding(asset=a, title="SQL Injection", category="CWE-89",
                   severity=Severity.HIGH, source_tools=["zap"],
                   evidence=[Evidence(type="http", ref="http://site/item")])


def test_xss_confirmed_when_marker_reflected():
    http = FakeHttpClient(lambda url, p: HttpResponse(200, f"<div>{p.get('ptiq','')}</div>", 3.0, url))
    f = _xss_finding()
    outcome = ReflectedXSSValidator().validate(f, http)
    assert outcome.result == ValidationResult.CONFIRMED
    assert "reflected" in outcome.evidence_desc.lower()


def test_xss_dismissed_when_not_reflected():
    http = FakeHttpClient(lambda url, p: HttpResponse(200, "<div>safe, encoded</div>", 3.0, url))
    outcome = ReflectedXSSValidator().validate(_xss_finding(), http)
    assert outcome.result == ValidationResult.NOT_EXPLOITABLE


def test_sqli_confirmed_by_boolean_differential():
    def handler(url, p):
        v = p.get("ptiq")
        if v is None or v == "":            # baseline
            return HttpResponse(200, "RESULT" * 20, 3.0, url)
        if "'1'='1" in v:                    # TRUE ~ baseline
            return HttpResponse(200, "RESULT" * 20, 3.0, url)
        return HttpResponse(200, "no rows", 3.0, url)   # FALSE differs
    outcome = SqliValidator().validate(_sqli_finding(), FakeHttpClient(handler))
    assert outcome.result == ValidationResult.CONFIRMED


def test_sqli_inconclusive_when_no_differential():
    http = FakeHttpClient(lambda url, p: HttpResponse(200, "same for everything", 3.0, url))
    outcome = SqliValidator().validate(_sqli_finding(), http)
    assert outcome.result == ValidationResult.INCONCLUSIVE


def test_engine_applies_status_and_evidence():
    http = FakeHttpClient(lambda url, p: HttpResponse(200, f"x{p.get('ptiq','')}x", 3.0, url))
    xss = _xss_finding()
    unrelated = Finding(asset=Asset(type=AssetType.WEB, identifier="http://site"),
                        title="Info header", category="CWE-16", severity=Severity.LOW)
    engine = ValidationEngine([ReflectedXSSValidator(), SqliValidator()], http)
    engine.validate([xss, unrelated])
    # xss confirmed -> validated + high confidence + validation evidence appended
    assert xss.status == FindingStatus.VALIDATED
    assert xss.confidence == Confidence.HIGH
    assert xss.validation.attempted and xss.validation.result == ValidationResult.CONFIRMED
    assert any(e.type == "validation" for e in xss.evidence)
    # unrelated finding untouched (no validator applied)
    assert unrelated.validation.attempted is False
    assert unrelated.status == FindingStatus.DETECTED

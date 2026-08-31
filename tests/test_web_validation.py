from pentestiq.config import AppConfig
from pentestiq.logging_setup import get_logger
from pentestiq.core.module_base import ModuleContext
from pentestiq.core.analysis import analyze
from pentestiq.modules.web import WebModule
from pentestiq.validators.base import HttpClient, HttpResponse
from pentestiq.models import (
    Asset, AssetType, Finding, Severity, FindingStatus, Engagement,
)


class FakeHttpClient(HttpClient):
    def __init__(self, reflect): self.reflect = reflect
    def get(self, url, params=None):
        p = params or {}
        body = f"<b>{p.get('ptiq','')}</b>" if self.reflect else "<b>encoded</b>"
        return HttpResponse(200, body, 2.0, url)


def _ctx(http):
    asset = Asset(type=AssetType.WEB, identifier="http://site/x")
    return ModuleContext(engagement=Engagement(), asset=asset,
                         config=AppConfig(), logger=get_logger("test"),
                         extra={"http_client": http})


def test_web_validate_confirms_reflected_xss_and_boosts_risk():
    asset = Asset(type=AssetType.WEB, identifier="http://site/x")
    xss = Finding(asset=asset, title="Reflected XSS", category="CWE-79",
                  severity=Severity.MEDIUM, source_tools=["zap"])
    module = WebModule()
    module.validate(_ctx(FakeHttpClient(reflect=True)), [xss])
    assert xss.status == FindingStatus.VALIDATED

    # analyze re-scores: a validated medium should outrank an unvalidated medium
    eng = Engagement(); eng.add_findings([xss])
    other = Finding(asset=Asset(type=AssetType.WEB, identifier="http://site/y"),
                    title="unvalidated medium", category="CWE-16", severity=Severity.MEDIUM)
    eng2 = Engagement(); eng2.add_findings([other])
    analyze(eng); analyze(eng2)
    assert eng.findings[0].risk_score > eng2.findings[0].risk_score


def test_web_validate_dismisses_false_positive():
    asset = Asset(type=AssetType.WEB, identifier="http://site/x")
    xss = Finding(asset=asset, title="Reflected XSS", category="CWE-79",
                  severity=Severity.MEDIUM, source_tools=["zap"])
    module = WebModule()
    module.validate(_ctx(FakeHttpClient(reflect=False)), [xss])
    assert xss.status == FindingStatus.FALSE_POSITIVE
    eng = Engagement(); eng.add_findings([xss]); analyze(eng)
    assert eng.findings[0].risk_score == 0.0    # dismissed -> zero risk

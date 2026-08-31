from pentestiq.core.analysis import RiskScorer, Correlator, analyze
from pentestiq.models import (
    Asset, AssetType, Finding, Severity, Confidence, FindingStatus, CVSS, Evidence, Engagement,
)


def _f(**kw):
    kw.setdefault("asset", Asset(type=AssetType.WEB, identifier="http://10.0.0.5"))
    kw.setdefault("title", "x")
    return Finding(**kw)


def test_risk_score_orders_by_severity():
    s = RiskScorer()
    assert s.score(_f(severity=Severity.CRITICAL)) > s.score(_f(severity=Severity.HIGH))
    assert s.score(_f(severity=Severity.HIGH)) > s.score(_f(severity=Severity.LOW))


def test_false_positive_scores_zero():
    assert RiskScorer().score(_f(severity=Severity.CRITICAL,
                                 status=FindingStatus.FALSE_POSITIVE)) == 0.0


def test_validation_boosts_score():
    s = RiskScorer()
    base = s.score(_f(severity=Severity.HIGH))
    validated = s.score(_f(severity=Severity.HIGH, status=FindingStatus.VALIDATED))
    assert validated > base


def test_cvss_can_raise_score():
    s = RiskScorer()
    low_no_cvss = s.score(_f(severity=Severity.LOW))
    low_high_cvss = s.score(_f(severity=Severity.LOW, cvss=CVSS(base_score=9.8)))
    assert low_high_cvss > low_no_cvss


def test_correlation_groups_by_host_and_port():
    # nmap-style open port + a web vuln on the same host:port -> same chain
    nmap_f = Finding(asset=Asset(type=AssetType.INFRA, identifier="10.0.0.5"),
                     title="Open 80", category="open-port", source_tools=["nmap"],
                     evidence=[Evidence(type="service", ref="10.0.0.5:80/tcp")])
    web_f = Finding(asset=Asset(type=AssetType.WEB, identifier="http://10.0.0.5:80"),
                    title="SQLi", category="CWE-89", source_tools=["zap"])
    other = Finding(asset=Asset(type=AssetType.INFRA, identifier="10.0.0.5"),
                    title="Open 22", category="open-port", source_tools=["nmap"],
                    evidence=[Evidence(type="service", ref="10.0.0.5:22/tcp")])
    groups = Correlator().correlate([nmap_f, web_f, other])
    assert nmap_f.correlation_id == web_f.correlation_id == "10.0.0.5:80"
    assert other.correlation_id == "10.0.0.5:22"
    assert len(groups["10.0.0.5:80"]) == 2


def test_analyze_sets_scores_and_sorts():
    eng = Engagement()
    eng.add_findings([
        _f(title="low", severity=Severity.LOW),
        _f(asset=Asset(type=AssetType.WEB, identifier="http://a"), title="crit", severity=Severity.CRITICAL),
    ])
    analyze(eng)
    assert all(f.risk_score is not None for f in eng.findings)
    assert eng.sorted_findings()[0].severity == Severity.CRITICAL

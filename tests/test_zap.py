from pathlib import Path
from pentestiq.integrations.zap_tool import ZapIntegration
from pentestiq.models import Asset, AssetType, Severity

FIX = Path(__file__).parent / "fixtures"


def _web():
    return Asset(type=AssetType.WEB, identifier="http://10.0.0.5")


def test_zap_parse_alerts():
    raw = (FIX / "zap_sample.json").read_text()
    findings = ZapIntegration().parse(raw, _web())
    assert len(findings) == 2
    sqli = [f for f in findings if "SQL" in f.title][0]
    assert sqli.severity == Severity.HIGH
    assert sqli.category == "CWE-89"
    assert sqli.source_tools == ["zap"]
    assert len(sqli.references) == 2
    # solution HTML is stripped
    assert "<" not in (sqli.remediation or "")
    assert "parameterized" in sqli.remediation
    assert sqli.evidence[0].ref == "http://10.0.0.5:80/login"


def test_zap_empty_is_safe():
    assert ZapIntegration().parse("", _web()) == []

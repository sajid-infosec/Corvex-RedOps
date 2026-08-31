from pathlib import Path
from pentestiq.integrations.wpscan_tool import WpscanIntegration
from pentestiq.models import Asset, AssetType, Severity

FIX = Path(__file__).parent / "fixtures"


def _wp():
    return Asset(type=AssetType.WORDPRESS, identifier="http://blog.example.com")


def test_wpscan_parse():
    raw = (FIX / "wpscan_sample.json").read_text()
    findings = WpscanIntegration().parse(raw, _wp())
    cats = [f.category for f in findings]
    assert "wordpress-core" in cats
    assert "wordpress-plugin" in cats
    assert "user-enumeration" in cats
    assert "wordpress-info" in cats
    core = [f for f in findings if f.category == "wordpress-core"][0]
    assert core.severity == Severity.HIGH
    assert any("CVE-2020-11111" in r for r in core.references)
    assert "5.4.2" in (core.remediation or "")
    users = [f for f in findings if f.category == "user-enumeration"][0]
    assert users.severity == Severity.LOW
    assert "admin" in users.evidence[0].ref

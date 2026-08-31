from pathlib import Path
from pentestiq.integrations.mobsf_tool import MobsfIntegration
from pentestiq.models import Asset, AssetType, Severity

FIX = Path(__file__).parent / "fixtures"


def _apk():
    return Asset(type=AssetType.MOBILE, identifier="/tmp/DemoBank.apk")


def test_mobsf_parse():
    raw = (FIX / "mobsf_sample.json").read_text()
    findings = MobsfIntegration().parse(raw, _apk())
    cats = [f.category for f in findings]
    # code analysis
    assert "CWE-919" in cats and "CWE-330" in cats
    webview = [f for f in findings if f.category == "CWE-919"][0]
    assert webview.severity == Severity.HIGH
    assert any("MSTG-CODE-2" in r for r in webview.references)
    assert webview.evidence[0].ref == "com/demo/bank/WebActivity.java"
    # manifest
    assert "mobile-manifest" in cats
    dbg = [f for f in findings if "debuggable" in f.title][0]
    assert dbg.severity == Severity.HIGH
    # dangerous permissions summary (READ_SMS + ACCESS_FINE_LOCATION, not INTERNET)
    perm = [f for f in findings if f.category == "mobile-permissions"][0]
    assert perm.severity == Severity.LOW and "2" in perm.title
    assert "READ_SMS" in perm.evidence[0].ref and "INTERNET" not in perm.evidence[0].ref
    # secrets
    secrets = [f for f in findings if f.category == "mobile-secret"]
    assert len(secrets) == 2 and all(f.severity == Severity.MEDIUM for f in secrets)
    # certificate
    assert any(f.category == "mobile-certificate" for f in findings)


def test_mobsf_empty_safe():
    assert MobsfIntegration().parse("", _apk()) == []


def test_mobsf_unavailable_without_api_key(monkeypatch):
    monkeypatch.delenv("MOBSF_API_KEY", raising=False)
    m = MobsfIntegration()
    assert m.is_available() is False
    assert m.scan(_apk()) == []            # skips gracefully


def test_mobile_module_registered_and_typing():
    from pentestiq.core.registry import registry
    from pentestiq.engine import infer_asset_type
    import pentestiq.modules  # noqa
    assert "mobile" in [m.name for m in registry.for_asset_type(AssetType.MOBILE)]
    assert infer_asset_type("app.apk") == AssetType.MOBILE
    assert infer_asset_type("App.ipa") == AssetType.MOBILE

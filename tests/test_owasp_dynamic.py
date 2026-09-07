"""OWASP coverage catalogue + AI-assisted dynamic-kit planner."""
from __future__ import annotations

from pentestiq.checks.owasp_catalog import coverage_summary, owasp_for_slug
from pentestiq.kit.dynamic import build_plan, detect_platform, assess_protections, FRIDA_SCRIPTS
from pentestiq.models import Engagement, Scope, Asset, Finding
from pentestiq.models.enums import AssetType, Severity


def test_owasp_coverage_summary_shape():
    s = coverage_summary()
    assert s["total"] > 60
    assert 0 <= s["weighted_pct"] <= 100
    keys = {st["key"] for st in s["standards"]}
    assert {"web-2021", "api-2023", "wstg", "masvs"} <= keys
    # every check carries an OWASP ref + coverage grade
    for c in s["checks"]:
        assert c["ref"] and c["coverage"] in ("yes", "partial", "planned")


def test_slug_to_owasp_mapping():
    assert owasp_for_slug("options-method") == "A05:2021"
    assert owasp_for_slug("tls-version") == "A02:2021"
    assert owasp_for_slug("bola-idor") == "API1:2023"
    assert owasp_for_slug("") is None


def _mobile_eng(path="/tmp/x/demo.apk"):
    a = Asset(type=AssetType.MOBILE, identifier=path, label=path.split("/")[-1])
    return Engagement(name="Demo", scope=Scope(name="s", in_scope=[path]), assets=[a])


def test_detect_platform():
    assert detect_platform(_mobile_eng("/x/a.apk")) == "android"
    assert detect_platform(_mobile_eng("/x/a.ipa")) == "ios"
    d = Engagement(name="D", scope=Scope(name="s", in_scope=["/x/app.exe"]),
                   assets=[Asset(type=AssetType.DESKTOP, identifier="/x/app.exe")])
    assert detect_platform(d) == "desktop"


def test_build_plan_android():
    eng = _mobile_eng()
    plan = build_plan(eng, None)
    assert plan["platform"] == "android"
    names = {s["name"] for s in plan["scripts"]}
    assert "ssl-pinning-bypass.js" in names and "root-jailbreak-bypass.js" in names
    assert len(plan["plan"]) >= 5
    assert any(p["key"] == "ssl_pinning" for p in plan["protections"])
    assert plan["ai_available"] is False  # no provider


def test_protections_flag_pinning_present():
    eng = _mobile_eng()
    eng.add_findings([Finding(asset=eng.assets[0], title="Certificate pinning implemented",
                              category="mobile-code", severity=Severity.INFO)])
    prot = {p["key"]: p for p in assess_protections(eng, "android")}
    assert prot["ssl_pinning"]["status"] == "present"


def test_ios_scripts_exclude_android_only():
    plan = build_plan(_mobile_eng("/x/a.ipa"), None)
    names = {s["name"] for s in plan["scripts"]}
    assert "webview-inspect.js" not in names  # android-only
    assert "ssl-pinning-bypass.js" in names

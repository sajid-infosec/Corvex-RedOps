"""ValidationPlanner — honest per-finding validation coverage: safe/active/
manual/none, allow_active gating, and exploit-backed manual plans."""
from __future__ import annotations

from pentestiq.intel import ExploitIntel
from pentestiq.validators import ValidationPlanner
from pentestiq.validators.base import ValidationOutcome
from pentestiq.models import Finding, Asset, Severity, ValidationResult
from pentestiq.models.enums import AssetType


class _SafeV:
    name = "safe-xss"
    def applies_to(self, f): return f.category == "A03:2021"
    def validate(self, f, http): return ValidationOutcome(ValidationResult.CONFIRMED)


class _ActiveV:
    name = "active-probe"
    active = True
    def applies_to(self, f): return f.category == "ACTIVE"
    def validate(self, f, http): return ValidationOutcome(ValidationResult.CONFIRMED)


def _f(title, category, **kw):
    a = Asset(type=AssetType.WEB, identifier="https://t.example")
    return Finding(asset=a, title=title, severity=Severity.HIGH, category=category, **kw)


def _planner():
    return ValidationPlanner(validators=[_SafeV(), _ActiveV()],
                             exploit_intel=ExploitIntel(offline=True))


def test_safe_validator_is_auto():
    p = _planner().plan_one(_f("Reflected XSS", "A03:2021"))
    assert p.method == "safe" and p.auto is True and p.validator == "safe-xss"


def test_active_validator_gated_then_allowed():
    pl = _planner()
    gated = pl.plan_one(_f("state-changing probe", "ACTIVE"), allow_active=False)
    assert gated.method == "active" and gated.auto is False
    allowed = pl.plan_one(_f("state-changing probe", "ACTIVE"), allow_active=True)
    assert allowed.method == "active" and allowed.auto is True


def test_manual_plan_cites_public_exploit():
    # no safe validator for A06, but the CVE has a public exploit in the seed
    p = _planner().plan_one(_f("Outdated Apache", "A06:2021", references=["CVE-2021-41773"]))
    assert p.method == "manual" and p.auto is False
    assert p.maturity == "weaponized"
    assert p.exploit_url and "exploit-db.com" in p.exploit_url
    assert "authorization" in p.rationale.lower()


def test_none_when_no_validator_and_no_exploit():
    p = _planner().plan_one(_f("Verbose logging", "A09:2021"))
    assert p.method == "none" and p.auto is False


def test_coverage_summary():
    findings = [
        _f("Reflected XSS", "A03:2021"),                              # safe/auto
        _f("Outdated Apache", "A06:2021", references=["CVE-2021-41773"]),  # manual
        _f("Verbose logging", "A09:2021"),                            # none
    ]
    cov = _planner().coverage(findings)
    assert cov["total"] == 3
    assert cov["auto_validatable"] == 1
    assert cov["by_method"]["safe"] == 1
    assert cov["by_method"]["manual"] == 1
    assert cov["by_method"]["none"] == 1
    assert cov["manual_with_exploit"] == 1


def test_planner_without_exploit_intel_degrades():
    pl = ValidationPlanner(validators=[_SafeV()], exploit_intel=None)
    p = pl.plan_one(_f("Outdated Apache", "A06:2021", references=["CVE-2021-41773"]))
    assert p.method == "none"       # no oracle → honestly cannot claim an exploit


# ---- DirectoryListingValidator (safe, text-only confirmation) ----------
class _FakeHttp:
    def __init__(self, status, text):
        self._s, self._t = status, text
    def get(self, url, params=None):
        from pentestiq.validators.base import HttpResponse
        return HttpResponse(status=self._s, text=self._t, elapsed_ms=1.0, url=url)


def test_directory_listing_confirmed():
    from pentestiq.validators import DirectoryListingValidator
    v = DirectoryListingValidator()
    f = _f("Directory listing enabled", "A05:2021")
    assert v.applies_to(f)
    out = v.validate(f, _FakeHttp(200, "<html><title>Index of /uploads</title>"
                                       "<a href='..'>Parent Directory</a>"))
    assert out.result == ValidationResult.CONFIRMED and out.evidence_ref


def test_directory_listing_inconclusive_without_markers():
    from pentestiq.validators import DirectoryListingValidator
    v = DirectoryListingValidator()
    f = _f("Directory listing enabled", "A05:2021")
    out = v.validate(f, _FakeHttp(200, "<html><body>Access denied</body></html>"))
    assert out.result == ValidationResult.INCONCLUSIVE

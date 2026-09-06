"""New passive checks (CSRF, vulnerable JS lib) + active-by-default wiring."""
from pentestiq.models import Asset, AssetType
from pentestiq.checks.base import CheckContext, RealHttpClient
from pentestiq.checks.passive_checks import CsrfTokenCheck, VulnerableJsLibraryCheck
from pentestiq.engine import build_scope_and_assets


def _ctx(meta):
    a = Asset(type=AssetType.WEB, identifier="http://t/", metadata=meta)
    return CheckContext(asset=a, base_url="http://t/", http=RealHttpClient(), extra=meta)


def test_csrf_token_check_flags_form_without_token():
    meta = {"discovered_forms": [
        {"action": "http://t/transfer", "method": "POST", "inputs": ["amount", "to"]}]}
    out = CsrfTokenCheck().run(_ctx(meta))
    assert out and "CSRF" in out[0].title.upper()


def test_csrf_token_check_passes_form_with_token():
    meta = {"discovered_forms": [
        {"action": "http://t/x", "method": "POST", "inputs": ["amount", "csrf_token"]}]}
    assert CsrfTokenCheck().run(_ctx(meta)) == []


def test_vulnerable_js_library_check():
    meta = {"assets": ["http://t/static/jquery-1.12.4.min.js",
                       "http://cdn/lodash-4.17.10.js",
                       "http://t/static/jquery-3.6.0.min.js"]}  # last is safe
    out = VulnerableJsLibraryCheck().run(_ctx(meta))
    titles = " ".join(f.title for f in out)
    assert "jquery 1.12.4" in titles.lower()
    assert "lodash 4.17.10" in titles.lower()
    assert "3.6.0" not in titles         # up-to-date jquery not flagged


def test_active_scan_default_sets_allow_active_on_web():
    scope, assets = build_scope_and_assets(
        {"scope": {"in_scope": ["web=https://app.example.com"]}})
    assert assets[0].metadata.get("allow_active") is True
    assert assets[0].metadata.get("spa_crawl") is True


def test_active_scan_can_be_disabled():
    scope, assets = build_scope_and_assets(
        {"scope": {"in_scope": ["https://app.example.com"]}, "active_scan": False})
    assert assets[0].metadata.get("allow_active") is None


def test_deep_mode_raises_budgets():
    _, shallow = build_scope_and_assets({"scope": {"in_scope": ["web=https://a.com"]}})
    _, deep = build_scope_and_assets({"scope": {"in_scope": ["web=https://a.com"]}, "deep": True})
    assert deep[0].metadata["fuzz_max_requests"] > shallow[0].metadata["fuzz_max_requests"]

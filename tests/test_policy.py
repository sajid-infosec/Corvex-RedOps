from pentestiq.models import Scope, Enforcement
from pentestiq.core.policy import ScopeManager, SafeModeGovernor, ActionClass


def test_scope_manager_allow_deny():
    sm = ScopeManager(Scope(in_scope=["example.com"], enforcement=Enforcement.BLOCK))
    assert sm.authorize_asset("http://example.com/x").allowed is True
    d = sm.authorize_asset("http://evil.com")
    assert d.allowed is False and "not in the engagement scope" in d.reason
    assert sm.is_enforcing() is True


def test_scope_off_allows_everything():
    sm = ScopeManager(Scope(in_scope=["example.com"], enforcement=Enforcement.OFF))
    assert sm.authorize_asset("http://evil.com").allowed is True


def test_governor_safe_actions_allowed():
    g = SafeModeGovernor(Scope(safe_mode=True))
    for a in (ActionClass.DISCOVER, ActionClass.ASSESS, ActionClass.VALIDATE_SAFE):
        assert g.authorize_action(a).allowed is True


def test_governor_blocks_intrusive_in_safe_mode():
    g = SafeModeGovernor(Scope(safe_mode=True))
    assert g.authorize_action(ActionClass.EXPLOIT).allowed is False
    assert g.authorize_action(ActionClass.VALIDATE_INTRUSIVE).allowed is False


def test_governor_allows_intrusive_with_optin():
    g = SafeModeGovernor(Scope(safe_mode=False, allowed_actions=["exploit"]))
    assert g.authorize_action(ActionClass.EXPLOIT).allowed is True


def test_governor_denies_intrusive_without_optin_even_if_safe_mode_off():
    g = SafeModeGovernor(Scope(safe_mode=False, allowed_actions=["assess"]))
    assert g.authorize_action(ActionClass.EXPLOIT).allowed is False

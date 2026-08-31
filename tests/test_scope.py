from pentestiq.models import Scope, Enforcement


def test_empty_in_scope_is_permissive():
    s = Scope()
    assert s.is_in_scope("http://anything.example.com") is True


def test_host_and_domain_match():
    s = Scope(in_scope=["example.com"])
    assert s.is_in_scope("http://example.com/login") is True
    assert s.is_in_scope("http://api.example.com") is True
    assert s.is_in_scope("http://evil.com") is False


def test_cidr_match():
    s = Scope(in_scope=["10.0.0.0/24"])
    assert s.is_in_scope("10.0.0.5") is True
    assert s.is_in_scope("10.0.1.5") is False


def test_wildcard_match():
    s = Scope(in_scope=["*.example.com"])
    assert s.is_in_scope("http://a.example.com") is True
    assert s.is_in_scope("http://example.com") is True


def test_exclusions_win():
    s = Scope(in_scope=["example.com"], exclusions=["admin.example.com"])
    assert s.is_in_scope("http://admin.example.com") is False
    assert s.is_in_scope("http://shop.example.com") is True


def test_default_enforcement_is_warn():
    assert Scope().enforcement == Enforcement.WARN


def test_url_form_in_scope_matches():
    s = Scope(in_scope=["http://localhost:3000"])
    assert s.is_in_scope("http://localhost:3000") is True
    assert s.is_in_scope("http://localhost:3000/rest/products") is True
    assert s.is_in_scope("http://evil.com") is False

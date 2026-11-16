"""Throttle keys: IPv4 as itself, IPv6 by /64, IPv4-mapped IPv6 as IPv4."""
from fastapi.testclient import TestClient

from pentestiq.api.app import create_app
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore


def test_ip_bucket_rules():
    b = AuthService.ip_bucket
    assert b("203.0.113.5") == "203.0.113.5"
    assert b("2001:db8:1:2::10") == b("2001:db8:1:2:ffff:ffff:ffff:ffff") == "2001:db8:1:2::/64"
    assert b("2001:db8:1:3::10") != b("2001:db8:1:2::10")
    assert b("::ffff:203.0.113.5") == "203.0.113.5"
    assert b("testclient") == "testclient"          # not an address: used as-is


def _app(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_ADMIN_USER", "corvex")
    monkeypatch.setenv("CORVEX_ADMIN_PASSWORD", "right-pass-123")
    monkeypatch.setenv("CORVEX_ADMIN_FORCE_CHANGE", "0")
    db = str(tmp_path / "pentestiq.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    return create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path)))


def _fail(c):
    return c.post("/auth/login", json={"username": "corvex", "password": "wrong-guess-1"}).status_code


def test_two_addresses_in_one_64_share_a_counter(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    a, b = TestClient(app, client=("2001:db8:1:2::10", 4000)), TestClient(app, client=("2001:db8:1:2::abcd", 4000))
    other = TestClient(app, client=("2001:db8:1:3::10", 4000))
    assert [_fail(a), _fail(b), _fail(a), _fail(b), _fail(a)] == [401] * 5
    assert _fail(b) == 429                       # rotating inside the /64 doesn't help
    assert _fail(other) == 401                   # the next /64 is separate


def test_ipv4_mapped_ipv6_shares_the_ipv4_counter(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    v4, mapped = TestClient(app, client=("203.0.113.5", 4000)), TestClient(app, client=("::ffff:203.0.113.5", 4000))
    assert [_fail(v4), _fail(mapped), _fail(v4), _fail(mapped), _fail(v4)] == [401] * 5
    assert _fail(mapped) == 429

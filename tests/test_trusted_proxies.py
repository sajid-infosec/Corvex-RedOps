"""Trusted proxies through uvicorn's own ProxyHeadersMiddleware (applied in create_app):
X-Forwarded-For counts only from CORVEX_TRUSTED_PROXIES; '*' is refused at start-up."""
import pytest
from fastapi.testclient import TestClient

from pentestiq.api.app import create_app
from pentestiq.api.proxies import trusted_proxies
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore


def _app(tmp_path, monkeypatch, trusted=None):
    monkeypatch.setenv("CORVEX_ADMIN_USER", "corvex")
    monkeypatch.setenv("CORVEX_ADMIN_PASSWORD", "right-pass-123")
    monkeypatch.setenv("CORVEX_ADMIN_FORCE_CHANGE", "0")
    if trusted is None:
        monkeypatch.delenv("CORVEX_TRUSTED_PROXIES", raising=False)
    else:
        monkeypatch.setenv("CORVEX_TRUSTED_PROXIES", trusted)
    db = str(tmp_path / "pentestiq.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    return create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path))), auth


def _fail(c, xff=None):
    h = {"X-Forwarded-For": xff} if xff else {}
    return c.post("/auth/login", json={"username": "corvex", "password": "wrong-guess-1"}, headers=h)


def _counted_ips(auth):
    rows = auth.store._conn.execute("SELECT key FROM login_failures WHERE key LIKE 'ip:%'").fetchall()
    return {r[0][3:] for r in rows}


def test_untrusted_peer_with_spoofed_header_is_throttled_by_the_peer(tmp_path, monkeypatch):
    app, auth = _app(tmp_path, monkeypatch)                    # default trust: loopback only
    c = TestClient(app, client=("198.51.100.9", 4000))
    for i in range(5):
        assert _fail(c, xff=f"203.0.113.{i}").status_code == 401   # a different "client" each time
    assert _fail(c, xff="203.0.113.99").status_code == 429         # still the same peer
    assert _counted_ips(auth) == {"198.51.100.9"}


def test_trusted_peer_uses_the_real_client_not_the_spoofed_entry(tmp_path, monkeypatch):
    app, auth = _app(tmp_path, monkeypatch, trusted="198.51.100.9")
    proxy = TestClient(app, client=("198.51.100.9", 4000))
    # the client sent "X-Forwarded-For: 6.6.6.6"; the proxy appended the real address
    for _ in range(5):
        assert _fail(proxy, xff="6.6.6.6, 203.0.113.7").status_code == 401
    assert _fail(proxy, xff="6.6.6.6, 203.0.113.7").status_code == 429    # throttled by the real client
    assert _fail(proxy, xff="6.6.6.6, 203.0.113.8").status_code == 401    # another real client is not
    assert _counted_ips(auth) == {"203.0.113.7", "203.0.113.8"}           # never the spoofed 6.6.6.6


def test_a_cidr_trust_entry_works(tmp_path, monkeypatch):
    app, auth = _app(tmp_path, monkeypatch, trusted="127.0.0.1,::1,10.20.0.0/16")
    c = TestClient(app, client=("10.20.3.4", 4000))
    _fail(c, xff="203.0.113.50")
    assert _counted_ips(auth) == {"203.0.113.50"}


def test_star_is_refused_at_start_up(tmp_path, monkeypatch):
    for bad in ("*", "127.0.0.1,*", " * "):
        with pytest.raises(ValueError, match=r"must not contain '\*'"):
            _app(tmp_path, monkeypatch, trusted=bad)


def test_invalid_entries_are_refused():
    with pytest.raises(ValueError, match="not an IP address or CIDR"):
        trusted_proxies("10.0.0.0/33")
    with pytest.raises(ValueError, match="not an IP address or CIDR"):
        trusted_proxies("proxy.example.com")
    assert trusted_proxies("127.0.0.1, ::1,10.0.0.0/8") == ["127.0.0.1", "::1", "10.0.0.0/8"]


def test_serve_disables_uvicorns_own_proxy_headers_and_deps_pin_uvicorn():
    from pathlib import Path
    root = Path(__file__).resolve().parents[1]
    assert "proxy_headers=False" in (root / "pentestiq/cli.py").read_text()
    pyproject = (root / "pyproject.toml").read_text()
    assert '"uvicorn>=0.31"' in pyproject and '"uvicorn>=0.29"' not in pyproject


ROUTE = """Iface\tDestination\tGateway \tFlags\tRefCnt\tUse\tMetric\tMask\t\tMTU\tWindow\tIRTT
eth0\t00000000\t010011AC\t0003\t0\t0\t0\t00000000\t0\t0\t0
eth0\t000011AC\t00000000\t0001\t0\t0\t0\t0000FFFF\t0\t0\t0
"""


def test_default_gateway_is_read_from_the_routing_table(tmp_path):
    from pentestiq.api.proxies import default_gateway
    f = tmp_path / "route"; f.write_text(ROUTE)
    assert default_gateway(str(f)) == "172.17.0.1"
    (tmp_path / "noroute").write_text(ROUTE.splitlines()[0] + "\n")
    assert default_gateway(str(tmp_path / "noroute")) is None
    assert default_gateway(str(tmp_path / "missing")) is None


def _gw_app(tmp_path, monkeypatch, gw, trusted=None):
    import pentestiq.api.proxies as px
    monkeypatch.setattr(px, "default_gateway", lambda *a, **k: gw)
    return _app(tmp_path, monkeypatch, trusted=trusted)


def test_warns_once_when_an_untrusted_peer_is_the_gateway(tmp_path, monkeypatch, caplog):
    app, _ = _gw_app(tmp_path, monkeypatch, "172.17.0.1")
    c = TestClient(app, client=("172.17.0.1", 4000))
    with caplog.at_level("WARNING", logger="pentestiq"):
        c.get("/health"); c.get("/edition"); _fail(c)
    msgs = [r.getMessage() for r in caplog.records if "default gateway" in r.getMessage()]
    assert len(msgs) == 1 and "172.17.0.1" in msgs[0] and "--listen 127.0.0.1" in msgs[0]


def test_no_warning_for_other_peers_or_a_trusted_gateway(tmp_path, monkeypatch, caplog):
    app, _ = _gw_app(tmp_path, monkeypatch, "172.17.0.1")
    with caplog.at_level("WARNING", logger="pentestiq"):
        TestClient(app, client=("203.0.113.7", 4000)).get("/health")
    app2, _ = _gw_app(tmp_path / "t", monkeypatch, "172.17.0.1", trusted="127.0.0.1,::1,172.17.0.1")
    with caplog.at_level("WARNING", logger="pentestiq"):
        TestClient(app2, client=("172.17.0.1", 4000)).get("/health")
    assert not [r for r in caplog.records if "default gateway" in r.getMessage()]

"""External discovery (EASM) — crt.sh parsing, orchestration, inventory feed."""
from __future__ import annotations

import json
import tempfile

import pytest
from fastapi.testclient import TestClient

from pentestiq.checks.base import Response
from pentestiq.discovery import discover, run_discovery
from pentestiq.discovery.sources import crtsh_subdomains
from pentestiq.inventory import SqliteInventoryStore
from pentestiq.api.app import create_app
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


class MockHttp:
    """crt.sh JSON + per-host probe responses."""
    def get(self, url, headers=None):
        if "crt.sh" in url:
            data = [{"name_value": "www.example.com\n*.example.com"},
                    {"name_value": "api.example.com"},
                    {"common_name": "admin.example.com"},
                    {"name_value": "evil.notexample.com"}]   # out-of-scope, must be dropped
            return Response(status=200, headers={}, text=json.dumps(data), elapsed_ms=1, url=url)
        if url.startswith("https://www.example.com"):
            return Response(status=200, headers={"server": "Apache"},
                            text="<title>Home</title>", elapsed_ms=1, url=url)
        if url.startswith("https://api.example.com"):
            return Response(status=200, headers={"server": "nginx"},
                            text="<title>API Gateway</title>", elapsed_ms=1, url=url)
        return Response(status=0, headers={}, text="", elapsed_ms=1, url=url)


def _resolver(h):
    return ["1.2.3.4"] if h in ("www.example.com", "api.example.com", "example.com") else []


def test_crtsh_parsing_and_scope():
    subs = crtsh_subdomains("example.com", MockHttp().get)
    assert "www.example.com" in subs and "api.example.com" in subs and "admin.example.com" in subs
    assert "example.com" in subs                       # wildcard *.example.com -> example.com
    assert not any("notexample" in s for s in subs)    # out-of-scope dropped


def test_discover_resolves_and_probes():
    res = discover("example.com", http_client=MockHttp(), resolver=_resolver, use_subfinder=False)
    assert res.stats["resolved"] == 3 and res.stats["alive_http"] == 2
    api = [h for h in res.hosts if h.host == "api.example.com"][0]
    assert api.alive_http and api.scheme == "https" and api.server == "nginx"
    assert api.title == "API Gateway" and "crtsh" in api.sources
    admin = [h for h in res.hosts if h.host == "admin.example.com"][0]
    assert not admin.resolved and not admin.alive_http


def test_run_discovery_feeds_inventory():
    inv = SqliteInventoryStore(tempfile.mktemp(suffix=".db"))
    summ = run_discovery(inv, "t", "example.com", http_client=MockHttp(),
                         resolver=_resolver, use_subfinder=False)
    # only resolved hosts are filed; source=easm, tagged external
    idents = sorted(a.identifier for a in inv.list("t"))
    assert idents == ["api.example.com", "example.com", "www.example.com"]
    assert all(a.source == "easm" and "external" in a.tags for a in inv.list("t"))
    assert summ["stats"]["registered"] == 3


@pytest.fixture
def client(tmp_path):
    db = str(tmp_path / "t.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="test-secret", session_ttl=3600)
    return TestClient(create_app(store=SqliteEngagementStore(db), auth=auth))


def test_discovery_endpoint_validates_domain(client):
    tok = client.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    H = {"Authorization": "Bearer " + tok}
    assert client.post("/discovery", json={"domain": "not a domain/x"}, headers=H).status_code == 422
    assert client.post("/discovery", json={"domain": ""}, headers=H).status_code == 422
    # viewer cannot run discovery
    client.post("/users", json={"username": "ro", "password": "readonly1", "role": "viewer"}, headers=H)
    vt = client.post("/auth/login", json={"username": "ro", "password": "readonly1"}).json()["token"]
    assert client.post("/discovery", json={"domain": "example.com"},
                       headers={"Authorization": "Bearer " + vt}).status_code == 403

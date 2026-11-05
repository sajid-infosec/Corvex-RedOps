"""Open-core scan-type gating: Community keeps the 10 app-layer scans; the 8
Premium scan types (desktop, container, IaC, cloud, network-device, firewall,
hardening, Active Directory) are refused server-side on Community (HTTP 402)
and allowed on Premium."""
import pytest
from fastapi.testclient import TestClient

from pentestiq.api.app import create_app
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore


def _client(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login",
                 json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}


def _mk(c, H, entry):
    return c.post("/engagements", headers=H,
                  json={"engagement": {"name": "t"}, "scope": {"in_scope": [entry]}})


def test_community_allows_free_scan_types(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "community")
    c, H = _client(tmp_path)
    for entry in ("web=https://app.example.com", "api=https://api.example.com",
                  "infra=192.0.2.0/24"):
        assert _mk(c, H, entry).status_code == 201, entry


def test_community_blocks_premium_scan_types(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "community")
    c, H = _client(tmp_path)
    for entry in ("network_device=10.0.0.1", "firewall=10.0.0.2",
                  "hardening=10.0.0.3", "active_directory=10.0.0.4"):
        r = _mk(c, H, entry)
        assert r.status_code == 402, f"{entry} -> {r.status_code}"
        assert r.json()["detail"]["feature"] == "advanced_scanners"


def test_community_blocks_container_and_cloud_routes(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "community")
    c, H = _client(tmp_path)
    assert c.post("/engagements/container", headers=H,
                  json={"image": "nginx:latest"}).status_code == 402
    assert c.post("/engagements/prowler", headers=H,
                  json={"provider": "aws"}).status_code == 402


def test_premium_allows_premium_scan_types(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "premium")
    c, H = _client(tmp_path)
    assert _mk(c, H, "network_device=10.0.0.1").status_code == 201
    assert _mk(c, H, "active_directory=10.0.0.4").status_code == 201

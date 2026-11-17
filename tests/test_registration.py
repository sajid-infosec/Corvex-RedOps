"""B1: self-service registration is closed by default."""
from pathlib import Path

from fastapi.testclient import TestClient

from pentestiq.api.app import create_app
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore

ROOT = Path(__file__).resolve().parents[1]


def _client(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    return TestClient(create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path))))


BODY = {"tenant_name": "Acme", "username": "eve", "password": "long-enough-pass-1"}


def test_registration_closed_by_default(tmp_path, monkeypatch):
    monkeypatch.delenv("CORVEX_ALLOW_REGISTRATION", raising=False)
    c = _client(tmp_path)
    r = c.post("/auth/register", json=BODY)
    assert r.status_code == 403 and r.json()["detail"]["error"] == "registration_disabled"
    assert c.get("/auth/options").json() == {"registration_open": False}
    assert c.post("/auth/login", json={"username": "eve", "password": BODY["password"]}).status_code == 401


def test_only_exactly_1_opens_it(tmp_path, monkeypatch):
    for v in ("true", "yes", "0", ""):
        monkeypatch.setenv("CORVEX_ALLOW_REGISTRATION", v)
        assert _client(tmp_path / v.replace("", "x")).post("/auth/register", json=BODY).status_code == 403, v


def test_registration_open_when_enabled(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_ALLOW_REGISTRATION", "1")
    c = _client(tmp_path)
    assert c.get("/auth/options").json() == {"registration_open": True}
    r = c.post("/auth/register", json=BODY)
    assert r.status_code == 201 and r.json()["role"] == "owner"


def test_options_endpoint_needs_no_auth_and_leaks_nothing(tmp_path, monkeypatch):
    monkeypatch.delenv("CORVEX_ALLOW_REGISTRATION", raising=False)
    r = _client(tmp_path).get("/auth/options")
    assert r.status_code == 200 and set(r.json()) == {"registration_open"}


def test_console_hides_create_workspace_unless_open():
    html = (ROOT / "pentestiq/api/static/index.html").read_text(encoding="utf-8")
    assert 'id="btn_register" onclick="register()" hidden>Create workspace' in html
    assert 'fetch("/auth/options")' in html and "b.hidden=!o.registration_open" in html


def test_docs_and_compose_describe_the_closed_default():
    assert "CORVEX_ALLOW_REGISTRATION" in (ROOT / "README.md").read_text(encoding="utf-8")
    compose = (ROOT / "deploy/docker-compose.yml").read_text(encoding="utf-8")
    assert "registration is OFF" in compose and "register, then Upload" not in compose

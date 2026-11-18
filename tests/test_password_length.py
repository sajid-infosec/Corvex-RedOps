"""Every NEW password is at least 12 characters (one constant); sign-in never checks length,
so existing shorter passwords keep working."""
import re
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

from pentestiq.api import schemas
from pentestiq.api.app import create_app
from pentestiq.auth.models import Role
from pentestiq.auth.passwords import MIN_PASSWORD_LENGTH, hash_password
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore

ROOT = Path(__file__).resolve().parents[1]
P11, P12 = "a" * 9 + "-1", "a" * 10 + "-1"            # 11 and 12 characters
assert (len(P11), len(P12)) == (11, 12)


def test_the_minimum_is_12_and_one_constant():
    assert MIN_PASSWORD_LENGTH == 12
    for model, field in ((schemas.RegisterRequest, "password"), (schemas.ChangePasswordRequest, "new_password"),
                         (schemas.CreateUserRequest, "password")):
        assert any(getattr(m, "min_length", None) == MIN_PASSWORD_LENGTH
                   for m in model.model_fields[field].metadata), model.__name__
    login = schemas.LoginRequest.model_fields["password"].metadata
    assert not any(getattr(m, "min_length", None) for m in login)            # sign-in: no length rule


@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "premium")
    db = str(tmp_path / "pentestiq.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    c = TestClient(create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path))))
    import os
    tok = c.post("/auth/login", json={"username": os.environ["CORVEX_ADMIN_USER"],
                                      "password": os.environ["CORVEX_ADMIN_PASSWORD"]}).json()["token"]
    return c, auth, {"Authorization": "Bearer " + tok}


def test_api_register(ctx):
    c, _, _ = ctx
    assert c.post("/auth/register", json={"tenant_name": "a", "username": "u11", "password": P11}).status_code == 422
    assert c.post("/auth/register", json={"tenant_name": "b", "username": "u12", "password": P12}).status_code == 201


def test_api_create_user(ctx):
    c, _, H = ctx
    assert c.post("/users", headers=H, json={"username": "v11", "password": P11, "role": "viewer"}).status_code == 422
    assert c.post("/users", headers=H, json={"username": "v12", "password": P12, "role": "viewer"}).status_code == 201


def test_api_change_password(ctx):
    c, _, _ = ctx
    r = c.post("/auth/register", json={"tenant_name": "t", "username": "cp", "password": "starting-pass-1"})
    H = {"Authorization": "Bearer " + r.json()["token"]}
    body = {"current_password": "starting-pass-1"}
    assert c.post("/auth/change-password", headers=H, json={**body, "new_password": P11}).status_code == 422
    assert c.post("/auth/change-password", headers=H, json={**body, "new_password": P12}).status_code == 200


def test_service_entry_points(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "premium")
    a = AuthService(SqliteAuthStore(str(tmp_path / "x.db")), secret_key="s")
    with pytest.raises(ValueError, match="at least 12"):
        a.register("t1", "r11", P11)
    p, _ = a.register("t2", "r12", P12)
    with pytest.raises(ValueError, match="at least 12"):
        a.create_member(p.tenant_id, "m11", P11, Role.VIEWER)
    a.create_member(p.tenant_id, "m12", P12, Role.VIEWER)
    with pytest.raises(ValueError, match="at least 12"):
        a.reset_password("m12", P11)
    assert a.reset_password("m12", P12) == P12
    uid = a.store.get_user_auth("r12")["user_id"]
    with pytest.raises(ValueError, match="at least 12"):
        a.change_password(uid, P12, P11)
    assert a.change_password(uid, P12, P12 + "x") is True
    assert len(a.reset_password("m12")) == 16                 # generated: token_urlsafe(12)
    assert a.store.get_user_auth("r11") is None and a.store.count_tenants() == 1   # t1: nothing made


def test_cli_init_tenant_and_reset_password(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from pentestiq.cli import app
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CORVEX_EDITION", "premium")
    r = CliRunner().invoke(app, ["init-tenant", "--username", "o11", "--password", P11])
    assert r.exit_code == 1 and "at least 12 characters" in r.output
    assert CliRunner().invoke(app, ["init-tenant", "--username", "o12", "--password", P12]).exit_code == 0
    r = CliRunner().invoke(app, ["reset-password", "o12", "--password", P11])
    assert r.exit_code == 1 and "at least 12" in r.output
    assert CliRunner().invoke(app, ["reset-password", "o12", "--password", P12]).exit_code == 0
    assert "12+ characters" in CliRunner().invoke(app, ["init-tenant", "--help"]).output


def test_an_existing_8_character_password_still_signs_in(ctx):
    c, auth, _ = ctx
    auth.store.create_workspace("old", "legacy8", hash_password("8charpw!"), Role.OWNER, None)
    r = c.post("/auth/login", json={"username": "legacy8", "password": "8charpw!"})
    assert r.status_code == 200 and r.json()["password_change_required"] is False


def test_console_and_docs_say_12():
    html = (ROOT / "pentestiq/api/static/index.html").read_text(encoding="utf-8")
    assert not re.search(r"\b8\+? ?char|length<8\b|at least 8\b|min 8\b", html)
    assert set(re.findall(r"(?:pw|p|nw)\.length<(\d+)", html)) == {"12"}
    assert html.count("at least 12 characters") >= 4
    for doc in ("README.md", "INSTALL.md"):
        t = (ROOT / doc).read_text(encoding="utf-8")
        assert not re.search(r"8\+ char|at least 8 char", t), doc

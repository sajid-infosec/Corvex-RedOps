"""Community includes one workspace (edition.LIMITS max_workspaces = 1); Premium any number.
Enforced where a workspace is created (register: API, CLI, first-run admin), atomically;
existing installs that already have more keep working."""
import threading

import pytest
from fastapi.testclient import TestClient

from pentestiq.api.app import create_app
from pentestiq.auth.models import Role
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore, WorkspaceLimit
from pentestiq.auth.passwords import hash_password

MSG = AuthService.WORKSPACE_LIMIT_MESSAGE


def _app(tmp_path, monkeypatch, edition):
    monkeypatch.setenv("CORVEX_EDITION", edition)
    db = str(tmp_path / "pentestiq.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    return TestClient(app), auth


def _register(c, name, user):
    return c.post("/auth/register", json={"tenant_name": name, "username": user, "password": "long-enough-pw-1"})


def test_message_names_premium():
    assert "one workspace" in MSG and "Corvex-RedOps Premium" in MSG


def test_community_refuses_a_second_workspace_via_the_api(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch, "community")      # the first-run admin made the first
    assert auth.store.count_tenants() == 1
    r = _register(c, "second", "bob")
    assert r.status_code == 403
    assert r.json()["detail"] == {"error": "workspace_limit", "message": MSG}
    assert auth.store.count_tenants() == 1 and auth.store.get_user_auth("bob") is None
    assert c.get("/auth/options").json() == {"registration_open": False}   # no button that can't work


def test_community_closed_registration_doesnt_suggest_adding_a_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_ALLOW_REGISTRATION", "0")
    c, _ = _app(tmp_path, monkeypatch, "community")
    d = _register(c, "x", "bob").json()["detail"]
    assert d["error"] == "registration_disabled" and "init-tenant" not in d["message"]
    p, _ = _app(tmp_path / "p", monkeypatch, "premium")
    assert "init-tenant" in _register(p, "x", "bob").json()["detail"]["message"]


def test_premium_allows_more_workspaces(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch, "premium")
    assert _register(c, "second", "bob").status_code == 201
    assert _register(c, "third", "carol").status_code == 201
    assert auth.store.count_tenants() == 3
    assert c.get("/auth/options").json() == {"registration_open": True}


def test_cli_refuses_a_second_workspace_on_community(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from pentestiq.cli import app
    monkeypatch.chdir(tmp_path)
    monkeypatch.setenv("CORVEX_EDITION", "community")
    r = CliRunner().invoke(app, ["init-tenant", "--username", "owner1"])     # a fresh install: its first
    assert r.exit_code == 0 and "Tenant created" in r.output
    r = CliRunner().invoke(app, ["init-tenant", "--tenant", "Two", "--username", "owner2"])
    assert r.exit_code == 1
    assert " ".join(r.output.split()) == MSG                                  # the same text as the API
    monkeypatch.setenv("CORVEX_EDITION", "premium")
    assert CliRunner().invoke(app, ["init-tenant", "--tenant", "Two", "--username", "owner2"]).exit_code == 0


def test_ten_concurrent_creates_make_at_most_one(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "community")
    auth = AuthService(SqliteAuthStore(str(tmp_path / "pentestiq.db")), secret_key="s")
    start, results = threading.Barrier(10), []

    def one(i):
        start.wait()
        try:
            auth.register(f"ws-{i}", f"user-{i}", "long-enough-pw-1")
            results.append("ok")
        except WorkspaceLimit:
            results.append("limit")
    ts = [threading.Thread(target=one, args=(i,)) for i in range(10)]
    for t in ts: t.start()
    for t in ts: t.join()
    assert results.count("ok") == 1 and results.count("limit") == 9
    assert auth.store.count_tenants() == 1 and len(auth.store.list_usernames()) == 1   # nothing half-made


def test_concurrent_creates_from_separate_processes_respect_the_limit(tmp_path, monkeypatch):
    # the CLI next to a running console: two connections, the immediate transaction decides
    monkeypatch.setenv("CORVEX_EDITION", "community")
    db = str(tmp_path / "pentestiq.db")
    a = AuthService(SqliteAuthStore(db), secret_key="s")
    b = AuthService(SqliteAuthStore(db), secret_key="s")
    a.register("one", "u1", "long-enough-pw-1")
    with pytest.raises(WorkspaceLimit):
        b.register("two", "u2", "long-enough-pw-1")


def test_a_database_that_already_holds_two_workspaces_keeps_working(tmp_path, monkeypatch):
    db = str(tmp_path / "pentestiq.db")
    st = SqliteAuthStore(db)                                 # created before the limit existed
    for name, user in (("first", "alice"), ("second", "bob")):
        st.create_workspace(name, user, hash_password("long-enough-pw-1"), Role.OWNER, None)
    c, auth = _app(tmp_path, monkeypatch, "community")
    for user in ("alice", "bob"):
        r = c.post("/auth/login", json={"username": user, "password": "long-enough-pw-1"})
        assert r.status_code == 200, user
        assert c.get("/me", headers={"Authorization": "Bearer " + r.json()["token"]}).status_code == 200
    assert auth.store.count_tenants() == 2                   # nothing deleted, nothing locked
    assert _register(c, "third", "carol").status_code == 403  # only new ones are refused


def test_first_run_admin_on_a_full_community_install_is_skipped_not_fatal(tmp_path, monkeypatch, caplog):
    monkeypatch.setenv("CORVEX_EDITION", "community")
    db = str(tmp_path / "pentestiq.db")
    SqliteAuthStore(db).create_workspace("first", "alice", hash_password("long-enough-pw-1"), Role.OWNER, None)
    monkeypatch.setenv("CORVEX_ADMIN_USER", "someone-else")
    c, auth = _app(tmp_path, monkeypatch, "community")      # starts fine
    assert auth.store.count_tenants() == 1 and auth.store.get_user_auth("someone-else") is None
    assert "first-run admin" in caplog.text and "Premium" in caplog.text


def test_a_taken_username_no_longer_leaves_an_empty_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_EDITION", "premium")
    auth = AuthService(SqliteAuthStore(str(tmp_path / "pentestiq.db")), secret_key="s")
    auth.register("one", "alice", "long-enough-pw-1")
    from pentestiq.storage import DuplicateUser
    with pytest.raises(DuplicateUser):
        auth.register("two", "alice", "long-enough-pw-1")
    assert auth.store.count_tenants() == 1

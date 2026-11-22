"""D8: no shipped default password. A pinned first-run admin (CORVEX_ADMIN_PASSWORD) must
change it at the first sign-in (without one, nothing is created: first-visit setup); until then the session opens nothing but change-password,
/me and /edition. Operator resets are one-time too, and an admin still on the old shipped
password ('corvex') is forced to change it."""
import sqlite3

import pytest
from fastapi.testclient import TestClient

from pentestiq.api.app import create_app
from pentestiq.auth.passwords import hash_password
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore


def _app(tmp_path, monkeypatch, user="corvex", password=None, force=None):
    monkeypatch.setenv("CORVEX_ADMIN_USER", user)
    if password is None:
        monkeypatch.delenv("CORVEX_ADMIN_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("CORVEX_ADMIN_PASSWORD", password)
    if force is None:
        monkeypatch.delenv("CORVEX_ADMIN_FORCE_CHANGE", raising=False)   # production default
    else:
        monkeypatch.setenv("CORVEX_ADMIN_FORCE_CHANGE", force)
    db = str(tmp_path / "pentestiq.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    return TestClient(app), auth


def _login(c, user, pw):
    r = c.post("/auth/login", json={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    return r.json(), {"Authorization": "Bearer " + r.json()["token"]}


def test_one_time_password_must_be_changed_before_anything_else(tmp_path, monkeypatch):
    c, _ = _app(tmp_path, monkeypatch, password="installer-one-time-9xQ")
    body, H = _login(c, "corvex", "installer-one-time-9xQ")
    assert body["password_change_required"] is True
    # everything except change-password, /me and /edition is refused, server-side
    for path in ("/engagements", "/users", "/apikeys"):
        r = c.get(path, headers=H)
        assert r.status_code == 403 and r.json()["detail"]["error"] == "password_change_required", path
    assert c.post("/apikeys", headers=H, json={"name": "ci"}).status_code == 403
    me = c.get("/me", headers=H)
    assert me.status_code == 200 and me.json()["password_change_required"] is True
    assert c.get("/edition").status_code == 200
    # reusing the one-time password, or the old shipped one, is refused
    r = c.post("/auth/change-password", headers=H,
               json={"current_password": "installer-one-time-9xQ", "new_password": "installer-one-time-9xQ"})
    assert r.status_code == 422
    r = c.post("/auth/change-password", headers=H,
               json={"current_password": "installer-one-time-9xQ", "new_password": "corvex"})
    assert r.status_code == 422
    r = c.post("/auth/change-password", headers=H,
               json={"current_password": "installer-one-time-9xQ", "new_password": "my-own-strong-pass-7"})
    assert r.status_code == 200
    # the token from before the change is dead; the fresh one returned by change-password works
    assert c.get("/engagements", headers=H).status_code == 401
    assert c.get("/engagements", headers={"Authorization": "Bearer " + r.json()["token"]}).status_code == 200
    body2, _ = _login(c, "corvex", "my-own-strong-pass-7")
    assert body2["password_change_required"] is False


def test_without_a_pinned_password_nothing_is_created_or_generated(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch, user="admin", password=None)
    assert auth.store.count_users() == 0
    assert c.get("/setup/status").json()["setup_required"] is True
    assert auth.ensure_default_admin()["password"] is None


def test_force_change_opt_out_for_provisioning(tmp_path, monkeypatch):
    c, _ = _app(tmp_path, monkeypatch, password="vault-managed-pass-1", force="0")
    body, H = _login(c, "corvex", "vault-managed-pass-1")
    assert body["password_change_required"] is False
    assert c.get("/engagements", headers=H).status_code == 200


def test_a_short_pinned_password_refuses_to_start(tmp_path, monkeypatch):
    # first boot with CORVEX_ADMIN_PASSWORD under 12 characters (the old shipped 'corvex'
    # included): no admin is seeded with a password nobody could set today
    import pytest
    for pw in ("corvex", "elevenchars"):
        with pytest.raises(RuntimeError, match=rf"CORVEX_ADMIN_PASSWORD is {len(pw)} characters.*at least 12"):
            _app(tmp_path / pw, monkeypatch, password=pw, force="0")
    _app(tmp_path / "ok", monkeypatch, password="twelve-chars", force="0")       # 12 starts


def test_existing_install_on_old_password_is_forced_at_next_start(tmp_path, monkeypatch):
    # an install created by the old installer: admin exists with 'corvex', no flag column yet
    db = tmp_path / "pentestiq.db"
    con = sqlite3.connect(db)
    con.execute("CREATE TABLE tenants (id TEXT PRIMARY KEY, name TEXT NOT NULL, created_at TEXT NOT NULL)")
    con.execute("CREATE TABLE users (id TEXT PRIMARY KEY, username TEXT UNIQUE NOT NULL, password_hash TEXT NOT NULL, created_at TEXT NOT NULL)")
    con.execute("CREATE TABLE memberships (user_id TEXT NOT NULL, tenant_id TEXT NOT NULL, role TEXT NOT NULL, PRIMARY KEY(user_id, tenant_id))")
    con.execute("INSERT INTO tenants VALUES ('t1','Corvex-RedOps','2026-01-01')")
    con.execute("INSERT INTO users VALUES ('u1','corvex',?,'2026-01-01')", (hash_password("corvex"),))
    con.execute("INSERT INTO memberships VALUES ('u1','t1','owner')")
    con.commit(); con.close()
    c, auth = _app(tmp_path, monkeypatch, password="", force="0")   # column added in place on open
    body, H = _login(c, "corvex", "corvex")
    assert body["password_change_required"] is True
    assert c.get("/engagements", headers=H).status_code == 403


def test_operator_reset_password_is_one_time(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch, password="first-pass-123", force="0")
    pw = auth.reset_password("corvex")
    body, H = _login(c, "corvex", pw)
    assert body["password_change_required"] is True
    assert c.get("/engagements", headers=H).status_code == 403


def test_api_keys_are_not_blocked_by_a_flagged_user(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch, password="first-pass-123", force="0")
    _, H = _login(c, "corvex", "first-pass-123")
    key = c.post("/apikeys", headers=H, json={"name": "ci"}).json()["api_key"]
    auth.reset_password("corvex")                     # the human must change their password ...
    assert c.get("/engagements", headers={"X-API-Key": key}).status_code == 200   # ... machines keep working

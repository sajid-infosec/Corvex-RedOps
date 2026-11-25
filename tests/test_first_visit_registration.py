"""First visit, email verification off (the default for now): the registration form asks for
full name, email, username and the password twice, and creates the owner account at once. A
console reachable from other machines also asks for the one-time setup code. An older install
whose only account is the built-in one on the publicly known password gets the form too, and
registering takes that account over with its workspace and data. `corvex reset-setup` brings
the form back for an install whose sign-in is lost, keeping the workspaces."""
import sqlite3

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from pentestiq.api.app import create_app
from pentestiq.auth import setup as setup_mod
from pentestiq.auth.passwords import hash_password
from pentestiq.auth.registry import RegistryClient
from pentestiq.auth.service import AuthService
from pentestiq.cli import app as cli_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore

PW = "my-own-strong-pass-7"
FORM = {"full_name": "  Nadia   Rahman ", "email": "Nadia@Example.ORG", "username": "nadia",
        "password": PW, "password_confirm": PW}


def _app(tmp_path, monkeypatch, db_name="corvex-redops.db"):
    for var in ("CORVEX_ADMIN_USER", "CORVEX_ADMIN_PASSWORD", "CORVEX_SETUP_CODE_REQUIRED", "CORVEX_REGISTRY"):
        monkeypatch.delenv(var, raising=False)
    db = str(tmp_path / db_name)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    c = TestClient(create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path))))
    return c, auth


def _register(c, **over):
    return c.post("/setup/register", json={**FORM, **over})


def _login(c, user, pw=PW):
    r = c.post("/auth/login", json={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def test_email_verification_is_off_by_default_and_never_touches_the_network(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch)
    assert RegistryClient(auth.store).enabled is False
    def boom(*a, **k):
        raise AssertionError("the registry must not be contacted")
    monkeypatch.setattr("urllib.request.urlopen", boom)
    st = c.get("/setup/status").json()
    assert st == {"setup_required": True, "default_username": "admin", "signup": "form",
                  "setup_code_required": False, "replaces_admin": False}
    assert _register(c).status_code == 201
    h = _login(c, "nadia")
    assert c.get("/engagements", headers=h).status_code == 200


def test_the_form_creates_the_owner_and_signs_in_with_it(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch)
    r = _register(c)
    assert r.status_code == 201 and r.json() == {"ok": True, "username": "nadia", "full_name": "Nadia Rahman"}
    me = c.get("/me", headers=_login(c, "nadia")).json()
    assert me["role"] == "owner" and me["username"] == "nadia" and me["full_name"] == "Nadia Rahman"
    assert me["email"] == "Nadia@example.org" and me["email_verified"] is False      # stored, not verified yet
    assert me["email_verification_required"] is False and me["password_change_required"] is False
    assert c.get("/setup/status").json()["setup_required"] is False
    assert _register(c, username="second").status_code == 409                         # only the first visit
    assert c.post("/auth/options").status_code in (200, 405)


@pytest.mark.parametrize("over, says", [
    ({"full_name": "   "}, "full name"),
    ({"full_name": "x" * 101}, "full name"),
    ({"email": "not-an-email"}, "email"),
    ({"username": "has space"}, "username"),
    ({"username": ""}, "username"),
    ({"password": "short", "password_confirm": "short"}, "12"),
    ({"password_confirm": "something-else-entirely"}, "match"),
    ({"password": "corvex", "password_confirm": "corvex"}, ""),
])
def test_the_form_is_checked_and_nothing_is_created(tmp_path, monkeypatch, over, says):
    c, auth = _app(tmp_path, monkeypatch)
    r = _register(c, **over)
    assert r.status_code == 422, r.text
    assert says.lower() in str(r.json()["detail"]).lower()
    assert auth.store.count_users() == 0 and auth.store.count_tenants() == 0


def test_a_console_reachable_from_elsewhere_also_needs_the_setup_code(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch)
    monkeypatch.setenv("CORVEX_SETUP_CODE_REQUIRED", "1")
    assert c.get("/setup/status").json()["setup_code_required"] is True
    assert _register(c).status_code == 403
    assert _register(c, setup_code="WRONG234").status_code == 403
    code = setup_mod.new_code(auth.store)
    assert _register(c, setup_code=code).status_code == 201
    assert auth.store.get_setup_code() is None                         # used up


def test_old_builtin_account_on_the_shipped_password_is_taken_over_with_its_data(tmp_path, monkeypatch):
    # an install from the old installer: 'admin' on the public password, a workspace with work in it
    db = tmp_path / "corvex-redops.db"
    store = SqliteAuthStore(str(db))
    t, u = store.create_workspace("Corvex-RedOps", "admin", hash_password("corvex"), __import__(
        "pentestiq.auth.models", fromlist=["Role"]).Role.OWNER)
    eng = SqliteEngagementStore(str(db))
    from pentestiq.engine import Engine
    eid = eng.create(t.id, Engine(AppConfig(data_dir=str(tmp_path))).build_from_dict({"name": "old work"})).id
    c, auth = _app(tmp_path, monkeypatch)
    st = c.get("/setup/status").json()
    assert st["setup_required"] is True and st["replaces_admin"] is True
    assert c.post("/auth/login", json={"username": "admin", "password": "corvex"}).status_code == 503
    assert _register(c).status_code == 201
    assert auth.store.count_users() == 1 and auth.store.count_tenants() == 1
    h = _login(c, "nadia")
    me = c.get("/me", headers=h).json()
    assert me["user_id"] == u.id and me["tenant_id"] == t.id and me["full_name"] == "Nadia Rahman"
    assert [e["id"] for e in c.get("/engagements", headers=h).json()] == [eid]       # the data stayed
    assert c.post("/auth/login", json={"username": "admin", "password": "corvex"}).status_code == 401


def test_an_admin_with_their_own_password_is_never_replaced(tmp_path, monkeypatch):
    store = SqliteAuthStore(str(tmp_path / "corvex-redops.db"))
    from pentestiq.auth.models import Role
    store.create_workspace("Corvex-RedOps", "admin", hash_password("a-real-chosen-password-1"), Role.OWNER)
    c, auth = _app(tmp_path, monkeypatch)
    assert c.get("/setup/status").json()["setup_required"] is False
    assert _register(c).status_code == 409
    _login(c, "admin", "a-real-chosen-password-1")


def test_reset_setup_brings_the_form_back_and_keeps_the_workspace(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_DATA_DIR", str(tmp_path))
    c, auth = _app(tmp_path, monkeypatch)
    assert _register(c).status_code == 201
    h = _login(c, "nadia")
    eid = c.post("/engagements", headers=h, json={"engagement": {"name": "keep me"}}).json()["id"]
    tenant = c.get("/me", headers=h).json()["tenant_id"]
    r = CliRunner().invoke(cli_app, ["reset-setup"], input="n\n")
    assert r.exit_code == 1 and "Nothing changed" in r.output and auth.store.count_users() == 1
    r = CliRunner().invoke(cli_app, ["reset-setup", "--yes"])
    assert r.exit_code == 0 and "nadia" in r.output, r.output
    assert auth.store.count_users() == 0 and auth.store.count_tenants() == 1
    assert c.post("/auth/login", json={"username": "nadia", "password": PW}).status_code == 503
    # a new owner registers: same workspace, its data still there (Community's one workspace)
    assert _register(c, username="rahim", full_name="Rahim Uddin", email="rahim@example.org").status_code == 201
    h2 = _login(c, "rahim")
    assert c.get("/me", headers=h2).json()["tenant_id"] == tenant
    assert [e["id"] for e in c.get("/engagements", headers=h2).json()] == [eid]
    r = CliRunner().invoke(cli_app, ["reset-setup", "--yes"])
    assert "rahim" in r.output


def test_racing_registrations_create_one_owner(tmp_path, monkeypatch):
    import threading
    c, auth = _app(tmp_path, monkeypatch)
    out = []
    def go(i):
        out.append(auth_register(auth, i))
    def auth_register(a, i):
        try:
            a.register_first_account("Person %d" % i, "p%d@example.org" % i, "user%d" % i, PW, PW)
            return "ok"
        except Exception as exc:
            return type(exc).__name__
    ts = [threading.Thread(target=go, args=(i,)) for i in range(6)]
    [t.start() for t in ts]; [t.join() for t in ts]
    assert out.count("ok") == 1 and set(out) - {"ok"} <= {"SetupAlreadyDone"}
    assert auth.store.count_users() == 1 and auth.store.count_tenants() == 1


def test_members_carry_a_full_name(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch)
    _register(c)
    me = c.get("/me", headers=_login(c, "nadia")).json()
    auth.create_member(me["tenant_id"], "rahim", "another-good-pass-9", full_name="  Rahim   Uddin ")
    members = {m["username"]: m for m in auth.list_members(me["tenant_id"])}
    assert members["rahim"]["full_name"] == "Rahim Uddin" and members["nadia"]["full_name"] == "Nadia Rahman"

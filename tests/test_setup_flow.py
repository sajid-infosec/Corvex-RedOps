"""First visit sets the admin password. A fresh install has no admin and no password; until the
setup page has created one, every API route except setup and health refuses. The page takes a
one-time setup code (8 characters, valid until used, replaced by a newer one) that is never
written to any log; `corvex setup-code` prints one, and `corvex serve` shows the address and a
code only when it prints to a terminal. CORVEX_ADMIN_PASSWORD still creates the admin directly,
and an install that already has an admin never sees the page."""
import logging
import re

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from pentestiq.api.app import create_app
from pentestiq.auth import setup as setup_mod
from pentestiq.auth.service import AuthService
from pentestiq.cli import app as cli_app, setup_notice
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore

PW = "my-own-strong-pass-7"


def _app(tmp_path, monkeypatch, password=None):
    monkeypatch.delenv("CORVEX_ADMIN_USER", raising=False)
    if password is None:
        monkeypatch.delenv("CORVEX_ADMIN_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("CORVEX_ADMIN_PASSWORD", password)
    monkeypatch.setenv("CORVEX_ADMIN_FORCE_CHANGE", "0")
    db = str(tmp_path / "pentestiq.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    return TestClient(create_app(store=SqliteEngagementStore(db), auth=auth,
                                 config=AppConfig(data_dir=str(tmp_path)))), auth


def _setup(c, code, user="admin", pw=PW, pw2=None):
    return c.post("/setup", json={"code": code, "username": user, "password": pw,
                                  "password_confirm": pw if pw2 is None else pw2})


def test_a_fresh_install_has_no_admin_and_only_setup_and_health_answer(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch)
    assert auth.store.count_users() == 0
    assert c.get("/setup/status").json() == {"setup_required": True, "default_username": "admin",
                                             "signup": "form", "setup_code_required": False,
                                             "replaces_admin": False}    # email verification off
    assert c.get("/health").status_code == 200 and c.get("/").status_code == 200
    for method, path in (("GET", "/engagements"), ("GET", "/me"), ("POST", "/auth/login"),
                         ("POST", "/auth/register"), ("GET", "/edition"), ("GET", "/settings"),
                         ("POST", "/engagements")):
        r = c.request(method, path, json={})
        assert r.status_code == 503 and r.json()["detail"]["error"] == "setup_required", path


def test_the_setup_page_creates_the_admin_then_sign_in_works_normally(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch)
    code = auth.new_setup_code()
    assert re.fullmatch(rf"[{setup_mod.ALPHABET}]{{8}}", code)
    assert _setup(c, "WRONG234").status_code == 403
    assert _setup(c, code, pw2="something-else-12").status_code == 422          # twice, the same
    assert _setup(c, code, pw="too-short").status_code == 422                    # 12+ characters
    assert _setup(c, code, user="has space").status_code == 422
    r = _setup(c, code.lower())                                                   # typed in any case
    assert r.status_code == 200 and r.json() == {"ok": True, "username": "admin"}
    assert c.get("/setup/status").json()["setup_required"] is False
    assert _setup(c, code).status_code == 409                                     # used up
    assert auth.store.get_setup_code() is None
    body = c.post("/auth/login", json={"username": "admin", "password": PW}).json()
    assert body["password_change_required"] is False                            # they chose it
    assert c.get("/engagements", headers={"Authorization": "Bearer " + body["token"]}).status_code == 200


def test_a_newer_code_replaces_the_older_one(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch)
    old = auth.new_setup_code(); new = auth.new_setup_code()
    assert _setup(c, old).status_code == 403 and _setup(c, new).status_code == 200


def test_guessing_codes_is_throttled(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch)
    code = auth.new_setup_code()
    assert [_setup(c, f"WRONG{i:03d}").status_code for i in range(5)] == [403] * 5
    assert _setup(c, code).status_code == 429                       # even the right code, for now


def test_pinned_admin_password_skips_the_page(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch, password="headless-pass-123")
    assert c.get("/setup/status").json()["setup_required"] is False
    assert c.post("/auth/login", json={"username": "admin", "password": "headless-pass-123"}).status_code == 200
    with pytest.raises(Exception):
        auth.new_setup_code()


def test_an_install_that_already_has_an_admin_never_sees_the_page(tmp_path, monkeypatch):
    db = str(tmp_path / "pentestiq.db")
    AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600).register("Corvex-RedOps", "corvex", PW)
    c, _ = _app(tmp_path, monkeypatch)
    assert c.get("/setup/status").json()["setup_required"] is False
    assert c.post("/auth/login", json={"username": "corvex", "password": PW}).status_code == 200


def test_the_code_is_never_logged(tmp_path, monkeypatch, caplog):
    caplog.set_level(logging.DEBUG)
    monkeypatch.setenv("CORVEX_SETUP_CODE_REQUIRED", "1")        # reachable from elsewhere: a code is needed
    c, auth = _app(tmp_path, monkeypatch)
    code = auth.new_setup_code()
    _setup(c, "WRONG234"); _setup(c, code)
    assert code not in caplog.text and code.lower() not in caplog.text
    assert "corvex setup-code" in caplog.text            # the startup message says how to get one
    raw = (tmp_path / "pentestiq.db").read_bytes()
    assert code.encode() not in raw                      # only a salted hash was ever stored


def test_cli_setup_code_prints_a_fresh_code_and_refuses_after_setup(tmp_path, monkeypatch):
    monkeypatch.delenv("CORVEX_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("CORVEX_DATA_DIR", str(tmp_path))
    r1 = CliRunner().invoke(cli_app, ["setup-code"])
    first = re.search(r"One-time setup code: ([A-Z0-9]{8})", r1.output).group(1)
    second = CliRunner().invoke(cli_app, ["setup-code", "--quiet"]).output.strip()
    assert re.fullmatch(r"[A-Z0-9]{8}", second) and second != first
    auth = AuthService(SqliteAuthStore(str(tmp_path / "corvex-redops.db")), secret_key="s", session_ttl=3600)
    assert not setup_mod.check_code(auth.store, first) and setup_mod.check_code(auth.store, second)
    auth.complete_setup(second, "admin", PW)
    r3 = CliRunner().invoke(cli_app, ["setup-code"])
    assert r3.exit_code == 3 and "Setup is already done" in r3.output


def test_serve_on_this_machine_only_points_at_the_form(tmp_path, monkeypatch):
    monkeypatch.delenv("CORVEX_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("CORVEX_SETUP_CODE_REQUIRED", raising=False)
    auth = AuthService(SqliteAuthStore(str(tmp_path / "a.db")), secret_key="s", session_ttl=3600)
    for to_terminal in (True, False):
        out = setup_notice("127.0.0.1", 8000, to_terminal, auth=auth)
        assert out == "Create your Corvex-RedOps account: open http://127.0.0.1:8000"
    assert auth.store.get_setup_code() is None                               # no code minted


def test_serve_shows_the_address_and_a_code_only_on_a_terminal(tmp_path, monkeypatch):
    monkeypatch.delenv("CORVEX_ADMIN_PASSWORD", raising=False)
    monkeypatch.setenv("CORVEX_SETUP_CODE_REQUIRED", "1")
    auth = AuthService(SqliteAuthStore(str(tmp_path / "a.db")), secret_key="s", session_ttl=3600)
    tty = setup_notice("127.0.0.1", 8000, True, auth=auth)
    assert "open http://127.0.0.1:8000" in tty
    code = re.search(r"One-time setup code: ([A-Z0-9]{8})", tty).group(1)
    assert setup_mod.check_code(auth.store, code)
    piped = setup_notice("0.0.0.0", 8080, False, auth=auth)               # a service / container / log
    assert "http://127.0.0.1:8080" in piped and "corvex setup-code" in piped
    assert not re.search(r"code: [A-Z0-9]{8}", piped)
    auth.complete_setup(code, "admin", PW)
    assert setup_notice("127.0.0.1", 8000, True, auth=auth) == ""            # set up: nothing to say


def test_serve_writes_the_notice_to_the_terminal_not_the_logger():
    import inspect
    from pentestiq import cli
    src = inspect.getsource(cli.serve)
    assert "setup_notice(host, port, _sys.stdout.isatty())" in src and "_sys.stdout.write(notice" in src

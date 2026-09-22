import time
from pentestiq.auth.passwords import hash_password, verify_password
from pentestiq.auth.tokens import sign_token, verify_token
from pentestiq.auth.models import Role


def test_password_hash_roundtrip():
    h = hash_password("correct horse battery staple")
    assert h.startswith("pbkdf2_sha256$")
    assert verify_password("correct horse battery staple", h) is True
    assert verify_password("wrong", h) is False
    # two hashes of the same password differ (random salt)
    assert h != hash_password("correct horse battery staple")


def test_token_sign_verify_and_expiry():
    tok = sign_token({"sub": "u1", "tenant": "t1", "role": "owner"}, "secret", ttl_seconds=60)
    p = verify_token(tok, "secret")
    assert p and p["tenant"] == "t1" and p["role"] == "owner"
    assert verify_token(tok, "wrong-secret") is None            # bad signature
    assert verify_token(tok + "x", "secret") is None            # tampered
    expired = sign_token({"sub": "u1"}, "secret", ttl_seconds=-1)
    assert verify_token(expired, "secret") is None              # expired


def test_role_ranking():
    assert Role.OWNER.satisfies(Role.MEMBER)
    assert Role.VIEWER.satisfies(Role.MEMBER) is False
    assert Role.ADMIN.satisfies(Role.ADMIN)


def test_first_boot_generates_random_admin_password(tmp_path, monkeypatch):
    """No password is shipped: first boot generates a random one (or uses env)."""
    from pentestiq.auth.service import AuthService
    from pentestiq.storage import SqliteAuthStore
    monkeypatch.delenv("CORVEX_ADMIN_PASSWORD", raising=False)
    monkeypatch.delenv("CORVEX_ADMIN_USER", raising=False)
    a = AuthService(SqliteAuthStore(str(tmp_path / "a.db")), secret_key="s", session_ttl=3600)
    res = a.ensure_default_admin()
    assert res["created"] and res["user"] == "admin"
    assert res["password"] and len(res["password"]) >= 12       # generated, strong
    assert a.login("admin", res["password"])                    # the generated pw works
    # idempotent + never re-emits the password
    res2 = a.ensure_default_admin()
    assert res2["created"] is False and res2["password"] is None


def test_first_boot_honours_env_credentials(tmp_path, monkeypatch):
    from pentestiq.auth.service import AuthService
    from pentestiq.storage import SqliteAuthStore
    monkeypatch.setenv("CORVEX_ADMIN_USER", "root")
    monkeypatch.setenv("CORVEX_ADMIN_PASSWORD", "pinned-secret-123")
    a = AuthService(SqliteAuthStore(str(tmp_path / "a.db")), secret_key="s", session_ttl=3600)
    res = a.ensure_default_admin()
    assert res["created"] and res["user"] == "root"
    assert res["password"] is None                              # env-pinned → not echoed
    assert a.login("root", "pinned-secret-123")


def test_first_boot_empty_env_password_still_generates(tmp_path, monkeypatch):
    """Compose passes CORVEX_ADMIN_PASSWORD="" when unset: treat it as unset,
    generate a password and return it so it is printed once (never a silent,
    unrecoverable random password)."""
    from pentestiq.auth.service import AuthService
    from pentestiq.storage import SqliteAuthStore
    monkeypatch.setenv("CORVEX_ADMIN_PASSWORD", "")
    monkeypatch.delenv("CORVEX_ADMIN_USER", raising=False)
    a = AuthService(SqliteAuthStore(str(tmp_path / "a.db")), secret_key="s", session_ttl=3600)
    res = a.ensure_default_admin()
    assert res["created"] and res["password"]
    assert a.login("admin", res["password"])


def test_reset_password_recovers_login(tmp_path):
    import pytest
    from pentestiq.auth.service import AuthService
    from pentestiq.storage import SqliteAuthStore
    st = SqliteAuthStore(str(tmp_path / "a.db"))
    a = AuthService(st, secret_key="s", session_ttl=3600)
    a.register("T", "alice", "old-password-1")
    new = a.reset_password("alice")                      # generated
    assert len(new) >= 12 and a.login("alice", new) and not a.login("alice", "old-password-1")
    assert a.reset_password("alice", "chosen-pass-9") == "chosen-pass-9"
    assert a.login("alice", "chosen-pass-9")
    with pytest.raises(KeyError):
        a.reset_password("nobody")
    with pytest.raises(ValueError):
        a.reset_password("alice", "short")
    assert st.list_usernames() == ["alice"]


def test_cli_reset_password_and_no_default_tenant_password(tmp_path, monkeypatch):
    from typer.testing import CliRunner
    from pentestiq.cli import app
    monkeypatch.chdir(tmp_path)
    r = CliRunner().invoke(app, ["init-tenant", "--username", "owner1"])
    assert r.exit_code == 0 and "Owner login: owner1 / " in r.output and "p3nt3st" not in r.output
    r = CliRunner().invoke(app, ["reset-password", "owner1", "--password", "brand-new-pw-1"])
    assert r.exit_code == 0 and "Password reset" in r.output
    r = CliRunner().invoke(app, ["reset-password"])
    assert "owner1" in r.output
    r = CliRunner().invoke(app, ["reset-password", "ghost"])
    assert r.exit_code == 1 and "no such user" in r.output

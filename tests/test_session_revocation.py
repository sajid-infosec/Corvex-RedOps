"""B2: sessions end when credentials change. Tokens carry an issued-at time; each user has a
'sessions valid after' time moved forward by change-password and reset-password; the role
comes from the store, and tokens for deleted users/memberships stop working."""
from fastapi.testclient import TestClient

from pentestiq.api.app import create_app
from pentestiq.auth.service import AuthService
from pentestiq.auth.tokens import sign_token
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore


def _app(tmp_path, monkeypatch, force="0"):
    monkeypatch.setenv("CORVEX_ADMIN_USER", "corvex")
    monkeypatch.setenv("CORVEX_ADMIN_PASSWORD", "first-pass-123")
    monkeypatch.setenv("CORVEX_ADMIN_FORCE_CHANGE", force)
    db = str(tmp_path / "pentestiq.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s3cret", session_ttl=3600)
    return TestClient(create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path)))), auth


def _login(c, pw):
    r = c.post("/auth/login", json={"username": "corvex", "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def test_token_from_before_the_forced_change_is_rejected(tmp_path, monkeypatch):
    c, _ = _app(tmp_path, monkeypatch, force="1")
    old = _login(c, "first-pass-123")
    other = _login(c, "first-pass-123")                      # a second browser, same user
    r = c.post("/auth/change-password", headers=old,
               json={"current_password": "first-pass-123", "new_password": "my-new-pass-77"})
    assert r.status_code == 200
    new = {"Authorization": "Bearer " + r.json()["token"]}
    for h in (old, other):
        assert c.get("/me", headers=h).status_code == 401
    assert c.get("/engagements", headers=new).status_code == 200


def test_token_from_before_a_reset_is_rejected(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch)
    old = _login(c, "first-pass-123")
    assert c.get("/engagements", headers=old).status_code == 200
    pw = auth.reset_password("corvex")
    assert c.get("/me", headers=old).status_code == 401
    assert c.get("/me", headers=_login(c, pw)).status_code == 200   # the reset password still signs in


def test_tokens_without_issued_at_are_rejected(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch)
    _login(c, "first-pass-123")
    row = auth.store.get_user_auth("corvex")
    legacy = sign_token({"sub": row["user_id"], "tenant": row["tenant_id"], "role": "owner"}, "s3cret", 3600)
    assert c.get("/me", headers={"Authorization": "Bearer " + legacy}).status_code == 401


def test_role_comes_from_the_store_not_the_token(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch)
    h = _login(c, "first-pass-123")
    row = auth.store.get_user_auth("corvex")
    auth.store._conn.execute("UPDATE memberships SET role='viewer' WHERE user_id=?", (row["user_id"],))
    auth.store._conn.commit()
    me = c.get("/me", headers=h)
    assert me.status_code == 200 and me.json()["role"] == "viewer"     # the token still says owner
    assert c.post("/apikeys", headers=h, json={"name": "x"}).status_code == 403


def test_tokens_for_removed_memberships_or_users_are_rejected(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch)
    h = _login(c, "first-pass-123")
    row = auth.store.get_user_auth("corvex")
    auth.store._conn.execute("DELETE FROM memberships WHERE user_id=?", (row["user_id"],))
    auth.store._conn.commit()
    assert c.get("/me", headers=h).status_code == 401
    auth.store._conn.execute("DELETE FROM users WHERE id=?", (row["user_id"],))
    auth.store._conn.commit()
    assert c.get("/me", headers=h).status_code == 401


def test_forged_role_in_a_validly_signed_token_does_not_escalate(tmp_path, monkeypatch):
    c, auth = _app(tmp_path, monkeypatch)
    _login(c, "first-pass-123")
    row = auth.store.get_user_auth("corvex")
    auth.store._conn.execute("UPDATE memberships SET role='viewer' WHERE user_id=?", (row["user_id"],))
    auth.store._conn.commit()
    import time
    tok = sign_token({"sub": row["user_id"], "tenant": row["tenant_id"], "role": "owner",
                      "iat": int(time.time() * 1000)}, "s3cret", 3600)
    assert c.get("/me", headers={"Authorization": "Bearer " + tok}).json()["role"] == "viewer"


def test_session_stamps_never_repeat_on_a_coarse_clock(monkeypatch):
    # Windows before Python 3.13 ticks every ~15.6 ms: a session issued in the same tick as a
    # password reset must still end with it.
    import pentestiq.auth.service as svc
    monkeypatch.setattr(svc.time, "time", lambda: 1_800_000_000.0)      # a frozen clock
    a, b, c = svc._now_ms(), svc._now_ms(), svc._now_ms()
    assert a < b < c


def test_a_change_in_the_same_clock_tick_still_ends_earlier_sessions(tmp_path, monkeypatch):
    import pentestiq.auth.service as svc
    c, _ = _app(tmp_path, monkeypatch, force="1")
    monkeypatch.setattr(svc.time, "time", lambda: 1_800_000_000.0)      # every step in one tick
    old = _login(c, "first-pass-123")
    r = c.post("/auth/change-password", headers=old,
               json={"current_password": "first-pass-123", "new_password": "my-new-pass-77"})
    assert r.status_code == 200
    assert c.get("/me", headers=old).status_code == 401
    assert c.get("/me", headers={"Authorization": "Bearer " + r.json()["token"]}).status_code == 200

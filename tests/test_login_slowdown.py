"""Per-username slowdown: above 50 wrong passwords in an hour for one username (all
addresses), every attempt waits 1.5 s before it is answered; never a lock; unknown
usernames behave the same. Sleep is stubbed."""
from fastapi.testclient import TestClient

import pentestiq.auth.service as svc
from pentestiq.api.app import create_app
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore


def _app(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_ADMIN_USER", "corvex")
    monkeypatch.setenv("CORVEX_ADMIN_PASSWORD", "right-pass-123")
    monkeypatch.setenv("CORVEX_ADMIN_FORCE_CHANGE", "0")
    db = str(tmp_path / "pentestiq.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    return create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path))), auth


def _sleeps(monkeypatch):
    calls = []
    monkeypatch.setattr(svc, "_sleep", lambda s: calls.append(s))
    return calls


def _spray(app, user, n):
    # n failures for one username, each from a different address (so per-IP limits don't trip)
    for i in range(n):
        c = TestClient(app, client=(f"198.51.{100 + i // 250}.{i % 250 + 1}", 4000))
        assert c.post("/auth/login", json={"username": user, "password": "wrong-guess-1"}).status_code == 401


def test_slowdown_after_50_failures_but_the_right_password_still_works(tmp_path, monkeypatch):
    app, _ = _app(tmp_path, monkeypatch)
    calls = _sleeps(monkeypatch)
    _spray(app, "corvex", 50)
    assert calls == []                                    # 50 is not "above 50"
    _spray(app, "corvex", 1)                              # the 51st failure
    owner = TestClient(app, client=("203.0.113.9", 4000))
    r = owner.post("/auth/login", json={"username": "corvex", "password": "right-pass-123"})
    assert r.status_code == 200                           # never a lock
    assert calls and calls[-1] == 1.5                     # but it waited 1.5 s first


def test_unknown_usernames_are_slowed_the_same_way(tmp_path, monkeypatch):
    app, _ = _app(tmp_path, monkeypatch)
    calls = _sleeps(monkeypatch)
    _spray(app, "ghost-user", 51)
    n_before = len(calls)
    c = TestClient(app, client=("203.0.113.10", 4000))
    assert c.post("/auth/login", json={"username": "ghost-user", "password": "x-guess-12"}).status_code == 401
    assert len(calls) == n_before + 1 and calls[-1] == 1.5


def test_other_usernames_are_not_slowed(tmp_path, monkeypatch):
    app, _ = _app(tmp_path, monkeypatch)
    calls = _sleeps(monkeypatch)
    _spray(app, "someone-else", 60)
    n_before = len(calls)
    c = TestClient(app, client=("203.0.113.11", 4000))
    assert c.post("/auth/login", json={"username": "corvex", "password": "right-pass-123"}).status_code == 200
    assert len(calls) == n_before

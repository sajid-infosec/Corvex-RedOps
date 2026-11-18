"""Per-username slowdown: above 50 wrong passwords in the last hour for one username (all
addresses), every attempt waits 1.5 s (awaited) before it is answered; never a lock;
unknown usernames behave the same. The async sleep is stubbed, and the service's clock is
frozen (mid-hour unless a test moves it), so no test depends on the time it runs."""
import time as _time

import pytest
from fastapi.testclient import TestClient

import pentestiq.auth.service as svc
from pentestiq.api.app import create_app
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore


HOUR = 3600
TOP = 1_800_000_000 - 1_800_000_000 % HOUR          # hh:00:00
MID = TOP + HOUR // 2                                # hh:30:00


class _Clock:
    """Stands in for the `time` module inside pentestiq.auth.service only."""

    def __init__(self, t):
        self.t = t

    def time(self):
        return float(self.t)

    def __getattr__(self, name):
        return getattr(_time, name)


@pytest.fixture(autouse=True)
def clock(monkeypatch):
    c = _Clock(MID)
    monkeypatch.setattr(svc, "time", c)
    return c


def _app(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_ADMIN_USER", "corvex")
    monkeypatch.setenv("CORVEX_ADMIN_PASSWORD", "right-pass-123")
    monkeypatch.setenv("CORVEX_ADMIN_FORCE_CHANGE", "0")
    db = str(tmp_path / "pentestiq.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    return create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path))), auth


def _sleeps(monkeypatch):
    calls = []

    async def fake(s):
        calls.append(s)
    monkeypatch.setattr(svc, "slowdown_sleep", fake)
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


def _one(app, user="corvex"):
    c = TestClient(app, client=("203.0.113.20", 4000))
    assert c.post("/auth/login", json={"username": user, "password": "wrong-guess-1"}).status_code == 401


def test_the_slowdown_carries_over_the_top_of_the_hour(tmp_path, monkeypatch, clock):
    app, _ = _app(tmp_path, monkeypatch)
    calls = _sleeps(monkeypatch)
    clock.t = TOP + HOUR - 10                             # hh:59:50
    _spray(app, "corvex", 51)                             # slowed from here on
    n = len(calls)
    clock.t = TOP + HOUR + 5                              # hh+1:00:05, a new hourly window
    _one(app)
    assert len(calls) == n + 1 and calls[-1] == 1.5       # still slowed (it used to reset here)


def test_fifty_before_the_top_of_the_hour_is_still_not_above_fifty(tmp_path, monkeypatch, clock):
    # same threshold as within one hour: 50 earlier failures are not "above 50"
    app, _ = _app(tmp_path, monkeypatch)
    calls = _sleeps(monkeypatch)
    clock.t = TOP + HOUR - 10
    _spray(app, "corvex", 50)
    clock.t = TOP + HOUR + 5
    _one(app)
    assert calls == []


def test_the_slowdown_ends_once_the_failures_are_two_hours_old(tmp_path, monkeypatch, clock):
    app, _ = _app(tmp_path, monkeypatch)
    calls = _sleeps(monkeypatch)
    _spray(app, "corvex", 51)
    _one(app)
    assert calls and calls[-1] == 1.5                     # slowed now
    n = len(calls)
    clock.t = MID + 2 * HOUR
    _one(app)
    assert len(calls) == n                                # two hours later: not slowed


def test_the_previous_hour_fades_out_across_the_new_one(tmp_path, monkeypatch, clock):
    # 60 failures late in one hour count less the further the next hour gets: estimate =
    # 60 * (3600 - elapsed) / 3600 + this window's attempts (this one included)
    calls = _sleeps(monkeypatch)
    for elapsed, slowed in ((60, True), (600, False)):     # 59 + 1 - 1 = 59 > 50; 50 + 1 - 1 = 50
        app, _ = _app(tmp_path / str(elapsed), monkeypatch)
        clock.t = TOP + HOUR - 10
        _spray(app, "corvex", 60)
        n = len(calls)
        clock.t = TOP + HOUR + elapsed
        _one(app)
        assert (len(calls) == n + 1) is slowed, elapsed

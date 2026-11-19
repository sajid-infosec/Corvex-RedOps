"""B3: sign-in throttling — per username+IP 5 failures / 15 min and per IP 30 failures /
15 min answer 429; no account-wide lock; unknown usernames cost the same (dummy hash) and
get an identical 401."""
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
    return create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path)))


def _from(app, ip):
    return TestClient(app, client=(ip, 40000))


def _login(c, user, pw):
    return c.post("/auth/login", json={"username": user, "password": pw})


def test_username_ip_pair_is_throttled_but_the_owner_elsewhere_is_not(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    atk, owner = _from(app, "192.0.2.10"), _from(app, "203.0.113.5")
    for _ in range(5):
        assert _login(atk, "corvex", "wrong-guess-1").status_code == 401
    r = _login(atk, "corvex", "right-pass-123")              # even the right password, from that IP
    assert r.status_code == 429 and int(r.headers["Retry-After"]) > 0
    assert _login(owner, "corvex", "right-pass-123").status_code == 200   # no account lock


def test_per_ip_limit_across_usernames(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    spray, other = _from(app, "192.0.2.20"), _from(app, "203.0.113.6")
    for i in range(30):
        assert _login(spray, f"user{i}", "pw-guess-123").status_code == 401
    assert _login(spray, "someone-new", "pw-guess-123").status_code == 429
    assert _login(spray, "corvex", "right-pass-123").status_code == 429
    assert _login(other, "corvex", "right-pass-123").status_code == 200


def test_successful_sign_ins_do_not_count(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    c = _from(app, "192.0.2.30")
    for _ in range(10):
        assert _login(c, "corvex", "right-pass-123").status_code == 200
    for _ in range(4):
        assert _login(c, "corvex", "wrong-guess-1").status_code == 401
    assert _login(c, "corvex", "right-pass-123").status_code == 200


def test_unknown_usernames_answer_identically_and_run_a_dummy_hash(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    c = _from(app, "192.0.2.40")
    calls = []
    real = svc.verify_password
    monkeypatch.setattr(svc, "verify_password", lambda pw, stored: calls.append(stored) or real(pw, stored))
    known = _login(c, "corvex", "wrong-guess-1")
    unknown = _login(c, "nobody-here", "wrong-guess-1")
    assert known.status_code == unknown.status_code == 401
    assert known.json() == unknown.json()
    assert len(calls) == 2 and calls[1] == AuthService._dummy()   # the unknown user paid for a hash too


def test_unknown_usernames_are_throttled_the_same_way(tmp_path, monkeypatch):
    app = _app(tmp_path, monkeypatch)
    c = _from(app, "192.0.2.50")
    seen = {}
    for user in ("corvex", "ghost-user"):
        seen[user] = [_login(c, user, "wrong-guess-1").status_code for _ in range(6)]
    assert seen["corvex"] == seen["ghost-user"] == [401] * 5 + [429]


# ---- the 15-minute windows are fixed, on purpose --------------------------------------------
# The username+IP and IP counters restart at :00, :15, :30 and :45 (not a sliding 15 minutes),
# so a burst that straddles a boundary gets a fresh count. The per-username hourly slowdown
# still carries over (tests/test_login_slowdown.py). The throttle clock is pinned by the
# `throttle_clock` fixture in tests/conftest.py.

def test_the_throttle_clock_is_pinned_mid_window_and_mid_hour(throttle_clock):
    assert throttle_clock.t % 900 == 450                  # 7.5 minutes into a 15-minute window
    assert throttle_clock.t % 3600 == 37 * 60 + 30        # hh:37:30


def test_a_sixth_failure_in_the_same_window_is_refused_until_it_ends(tmp_path, monkeypatch, throttle_clock):
    app = _app(tmp_path, monkeypatch)
    c = _from(app, "192.0.2.60")
    hour = throttle_clock.t - throttle_clock.t % 3600
    throttle_clock.t = hour + 14 * 60 + 59                # hh:14:59
    assert [_login(c, "corvex", "wrong-guess-1").status_code for _ in range(5)] == [401] * 5
    r = _login(c, "corvex", "wrong-guess-1")
    assert r.status_code == 429 and r.headers["Retry-After"] == "1"   # the window ends at hh:15:00


def test_five_failures_at_14_59_then_one_at_15_00_is_not_refused(tmp_path, monkeypatch, throttle_clock):
    app = _app(tmp_path, monkeypatch)
    c = _from(app, "192.0.2.61")
    hour = throttle_clock.t - throttle_clock.t % 3600
    throttle_clock.t = hour + 14 * 60 + 59                # hh:14:59
    assert [_login(c, "corvex", "wrong-guess-1").status_code for _ in range(5)] == [401] * 5
    throttle_clock.t = hour + 15 * 60                     # hh:15:00, a new window
    assert _login(c, "corvex", "wrong-guess-1").status_code == 401   # counted afresh, not refused

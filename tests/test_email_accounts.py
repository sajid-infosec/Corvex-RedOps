"""Email accounts: sign-up on first visit, emailed codes, verification before use, password
reset by email and invites — all through the account registry (auth/registry.py), faked here.
With the registry off or unreachable, setup falls back to the one-time setup code and nobody
is held up; with it on, a signed-in user without a verified email reaches only the
verification routes."""
import io
import json
import urllib.error

import pytest
from fastapi.testclient import TestClient

from pentestiq.api.app import create_app
from pentestiq.auth import setup as setup_mod
from pentestiq.auth.models import Role
from pentestiq.auth.registry import RegistryClient, RegistryError, RegistryUnavailable
from pentestiq.auth.service import AuthService, normalize_email, registry_name
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore

PW = "my-own-strong-pass-7"
NEW_PW = "another-strong-pass-8"


class FakeRegistry:
    """Behaves like the registry service: codes, one use, reset only to verified emails."""

    enabled = True

    def __init__(self, up: bool = True) -> None:
        self.up, self.sent, self.codes, self.verified = up, [], {}, {}

    def available(self, refresh: bool = False, wait: bool = True) -> bool:
        return self.up

    def send_code(self, purpose, username, email, role=None, inviter=None):
        if not self.up:
            raise RegistryUnavailable("down")
        if purpose == "reset" and (self.verified.get(username) or "").lower() != email.lower():
            raise RegistryError(404, "not_verified", "no verified email")
        vid, code = f"v{len(self.sent)}", f"{314159 + len(self.sent):06d}"
        self.codes[vid] = {"code": code, "purpose": purpose, "username": username, "email": email, "used": False}
        self.sent.append({"purpose": purpose, "username": username, "email": email, "role": role,
                          "inviter": inviter, "code": code})
        return {"verification_id": vid, "expires_in": 900, "sent_to": "x***@" + email.split("@")[1]}

    def check_code(self, vid, code):
        if not self.up:
            raise RegistryUnavailable("down")
        v = self.codes.get(vid)
        if v is None:
            raise RegistryError(404, "unknown", "no such code request")
        if v["used"]:
            raise RegistryError(410, "expired", "used")
        if code != v["code"]:
            raise RegistryError(400, "wrong_code", "that code isn't right", remaining=4)
        v["used"] = True
        if v["purpose"] in ("register", "invite"):
            self.verified[v["username"]] = v["email"]
        return {"ok": True, "purpose": v["purpose"], "username": v["username"], "email": v["email"]}

    def last(self):
        return self.sent[-1]


def _app(tmp_path, monkeypatch, registry=None, admin_password=None):
    monkeypatch.delenv("CORVEX_ADMIN_USER", raising=False)
    monkeypatch.delenv("CORVEX_SETUP_CODE_REQUIRED", raising=False)
    if admin_password is None:
        monkeypatch.delenv("CORVEX_ADMIN_PASSWORD", raising=False)
    else:
        monkeypatch.setenv("CORVEX_ADMIN_PASSWORD", admin_password)
    monkeypatch.setenv("CORVEX_ADMIN_FORCE_CHANGE", "0")
    db = str(tmp_path / "corvex-redops.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    auth.registry = registry if registry is not None else FakeRegistry()
    c = TestClient(create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path))))
    return c, auth


def _signup(c, user="sajid", email="Sajid@Example.org", pw=PW, pw2=None, **extra):
    return c.post("/setup/signup", json={"username": user, "email": email, "password": pw,
                                         "password_confirm": pw if pw2 is None else pw2, **extra})


def _login(c, user="sajid", pw=PW):
    r = c.post("/auth/login", json={"username": user, "password": pw})
    assert r.status_code == 200, r.text
    return {"Authorization": "Bearer " + r.json()["token"]}


def _register_owner(c, reg):
    r = _signup(c)
    assert r.status_code == 202, r.text
    v = c.post("/setup/signup/verify", json={"pending_id": r.json()["pending_id"], "code": reg.last()["code"]})
    assert v.status_code == 200, v.text
    return v


# ---------------------------------------------------------------- first visit
def test_first_visit_signup_by_email(tmp_path, monkeypatch):
    reg = FakeRegistry()
    c, auth = _app(tmp_path, monkeypatch, reg)
    st = c.get("/setup/status").json()
    assert st["setup_required"] is True and st["signup"] == "email" and st["setup_code_required"] is False
    r = _signup(c)
    assert r.status_code == 202 and r.json()["sent_to"] == "x***@example.org"
    assert reg.last() == {"purpose": "register", "username": "sajid", "email": "Sajid@example.org", "role": "owner",
                          "inviter": None, "code": reg.last()["code"]}
    assert auth.store.count_users() == 0                       # nothing exists until the code comes back
    assert c.post("/auth/login", json={"username": "sajid", "password": PW}).status_code in (401, 503)
    bad = c.post("/setup/signup/verify", json={"pending_id": r.json()["pending_id"], "code": "000000"})
    assert bad.status_code == 400 and bad.json()["detail"]["error"] == "wrong_code"
    ok = c.post("/setup/signup/verify", json={"pending_id": r.json()["pending_id"], "code": reg.last()["code"]})
    assert ok.status_code == 200 and ok.json() == {"ok": True, "username": "sajid"}
    assert c.get("/setup/status").json()["setup_required"] is False
    h = _login(c)
    me = c.get("/me", headers=h).json()
    assert me["role"] == "owner" and me["email"] == "Sajid@example.org" and me["email_verified"] is True
    assert me["email_verification_required"] is False
    assert c.get("/engagements", headers=h).status_code == 200
    # the password never went to the registry
    assert PW not in json.dumps(reg.sent)


def test_signup_form_is_checked_before_any_email(tmp_path, monkeypatch):
    reg = FakeRegistry()
    c, _ = _app(tmp_path, monkeypatch, reg)
    assert _signup(c, pw2="something-else-entirely").status_code == 422
    assert _signup(c, pw="short").status_code == 422
    assert _signup(c, pw="corvex", pw2="corvex").status_code == 422
    assert _signup(c, email="not-an-email").status_code == 422
    assert _signup(c, user="has space").status_code == 422
    assert reg.sent == []


def test_signup_resend_and_expired_request(tmp_path, monkeypatch):
    reg = FakeRegistry()
    c, auth = _app(tmp_path, monkeypatch, reg)
    pid = _signup(c).json()["pending_id"]
    first = reg.last()["code"]
    assert c.post("/setup/signup/resend", json={"pending_id": pid}).status_code == 200
    assert reg.last()["code"] != first
    assert c.post("/setup/signup/verify", json={"pending_id": pid, "code": first}).status_code == 400   # old code is dead
    assert c.post("/setup/signup/verify", json={"pending_id": pid, "code": reg.last()["code"]}).status_code == 200
    assert c.post("/setup/signup/verify", json={"pending_id": "nope", "code": "1"}).status_code == 409


def test_offline_install_falls_back_to_the_setup_code(tmp_path, monkeypatch):
    reg = FakeRegistry(up=False)
    c, auth = _app(tmp_path, monkeypatch, reg)
    st = c.get("/setup/status").json()
    assert st["signup"] == "code"
    r = _signup(c)
    assert r.status_code == 503 and r.json()["detail"]["error"] == "registry_unavailable"
    code = setup_mod.new_code(auth.store)
    assert c.post("/setup", json={"code": code, "username": "admin", "password": PW, "password_confirm": PW}).status_code == 200
    h = _login(c, "admin")
    assert c.get("/engagements", headers=h).status_code == 200        # offline: nobody is held up
    assert c.get("/me", headers=h).json()["email_verification_required"] is False


def test_exposed_console_also_needs_the_setup_code(tmp_path, monkeypatch):
    reg = FakeRegistry()
    c, auth = _app(tmp_path, monkeypatch, reg)
    monkeypatch.setenv("CORVEX_SETUP_CODE_REQUIRED", "1")
    assert c.get("/setup/status").json()["setup_code_required"] is True
    r = _signup(c, setup_code="WRONGCODE")
    assert r.status_code == 403 and reg.sent == []
    code = setup_mod.new_code(auth.store)
    assert _signup(c, setup_code=code).status_code == 202


# ---------------------------------------------------------------- verification gate
def test_existing_user_must_verify_before_using_the_console(tmp_path, monkeypatch):
    reg = FakeRegistry()
    c, auth = _app(tmp_path, monkeypatch, reg, admin_password=PW)   # seeded admin, no email (upgrade, headless)
    c.get("/health")
    h = _login(c, "admin")
    assert c.get("/me", headers=h).json()["email_verification_required"] is True
    blocked = c.get("/engagements", headers=h)
    assert blocked.status_code == 403 and blocked.json()["detail"]["error"] == "email_verification_required"
    r = c.post("/auth/email/start", json={"email": "owner@example.org"}, headers=h)
    assert r.status_code == 202 and reg.last()["role"] == "owner"
    wrong = c.post("/auth/email/verify", json={"pending_id": r.json()["pending_id"], "code": "999999"}, headers=h)
    assert wrong.status_code == 400
    ok = c.post("/auth/email/verify", json={"pending_id": r.json()["pending_id"], "code": reg.last()["code"]}, headers=h)
    assert ok.status_code == 200 and ok.json()["email"] == "owner@example.org"
    assert c.get("/engagements", headers=h).status_code == 200


def test_gate_lifts_when_the_registry_is_unreachable(tmp_path, monkeypatch):
    reg = FakeRegistry()
    c, auth = _app(tmp_path, monkeypatch, reg, admin_password=PW)
    c.get("/health")
    h = _login(c, "admin")
    assert c.get("/engagements", headers=h).status_code == 403
    reg.up = False
    assert c.get("/engagements", headers=h).status_code == 200


def test_another_users_pending_code_cannot_be_used(tmp_path, monkeypatch):
    reg = FakeRegistry()
    c, auth = _app(tmp_path, monkeypatch, reg, admin_password=PW)
    c.get("/health")
    tenant = auth.store.get_user_profile(username="admin")["tenant_id"]
    auth.create_member(tenant, "rahim", PW, Role.MEMBER)
    ha, hr = _login(c, "admin"), _login(c, "rahim")
    pid = c.post("/auth/email/start", json={"email": "admin@example.org"}, headers=ha).json()["pending_id"]
    r = c.post("/auth/email/verify", json={"pending_id": pid, "code": reg.last()["code"]}, headers=hr)
    assert r.status_code == 410
    assert auth.store.get_user_profile(username="rahim")["email_verified_at"] is None


# ---------------------------------------------------------------- password reset
def test_password_reset_by_email(tmp_path, monkeypatch):
    reg = FakeRegistry()
    c, auth = _app(tmp_path, monkeypatch, reg)
    _register_owner(c, reg)
    old = _login(c)
    assert c.get("/auth/options").json()["password_reset"] is True
    r = c.post("/auth/password-reset/start", json={"username": "sajid"})
    assert r.status_code == 202 and reg.last()["purpose"] == "reset" and reg.last()["email"] == "Sajid@example.org"
    pid = r.json()["pending_id"]
    weak = c.post("/auth/password-reset/finish", json={"pending_id": pid, "code": reg.last()["code"],
                                                       "new_password": "short", "new_password_confirm": "short"})
    assert weak.status_code == 422                           # checked before the code is used up
    ok = c.post("/auth/password-reset/finish", json={"pending_id": pid, "code": reg.last()["code"],
                                                     "new_password": NEW_PW, "new_password_confirm": NEW_PW})
    assert ok.status_code == 200
    assert c.get("/me", headers=old).status_code == 401      # sessions from before the reset end
    assert c.post("/auth/login", json={"username": "sajid", "password": PW}).status_code == 401
    _login(c, pw=NEW_PW)


def test_password_reset_reply_is_the_same_for_unknown_users(tmp_path, monkeypatch):
    reg = FakeRegistry()
    c, auth = _app(tmp_path, monkeypatch, reg)
    _register_owner(c, reg)
    n = len(reg.sent)
    known = c.post("/auth/password-reset/start", json={"username": "sajid"}).json()
    unknown = c.post("/auth/password-reset/start", json={"username": "nobody"}).json()
    assert set(known) == set(unknown) == {"pending_id", "message"} and known["message"] == unknown["message"]
    assert len(reg.sent) == n + 1                            # only the real account got an email
    r = c.post("/auth/password-reset/finish", json={"pending_id": unknown["pending_id"], "code": "123456",
                                                    "new_password": NEW_PW, "new_password_confirm": NEW_PW})
    assert r.status_code == 400 and r.json()["detail"]["error"] == "wrong_code"


def test_password_reset_needs_the_registry(tmp_path, monkeypatch):
    reg = FakeRegistry()
    c, _ = _app(tmp_path, monkeypatch, reg)
    _register_owner(c, reg)
    reg.up = False
    assert c.get("/auth/options").json()["password_reset"] is False
    r = c.post("/auth/password-reset/start", json={"username": "sajid"})
    assert r.status_code == 503 and "reset-password" in r.json()["detail"]["message"]


# ---------------------------------------------------------------- invites (service level)
def test_invite_member_sets_password_from_code(tmp_path, monkeypatch):
    reg = FakeRegistry()
    c, auth = _app(tmp_path, monkeypatch, reg)
    _register_owner(c, reg)
    owner = auth.store.get_user_profile(username="sajid")
    out = auth.invite_member(owner["tenant_id"], owner["user_id"], "rahim", "rahim@example.org", Role.MEMBER)
    assert out["username"] == "rahim" and reg.last()["inviter"] == "sajid" and reg.last()["role"] == "member"
    assert c.post("/auth/login", json={"username": "rahim", "password": PW}).status_code == 401
    bad = c.post("/auth/invite/accept", json={"username": "rahim", "code": "000000", "password": PW, "password_confirm": PW})
    assert bad.status_code == 400
    ok = c.post("/auth/invite/accept", json={"username": "rahim", "code": reg.last()["code"],
                                             "password": PW, "password_confirm": PW})
    assert ok.status_code == 200
    h = _login(c, "rahim")
    me = c.get("/me", headers=h).json()
    assert me["role"] == "member" and me["email_verified"] is True and me["email_verification_required"] is False


def test_failed_invite_email_leaves_no_user(tmp_path, monkeypatch):
    reg = FakeRegistry()
    c, auth = _app(tmp_path, monkeypatch, reg)
    _register_owner(c, reg)
    owner = auth.store.get_user_profile(username="sajid")
    reg.up = False
    with pytest.raises(RegistryUnavailable):
        auth.invite_member(owner["tenant_id"], owner["user_id"], "karim", "karim@example.org", Role.VIEWER)
    assert auth.store.get_user_profile(username="karim") is None


# ---------------------------------------------------------------- helpers and client
def test_helpers():
    assert normalize_email("  Me@EXAMPLE.Org ") == "Me@example.org"
    with pytest.raises(ValueError):
        normalize_email("me@")
    assert registry_name("ölaf smith") == "_laf_smith" and registry_name("") == "user"


class _Resp(io.BytesIO):
    def __enter__(self):
        return self

    def __exit__(self, *a):
        return False


def _opener(routes, calls):
    def op(req, timeout=None):
        calls.append((req.get_method(), req.full_url, req.get_header("Authorization"), req.data))
        status, body = routes[(req.get_method(), req.full_url.split("/registry")[1])]
        if status >= 400:
            raise urllib.error.HTTPError(req.full_url, status, "x", {"Retry-After": "7"}, io.BytesIO(json.dumps(body).encode()))
        return _Resp(json.dumps(body).encode())
    return op


def test_client_registers_the_install_once_and_maps_errors(tmp_path):
    store = SqliteAuthStore(str(tmp_path / "a.db"))
    calls = []
    routes = {("GET", "/v1/health"): (200, {"ok": True}),
              ("POST", "/v1/installs"): (201, {"install_id": "i1", "token": "t1"}),
              ("POST", "/v1/verifications"): (201, {"verification_id": "v1", "expires_in": 900, "sent_to": "a***@b.c"}),
              ("POST", "/v1/verifications/v1/check"): (400, {"detail": {"error": "wrong_code", "message": "no", "remaining": 3}})}
    cl = RegistryClient(store, url="https://r.example/registry", enabled=True, opener=_opener(routes, calls))
    assert cl.available() is True
    assert cl.send_code("register", "admin", "a@b.c")["verification_id"] == "v1"
    cl.send_code("register", "admin", "a@b.c")
    assert [c[1] for c in calls].count("https://r.example/registry/v1/installs") == 1
    body = json.loads(next(c[3] for c in calls if c[1].endswith("/v1/installs")))
    assert body["edition"] in ("community", "premium") and isinstance(body["version"], str)
    assert calls[-1][2] == "Bearer i1.t1"
    with pytest.raises(RegistryError) as e:
        cl.check_code("v1", "1")
    assert e.value.error == "wrong_code" and e.value.remaining == 3
    # nginx answering 502 (service down) is "unavailable", not a refusal
    routes[("POST", "/v1/verifications")] = (502, {})
    with pytest.raises(RegistryUnavailable):
        cl.send_code("register", "admin", "a@b.c")
    assert cl.available() is False                         # remembered as down


def test_client_reregisters_after_registry_reset(tmp_path):
    store = SqliteAuthStore(str(tmp_path / "a.db"))
    store.set_registry_state("https://r.example/registry", "old", "stale")
    calls = []
    state = {"n": 0}

    def op(req, timeout=None):
        calls.append(req.full_url)
        path = req.full_url.split("/registry")[1]
        if path == "/v1/verifications" and req.get_header("Authorization") == "Bearer old.stale":
            raise urllib.error.HTTPError(req.full_url, 401, "x", {}, io.BytesIO(b'{"detail":{"error":"error","message":"unknown install token"}}'))
        if path == "/v1/installs":
            state["n"] += 1
            return _Resp(b'{"install_id":"new","token":"fresh"}')
        return _Resp(b'{"verification_id":"v9","expires_in":900}')
    cl = RegistryClient(store, url="https://r.example/registry", enabled=True, opener=op)
    assert cl.send_code("register", "admin", "a@b.c")["verification_id"] == "v9"
    assert state["n"] == 1 and store.get_registry_state("https://r.example/registry") == ("new", "fresh")


def test_registry_off_never_touches_the_network(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_REGISTRY", "off")

    def boom(*a, **k):
        raise AssertionError("network used")
    cl = RegistryClient(SqliteAuthStore(str(tmp_path / "a.db")), opener=boom)
    assert cl.available() is False
    with pytest.raises(RegistryUnavailable):
        cl.send_code("register", "a", "a@b.c")


def test_signed_in_requests_never_wait_on_an_unreachable_registry(tmp_path):
    """A network that drops outbound traffic makes every registry call hang until its timeout.
    The check on each signed-in request must answer at once and refresh in the background."""
    import threading
    import time as _time
    release = threading.Event()
    calls = []

    def hanging(req, timeout=None):
        calls.append(req.full_url)
        release.wait(2)                       # a blackholed connection
        raise urllib.error.URLError("timed out")
    cl = RegistryClient(SqliteAuthStore(str(tmp_path / "a.db")), url="https://r.example/registry",
                        enabled=True, opener=hanging)
    t0 = _time.monotonic()
    assert cl.available(wait=False) is False          # no answer yet: don't gate anyone
    assert cl.available(wait=False) is False          # still refreshing: no second probe
    assert _time.monotonic() - t0 < 0.2
    release.set()
    for _ in range(50):
        if not cl._refreshing:
            break
        _time.sleep(0.02)
    assert len(calls) == 1 and cl._state is not None and cl._state[0] is False


def test_registered_install_identifies_itself_on_health_checks(tmp_path):
    """Before registering, the health check carries nothing; afterwards it carries the
    install token, version and edition (how the monitor tells which installs are in use)."""
    store = SqliteAuthStore(str(tmp_path / "a.db"))
    calls = []
    routes = {("GET", "/v1/health"): (200, {"ok": True}),
              ("POST", "/v1/installs"): (201, {"install_id": "i1", "token": "t1"}),
              ("POST", "/v1/verifications"): (201, {"verification_id": "v1", "expires_in": 900})}

    def op(req, timeout=None):
        calls.append((req.full_url, req.get_header("Authorization"), req.get_header("X-corvex-version"),
                      req.get_header("X-corvex-edition")))
        return _opener(routes, [])(req, timeout)
    cl = RegistryClient(store, url="https://r.example/registry", enabled=True, opener=op)
    cl.available(refresh=True)
    assert calls[-1][1:] == (None, None, None)
    cl.send_code("register", "admin", "a@b.c")
    cl.available(refresh=True)
    url, auth_, ver, ed = calls[-1]
    assert url.endswith("/v1/health") and auth_ == "Bearer i1.t1" and ver and ed in ("community", "premium")

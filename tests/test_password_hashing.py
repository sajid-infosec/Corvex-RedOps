"""B4: PBKDF2-HMAC-SHA256 at 600,000 iterations; older hashes upgraded on the next successful
sign-in (the stored format records the count)."""
from fastapi.testclient import TestClient

from pentestiq.api.app import create_app
from pentestiq.auth.passwords import hash_password, needs_rehash, verify_password
from pentestiq.auth.service import AuthService
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore


def test_new_hashes_use_600k_iterations():
    h = hash_password("correct horse")
    assert h.startswith("pbkdf2_sha256$600000$")
    assert verify_password("correct horse", h) and not verify_password("wrong", h)
    assert not needs_rehash(h)


def test_needs_rehash():
    assert needs_rehash(hash_password("x", iterations=240_000))
    assert needs_rehash("bcrypt$whatever")
    assert needs_rehash("garbage")


def test_old_hash_is_upgraded_on_the_next_successful_sign_in(tmp_path, monkeypatch):
    monkeypatch.setenv("CORVEX_ADMIN_USER", "corvex")
    monkeypatch.setenv("CORVEX_ADMIN_PASSWORD", "right-pass-123")
    monkeypatch.setenv("CORVEX_ADMIN_FORCE_CHANGE", "0")
    db = str(tmp_path / "pentestiq.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    c = TestClient(create_app(store=SqliteEngagementStore(db), auth=auth, config=AppConfig(data_dir=str(tmp_path))))
    auth.store.set_password_hash("corvex", hash_password("right-pass-123", iterations=240_000))
    before = c.post("/auth/login", json={"username": "corvex", "password": "right-pass-123"}).json()["token"]
    stored = auth.store.get_user_auth("corvex")["password_hash"]
    assert stored.startswith("pbkdf2_sha256$600000$") and verify_password("right-pass-123", stored)
    # a wrong password never rewrites the hash
    auth.store.set_password_hash("corvex", hash_password("right-pass-123", iterations=240_000))
    assert c.post("/auth/login", json={"username": "corvex", "password": "nope-nope-1"}).status_code == 401
    assert auth.store.get_user_auth("corvex")["password_hash"].startswith("pbkdf2_sha256$240000$")
    # the upgrade is not a credential change: the session from before it still works
    assert c.get("/me", headers={"Authorization": "Bearer " + before}).status_code == 200

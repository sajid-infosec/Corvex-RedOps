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

"""G1 — encrypted credential vault + authenticated (credentialed) scanning."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pentestiq.vault import VaultCipher, VaultLocked, Credential, SqliteCredentialStore
from pentestiq.authscan import run_authenticated_scan, run_local_checks
from pentestiq.authscan.runner import AuthScanError
from pentestiq.intel import ServiceCVEMatcher
from pentestiq.intel import ThreatIntel
from pentestiq.models import Asset, AssetType, Engagement, Scope, Severity
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


# ---- crypto -------------------------------------------------------------
def test_cipher_roundtrip():
    c = VaultCipher(passphrase="hunter2")
    tok = c.encrypt("s3cr3t-password")
    assert tok != "s3cr3t-password"
    c2 = VaultCipher.from_salt_b64("hunter2", c.salt_b64)
    assert c2.decrypt(tok) == "s3cr3t-password"

def test_cipher_wrong_passphrase():
    c = VaultCipher(passphrase="right")
    tok = c.encrypt("x")
    wrong = VaultCipher.from_salt_b64("wrong", c.salt_b64)
    with pytest.raises(VaultLocked):
        wrong.decrypt(tok)


# ---- store: encrypted at rest, redaction --------------------------------
def test_store_encrypts_and_redacts(tmp_path):
    s = SqliteCredentialStore(str(tmp_path / "v.db"), passphrase="k")
    cred = Credential(name="prod-ssh", kind="ssh_password", username="root",
                      target="10.0.0.5", secret="toor")
    s.add("t1", cred)
    # list/get never carry the secret
    got = s.list("t1")[0]
    assert got.secret is None and got.public()["has_secret"] is True
    assert "secret" not in got.public()
    # reveal decrypts for in-process use
    rv = s.reveal("t1", cred.id)
    assert rv.secret == "toor"
    # ciphertext on disk is not the plaintext
    import sqlite3
    raw = sqlite3.connect(str(tmp_path / "v.db")).execute(
        "SELECT secret_enc FROM vault_credential").fetchone()[0]
    assert "toor" not in raw

def test_store_persists_salt(tmp_path):
    db = str(tmp_path / "v.db")
    s = SqliteCredentialStore(db, passphrase="k")
    s.add("t1", Credential(name="c", secret="pw"))
    cid = s.list("t1")[0].id
    # reopen with same passphrase → still decryptable (salt persisted)
    s2 = SqliteCredentialStore(db, passphrase="k")
    assert s2.reveal("t1", cid).secret == "pw"

def test_store_tenant_isolation(tmp_path):
    s = SqliteCredentialStore(str(tmp_path / "v.db"), passphrase="k")
    s.add("t1", Credential(name="a", secret="pw"))
    assert s.list("t2") == []


# ---- local checks: find a local-only issue ------------------------------
def _asset():
    return Asset(type=AssetType.INFRA, identifier="10.0.0.5")

def test_check_sudo_nopasswd():
    def run(cmd):
        if "sudo -n -l" in cmd:
            return "User www-data may run the following commands:\n    (ALL) NOPASSWD: /usr/bin/vim"
        return ""
    fs = run_local_checks(run, _asset())
    assert any("NOPASSWD" in f.title for f in fs)
    assert any(f.severity == Severity.HIGH for f in fs)

def test_check_world_writable_and_shadow():
    def run(cmd):
        if cmd.startswith("ls -l /etc/passwd"):
            return ("-rw-rw-rw- 1 root root 2400 /etc/passwd\n"
                    "-rw-r--r-- 1 root shadow 1200 /etc/shadow")
        return ""
    fs = run_local_checks(run, _asset())
    titles = " ".join(f.title for f in fs)
    assert "World-writable" in titles and any(f.severity == Severity.CRITICAL for f in fs)

def test_check_dangerous_suid():
    def run(cmd):
        if "-perm -4000" in cmd:
            return "/usr/bin/find\n/usr/bin/passwd\n/usr/bin/vim"
        return ""
    fs = run_local_checks(run, _asset())
    assert any("SUID" in f.title for f in fs)

def test_check_service_versions_uses_g2_matcher():
    m = ServiceCVEMatcher(intel=ThreatIntel(offline=True), offline=True)
    def run(cmd):
        if cmd.startswith("ssh -V"):
            return "OpenSSH_7.6p1 Ubuntu-4ubuntu0.3, OpenSSL 1.0.1f"
        return ""
    fs = run_local_checks(run, _asset(), matcher=m)
    assert any("openssh" in f.title.lower() and "CVE" in " ".join(f.references) for f in fs)


# ---- runner: authorization gate + injected runner -----------------------
def test_runner_requires_authorization():
    with pytest.raises(AuthScanError):
        run_authenticated_scan(_asset(), Credential(name="c", secret="pw"),
                               authorized=False, runner=lambda c: "")

def test_runner_injected_finds_issue():
    def run(cmd):
        return "(ALL) NOPASSWD: ALL" if "sudo -n -l" in cmd else ""
    r = run_authenticated_scan(_asset(), Credential(name="c", secret="pw"),
                               authorized=True, runner=run)
    assert r["connected"] and r["count"] >= 1

def test_runner_no_paramiko_graceful():
    # no runner injected, paramiko absent → graceful "not connected", no crash
    r = run_authenticated_scan(_asset(), Credential(name="c", kind="ssh_password",
                               username="root", secret="pw"), authorized=True)
    assert r["connected"] is False and r["count"] == 0


# ---- API ----------------------------------------------------------------
@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth,
                     config=AppConfig(data_dir=str(tmp_path), intel_offline=True))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq",
                                      "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}, store


def test_api_vault_crud_never_echoes_secret(ctx):
    c, H, _ = ctx
    r = c.post("/vault/credentials", headers=H, json={
        "name": "prod-ssh", "kind": "ssh_password", "username": "root",
        "target": "10.0.0.5", "secret": "toor"})
    assert r.status_code == 201
    body = r.json()
    assert "secret" not in body and body["has_secret"] is True
    cid = body["id"]
    lst = c.get("/vault/credentials", headers=H).json()
    assert lst["credentials"][0]["id"] == cid and "secret" not in lst["credentials"][0]
    assert c.delete(f"/vault/credentials/{cid}", headers=H).status_code == 204
    assert c.get("/vault/credentials", headers=H).json()["credentials"] == []

def test_api_vault_validation(ctx):
    c, H, _ = ctx
    assert c.post("/vault/credentials", headers=H,
                  json={"name": "x", "kind": "bogus", "secret": "y"}).status_code == 422
    assert c.post("/vault/credentials", headers=H,
                  json={"name": "x", "kind": "ssh_password"}).status_code == 422

def test_api_authscan_requires_authorization(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    a = Asset(type=AssetType.INFRA, identifier="10.0.0.5")
    rec = store.create(tid, Engagement(name="i", scope=Scope(name="s"), assets=[a]),
                       status="completed")
    cid = c.post("/vault/credentials", headers=H,
                 json={"name": "c", "secret": "pw", "username": "root"}).json()["id"]
    # missing authorized → 422
    assert c.post(f"/engagements/{rec.id}/authscan", headers=H,
                  json={"credential_id": cid}).status_code == 422
    # authorized but paramiko absent → 202 with a graceful not-connected result
    r = c.post(f"/engagements/{rec.id}/authscan", headers=H,
               json={"credential_id": cid, "authorized": True})
    assert r.status_code == 202
    assert r.json()["targets"][0]["connected"] is False

"""C3t — secret scanning: detectors, entropy/placeholder FP control, redaction, API."""
from __future__ import annotations

import os
import zipfile

import pytest
from fastapi.testclient import TestClient

from pentestiq.secrets import scan_secrets, scan_line, shannon_entropy, redact
from pentestiq.models import Severity, AssetType
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService

GHP = "ghp_abcdefghijklmnopqrstuvwxyz0123456789"     # 36 chars
AKIA = "AKIAIOSFODNN7EXAMPLE"
STRIPE = "sk_live_51H8xABCdefGHIjklMNOpqrstUVwx"
PRIVKEY = "-----BEGIN RSA PRIVATE KEY-----"


def _ids(line):
    return sorted(r.id for r, _ in scan_line(line))


# ---- detectors ----------------------------------------------------------
def test_provider_rules_fire():
    assert "aws-access-key-id" in _ids(f'AWS_KEY = "{AKIA}"')
    assert "github-pat" in _ids(f'token="{GHP}"')
    assert "stripe-live" in _ids(f'k = "{STRIPE}"')
    assert "private-key" in _ids(PRIVKEY)
    assert "basic-auth-url" in _ids('u = "postgres://admin:s3cr3tPass@db/app"')
    assert "gcp-api-key" in _ids('g="AIzaSyD1234567890abcdefghijklmnopqrstuv"')


def test_specific_rule_suppresses_generic_duplicate():
    # a Stripe key assigned to API_SECRET must report once, as the precise rule
    ids = _ids(f'API_SECRET = "{STRIPE}"')
    assert ids == ["stripe-live"]


def test_placeholders_and_env_refs_are_ignored():
    assert _ids('password = "changeme"') == []
    assert _ids('password = "${DB_PASSWORD}"') == []
    assert _ids('secret = "<your-secret-here>"') == []
    assert _ids('api_key = "aaaaaaaaaaaa"') == []          # low variety
    assert _ids('token = "os.environ[\'X\']"') == []


def test_generic_high_entropy_assignment_fires():
    assert "generic-secret-assignment" in _ids('db_password = "Xy7$Kq2!mZr9Bw4Lp0Tc"')


def test_entropy_and_redaction():
    assert shannon_entropy("aaaaaaaa") < 1.0
    assert shannon_entropy("Xy7$Kq2!mZr9Bw4L") > 3.0
    r = redact("sk_live_1234567890abcdef")
    assert r.startswith("sk_") and r.endswith("chars)") and "1234567890" not in r


# ---- scanner ------------------------------------------------------------
def test_scan_finds_and_redacts(tmp_path):
    (tmp_path / "config.py").write_text(f'API_SECRET = "{STRIPE}"\nAWS = "{AKIA}"\n')
    (tmp_path / ".env").write_text(f"GITHUB_TOKEN={GHP}\n")
    # a vendored dir must be skipped
    nm = tmp_path / "node_modules"; nm.mkdir()
    (nm / "junk.js").write_text(f'k="{AKIA}"')
    res = scan_secrets(str(tmp_path), subject="my-app")
    assert res.files_scanned == 2 and res.files_with_secrets == 2
    kinds = {f.title.split(" committed")[0] for f in res.findings}
    assert "Stripe live secret key" in kinds and "AWS access key ID" in kinds
    stripe = next(f for f in res.findings if "Stripe" in f.title)
    assert stripe.severity is Severity.CRITICAL and stripe.category == "A07:2021"
    assert stripe.asset.type is AssetType.CODEBASE and stripe.location == "config.py:1"
    assert "CWE-798" in stripe.references
    # the raw secret must never appear in the finding
    blob = " ".join([stripe.title, stripe.evidence[0].description, stripe.location])
    assert STRIPE not in blob and stripe.evidence[0].description


def test_scan_planted_secret_in_archive(tmp_path):
    zp = tmp_path / "repo.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("src/settings.py", f'STRIPE_KEY = "{STRIPE}"')
        z.writestr("../evil.py", f'k="{AKIA}"')       # zip-slip attempt
    res = scan_secrets(str(zp), subject="repo.zip")
    titles = [f.title for f in res.findings]
    assert any("Stripe" in t for t in titles)          # planted secret found
    assert all("evil" not in (f.location or "") for f in res.findings)


# ---- API ----------------------------------------------------------------
@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTESTIQ_INTEL_OFFLINE", "1")
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}


def test_api_secret_scan_upload(ctx, tmp_path):
    c, H = ctx
    zp = tmp_path / "src.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("app/config.py", f'API_SECRET = "{STRIPE}"\nAWS = "{AKIA}"')
    with open(zp, "rb") as fh:
        r = c.post("/engagements/upload", headers=H,
                   data={"asset_type": "secrets", "name": "my-service"},
                   files={"file": ("src.zip", fh, "application/zip")})
    assert r.status_code == 201
    eid = r.json()["id"]
    det = c.get(f"/engagements/{eid}", headers=H).json()
    a0 = det["engagement"]["assets"][0]
    assert a0["type"] == "codebase" and a0["metadata"]["tool"] == "pentestiq-secrets"
    fs = det["engagement"]["findings"]
    assert fs and all(f["category"] == "A07:2021" for f in fs)
    # secret redacted end-to-end through the API
    assert STRIPE not in det["engagement"]["findings"][0]["evidence"][0]["description"]
    assert any(x["identifier"] == "my-service" for x in c.get("/assets", headers=H).json())

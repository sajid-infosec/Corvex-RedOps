"""C2t — SAST via Semgrep: SARIF→findings, CODEBASE rehoming, archive safety, API."""
from __future__ import annotations

import json
import os
import tempfile
import zipfile
from pathlib import Path

import pytest
from fastapi.testclient import TestClient

import pentestiq.sast as sast_pkg
from pentestiq.sast import scan_source, SemgrepRunner, SastResult
from pentestiq.sast.semgrep_tool import materialize, _safe_join
from pentestiq.models import Severity, AssetType, Finding, Asset
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


SEMGREP_SARIF = {
    "$schema": "https://json.schemastore.org/sarif-2.1.0.json", "version": "2.1.0",
    "runs": [{
        "tool": {"driver": {"name": "Semgrep", "rules": [
            {"id": "python.lang.security.dangerous-subprocess-use",
             "name": "dangerous-subprocess-use",
             "shortDescription": {"text": "subprocess with shell=True"},
             "fullDescription": {"text": "OS command injection risk."},
             "defaultConfiguration": {"level": "error"},
             "properties": {"cwe": ["CWE-78: OS Command Injection"], "security-severity": "8.8"}},
            {"id": "python.flask.security.hardcoded-secret", "name": "hardcoded-secret",
             "defaultConfiguration": {"level": "warning"},
             "properties": {"cwe": ["CWE-798"], "security-severity": "5.5"}}]}},
        "results": [
            {"ruleId": "python.lang.security.dangerous-subprocess-use", "level": "error",
             "message": {"text": "shell=True"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/run.py"},
                                                 "region": {"startLine": 42}}}]},
            {"ruleId": "python.flask.security.hardcoded-secret", "level": "warning",
             "message": {"text": "hardcoded key"},
             "locations": [{"physicalLocation": {"artifactLocation": {"uri": "app/config.py"},
                                                 "region": {"startLine": 7}}}]}]}]}


def _fake_runner():
    return SemgrepRunner(run_fn=lambda target, config: SEMGREP_SARIF)


# ---- scan_source: mapping + rehoming ------------------------------------
def test_scan_source_maps_and_rehomes(tmp_path):
    (tmp_path / "x.py").write_text("x=1", encoding="utf-8")
    res = scan_source(str(tmp_path), subject="my-service", runner=_fake_runner())
    assert res.available and res.rules_run == 2 and len(res.findings) == 2
    assert res.files_flagged == 2
    cmd = next(f for f in res.findings if "subprocess" in f.title)
    assert cmd.severity is Severity.HIGH and cmd.category == "A03:2021"   # CWE-78
    assert cmd.asset.type is AssetType.CODEBASE and cmd.asset.identifier == "my-service"
    assert cmd.asset.metadata["file"] == "app/run.py" and cmd.location == "app/run.py:42"
    assert cmd.source_tools == ["semgrep"]
    secret = next(f for f in res.findings if "secret" in f.title)
    assert secret.category == "A07:2021"                                 # CWE-798


def test_scan_source_unavailable(tmp_path):
    res = scan_source(str(tmp_path), runner=SemgrepRunner(binary="nope-not-here"))
    assert res.available is False and res.error and res.findings == []


def test_scan_source_engine_error(tmp_path):
    def boom(target, config):
        raise RuntimeError("bad rules")
    res = scan_source(str(tmp_path), runner=SemgrepRunner(run_fn=boom))
    assert res.available is True and res.findings == [] and "semgrep failed" in res.error


# ---- archive safety -----------------------------------------------------
def test_archive_extraction_blocks_zip_slip(tmp_path):
    zp = tmp_path / "src.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("app/run.py", "import os")
        z.writestr("../evil.py", "pwned")          # traversal attempt
        z.writestr("app/config.py", "KEY=1")
    scan_dir, cleanup = materialize(str(zp))
    try:
        got = set()
        for root, _, files in os.walk(scan_dir):
            for f in files:
                got.add(Path(os.path.relpath(os.path.join(root, f), scan_dir)).as_posix())
        assert got == {"app/run.py", "app/config.py"}       # evil.py skipped
        parent = os.path.dirname(os.path.realpath(scan_dir))
        assert not os.path.exists(os.path.join(parent, "evil.py"))
    finally:
        cleanup()
    assert _safe_join("/base", "../x") is None


def test_scan_source_extracts_archive(tmp_path):
    zp = tmp_path / "repo.zip"
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("app/run.py", "import subprocess")
    res = scan_source(str(zp), subject="repo.zip", runner=_fake_runner())
    assert len(res.findings) == 2 and res.findings[0].asset.type is AssetType.CODEBASE


# ---- API ----------------------------------------------------------------
@pytest.fixture
def ctx(tmp_path, monkeypatch):
    monkeypatch.setenv("PENTESTIQ_INTEL_OFFLINE", "1")
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q-admin"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}


def _canned_result(subject):
    a = Asset(type=AssetType.CODEBASE, identifier=subject, metadata={"file": "app/run.py"})
    f = Finding(asset=a, title="dangerous-subprocess-use", category="A03:2021",
                severity=Severity.HIGH, location="app/run.py:42", source_tools=["semgrep"])
    return SastResult(subject=subject, findings=[f], sarif=SEMGREP_SARIF,
                      available=True, rules_run=2)


def test_api_sast_upload(ctx, monkeypatch):
    c, H = ctx
    monkeypatch.setattr(sast_pkg, "scan_source",
                        lambda path, subject=None, **kw: _canned_result(subject or "repo"))
    zp = tempfile.mktemp(suffix=".zip")
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("app/run.py", "import subprocess")
    with open(zp, "rb") as fh:
        r = c.post("/engagements/upload", headers=H,
                   data={"asset_type": "sast", "name": "my-service"},
                   files={"file": ("repo.zip", fh, "application/zip")})
    assert r.status_code == 201
    eid = r.json()["id"]
    det = c.get(f"/engagements/{eid}", headers=H).json()
    a0 = det["engagement"]["assets"][0]
    assert a0["type"] == "codebase" and a0["metadata"]["tool"] == "semgrep"
    fs = det["engagement"]["findings"]
    assert len(fs) == 1 and fs[0]["category"] == "A03:2021"
    assert any(x["identifier"] == "my-service" for x in c.get("/assets", headers=H).json())


def test_api_sast_semgrep_missing_returns_503(ctx, monkeypatch):
    c, H = ctx
    monkeypatch.setattr(sast_pkg, "scan_source",
                        lambda path, subject=None, **kw: SastResult(subject="x", available=False,
                                                                    error="Semgrep is not installed"))
    zp = tempfile.mktemp(suffix=".zip")
    with zipfile.ZipFile(zp, "w") as z:
        z.writestr("a.py", "x=1")
    with open(zp, "rb") as fh:
        r = c.post("/engagements/upload", headers=H, data={"asset_type": "sast"},
                   files={"file": ("repo.zip", fh, "application/zip")})
    assert r.status_code == 503


# ---- extraction through a symlinked / unresolved destination -----------------
def _symlink_dir(link, target):
    try:
        os.symlink(target, link, target_is_directory=True)
    except (OSError, NotImplementedError):
        pytest.skip("creating symlinks needs extra privileges on this platform")


def _zip(tmp_path, members):
    zp = tmp_path / "a.zip"
    with zipfile.ZipFile(zp, "w") as z:
        for name, body in members.items():
            z.writestr(name, body)
    return str(zp)


def test_extracts_into_a_destination_reached_through_a_symlink(tmp_path, monkeypatch):
    # macOS: mkdtemp() is under /var -> /private/var. The old check compared the resolved
    # member path with the unresolved base and rejected every member.
    from pentestiq.sast.semgrep_tool import _extract_zip
    (tmp_path / "real").mkdir()
    _symlink_dir(tmp_path / "link", tmp_path / "real")
    zp = _zip(tmp_path, {"app/run.py": "import os", "../evil.py": "pwned"})
    dest = tmp_path / "link" / "out"
    dest.mkdir()
    assert _extract_zip(zp, str(dest)) == 1
    assert (tmp_path / "real" / "out" / "app" / "run.py").read_text(encoding="utf-8") == "import os"
    assert not (tmp_path / "real" / "evil.py").exists() and not (tmp_path / "link" / "evil.py").exists()
    # and end-to-end, with the temp dir itself behind a symlink, as on macOS
    monkeypatch.setattr(tempfile, "tempdir", str(tmp_path / "link"))
    scan_dir, cleanup = materialize(zp)
    try:
        assert os.path.isfile(os.path.join(scan_dir, "app", "run.py"))
    finally:
        cleanup()


def test_symlink_inside_the_destination_cannot_escape(tmp_path):
    from pentestiq.sast.semgrep_tool import _extract_zip
    (tmp_path / "outside").mkdir()
    dest = tmp_path / "dest"
    dest.mkdir()
    _symlink_dir(dest / "out", tmp_path / "outside")
    zp = _zip(tmp_path, {"out/x.py": "escaped", "ok.py": "fine"})
    assert _extract_zip(zp, str(dest)) == 1
    assert not (tmp_path / "outside" / "x.py").exists()


def test_safe_join_compares_whole_path_components(tmp_path):
    from pentestiq.sast.semgrep_tool import _inside
    base = str(tmp_path / "b")
    assert _inside(base, str(tmp_path / "b" / "x"))
    assert not _inside(base, str(tmp_path / "bc" / "x"))          # sibling sharing a prefix
    assert _safe_join(os.path.realpath(base), "../b2/x") is None


def test_archive_with_files_but_nothing_extractable_is_an_error_not_an_empty_scan(tmp_path):
    import io
    import tarfile
    zp = _zip(tmp_path, {"../evil.py": "pwned", "../../x.py": "pwned"})
    with pytest.raises(ValueError, match="none of the archive's 2 file"):
        materialize(zp)
    tp = tmp_path / "a.tar"
    with tarfile.open(tp, "w") as t:
        info = tarfile.TarInfo("../evil.py"); data = b"pwned"; info.size = len(data)
        t.addfile(info, io.BytesIO(data))
    with pytest.raises(ValueError, match="none of the archive's 1 file"):
        materialize(str(tp))
    # an archive with no files at all is just empty, not an error
    (tmp_path / "e").mkdir()
    scan_dir, cleanup = materialize(_zip(tmp_path / "e", {}))
    assert os.listdir(scan_dir) == []
    cleanup()


def test_sast_scan_of_an_unextractable_archive_reports_an_error(tmp_path):
    zp = _zip(tmp_path, {"../evil.py": "pwned"})
    res = scan_source(zp, runner=SemgrepRunner(run_fn=lambda *_: {"runs": []}))
    assert res.error and "could be extracted safely" in res.error

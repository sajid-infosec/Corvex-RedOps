"""Deep Scan capture-proxy sub-slice: CA export, import-safety, store scan,
capture status, and the CLI/API surfaces. The live proxy backend (mitmproxy)
is optional, so tests that need it are skipped when it is absent."""
from __future__ import annotations

import json
import os
from pathlib import Path

import pytest
from fastapi.testclient import TestClient
from typer.testing import CliRunner

from corvex_deepscan import FlowStore, import_har, proxy_available
from corvex_deepscan.proxy import PROXY_INSTALL_HINT, ca, run_proxy
from pentestiq.api.app import create_app
from pentestiq.auth.service import AuthService
from pentestiq.cli import app as cli_app
from pentestiq.config import AppConfig
from pentestiq.deepscan import DEEPSCAN_TOOL, capture_status, scan_store
from pentestiq.storage import SqliteAuthStore, SqliteEngagementStore

HAR = str(Path(__file__).parent / "fixtures" / "deepscan_sample.har")


# --- import safety: importing the addon must open no files / bind no port ---

def test_addon_import_has_no_side_effects(tmp_path, monkeypatch):
    monkeypatch.chdir(tmp_path)
    import importlib

    import corvex_deepscan.proxy.addon as addon
    importlib.reload(addon)
    # the slice-1 regression we guard against: a FlowStore opened at import time
    assert not list(tmp_path.glob("*.db")), "importing addon must not create a store"
    assert addon.PROXY_INSTALL_HINT == PROXY_INSTALL_HINT


# --- CA helpers -------------------------------------------------------------

def test_export_ca_missing_raises(tmp_path):
    with pytest.raises(FileNotFoundError):
        ca.export_ca(str(tmp_path / "out.pem"), confdir=str(tmp_path / "empty"))


def test_export_ca_copies_pem(tmp_path):
    confdir = tmp_path / "conf"
    confdir.mkdir()
    (confdir / "mitmproxy-ca-cert.pem").write_text("---FAKE CA---")
    out = ca.export_ca(str(tmp_path / "exported.pem"), confdir=str(confdir))
    assert Path(out).read_text() == "---FAKE CA---"


# --- capture status ---------------------------------------------------------

def test_capture_status_shape(tmp_path):
    st = capture_status(confdir=str(tmp_path / "none"))
    assert st["available"] is proxy_available()
    assert st["default_port"] == 8083
    assert st["install_hint"] == PROXY_INSTALL_HINT
    assert st["ca_present"] is False and st["ca_path"] is None


def test_capture_status_finds_ca(tmp_path):
    confdir = tmp_path / "conf"
    confdir.mkdir()
    (confdir / "mitmproxy-ca-cert.pem").write_text("x")
    st = capture_status(confdir=str(confdir))
    assert st["ca_present"] is True and st["ca_path"].endswith(".pem")


@pytest.mark.skipif(proxy_available(), reason="proxy backend installed; degrade path not exercised")
def test_run_proxy_without_backend_raises():
    with pytest.raises(RuntimeError) as exc:
        run_proxy(store_path=":memory:", port=8083)
    assert "proxy" in str(exc.value).lower()


# --- scan a captured store --------------------------------------------------

def test_scan_store_over_captured_flows(tmp_path):
    db = str(tmp_path / "flows.db")
    store = FlowStore(db)
    try:
        assert import_har(HAR, store) == 4
    finally:
        store.close()
    findings, report = scan_store(db, engagement_id="E9")
    assert report["flow_count"] == 4
    assert report["flows_imported"] == 4
    assert all(f.source_tools == [DEEPSCAN_TOOL] for f in findings)
    assert findings


# --- CLI deepscan-scan ------------------------------------------------------

def test_cli_deepscan_scan_har(tmp_path):
    runner = CliRunner()
    out = tmp_path / "findings.json"
    res = runner.invoke(cli_app, ["deepscan-scan", HAR, "--out", str(out)])
    assert res.exit_code == 0, res.output
    assert "Deep Scan" in res.output and "Total findings" in res.output
    data = json.loads(out.read_text())
    assert isinstance(data, list) and data
    assert data[0]["source_tools"] == [DEEPSCAN_TOOL]


def test_cli_deepscan_scan_missing_source(tmp_path):
    runner = CliRunner()
    res = runner.invoke(cli_app, ["deepscan-scan", str(tmp_path / "nope.har")])
    assert res.exit_code == 1


def test_cli_export_ca_missing(tmp_path):
    runner = CliRunner()
    res = runner.invoke(cli_app, ["deepscan-export-ca", "--out", str(tmp_path / "ca.pem"),
                                  "--confdir", str(tmp_path / "empty")])
    assert res.exit_code == 1


# --- API capture status -----------------------------------------------------

@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login",
                 json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}


def test_api_capture_status(ctx):
    c, H = ctx
    r = c.get("/intel/deepscan/capture", headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["available"] is proxy_available()
    assert body["default_port"] == 8083
    assert body["install_hint"] == PROXY_INSTALL_HINT

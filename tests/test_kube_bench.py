"""E3 — kube-bench: CIS Kubernetes import, runner, detection, API."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from pentestiq.ingest import import_findings, detect_importer, get_importer, list_importers
from pentestiq.cloud import scan_cluster, KubeBenchRunner
from pentestiq.models import Severity, AssetType
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService

KB = {"Controls": [{"id": "1", "version": "1.23", "text": "Master Node", "node_type": "master",
    "tests": [{"section": "1.2", "desc": "API Server", "results": [
        {"test_number": "1.2.1", "test_desc": "Ensure the --anonymous-auth argument is set to false",
         "status": "FAIL", "scored": True, "remediation": "Set --anonymous-auth=false"},
        {"test_number": "1.2.16", "test_desc": "Ensure the --profiling argument is set to false",
         "status": "FAIL", "scored": False, "remediation": "Set --profiling=false"},
        {"test_number": "1.2.6", "test_desc": "Ensure --authorization-mode is not AlwaysAllow",
         "status": "WARN", "scored": False, "remediation": "Use RBAC"},
        {"test_number": "1.2.9", "test_desc": "Ensure admission plugins are set",
         "status": "PASS", "scored": True}]}],
    "total_pass": 1, "total_fail": 2, "total_warn": 1}],
    "Totals": {"total_fail": 2, "total_warn": 1, "total_pass": 1}}


def _blob():
    return json.dumps(KB).encode()


# ---- importer -----------------------------------------------------------
def test_kube_bench_importer_maps_failures():
    r = import_findings(_blob(), filename="kube-bench.json", prioritize=False)
    assert r.importer == "kube-bench" and r.imported_count == 3      # PASS skipped
    anon = next(f for f in r.findings if "anonymous-auth" in f.title)
    assert anon.severity is Severity.HIGH and anon.title.startswith("[FAIL]")
    assert anon.asset.type is AssetType.CLUSTER and anon.location == "CIS 1.2.1"
    assert anon.category == "A01:2021"                # access-control keyword
    assert any("1.2.1" in ref for ref in anon.references)
    prof = next(f for f in r.findings if "profiling" in f.title)
    assert prof.severity is Severity.MEDIUM           # FAIL but not scored
    warn = next(f for f in r.findings if f.title.startswith("[WARN]"))
    assert warn.severity is Severity.LOW


def test_detection_and_registry():
    assert detect_importer("out.json", _blob()) is get_importer("kube-bench")
    assert "kube-bench" in [i["name"] for i in list_importers()]


# ---- runner -------------------------------------------------------------
def test_runner_and_counts():
    res = scan_cluster(runner=KubeBenchRunner(run_fn=lambda: KB))
    assert res.available and len(res.findings) == 3
    assert res.fail_count == 2 and res.warn_count == 1


def test_runner_unavailable():
    res = scan_cluster(runner=KubeBenchRunner(binary="no-kube-bench-here"))
    assert res.available is False and res.error and res.findings == []


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


def test_api_kube_bench_run(ctx, monkeypatch):
    c, H = ctx
    import pentestiq.cloud as cloud_pkg
    monkeypatch.setattr(cloud_pkg, "scan_cluster",
                        lambda **kw: scan_cluster(runner=KubeBenchRunner(run_fn=lambda: KB), **kw))
    r = c.post("/engagements/kube-bench", headers=H, json={"name": "prod cluster"})
    assert r.status_code == 201
    eid = r.json()["id"]
    det = c.get(f"/engagements/{eid}", headers=H).json()
    fs = det["engagement"]["findings"]
    assert len(fs) == 3 and det["engagement"]["assets"][0]["type"] == "cluster"


def test_api_kube_bench_via_ingest(ctx):
    c, H = ctx
    # the uploaded kube-bench JSON auto-detects through the ingest importer
    r = c.post("/engagements/ingest", headers=H,
               files={"file": ("kube-bench.json", _blob(), "application/json")})
    assert r.status_code == 201
    assert r.json()["importer"] == "kube-bench" and r.json()["imported"] == 3

"""G3 — nuclei template freshness, coverage, tag scoping, API."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pentestiq.integrations.nuclei_templates import (
    template_coverage, templates_version, NucleiTemplateManager, find_templates_dir)
from pentestiq.integrations.nuclei_tool import NucleiIntegration
from pentestiq.config import AppConfig
from pentestiq.api.app import create_app
from pentestiq.storage import SqliteAuthStore
from pentestiq.auth.service import AuthService


TPL_A = """id: CVE-2021-44228
info:
  name: Apache Log4j RCE
  severity: critical
  tags: cve,cve2021,rce,log4j
"""
TPL_B = """id: git-config
info:
  name: Git Config Exposure
  severity: medium
  tags: exposure,config,git
"""
TPL_C = """id: default-login
info:
  name: Default Login
  severity: high
  tags: default-login,login
"""


@pytest.fixture
def tpldir(tmp_path):
    d = tmp_path / "nuclei-templates"
    (d / "cves" / "2021").mkdir(parents=True)
    (d / "exposures" / "configs").mkdir(parents=True)
    (d / "default-logins").mkdir(parents=True)
    (d / ".git").mkdir()                       # must be skipped
    (d / "cves" / "2021" / "CVE-2021-44228.yaml").write_text(TPL_A)
    (d / "exposures" / "configs" / "git-config.yaml").write_text(TPL_B)
    (d / "default-logins" / "default-login.yml").write_text(TPL_C)
    (d / ".git" / "junk.yaml").write_text("id: nope\ninfo:\n  severity: info\n")
    (d / ".templates-version").write_text("nuclei-templates v10.2.3\n")
    return d


# ---- coverage -----------------------------------------------------------
def test_coverage_counts(tpldir):
    cov = template_coverage(tpldir)
    assert cov["available"] and cov["total"] == 3          # .git skipped
    assert cov["packs"]["cves"]["count"] == 1
    assert cov["packs"]["cves"]["label"] == "CVEs"
    assert set(cov["packs"]) == {"cves", "exposures", "default-logins"}


def test_coverage_severities_and_tags(tpldir):
    cov = template_coverage(tpldir)
    assert cov["severities"]["critical"] == 1
    assert cov["severities"]["high"] == 1
    assert cov["severities"]["medium"] == 1
    tags = {t["tag"] for t in cov["top_tags"]}
    assert "rce" in tags and "log4j" in tags and "exposure" in tags
    assert cov["version"] == "10.2.3"


def test_coverage_shallow_skips_bodies(tpldir):
    cov = template_coverage(tpldir, deep=False)
    assert cov["total"] == 3 and cov["severities"] == {} and cov["top_tags"] == []


def test_coverage_missing_dir(tmp_path):
    cov = template_coverage(tmp_path / "nope")
    assert cov["available"] is False and cov["total"] == 0


def test_templates_version(tpldir):
    assert templates_version(tpldir) == "10.2.3"
    assert templates_version(None) is None


# ---- manager update (injected runner, no binary/network) ---------------
def test_manager_update_injected(tpldir):
    calls = {}
    def runner(cmd):
        calls["cmd"] = cmd
        return 0, "[INF] Successfully updated nuclei-templates (v10.2.3).\n"
    mgr = NucleiTemplateManager(templates_dir=str(tpldir), run_fn=runner)
    res = mgr.update()
    assert res["ok"] and res["version"] == "10.2.3"
    assert "-update-templates" in calls["cmd"]


def test_manager_update_missing_binary(tpldir, monkeypatch):
    # no run_fn injected and binary absent → graceful, not a crash
    monkeypatch.setattr("pentestiq.integrations.nuclei_templates.shutil.which",
                        lambda b: None)
    mgr = NucleiTemplateManager(templates_dir=str(tpldir))
    res = mgr.update()
    assert res["ok"] is False and res["available"] is False


def test_manager_coverage(tpldir):
    cov = NucleiTemplateManager(templates_dir=str(tpldir),
                                run_fn=lambda c: (0, "")).coverage()
    assert cov["total"] == 3 and "binary_available" in cov


# ---- tag / severity scoping into nuclei flags --------------------------
class _Ctx:
    def __init__(self, cfg):
        self.config = cfg

def test_template_scope_flags():
    cfg = AppConfig(nuclei_tags="cve,rce", nuclei_severity="critical,high")
    args = NucleiIntegration._template_scope(_Ctx(cfg))
    assert args == ["-tags", "cve,rce", "-severity", "critical,high"]

def test_template_scope_empty():
    assert NucleiIntegration._template_scope(_Ctx(AppConfig())) == []
    assert NucleiIntegration._template_scope(None) == []


# ---- API ----------------------------------------------------------------
@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(auth=auth, config=AppConfig(data_dir=str(tmp_path),
                                                 nuclei_tags="cve"))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq",
                                      "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}


def test_api_coverage(ctx, monkeypatch, tpldir):
    c, H = ctx
    monkeypatch.setattr("pentestiq.integrations.nuclei_templates.find_templates_dir",
                        lambda explicit=None: tpldir)
    r = c.get("/tools/nuclei/coverage", headers=H)
    assert r.status_code == 200
    body = r.json()
    assert body["total"] == 3 and body["scoped_tags"] == "cve"


def test_api_update(ctx, monkeypatch, tpldir):
    c, H = ctx
    monkeypatch.setattr(NucleiTemplateManager, "update",
                        lambda self: {"ok": True, "available": True, "version": "10.2.3"})
    monkeypatch.setattr(NucleiTemplateManager, "coverage",
                        lambda self, deep=True: {"total": 3})
    r = c.post("/tools/nuclei/update", headers=H)
    assert r.status_code == 200 and r.json()["version"] == "10.2.3"
    assert r.json()["coverage"]["total"] == 3

"""F1 — retest / diff workflow: lifecycle tagging, MTTR, and the retest API."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest
from fastapi.testclient import TestClient

from pentestiq.workflow.retest import merge_retest, mttr_stats, lifecycle_counts
from pentestiq.models import (Finding, Asset, AssetType, Severity, FindingStatus,
                              Engagement, Scope)
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


def _f(title, cat, sev, loc=None, first_seen=None, ident="https://app.example.com"):
    f = Finding(asset=Asset(type=AssetType.WEB, identifier=ident), title=title,
                category=cat, severity=sev, location=loc)
    if first_seen:
        f.first_seen = first_seen
    return f


# ---- merge_retest -------------------------------------------------------
def test_merge_tags_new_persisting_fixed():
    old = datetime.now(timezone.utc) - timedelta(days=7)
    prev = [_f("SQLi", "A03:2021", Severity.CRITICAL, "/a", old),
            _f("XSS", "A03:2021", Severity.HIGH, "/b", old)]
    curr = [_f("SQLi", "A03:2021", Severity.CRITICAL, "/a"),      # persisting
            _f("SSRF", "A10:2021", Severity.HIGH, "/d")]          # new
    merged, counts = merge_retest(prev, curr)
    assert counts == {"new": 1, "persisting": 1, "fixed": 1}
    by = {f.title: f for f in merged}
    assert by["SQLi"].lifecycle == "persisting" and by["SQLi"].first_seen == old
    assert by["SSRF"].lifecycle == "new"
    assert by["XSS"].lifecycle == "fixed"
    assert by["XSS"].status is FindingStatus.REMEDIATED and by["XSS"].remediated_at is not None


def test_false_positive_preserved_not_resurrected():
    fp = _f("noise", "A05:2021", Severity.INFO, "/x")
    fp.status = FindingStatus.FALSE_POSITIVE
    merged, counts = merge_retest([fp], [])       # gone from the fresh scan
    assert counts["fixed"] == 0                    # FP never counts as fixed
    assert any(f.status is FindingStatus.FALSE_POSITIVE for f in merged)


def test_refixed_then_reappears_clears_remediation():
    old = datetime.now(timezone.utc) - timedelta(days=3)
    f = _f("SQLi", "A03:2021", Severity.HIGH, "/a", old)
    f.status = FindingStatus.REMEDIATED
    f.remediated_at = datetime.now(timezone.utc)
    # it shows up again in a fresh scan → back to detected
    merged, counts = merge_retest([f], [_f("SQLi", "A03:2021", Severity.HIGH, "/a")])
    assert counts["persisting"] == 1
    assert merged[0].status is FindingStatus.DETECTED and merged[0].remediated_at is None


def test_mttr_and_lifecycle_counts():
    old = datetime.now(timezone.utc) - timedelta(days=10)
    prev = [_f("A", "A03:2021", Severity.HIGH, "/a", old),
            _f("B", "A03:2021", Severity.HIGH, "/b", old)]
    merged, _ = merge_retest(prev, [])            # both fixed
    m = mttr_stats(merged)
    assert m["remediated"] == 2 and 9.5 <= m["mean_days"] <= 10.5
    assert lifecycle_counts(merged) == {"new": 0, "persisting": 0, "fixed": 2, "untracked": 0}


# ---- API (fake engine so no real scan) ----------------------------------
class FakeEngine:
    config = type("C", (), {"scan_timeout_s": 30})()

    def __init__(self, fresh):
        self._fresh = fresh

    def execute(self, engagement, control=None, persist=None):
        engagement.add_findings(self._fresh)      # what the "scan" finds this run
        return engagement


@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    return db, store, auth, tmp_path


def test_api_retest_updates_lifecycle(ctx):
    db, store, auth, tmp_path = ctx
    # the fresh scan keeps SQLi, drops XSS, adds SSRF
    fresh = [_f("SQLi", "A03:2021", Severity.CRITICAL, "/a"),
             _f("SSRF", "A10:2021", Severity.HIGH, "/d")]
    app = create_app(store=store, auth=auth, engine=FakeEngine(fresh),
                     config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    H = {"Authorization": "Bearer " + tok}
    tid = c.get("/me", headers=H).json()["tenant_id"]
    old = datetime.now(timezone.utc) - timedelta(days=5)
    eng = Engagement(name="web", scope=Scope(name="s", in_scope=["https://app.example.com"]),
                     assets=[Asset(type=AssetType.WEB, identifier="https://app.example.com")])
    eng.add_findings([_f("SQLi", "A03:2021", Severity.CRITICAL, "/a", old),
                      _f("XSS", "A03:2021", Severity.HIGH, "/b", old)])
    rec = store.create(tid, eng, status="completed")

    r = c.post(f"/engagements/{rec.id}/retest", headers=H)
    assert r.status_code == 202 and r.json()["retest"] is True
    # TestClient runs the background task after the response
    det = c.get(f"/engagements/{rec.id}", headers=H).json()
    lc = {f["title"]: f.get("lifecycle") for f in det["engagement"]["findings"]}
    assert lc["SQLi"] == "persisting" and lc["SSRF"] == "new" and lc["XSS"] == "fixed"
    summ = c.get(f"/engagements/{rec.id}/retest", headers=H).json()
    assert summ["lifecycle"]["fixed"] == 1 and summ["lifecycle"]["new"] == 1
    assert summ["mttr"]["remediated"] == 1 and summ["mttr"]["mean_days"] is not None


def test_api_retest_rejects_non_scannable(ctx):
    db, store, auth, tmp_path = ctx
    app = create_app(store=store, auth=auth, engine=FakeEngine([]),
                     config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    H = {"Authorization": "Bearer " + tok}
    tid = c.get("/me", headers=H).json()["tenant_id"]
    eng = Engagement(name="sca", scope=Scope(name="s"),
                     assets=[Asset(type=AssetType.CODEBASE, identifier="app")])
    rec = store.create(tid, eng, status="completed")
    assert c.post(f"/engagements/{rec.id}/retest", headers=H).status_code == 422

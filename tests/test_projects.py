"""F4 — remediation projects: store, progress, CRUD API, seed-from-engagement."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pentestiq.workflow.projects import SqliteProjectStore, project_progress, Project
from pentestiq.models import (Finding, Asset, AssetType, Severity, FindingStatus,
                              Engagement, Scope)
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


# ---- store + progress ---------------------------------------------------
def test_store_crud(tmp_path):
    s = SqliteProjectStore(str(tmp_path / "p.db"))
    p = s.create("t1", "Sprint", owner="team", due_date="2026-10-01",
                 items=[{"engagement_id": "e1", "finding_id": "f1"}])
    assert p.name == "Sprint" and len(p.items) == 1
    assert s.get("t1", p.id).owner == "team"
    assert s.get("t2", p.id) is None                     # tenant-scoped
    s.update("t1", p.id, add_items=[{"engagement_id": "e1", "finding_id": "f2"},
                                    {"engagement_id": "e1", "finding_id": "f1"}])  # dupe ignored
    assert len(s.get("t1", p.id).items) == 2
    s.update("t1", p.id, remove_items=[{"engagement_id": "e1", "finding_id": "f1"}])
    assert len(s.get("t1", p.id).items) == 1
    assert s.delete("t1", p.id) and s.get("t1", p.id) is None


def test_progress_computation():
    p = Project(id="p", tenant_id="t", name="x",
                items=[{"engagement_id": "e", "finding_id": "a"},
                       {"engagement_id": "e", "finding_id": "b"},
                       {"engagement_id": "e", "finding_id": "gone"}])
    db = {"a": {"status": "remediated"}, "b": {"status": "detected"}}
    prog = project_progress(p, lambda eid, fid: db.get(fid))
    assert prog["total"] == 3 and prog["done"] == 1 and prog["missing"] == 1
    assert prog["percent"] == 50 and prog["complete"] is False   # 1 of 2 resolvable
    db["b"] = {"status": "false_positive"}
    prog2 = project_progress(p, lambda eid, fid: db.get(fid))
    assert prog2["complete"] is True and prog2["percent"] == 100


# ---- API ----------------------------------------------------------------
@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}, store


def _f(title, sev=Severity.HIGH, status=FindingStatus.DETECTED, loc=None):
    f = Finding(asset=Asset(type=AssetType.WEB, identifier="https://x"), title=title,
                category="A03:2021", severity=sev, location=loc or ("/" + title.replace(" ", "")))
    f.status = status
    return f


def test_api_project_lifecycle(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    f1, f2 = _f("SQLi"), _f("XSS")
    eng = Engagement(name="web", scope=Scope(name="s"))
    eng.add_findings([f1, f2])
    rec = store.create(tid, eng, status="completed")

    p = c.post("/projects", headers=H, json={"name": "Sprint", "owner": "team",
               "items": [{"engagement_id": rec.id, "finding_id": f1.id},
                         {"engagement_id": rec.id, "finding_id": f2.id}]}).json()
    assert p["progress"]["total"] == 2 and p["progress"]["done"] == 0 and p["status"] == "open"
    pid = p["id"]
    # detail resolves the findings
    det = c.get(f"/projects/{pid}", headers=H).json()
    assert len(det["finding_items"]) == 2 and det["finding_items"][0]["title"]

    # remediate both findings → project auto-closes
    f1.status = FindingStatus.REMEDIATED
    f2.status = FindingStatus.FALSE_POSITIVE
    store.update(tid, rec.id, engagement=eng)
    got = c.get(f"/projects/{pid}", headers=H).json()
    assert got["progress"]["complete"] is True and got["status"] == "closed"

    assert c.get("/projects", headers=H).json()[0]["id"] == pid
    assert c.delete(f"/projects/{pid}", headers=H).status_code == 204
    assert c.get(f"/projects/{pid}", headers=H).status_code == 404


def test_api_project_from_engagement(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    f1, f2 = _f("open one"), _f("already fixed", status=FindingStatus.REMEDIATED)
    eng = Engagement(name="web", scope=Scope(name="s"))
    eng.add_findings([f1, f2])
    rec = store.create(tid, eng, status="completed")
    p = c.post(f"/engagements/{rec.id}/project", headers=H, json={"owner": "sec"}).json()
    # only the open finding is seeded (remediated one excluded)
    assert p["progress"]["total"] == 1 and p["owner"] == "sec"


def test_api_validation(ctx):
    c, H, store = ctx
    assert c.post("/projects", headers=H, json={}).status_code == 422
    assert c.get("/projects/nope", headers=H).status_code == 404

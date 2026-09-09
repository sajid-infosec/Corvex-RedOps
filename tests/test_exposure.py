"""Per-asset exposure scoring + exposure-aware /assets API."""
from __future__ import annotations

import pytest
from fastapi.testclient import TestClient

from pentestiq.inventory import (exposure_score, exposure_band, rollup_findings,
                                 SqliteInventoryStore)
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService
from pentestiq.models import Engagement, Scope, Asset, Finding, AssetType, Severity


# ---- pure scoring -------------------------------------------------------
def test_exposure_score_formula():
    # KEV floors high regardless of the rest
    assert exposure_score("unknown", False, 10, has_kev=True) >= 90
    # internet-facing raises exposure
    assert exposure_score("high", True, 50) > exposure_score("high", False, 50)
    # worst finding PRP drives it
    assert exposure_score("low", False, 95) >= 80
    assert exposure_band(exposure_score("unknown", True, 100, True)) == "critical"
    assert exposure_band(10) == "low"


def test_rollup_counts_and_kev():
    a = Asset(type=AssetType.WEB, identifier="https://x")
    from pentestiq.intel import ThreatIntel
    ti = ThreatIntel(offline=True)
    fs = [Finding(asset=a, title="Log4Shell CVE-2021-44228", severity=Severity.HIGH,
                  references=["CVE-2021-44228"]),
          Finding(asset=a, title="header", severity=Severity.LOW)]
    r = rollup_findings(fs, ti)
    assert r["open"] == 2 and r["counts"]["high"] == 1 and r["has_kev"] is True
    assert r["worst_prp"] >= 88


# ---- API (aligned db so inventory + engagements share one store) --------
@pytest.fixture
def app_ctx(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    client = TestClient(app)
    tok = client.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return client, {"Authorization": "Bearer " + tok}, store, SqliteInventoryStore(db)


def _seed(store, inv, tid):
    a1 = Asset(type=AssetType.WEB, identifier="https://vpn.example.com")
    e1 = Engagement(name="ext", scope=Scope(name="s", in_scope=["https://vpn.example.com"]), assets=[a1])
    e1.add_findings([Finding(asset=a1, title="Log4Shell CVE-2021-44228", category="A06:2021",
                             severity=Severity.HIGH, references=["CVE-2021-44228"], risk_score=86)])
    r1 = store.create(tid, e1, status="completed")
    inv.upsert(tid, "https://vpn.example.com", asset_type="web", source="easm",
               tags=["external"], engagement_id=r1.id)
    a2 = Asset(type=AssetType.INFRA, identifier="10.0.0.5")
    e2 = Engagement(name="int", scope=Scope(name="s", in_scope=["10.0.0.5"]), assets=[a2])
    e2.add_findings([Finding(asset=a2, title="Missing header", category="A05:2021",
                             severity=Severity.LOW, risk_score=20)])
    r2 = store.create(tid, e2, status="completed")
    inv.upsert(tid, "10.0.0.5", source="engagement", engagement_id=r2.id)


def test_assets_ranked_by_exposure(app_ctx):
    client, H, store, inv = app_ctx
    tid = client.get("/me", headers=H).json()["tenant_id"]
    _seed(store, inv, tid)
    assets = client.get("/assets", headers=H).json()
    # KEV / internet-facing asset ranks first at critical exposure
    assert assets[0]["identifier"] == "vpn.example.com"
    assert assets[0]["exposure"] >= 90 and assets[0]["exposure_band"] == "critical"
    assert assets[0]["kev"] is True and assets[0]["internet_facing"] is True
    assert assets[0]["findings"]["high"] == 1
    assert assets[-1]["exposure"] < assets[0]["exposure"]


def test_assets_stats_and_detail(app_ctx):
    client, H, store, inv = app_ctx
    tid = client.get("/me", headers=H).json()["tenant_id"]
    _seed(store, inv, tid)
    s = client.get("/assets/stats", headers=H).json()
    assert s["total"] == 2 and s["external"] == 1 and s["kev_assets"] == 1
    assert s["max_exposure"] >= 90 and 0 < s["avg_exposure"] <= 100
    top = client.get("/assets", headers=H).json()[0]
    det = client.get("/assets/" + top["id"], headers=H).json()
    assert det["exposure"] >= 90
    assert any("Log4Shell" in it["title"] for it in det["finding_items"])

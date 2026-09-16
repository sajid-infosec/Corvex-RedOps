"""H — CTEM: posture snapshots, trend series, exposure alerts, API."""
from __future__ import annotations

from datetime import datetime, timezone, timedelta

import pytest
from fastapi.testclient import TestClient

from pentestiq.analytics import (compute_posture, trend_series, SqlitePostureStore,
                                 AlertConfig, SqliteAlertStore,
                                 evaluate_exposure_alerts, build_alert_payload)
from pentestiq.analytics.alerts import send_alert
from pentestiq.models import (Finding, Asset, AssetType, Severity, Engagement, Scope)
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


class _Rec:
    def __init__(self, eng, status="completed"):
        self.engagement = eng
        self.status = status


def _eng(findings):
    e = Engagement(name="e", scope=Scope(name="s"),
                   assets=[Asset(type=AssetType.WEB, identifier="app.example.com")])
    e.add_findings(findings)
    return e


def _f(title, sev, ident="app.example.com", **kw):
    return Finding(asset=Asset(type=AssetType.WEB, identifier=ident),
                   title=title, severity=sev, **kw)


# ---- posture compute ----------------------------------------------------
def test_compute_posture_counts():
    eng = _eng([_f("SQLi", Severity.CRITICAL, location="/a"),
                _f("XSS", Severity.HIGH, location="/b"),
                _f("Info", Severity.INFO, location="/c")])
    snap = compute_posture([_Rec(eng)])
    assert snap["total_findings"] == 3 and snap["open"] == 3
    assert snap["severities"]["critical"] == 1
    assert snap["open_by_severity"]["high"] == 1
    assert len(snap["open_keys"]) == 3


def test_compute_posture_fixed_excluded_from_open():
    f_fixed = _f("Old bug", Severity.HIGH, location="/x")
    f_fixed.remediated_at = datetime.now(timezone.utc)
    eng = _eng([f_fixed, _f("Live", Severity.HIGH, location="/y")])
    snap = compute_posture([_Rec(eng)])
    assert snap["open"] == 1 and snap["fixed"] == 1


def test_compute_posture_skips_noncompleted():
    eng = _eng([_f("X", Severity.HIGH, location="/z")])
    assert compute_posture([_Rec(eng, status="running")])["total_findings"] == 0


def test_posture_exposure_passthrough():
    snap = compute_posture([], exposure={"max_exposure": 87, "kev_assets": 2,
                                         "internet_facing_kev": 1, "total_assets": 10})
    assert snap["exposure_score"] == 87 and snap["internet_facing_kev"] == 1


# ---- trend series (new/resolved deltas) --------------------------------
def test_trend_series_deltas():
    t0 = "2026-01-01T00:00:00+00:00"; t1 = "2026-01-02T00:00:00+00:00"
    snaps = [
        {"ts": t0, "open": 2, "fixed": 0, "open_keys": ["a", "b"],
         "open_by_severity": {"critical": 1, "high": 1}, "exposure_score": 50},
        {"ts": t1, "open": 2, "fixed": 1, "open_keys": ["b", "c"],
         "open_by_severity": {"critical": 0, "high": 2}, "exposure_score": 60},
    ]
    s = trend_series(snaps)
    assert s["count"] == 2
    p1 = s["points"][1]
    assert p1["new"] == 1 and p1["resolved"] == 1        # +c, -a
    assert s["latest"]["exposure_score"] == 60


def test_store_roundtrip(tmp_path):
    st = SqlitePostureStore(str(tmp_path / "p.db"))
    st.append("t1", {"ts": "2026-01-01T00:00:00+00:00", "open": 3, "open_keys": ["a"]})
    st.append("t1", {"ts": "2026-01-02T00:00:00+00:00", "open": 2, "open_keys": ["a"]})
    lst = st.list("t1")
    assert [s["open"] for s in lst] == [3, 2]            # oldest→newest
    assert st.latest("t1")["open"] == 2
    assert st.list("t2") == []


# ---- exposure alerts ----------------------------------------------------
def test_alert_new_kev_on_internet_facing():
    cfg = AlertConfig(enabled=True, webhook_url="https://h", min_severity="high",
                      only_internet_facing=True)
    findings = [_f("Log4Shell", Severity.CRITICAL, ident="ext.example.com"),
                _f("Internal medium", Severity.MEDIUM, ident="int.local")]
    events = evaluate_exposure_alerts(findings, cfg, prev_keys=set(),
                                      kev_of=lambda f: "Log4Shell" in f.title,
                                      internet_facing_idents={"ext.example.com"})
    assert len(events) == 1 and events[0]["kev"] and events[0]["internet_facing"]


def test_alert_suppresses_known_findings():
    cfg = AlertConfig(enabled=True, webhook_url="https://h", only_internet_facing=False)
    f = _f("SQLi", Severity.CRITICAL, location="/a")
    # already open last snapshot → not alerted
    assert evaluate_exposure_alerts([f], cfg, prev_keys={f.dedup_key}) == []


def test_alert_severity_floor():
    cfg = AlertConfig(enabled=True, webhook_url="https://h", min_severity="critical",
                      only_internet_facing=False)
    lows = [_f("Medium thing", Severity.MEDIUM, location="/m")]
    assert evaluate_exposure_alerts(lows, cfg, prev_keys=set()) == []


def test_alert_payload_and_send_injected():
    cfg = AlertConfig(style="slack", webhook_url="https://hooks.example")
    payload = build_alert_payload([{"title": "RCE", "severity": "critical",
                                    "kev": True, "asset": "x", "internet_facing": True}], cfg)
    assert payload["text"].startswith("🚨")
    posted = {}
    def poster(url, headers, body):
        posted.update(url=url, body=body); return 200, "ok"
    res = send_alert(cfg, payload, http_post=poster)
    assert res["ok"] and posted["url"] == "https://hooks.example"


def test_alert_config_masks_webhook():
    cfg = AlertConfig(webhook_url="https://hooks.slack.com/services/TAAA/BBBB/cccccccc")
    pub = cfg.public()
    assert pub["configured"] and pub["webhook_url"].endswith("…")


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


def test_api_snapshot_and_trends(ctx):
    c, H, store = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    store.create(tid, _eng([_f("SQLi", Severity.CRITICAL, location="/a"),
                            _f("XSS", Severity.HIGH, location="/b")]), status="completed")
    s1 = c.post("/analytics/snapshot", headers=H)
    assert s1.status_code == 201 and s1.json()["snapshot"]["open"] == 2
    # add a finding, snapshot again → trend shows a 'new'
    store.create(tid, _eng([_f("SSRF", Severity.HIGH, location="/c")]), status="completed")
    c.post("/analytics/snapshot", headers=H)
    tr = c.get("/analytics/trends", headers=H).json()
    assert tr["count"] == 2 and tr["points"][-1]["new"] >= 1


def test_api_alerts_config_masked(ctx):
    c, H, _ = ctx
    r = c.put("/settings/alerts", headers=H, json={"enabled": True,
              "webhook_url": "https://hooks.slack.com/services/T/B/cccccccc",
              "min_severity": "critical"})
    assert r.status_code == 200
    body = r.json()
    assert body["configured"] and body["webhook_url"].endswith("…")
    # blank webhook on update keeps the saved one
    r2 = c.put("/settings/alerts", headers=H, json={"enabled": False, "webhook_url": ""})
    assert r2.json()["configured"] is True


def test_api_alert_test_requires_webhook(ctx):
    c, H, _ = ctx
    assert c.post("/settings/alerts/test", headers=H).status_code == 422

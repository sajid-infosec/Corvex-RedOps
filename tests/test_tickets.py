"""F2 — ticketing: payload shaping per system, push, config store, API."""
from __future__ import annotations

import json

import pytest
from fastapi.testclient import TestClient

from pentestiq.workflow.tickets import (TicketConfig, build_ticket_request,
                                        push_ticket, SqliteTicketStore)
from pentestiq.models import (Finding, Asset, AssetType, Severity, Engagement, Scope)
from pentestiq.api.app import create_app
from pentestiq.config import AppConfig
from pentestiq.storage import SqliteEngagementStore, SqliteAuthStore
from pentestiq.auth.service import AuthService


def _f(title="SQL injection"):
    return Finding(asset=Asset(type=AssetType.WEB, identifier="https://app.example.com"),
                   title=title, category="A03:2021", severity=Severity.CRITICAL,
                   location="/search", references=["CWE-89"], remediation="Use params",
                   risk_score=95)


# ---- payload shaping ----------------------------------------------------
def test_jira_payload():
    cfg = TicketConfig(system="jira", endpoint="https://j/rest/api/2/issue",
                       auth_header="Basic abc", project_key="SEC", issue_type="Bug")
    req = build_ticket_request(_f(), cfg)
    assert req["headers"]["Authorization"] == "Basic abc"
    fields = req["body"]["fields"]
    assert fields["project"]["key"] == "SEC" and fields["issuetype"]["name"] == "Bug"
    assert fields["summary"].startswith("[CRITICAL] SQL injection")
    assert "pentestiq" in fields["labels"] and "critical" in fields["labels"]
    assert "Use params" in fields["description"]


def test_slack_and_webhook_payload():
    slack = build_ticket_request(_f(), TicketConfig(system="slack", endpoint="https://hooks"))
    assert slack["body"]["text"].startswith("*[CRITICAL] SQL injection*")
    assert "Authorization" not in slack["headers"]
    wh = build_ticket_request(_f(), TicketConfig(system="webhook", endpoint="https://h"))
    assert wh["body"]["severity"] == "critical" and wh["body"]["title"] == "SQL injection"


# ---- push with injected poster -----------------------------------------
def test_push_jira_parses_key():
    posted = {}
    def poster(url, headers, body):
        posted.update(url=url, headers=headers, body=body)
        return 201, json.dumps({"key": "SEC-42", "self": "https://j/rest/.../SEC-42"})
    cfg = TicketConfig(system="jira", endpoint="https://j/rest/api/2/issue",
                       auth_header="Basic x", project_key="SEC", base_url="https://j")
    res = push_ticket(_f(), cfg, http_post=poster)
    assert res["ok"] and res["key"] == "SEC-42" and res["url"] == "https://j/browse/SEC-42"
    assert posted["url"].endswith("/issue")


def test_push_config_errors():
    with pytest.raises(ValueError):
        push_ticket(_f(), TicketConfig(system="jira", endpoint=""))     # no endpoint
    with pytest.raises(ValueError):
        push_ticket(_f(), TicketConfig(system="jira", endpoint="https://x"))  # no project_key


def test_config_store_redacts_auth(tmp_path):
    s = SqliteTicketStore(str(tmp_path / "t.db"))
    s.set("t1", TicketConfig(system="slack", endpoint="https://hooks", auth_header="secret"))
    got = s.get("t1")
    assert got.system == "slack" and got.auth_header == "secret"
    assert "auth_header" not in got.public() and got.public()["has_auth"] is True


# ---- API ----------------------------------------------------------------
@pytest.fixture
def ctx(tmp_path):
    db = str(tmp_path / "pentestiq.db")
    store = SqliteEngagementStore(db)
    auth = AuthService(SqliteAuthStore(db), secret_key="s", session_ttl=3600)
    app = create_app(store=store, auth=auth, config=AppConfig(data_dir=str(tmp_path)))
    c = TestClient(app)
    tok = c.post("/auth/login", json={"username": "pentestiq", "password": "p3nt3st!q"}).json()["token"]
    return c, {"Authorization": "Bearer " + tok}, store, app


def test_api_config_and_push(ctx, monkeypatch):
    c, H, store, app = ctx
    tid = c.get("/me", headers=H).json()["tenant_id"]
    a = Asset(type=AssetType.WEB, identifier="https://app.example.com")
    eng = Engagement(name="web", scope=Scope(name="s"), assets=[a])
    f = _f()
    eng.add_findings([f])
    rec = store.create(tid, eng, status="completed")

    # not configured yet → 422
    assert c.post(f"/engagements/{rec.id}/findings/{f.id}/ticket", headers=H).status_code == 422
    # configure
    cfg = c.put("/settings/tickets", headers=H, json={"system": "jira",
                "endpoint": "https://j/rest/api/2/issue", "auth_header": "Basic x",
                "project_key": "SEC", "base_url": "https://j"}).json()
    assert cfg["configured"] and cfg["has_auth"] and "auth_header" not in cfg
    # patch the pusher so no network is used
    import pentestiq.workflow.tickets as tk
    monkeypatch.setattr(tk, "_urllib_post",
                        lambda url, headers, body: (201, json.dumps({"key": "SEC-7"})))
    r = c.post(f"/engagements/{rec.id}/findings/{f.id}/ticket", headers=H)
    assert r.status_code == 201 and r.json()["key"] == "SEC-7"
    # the ticket ref is stored on the finding
    det = c.get(f"/engagements/{rec.id}", headers=H).json()
    assert det["engagement"]["findings"][0]["ticket"]["key"] == "SEC-7"


def test_api_bad_system(ctx):
    c, H, store, app = ctx
    assert c.put("/settings/tickets", headers=H, json={"system": "trello"}).status_code == 422

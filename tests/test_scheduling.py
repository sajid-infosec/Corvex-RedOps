from pentestiq.scheduling.diff import diff_findings
from pentestiq.scheduling.service import ScheduleService
from pentestiq.scheduling.notify import build_payload
from pentestiq.storage import SqliteEngagementStore
from pentestiq.storage.schedule_store import SqliteScheduleStore
from pentestiq.models import (
    Asset, AssetType, Finding, Severity, FindingStatus, Engagement, Scope,
)


def _f(title, cat, sev=Severity.MEDIUM, status=FindingStatus.DETECTED):
    return Finding(asset=Asset(type=AssetType.WEB, identifier="http://x"),
                   title=title, category=cat, severity=sev, status=status)


def test_diff_new_fixed_persisting():
    A, B, C = _f("A", "c-a"), _f("B", "c-b"), _f("C", "c-c")
    d = diff_findings([A, B], [B, C])
    assert [f.title for f in d.new] == ["C"]
    assert [f.title for f in d.fixed] == ["A"]
    assert [f.title for f in d.persisting] == ["B"]
    assert d.counts == {"new": 1, "fixed": 1, "persisting": 1}


def test_diff_excludes_false_positives():
    A = _f("A", "c-a")
    fp = _f("B", "c-b", status=FindingStatus.FALSE_POSITIVE)
    d = diff_findings([], [A, fp])
    assert [f.title for f in d.new] == ["A"]     # false positive not counted


class ScriptedEngine:
    """Returns a preset finding-set on each execute() call."""
    def __init__(self, runs):
        self.runs = list(runs); self.i = 0
    def build_from_dict(self, raw):
        return Engagement(name="sched", scope=Scope())
    def execute(self, eng):
        fs = self.runs[min(self.i, len(self.runs) - 1)]; self.i += 1
        eng.add_findings(fs)
        return eng


class Capture:
    def __init__(self): self.sent = []
    def send(self, schedule, engagement, diff):
        self.sent.append((schedule.id, diff.counts)); return True


def test_service_runs_diffs_and_notifies(tmp_path):
    db = str(tmp_path / "s.db")
    eng_store = SqliteEngagementStore(db)
    sched_store = SqliteScheduleStore(db)
    cap = Capture()
    engine = ScriptedEngine([[_f("A", "c-a"), _f("B", "c-b")], [_f("B", "c-b"), _f("C", "c-c")]])
    svc = ScheduleService(eng_store, sched_store, engine, notifier=cap)

    sch = sched_store.create("t1", "nightly", {"engagement": {"name": "n"}, "scope": {"in_scope": []}}, 3600)

    # run 1 -> everything new
    _, d1 = svc.run_schedule(sched_store.get("t1", sch.id))
    assert d1.counts == {"new": 2, "fixed": 0, "persisting": 0}
    # run 2 -> C new, A fixed, B persists
    _, d2 = svc.run_schedule(sched_store.get("t1", sch.id))
    assert d2.counts == {"new": 1, "fixed": 1, "persisting": 1}
    assert len(cap.sent) == 2
    # two engagements stored under the schedule
    assert len(eng_store.list_by_schedule("t1", sch.id)) == 2


def test_tick_runs_due_and_advances(tmp_path):
    from datetime import datetime, timezone, timedelta
    db = str(tmp_path / "t.db")
    eng_store = SqliteEngagementStore(db); sched_store = SqliteScheduleStore(db)
    svc = ScheduleService(eng_store, sched_store, ScriptedEngine([[_f("A", "c-a")]]))
    sch = sched_store.create("t1", "due", {"engagement": {"name": "n"}, "scope": {"in_scope": []}}, 3600)
    # it's due immediately (next_run_at == created)
    assert svc.tick() == 1
    # next_run advanced into the future -> no longer due
    assert svc.tick() == 0
    assert sched_store.get("t1", sch.id).next_run_at > datetime.now(timezone.utc)


def test_webhook_payload_is_slack_compatible(tmp_path):
    from types import SimpleNamespace
    A = _f("SQL Injection", "CWE-89", sev=Severity.HIGH)
    d = diff_findings([], [A])
    sch = SimpleNamespace(id="s1", name="nightly", webhook_url="http://hook")
    eng = Engagement(name="e"); eng.add_findings([A])
    payload = build_payload(sch, eng, d)
    assert "text" in payload                      # Slack incoming-webhook field
    assert "SQL Injection" in payload["text"]
    assert payload["pentestiq"]["counts"]["new"] == 1

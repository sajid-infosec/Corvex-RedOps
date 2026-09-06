"""Live scan control: pause/resume/stop, deadline, progress snapshot, endpoints."""
import time
import pytest
from pentestiq.core.runcontrol import RunControl, ScanCancelled, run_with_timeout, RUNS


def test_pause_resume_state():
    c = RunControl("e1")
    assert c.state == "running"
    c.pause(); assert c.state == "paused"
    c.resume(); assert c.state == "running"


def test_stop_raises_on_check():
    c = RunControl("e2")
    c.stop()
    with pytest.raises(ScanCancelled):
        c.check()


def test_deadline_raises():
    c = RunControl("e3", deadline_s=1)
    c._start -= 5  # simulate 5s elapsed
    with pytest.raises(ScanCancelled):
        c.check()


def test_progress_snapshot_counts_findings():
    c = RunControl("e4")
    c.set_phase("assess", module="web", activity="running checks")
    c.bump(3)

    class F:
        class severity: value = "high"
        title = "Reflected XSS"
    c.on_finding(F())
    snap = c.snapshot()
    assert snap["phase"] == "assess" and snap["requests"] == 3
    assert snap["severity"]["high"] == 1 and snap["findings"] == 1
    assert any(e.get("f") for e in snap["log"])


def test_run_with_timeout_abandons_hang():
    def hang():
        time.sleep(5); return "done"
    assert run_with_timeout(hang, 0.3, default="gave-up") == "gave-up"
    assert run_with_timeout(lambda: "ok", 2, default=None) == "ok"


def test_registry():
    c = RUNS.create("reg1", 30)
    assert RUNS.get("reg1") is c
    RUNS.drop("reg1")
    assert RUNS.get("reg1") is None

from pentestiq.core.audit import AuditLogger


def test_audit_appends_jsonl(tmp_path):
    a = AuditLogger(tmp_path, engagement_id="eng1")
    a.log("authorize_asset", target="host", decision="allow", reason="in scope")
    a.log("phase:assess", target="host", result="2 findings")
    events = a.read_all()
    assert len(events) == 2
    assert events[0]["action"] == "authorize_asset"
    assert events[0]["decision"] == "allow"
    assert events[1]["result"] == "2 findings"
    assert all(e["engagement_id"] == "eng1" for e in events)
    # file really is under data_dir/audit/
    assert a.path.exists() and a.path.suffix == ".jsonl"

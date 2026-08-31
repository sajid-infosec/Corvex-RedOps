from pentestiq.config import AppConfig
from pentestiq.logging_setup import get_logger
from pentestiq.core.registry import ModuleRegistry
from pentestiq.core.module_base import PentestModule, ModuleContext
from pentestiq.core.workflow import WorkflowRunner
from pentestiq.core.audit import AuditLogger
from pentestiq.models import (
    Asset, AssetType, Finding, Severity, Engagement, Scope, Enforcement,
)


class DummyWebModule(PentestModule):
    asset_type = AssetType.WEB
    name = "dummy-web"

    def assess(self, ctx: ModuleContext):
        return [Finding(asset=ctx.asset, title="Test finding",
                        category="TEST", severity=Severity.HIGH,
                        source_tools=["dummy"])]


def _registry():
    r = ModuleRegistry()
    r.register(DummyWebModule)
    return r


def _run(scope, tmp_path):
    asset = Asset(type=AssetType.WEB, identifier="http://evil.com")
    eng = Engagement(name="t", scope=scope, assets=[asset])
    cfg = AppConfig(data_dir=str(tmp_path))
    runner = WorkflowRunner(cfg, get_logger("test"), _registry())
    runner.run(eng)
    audit = AuditLogger(tmp_path, eng.id).read_all()
    return eng, audit


def test_block_mode_blocks_out_of_scope(tmp_path):
    scope = Scope(in_scope=["example.com"], enforcement=Enforcement.BLOCK)
    eng, audit = _run(scope, tmp_path)
    assert len(eng.findings) == 0                      # module never ran
    denies = [e for e in audit if e["decision"] == "deny" and e["result"] == "blocked"]
    assert denies and denies[0]["action"] == "authorize_asset"


def test_warn_mode_allows_out_of_scope(tmp_path):
    scope = Scope(in_scope=["example.com"], enforcement=Enforcement.WARN)
    eng, audit = _run(scope, tmp_path)
    assert len(eng.findings) == 1                      # ran despite out-of-scope
    assert eng.findings[0].title == "Test finding"


def test_pipeline_records_phase_audit(tmp_path):
    scope = Scope(enforcement=Enforcement.OFF)          # empty in_scope + off = permissive
    eng, audit = _run(scope, tmp_path)
    assert len(eng.findings) == 1
    actions = {e["action"] for e in audit}
    assert "phase:assess" in actions
    assert "engagement_complete" in actions

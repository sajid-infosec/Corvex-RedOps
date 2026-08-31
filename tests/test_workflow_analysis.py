from pentestiq.config import AppConfig
from pentestiq.logging_setup import get_logger
from pentestiq.core.registry import ModuleRegistry
from pentestiq.core.module_base import PentestModule, ModuleContext
from pentestiq.core.workflow import WorkflowRunner
from pentestiq.models import (
    Asset, AssetType, Finding, Severity, Engagement, Scope, Enforcement,
)


class MultiFindingWebModule(PentestModule):
    asset_type = AssetType.WEB
    name = "multi"
    def assess(self, ctx: ModuleContext):
        a = ctx.asset
        return [
            Finding(asset=a, title="low issue", category="c1", severity=Severity.LOW,
                    source_tools=["t1"]),
            Finding(asset=a, title="critical issue", category="c2", severity=Severity.CRITICAL,
                    source_tools=["t2"]),
        ]


def test_workflow_scores_and_correlates(tmp_path):
    reg = ModuleRegistry(); reg.register(MultiFindingWebModule)
    asset = Asset(type=AssetType.WEB, identifier="http://target:8080")
    eng = Engagement(name="t", scope=Scope(enforcement=Enforcement.OFF), assets=[asset])
    runner = WorkflowRunner(AppConfig(data_dir=str(tmp_path)), get_logger("test"), reg)
    runner.run(eng)

    assert len(eng.findings) == 2
    # every finding scored + correlated after the run
    assert all(f.risk_score is not None for f in eng.findings)
    assert all(f.correlation_id == "target:8080" for f in eng.findings)
    # results come out prioritized: critical first
    assert eng.sorted_findings()[0].severity == Severity.CRITICAL

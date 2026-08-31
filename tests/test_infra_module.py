from pentestiq.config import AppConfig
from pentestiq.logging_setup import get_logger
from pentestiq.core.module_base import ModuleContext
from pentestiq.modules.infra import InfraModule
from pentestiq.models import (
    Asset, AssetType, Finding, Severity, Engagement,
)


class FakeTool:
    def __init__(self, findings):
        self._f = findings
    def scan(self, asset, ctx=None):
        return self._f


def test_infra_module_orchestrates_and_dedups_across_tools():
    asset = Asset(type=AssetType.INFRA, identifier="10.0.0.5")
    # same asset + category from two different tools -> must dedup+merge
    f_nmap = Finding(asset=asset, title="http service", category="http-service",
                     severity=Severity.INFO, source_tools=["nmap"])
    f_nuclei = Finding(asset=asset, title="nginx CVE-2021-1234", category="http-service",
                       severity=Severity.HIGH, source_tools=["nuclei"])

    module = InfraModule()
    module.tools = [FakeTool([f_nmap]), FakeTool([f_nuclei])]   # inject fakes
    ctx = ModuleContext(engagement=Engagement(), asset=asset,
                        config=AppConfig(), logger=get_logger("test"))

    out = module.assess(ctx)
    assert len(out) == 2                       # module returns both raw

    eng = Engagement()
    eng.add_findings(out)                       # dedup happens here
    assert len(eng.findings) == 1
    merged = eng.findings[0]
    assert set(merged.source_tools) == {"nmap", "nuclei"}
    assert merged.severity == Severity.HIGH     # keeps higher severity


def test_infra_module_registered_for_infra():
    from pentestiq.core.registry import registry
    import pentestiq.modules  # noqa: ensure built-ins loaded
    names = [m.name for m in registry.for_asset_type(AssetType.INFRA)]
    assert "infra" in names

from pentestiq.config import AppConfig
from pentestiq.logging_setup import get_logger
from pentestiq.core.module_base import ModuleContext
from pentestiq.modules.web import WebModule
from pentestiq.models import Asset, AssetType, Finding, Severity, Engagement


class FakeTool:
    def __init__(self, findings): self._f = findings
    def scan(self, asset, ctx=None): return self._f


def test_web_module_registered():
    from pentestiq.core.registry import registry
    import pentestiq.modules  # noqa
    assert "web" in [m.name for m in registry.for_asset_type(AssetType.WEB)]


def test_web_module_orchestrates_tools():
    asset = Asset(type=AssetType.WEB, identifier="http://site")
    module = WebModule()
    module.tools = [FakeTool([Finding(asset=asset, title="a", severity=Severity.HIGH)]),
                    FakeTool([Finding(asset=asset, title="b", severity=Severity.LOW)])]
    ctx = ModuleContext(engagement=Engagement(), asset=asset,
                        config=AppConfig(), logger=get_logger("test"))
    out = module.assess(ctx)
    assert len(out) == 2


def test_all_builtin_modules_registered():
    from pentestiq.core.registry import registry
    import pentestiq.modules  # noqa
    names = {m.name for m in registry.all()}
    assert {"infra", "web", "wordpress", "api"} <= names

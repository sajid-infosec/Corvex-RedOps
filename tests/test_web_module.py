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


class _UnreachableHttp:
    """Native checks get no responses -> emit nothing; keeps this test offline."""
    def request(self, method, url, headers=None, data=None):
        from pentestiq.checks.base import Response
        return Response(status=0, headers={}, text="", elapsed_ms=0.0, url=url)
    def get(self, url, headers=None):
        return self.request("GET", url, headers)


def test_web_module_orchestrates_tools():
    asset = Asset(type=AssetType.WEB, identifier="http://site")
    module = WebModule()
    module.tools = [FakeTool([Finding(asset=asset, title="a", severity=Severity.HIGH)]),
                    FakeTool([Finding(asset=asset, title="b", severity=Severity.LOW)])]
    ctx = ModuleContext(engagement=Engagement(), asset=asset,
                        config=AppConfig(), logger=get_logger("test"),
                        extra={"checks_http_client": _UnreachableHttp()})
    out = module.assess(ctx)
    # the two orchestrated tool findings are present (native checks add none here)
    assert len(out) == 2
    assert {f.title for f in out} == {"a", "b"}


def test_all_builtin_modules_registered():
    from pentestiq.core.registry import registry
    import pentestiq.modules  # noqa
    names = {m.name for m in registry.all()}
    assert {"infra", "web", "wordpress", "api"} <= names

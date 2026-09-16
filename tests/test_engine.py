import pytest
from pathlib import Path
from pentestiq.engine import Engine, load_scope, infer_asset_type
from pentestiq.models import AssetType


def test_infer_asset_type():
    assert infer_asset_type("http://localhost:3000") == AssetType.WEB
    assert infer_asset_type("10.0.0.0/24") == AssetType.INFRA
    assert infer_asset_type("192.168.1.10") == AssetType.INFRA
    assert infer_asset_type("example.com") == AssetType.WEB


@pytest.mark.live
def test_load_scope_and_empty_workflow(tmp_path: Path):
    scope_file = tmp_path / "scope.yaml"
    scope_file.write_text(
        "engagement:\n  name: T\nscope:\n  in_scope:\n"
        "    - http://localhost:3000\n    - 10.0.0.0/24\n"
        "safe_mode: true\nenforcement: warn\n"
    )
    scope, assets = load_scope(scope_file)
    assert scope.name == "T"
    assert len(assets) == 2

    engine = Engine()
    eng = engine.run(scope_file)
    # engine wiring: both assets visited, run completes without crashing.
    # (Modules are real now — the web module actively crawls/checks — so the
    # finding count depends on what the target returns; assert the shape, not 0.)
    assert len(eng.assets) == 2
    assert isinstance(eng.findings, list)

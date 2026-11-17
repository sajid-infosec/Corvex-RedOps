"""The GitHub workflows are valid YAML (a broken one makes GitHub record a failed run on
every push)."""
from pathlib import Path

import yaml

WF = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def test_every_workflow_parses():
    files = sorted(WF.glob("*.yml"))
    assert files
    for p in files:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        assert isinstance(doc, dict) and doc.get("jobs"), p.name


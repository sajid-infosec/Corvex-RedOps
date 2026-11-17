"""The GitHub workflows are valid YAML (a broken one makes GitHub record a failed run on
every push) and CI installs what the suite needs."""
from pathlib import Path

import yaml

WF = Path(__file__).resolve().parents[1] / ".github" / "workflows"


def test_every_workflow_parses():
    files = sorted(WF.glob("*.yml"))
    assert files
    for p in files:
        doc = yaml.safe_load(p.read_text(encoding="utf-8"))
        assert isinstance(doc, dict) and doc.get("jobs"), p.name


def test_ci_runs_the_whole_suite_everywhere_including_el9_sqlite():
    ci = yaml.safe_load((WF / "ci.yml").read_text(encoding="utf-8"))
    text = (WF / "ci.yml").read_text(encoding="utf-8")
    m = ci["jobs"]["test"]["strategy"]["matrix"]
    assert m["os"] == ["ubuntu-latest", "macos-latest", "windows-latest"]
    assert m["python"] == ["3.10", "3.11", "3.12"]
    # every extra the tests import without importorskip (httpx, pytest-timeout, lief, sklearn)
    assert text.count('".[api,reports,desktop,dev,ai]"') == 2
    assert text.count("--timeout=300 --timeout-method=thread") == 2
    el9 = ci["jobs"]["el9-sqlite"]
    assert el9["container"] == "almalinux:9"
    assert 'v.startswith("3.34.")' in text
    assert "bash -n install.sh" in text and "Language.Parser]::ParseFile" in text


def test_readme_shows_the_ci_badge_and_no_test_counts():
    import re
    readme = (WF.parents[1] / "README.md").read_text(encoding="utf-8")
    assert "https://github.com/sajid-infosec/corvex-redops/actions/workflows/ci.yml/badge.svg" in readme
    assert not re.search(r"badge/tests-|\d+\+?\s*(tests|passing)\b", readme)

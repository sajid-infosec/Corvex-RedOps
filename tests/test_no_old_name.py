"""No "PentestIQ" anywhere a user looks: docs, deploy files, installers, console text, CLI help
and generated reports. Allowed: the internal package path (`pentestiq/…`, `pentestiq.module`),
the hidden `pentestiq` alias, the fallback/migration code (marked `old-name` in the installers;
pentestiq/settings_env.py, pentestiq/storage/paths.py), older CHANGELOG sections and the
[Unreleased] note telling pip users to uninstall the old distribution."""
import re
from pathlib import Path

from typer.testing import CliRunner

ROOT = Path(__file__).resolve().parents[1]
OLD = re.compile(r"pentestiq", re.I)
# the package path stays `pentestiq`: a directory (pentestiq/...) or a module (pentestiq.cli)
PACKAGE_PATH = re.compile(r"(?<![\w-])pentestiq(?=/|\.(?!(?:db|yaml|yml|example|log|env|zip)\b)[a-z_]{2,}\b)")


def _hits(text: str, where: str, allow_marked: bool = False):
    hits, inside = [], False
    for n, line in enumerate(text.splitlines(), 1):
        if allow_marked and "old-name: begin" in line:
            inside = True; continue
        if allow_marked and "old-name: end" in line:
            inside = False; continue
        if inside or (allow_marked and "old-name" in line):
            continue
        rest = PACKAGE_PATH.sub("", line).replace("pip uninstall pentestiq", "")   # the upgrade note
        if OLD.search(rest):
            hits.append(f"{where}:{n}: {line.strip()[:120]}")
    return hits


def _user_facing_files():
    files = [ROOT / p for p in ("README.md", "INSTALL.md", "SECURITY.md", "CONTRIBUTING.md", "Dockerfile",
                                ".dockerignore")]
    files += sorted((ROOT / "docs").glob("*.md")) + sorted((ROOT / "deploy").glob("*.yml"))
    files += sorted((ROOT / "config").glob("*.yaml")) + sorted((ROOT / ".github/ISSUE_TEMPLATE").glob("*"))
    files += [p for p in (ROOT / "examples").rglob("*") if p.is_file() and p.suffix in (".md", ".html", ".yaml", ".json")]
    files += [p for p in (ROOT / "pentestiq/kit").rglob("*") if p.is_file() and p.suffix in (".md", ".js", ".txt")]
    files += [ROOT / "pentestiq/api/static/index.html"]
    return [f for f in files if f.is_file()]


def test_user_facing_files_use_the_new_name():
    hits = []
    for f in _user_facing_files():
        hits += _hits(f.read_text(encoding="utf-8", errors="replace"), str(f.relative_to(ROOT)))
    assert hits == []


def test_installers_mention_the_old_name_only_in_marked_migration_code():
    for name in ("install.sh", "install.ps1"):
        assert _hits((ROOT / name).read_text(encoding="utf-8"), name, allow_marked=True) == [], name


def test_changelog_unreleased_only_names_the_old_distribution_to_uninstall():
    text = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
    unreleased = re.search(r"^## \[Unreleased\][^\n]*\n(.*?)(?=^## \[)", text, re.S | re.M).group(1)
    lines = [l for l in unreleased.splitlines() if OLD.search(PACKAGE_PATH.sub("", l))]
    assert lines and all("pip uninstall pentestiq" in l for l in lines), lines


def test_cli_help_never_shows_the_old_name():
    from pentestiq.cli import app
    runner = CliRunner()
    out = runner.invoke(app, ["--help"], prog_name="corvex").output
    commands = re.findall(r"│ ([a-z][a-z-]+) +", out)
    assert "setup-code" in commands and "serve" in commands
    for cmd in [""] + commands:
        text = runner.invoke(app, ([cmd] if cmd else []) + ["--help"], prog_name="corvex").output
        assert not OLD.search(text), cmd


def test_reports_never_show_the_old_name_even_for_old_findings():
    from pentestiq.ingest import engagement_to_sarif
    from pentestiq.models import Asset, Engagement, Finding
    from pentestiq.models.enums import AssetType, Severity
    from pentestiq.reporting import (build_narrative, compute_stats, render_exec_html, render_html,
                                     render_markdown)
    a = Asset(type=AssetType.WEB, identifier="https://app.example.test")
    eng = Engagement(name="t", assets=[a], findings=[
        Finding(asset=a, title="XSS", category="A03:2021", severity=Severity.HIGH, source_tools=["pentestiq-fuzz"]),
        Finding(asset=a, title="Headers", category="A05:2021", severity=Severity.LOW, source_tools=["corvex-checks"])])
    stats = compute_stats(eng)
    narr = build_narrative(eng, stats, None)
    import json
    outputs = {"md": render_markdown(eng, stats, narr), "html": render_html(eng, stats, narr),
               "exec": render_exec_html(eng, stats, narr), "sarif": json.dumps(engagement_to_sarif(eng))}
    for kind, text in outputs.items():
        assert not OLD.search(text), kind


def test_the_hidden_alias_says_it_was_renamed(capsys, monkeypatch):
    import sys
    from pentestiq import cli
    monkeypatch.setattr(sys, "argv", ["pentestiq", "version"])
    try:
        cli.legacy_main()
    except SystemExit:
        pass
    captured = capsys.readouterr()
    assert "renamed to corvex" in captured.err and "Corvex-RedOps v" in captured.out


def test_distribution_and_entry_points():
    py = (ROOT / "pyproject.toml").read_text(encoding="utf-8")
    assert 'name = "corvex-redops"' in py
    assert 'corvex = "pentestiq.cli:app"' in py and 'pentestiq = "pentestiq.cli:legacy_main"' in py

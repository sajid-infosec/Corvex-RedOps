"""v0.2.0 release prep: one version everywhere; the CHANGELOG section that becomes the release
body; the release workflow's tag/version check, asset names, checksums and dry-run guard; the
docs that tell users how to check and open the binaries."""
import os
import re
import shutil
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

import pentestiq

ROOT = Path(__file__).resolve().parents[1]
WF = yaml.safe_load((ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8"))
ASSETS = ["corvex-redops-linux-x64", "corvex-redops-macos-arm64", "corvex-redops-windows-x64.exe"]


def _pyproject_version():
    return re.search(r'^version\s*=\s*"([^"]+)"', (ROOT / "pyproject.toml").read_text(encoding="utf-8"), re.M).group(1)


def test_package_versions_match():
    assert _pyproject_version() == pentestiq.__version__ == "0.2.0"


def test_cli_prints_exactly_the_version_the_smoke_test_expects():
    from typer.testing import CliRunner
    from pentestiq.cli import app
    assert CliRunner().invoke(app, ["version"]).output.strip() == f"Corvex-RedOps v{pentestiq.__version__}"


# ---- CHANGELOG ---------------------------------------------------------------
CHANGELOG = (ROOT / "CHANGELOG.md").read_text(encoding="utf-8")
SECTION = re.search(r"^## \[0\.2\.0\] — (\d{4}-\d{2}-\d{2})\n(.*?)(?=^## \[)", CHANGELOG, re.S | re.M)

# third-party tools and competitors that user-facing text must not name (standards and data
# sources such as OWASP, CWE, SARIF, CycloneDX, EPSS, CISA KEV, MITRE ATT&CK are fine)
NAMES = ["Ollama", "Nmap", "Nuclei", "ZAP", "Burp", "WPScan", "MobSF", "Semgrep", "Trivy", "Prowler",
         "kube-bench", "BloodHound", "mitmproxy", "Playwright", "Metasploit", "Exploit-DB", "searchsploit",
         "Nessus", "Qualys", "Acunetix", "OpenVAS", "OSV", "gitleaks", "Lynis", "Cisco", "iptables", "nipper",
         "Jira", "ServiceNow", "Slack", "Frida", "lief", "reportlab", "python-docx", "scikit-learn", "Juice Shop",
         "DVWA", "Typer", "PyInstaller", "Wiz", "Orca", "Snyk", "Shodan"]


def test_changelog_has_a_dated_0_2_0_section_with_the_groups():
    assert SECTION, "no ## [0.2.0] — YYYY-MM-DD section"
    groups = re.findall(r"^### (\w+)", SECTION.group(2), re.M)
    assert groups == ["Added", "Security", "Fixes", "Platforms", "Docs"]
    body = SECTION.group(2)
    for must in ("Community includes one workspace", "at least 12 characters", "WAL", "SHA256SUMS",
                 "code-signed", "SQLite 3.24"):
        assert must in body, must


def test_unreleased_lists_the_fixes_since_0_2_0():
    unreleased = re.search(r"^## \[Unreleased\]\n(.*?)(?=^## \[)", CHANGELOG, re.S | re.M).group(1)
    assert re.findall(r"^### (\w+)", unreleased, re.M) == ["Fixes"]
    assert "- The per-username sign-in slowdown no longer resets at the top of each hour." in unreleased
    assert "- Docs: the single-file binary's console is at http://127.0.0.1:8000, not 8080." in unreleased
    hits = [n for n in NAMES if re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", unreleased, re.I)]
    assert hits == []


def test_the_new_section_names_no_third_party_tools():
    body = SECTION.group(2)
    hits = [n for n in NAMES if re.search(rf"(?<![\w-]){re.escape(n)}(?![\w-])", body, re.I)]
    assert hits == []


# ---- release.yml -------------------------------------------------------------
def _step(job, name_start):
    return next(s for s in WF["jobs"][job]["steps"] if s.get("name", "").startswith(name_start))


def _run_version_step(tmp_path, ref_type, ref_name):
    for rel in ("pyproject.toml", "pentestiq/__init__.py", "CHANGELOG.md"):
        (tmp_path / rel).parent.mkdir(parents=True, exist_ok=True)
        shutil.copy(ROOT / rel, tmp_path / rel)
    (tmp_path / "step.py").write_text(_step("version", "Package version")["run"], encoding="utf-8")
    out = tmp_path / "out.txt"
    r = subprocess.run([sys.executable, "step.py"], cwd=tmp_path, capture_output=True, text=True, encoding="utf-8",
                       env={**os.environ, "REF_TYPE": ref_type, "REF_NAME": ref_name, "GITHUB_OUTPUT": str(out)})
    return r, out


def test_tag_must_match_the_package_version(tmp_path):
    r, out = _run_version_step(tmp_path / "ok", "tag", "v0.2.0")
    assert r.returncode == 0, r.stderr
    assert out.read_text() == "version=0.2.0\n"
    notes = (tmp_path / "ok" / "release-notes.md").read_text(encoding="utf-8")
    assert notes.startswith("Corvex-RedOps grows") and "### Security" in notes and "## [0.1.0]" not in notes
    r, _ = _run_version_step(tmp_path / "bad", "tag", "v0.2.1")
    assert r.returncode != 0 and "expected v0.2.0" in r.stderr
    r, _ = _run_version_step(tmp_path / "dispatch", "branch", "main")       # a dry run on a branch
    assert r.returncode == 0, r.stderr


def test_assets_checksums_and_the_dry_run_guard():
    on = WF.get("on", WF.get(True))                       # PyYAML reads the key `on` as True
    assert set(on) == {"push", "workflow_dispatch"} and on["push"] == {"tags": ["v*"]}
    assert [m["asset"] for m in WF["jobs"]["binaries"]["strategy"]["matrix"]["include"]] == ASSETS
    rel = WF["jobs"]["release"]
    assert set(rel["needs"]) == {"version", "wheels", "binaries"}
    publish = _step("release", "Publish the release")
    assert publish["if"] == "github.event_name == 'push' && github.ref_type == 'tag'"
    assert "--notes-file release-notes.md" in publish["run"] and "SHA256SUMS" in publish["run"]
    for a in ASSETS:
        assert a in publish["run"]
    # build jobs only upload; only the release job may write
    for job in ("version", "wheels", "binaries"):
        uses = [s.get("uses", "") for s in WF["jobs"][job]["steps"]]
        assert not any("gh-release" in u for u in uses) and "permissions" not in WF["jobs"][job]
        assert all("gh release" not in s.get("run", "") for s in WF["jobs"][job]["steps"])
    assert WF["permissions"] == {"contents": "read"} and rel["permissions"] == {"contents": "write"}
    text = (ROOT / ".github/workflows/release.yml").read_text(encoding="utf-8")
    assert "actions/upload-artifact@v6" in text and "actions/download-artifact@v7" in text
    assert "@v4" not in text


@pytest.mark.skipif(sys.platform == "win32", reason="runs the release job's bash step (ubuntu in CI)")
def test_checksum_step_covers_the_five_files_and_refuses_a_missing_one(tmp_path):
    script = _step("release", "SHA256SUMS").get("run").replace("${{ needs.version.outputs.version }}", "0.2.0")
    files = ["pentestiq-0.2.0-py3-none-any.whl", "pentestiq-0.2.0.tar.gz", *ASSETS]
    for f in files:
        (tmp_path / f).write_bytes(f.encode())
    (tmp_path / "release-notes.md").write_text("notes\n")
    r = subprocess.run(["bash", "-eo", "pipefail", "-c", script], cwd=tmp_path, capture_output=True, text=True)
    assert r.returncode == 0, r.stdout + r.stderr
    sums = (tmp_path / "SHA256SUMS").read_text().splitlines()
    assert [line.split("  ", 1)[1] for line in sums] == files
    # the documented per-file check works against it
    ok = subprocess.run(["bash", "-c", "grep ' corvex-redops-linux-x64$' SHA256SUMS | sha256sum -c -"],
                        cwd=tmp_path, capture_output=True, text=True)
    assert ok.returncode == 0 and "corvex-redops-linux-x64: OK" in ok.stdout
    (tmp_path / "corvex-redops-linux-x64").write_bytes(b"tampered")
    bad = subprocess.run(["bash", "-c", "grep ' corvex-redops-linux-x64$' SHA256SUMS | sha256sum -c -"],
                         cwd=tmp_path, capture_output=True, text=True)
    assert bad.returncode != 0
    (tmp_path / ASSETS[2]).unlink()
    r = subprocess.run(["bash", "-eo", "pipefail", "-c", script], cwd=tmp_path, capture_output=True, text=True)
    assert r.returncode != 0 and "missing corvex-redops-windows-x64.exe" in r.stdout


# ---- docs --------------------------------------------------------------------
def test_docs_use_the_new_asset_names_and_explain_signing_and_checksums():
    install = (ROOT / "INSTALL.md").read_text(encoding="utf-8")
    readme = (ROOT / "README.md").read_text(encoding="utf-8")
    for a in ASSETS:
        assert a in install and a in readme, a
    assert not re.search(r"pentestiq-(linux|macos|windows)", install + readme)
    assert "aren't code-signed yet" in install and "Gatekeeper" in install and "SmartScreen" in install
    assert "xattr -d com.apple.quarantine" in install and "Open Anyway" in install and "Run anyway" in install
    assert "sha256sum -c -" in install and "shasum -a 256 -c -" in install and "Get-FileHash" in install

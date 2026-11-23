"""The `installer` CI workflow runs the installers end to end: Docker without and with AI (a tiny
model), native (not root, data outside the checkout), Windows, and an upgrade from 0.2.1."""
from pathlib import Path

import yaml

ROOT = Path(__file__).resolve().parents[1]
TEXT = (ROOT / ".github/workflows/installer.yml").read_text(encoding="utf-8")
WF = yaml.safe_load(TEXT)


def _run(job):
    return "\n".join(s.get("run", "") for s in WF["jobs"][job]["steps"])


def test_the_five_jobs():
    assert set(WF["jobs"]) == {"docker", "docker-ai", "native", "windows", "upgrade"}
    assert WF["jobs"]["windows"]["runs-on"] == "windows-latest"


def test_docker_job_checks_health_setup_page_logs_and_listeners():
    r = _run("docker")
    assert "sudo --preserve-env=CORVEX_REGISTRY bash install.sh --docker --listen 127.0.0.1 --no-ai" in r
    assert "/health" in r and "$CHECK setup install.log" in r and "$CHECK listeners 8080" in r
    assert "docker logs corvex-redops-console" in r and "install.sh --down" in r


def test_ai_job_uses_a_tiny_model_and_proves_it():
    assert WF["jobs"]["docker-ai"]["env"]["CORVEX_AI_MODEL"] == "qwen2.5:0.5b"
    r = _run("docker-ai")
    assert "--ai" in r and "AI: ready" in r and "/ai/status" in r and "model_present" in r
    assert "skipping the download" in r


def test_native_job_asserts_not_root_and_data_outside_the_checkout():
    r = _run("native")
    assert "sudo --preserve-env=CORVEX_REGISTRY bash install.sh --native" in r and 'test "$user" != root' in r
    assert "CORVEX_DATA_DIR" in r and "$GITHUB_WORKSPACE" in r


def test_windows_job_runs_install_ps1_natively_with_a_health_check():
    r = _run("windows")
    assert "install.ps1 -Native" in r and "/health" in r


def test_upgrade_job_starts_from_0_2_1_and_checks_data_and_settings():
    assert len(WF["env"]["OLD_REF"]) == 40
    r = _run("upgrade")
    for part in ("git checkout -q \"$OLD_REF\"", "PENTESTIQ_SECRET_KEY=", "install.sh --update",
                 "kept-across-upgrade", "CORVEX_SECRET_KEY=ci-secret", "deploy_pentestiq-data corvex-redops-data",
                 "corvex-redops.db", "docker volume rm deploy_pentestiq-data"):
        assert part in r, part


def test_ci_never_contacts_the_account_registry():
    """CI installs must not create accounts in the real registry, and they test the
    setup-code path: the workflow turns the registry off and passes it through sudo."""
    import yaml
    wf = (ROOT / ".github/workflows/installer.yml").read_text(encoding="utf-8")
    assert yaml.safe_load(wf)["env"]["CORVEX_REGISTRY"] == "off"
    assert "sudo bash install.sh" not in wf                     # every sudo run keeps the setting

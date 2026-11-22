"""install.sh creates no admin and writes no password. Its last lines are the console address
and a one-time setup code (fetched from the console, kept in memory, never written to a file).
CORVEX_ADMIN_PASSWORD in the installer's environment creates the admin directly (headless) and
is blanked once the console is up. An existing install gets the right reset command."""
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# Never reach this machine's Docker, services or sudo from a test, whatever installer function runs.
_GUARD = ('docker(){ echo "docker $*" >> "${CORVEX_TEST_DOCKER_LOG:-/dev/null}"; return 1; }; '
          'systemctl(){ return 1; }; sudo(){ return 1; }; runuser(){ return 1; }; ')
SH = (ROOT / "install.sh").read_text(encoding="utf-8")

pytestmark = pytest.mark.skipif(sys.platform == "win32",
                                reason="drives install.sh through a POSIX bash (Windows installs with install.ps1)")


def _run(tmp_path, script, extra_env=None):
    env = {**os.environ, "CORVEX_INSTALL_SOURCE_ONLY": "1", "NO_COLOR": "1", **(extra_env or {})}
    env.pop("CORVEX_ADMIN_PASSWORD", None) if not extra_env or "CORVEX_ADMIN_PASSWORD" not in extra_env else None
    cmd = (f'source "{ROOT}/install.sh"; {_GUARD}SUDO=""; ENV_FILE="{tmp_path}/deploy/.env"; detect_distro; '
           f'native_layout; {script}')
    return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=env, timeout=60,
                          encoding="utf-8", errors="replace")


def test_sourcing_does_not_install_anything(tmp_path):
    r = _run(tmp_path, "echo sourced-ok")
    assert r.returncode == 0 and "sourced-ok" in r.stdout
    assert "one-command deploy" not in r.stdout          # main() (banner) did not run


def test_no_password_is_generated_or_written(tmp_path):
    r = _run(tmp_path, 'write_env >/dev/null; apply_headless_admin; cat "$ENV_FILE"')
    assert "CORVEX_ADMIN_PASSWORD" not in r.stdout and "CORVEX_ADMIN_USER" not in r.stdout
    assert oct((tmp_path / "deploy/.env").stat().st_mode)[-3:] == "600"
    for gone in ("gen_password", "FIRST_ADMIN_PW", "one-time password)", "CORVEX_ADMIN_PASSWORD=corvex"):
        assert gone not in SH, gone


def _summary_tail(tmp_path, code, extra="", engine="docker"):
    script = (f'ENGINE_USED={engine}; PORT=8080; SETUP_CODE="{code}"; {extra} '
              'summary | sed "/^$/d" | tail -n 2')
    return _run(tmp_path, script).stdout.splitlines()


def test_the_last_lines_are_the_address_and_the_setup_code(tmp_path):
    last = _summary_tail(tmp_path, "7KQ2MHX4")
    assert "Open http://127.0.0.1:8080 and set up the admin account" in last[0]
    assert "Setup code : 7KQ2MHX4" in last[1] and "sudo docker exec -it corvex-redops-console corvex setup-code" in last[1]


def test_the_setup_code_comes_from_the_console_and_only_when_setup_is_pending(tmp_path):
    stub = ('curl(){ printf \'{"setup_required": %s}\' "$PENDING"; }; '
            'compose(){ [ "$*" = "exec -T console corvex setup-code --quiet" ] && printf "7KQ2MHX4\\r\\n"; }; '
            'ENGINE_USED=docker; ')
    r = _run(tmp_path, stub + 'PENDING=true; fetch_setup_code && echo "CODE=$SETUP_CODE"')
    assert "CODE=7KQ2MHX4" in r.stdout
    r = _run(tmp_path, stub + 'PENDING=false; fetch_setup_code || echo "NONE=[$SETUP_CODE]"')
    assert "NONE=[]" in r.stdout
    assert not list(tmp_path.rglob("*")) or "7KQ2MHX4" not in "".join(
        p.read_text(errors="ignore") for p in tmp_path.rglob("*") if p.is_file())


def test_native_installs_fetch_the_code_as_the_service_user(tmp_path):
    r = _run(tmp_path, 'privileged(){ return 0; }; native_layout; NATIVE_MODE=system; SUDO=echo; native_cli setup-code --quiet')
    assert re.search(r"^runuser -u corvex-redops -- bash -c .*setup-code --quiet", r.stdout)


def test_headless_password_creates_the_admin_and_is_then_blanked(tmp_path):
    env = {"CORVEX_ADMIN_PASSWORD": "headless-pass-123", "CORVEX_ADMIN_USER": "ops"}
    r = _run(tmp_path, 'write_env >/dev/null; apply_headless_admin; grep ADMIN "$ENV_FILE"; '
                       'ENGINE_USED=docker; consume_admin_password; echo ---; grep ADMIN "$ENV_FILE"; '
                       'SETUP_CODE=""; PORT=8080; summary | sed "/^$/d" | tail -n 1', extra_env=env)
    before, after = r.stdout.split("---")
    assert "CORVEX_ADMIN_USER=ops" in before and "CORVEX_ADMIN_PASSWORD=headless-pass-123" in before
    assert "CORVEX_ADMIN_PASSWORD=\n" in after and "headless-pass-123" not in after
    assert "as ops with the CORVEX_ADMIN_PASSWORD you set (now removed from the settings file)" in after


def test_an_existing_install_gets_the_reset_command_for_its_engine(tmp_path):
    docker = _summary_tail(tmp_path, "")
    assert "with your admin account" in docker[0]
    assert "sudo docker exec -it corvex-redops-console corvex reset-password <user>" in docker[1]
    native = _run(tmp_path, 'privileged(){ return 0; }; native_layout; ENGINE_USED=native; PORT=8080; SETUP_CODE=""; '
                            'summary | sed "/^$/d" | tail -n 1').stdout
    assert "sudo runuser -u corvex-redops -- env CORVEX_DATA_DIR=" in native and "corvex reset-password <user>" in native


def test_the_code_is_fetched_after_the_stack_is_healthy_and_shown_last():
    main = SH[SH.index("main() {"):]
    assert main.index("try_docker") < main.index("fetch_setup_code") < main.index("summary")
    body = SH[SH.index("summary() {"):]
    assert body.index("signin_block") > body.index("stop : ")


def test_docs_no_longer_advertise_a_default_login():
    for name in ("README.md", "INSTALL.md", "install.sh"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "corvex / corvex" not in text and "`corvex` / `corvex`" not in text, name


def test_install_ps1_shows_the_setup_code_last_and_writes_no_password():
    ps1 = (ROOT / "install.ps1").read_text(encoding="utf-8")
    assert "function Get-SetupCode" in ps1 and '"corvex", "setup-code", "--quiet"' in ps1
    assert "Setup code : $script:SetupCode" in ps1
    assert "docker exec -it $ConsoleContainer corvex reset-password <user>" in ps1 and '$ConsoleContainer = "corvex-redops-console"' in ps1
    assert "first-run admin" not in ps1 and "one-time password in" not in ps1

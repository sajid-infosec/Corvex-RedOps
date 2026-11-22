"""D8: install.sh writes no fixed password. It generates a random one-time password, shows
it once in the summary, and blanks it in the env file once the console is up."""
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]


def _run(tmp_path, script):
    if sys.platform == "win32":   # install.sh is the Linux/macOS installer; Windows uses install.ps1
        pytest.skip("drives install.sh through a POSIX bash (Windows installs with install.ps1)")
    env = {**os.environ, "CORVEX_INSTALL_SOURCE_ONLY": "1", "NO_COLOR": "1"}
    cmd = f'source "{ROOT}/install.sh"; ENV_FILE="{tmp_path}/deploy/.env"; {script}'
    return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=env, timeout=60, encoding="utf-8", errors="replace")


def test_sourcing_does_not_install_anything(tmp_path):
    r = _run(tmp_path, "echo sourced-ok")
    assert r.returncode == 0 and "sourced-ok" in r.stdout
    assert "one-command deploy" not in r.stdout          # main() (banner) did not run


def test_no_fixed_password_is_written(tmp_path):
    text = (ROOT / "install.sh").read_text(encoding="utf-8")
    assert "CORVEX_ADMIN_PASSWORD=corvex" not in text
    assert "password: corvex" not in text


def test_env_file_gets_a_random_one_time_password(tmp_path):
    r = _run(tmp_path, 'write_env >/dev/null; echo "PW=$FIRST_ADMIN_PW"')
    assert r.returncode == 0, r.stderr
    pw = re.search(r"PW=(\S+)", r.stdout).group(1)
    assert re.fullmatch(r"[A-Za-z0-9]{20}", pw)
    env = (tmp_path / "deploy/.env").read_text(encoding="utf-8")
    assert f"CORVEX_ADMIN_PASSWORD={pw}" in env and "CORVEX_ADMIN_USER=corvex" in env
    assert oct((tmp_path / "deploy/.env").stat().st_mode)[-3:] == "600"
    # a second install gets a different password
    r2 = _run(tmp_path / "other", 'write_env >/dev/null; echo "PW=$FIRST_ADMIN_PW"')
    assert re.search(r"PW=(\S+)", r2.stdout).group(1) != pw


def test_password_is_shown_once_then_removed_from_the_env_file(tmp_path):
    r = _run(tmp_path, 'write_env >/dev/null; consume_admin_password; admin_password_hint; echo "PW=$FIRST_ADMIN_PW"')
    pw = re.search(r"PW=(\S+)", r.stdout).group(1)
    assert pw in r.stdout.split("PW=")[0]                         # shown in the summary
    assert "shown only this once" in r.stdout and "removed from" in r.stdout
    env = (tmp_path / "deploy/.env").read_text(encoding="utf-8")
    assert "CORVEX_ADMIN_PASSWORD=\n" in env and pw not in env    # blanked on disk


def test_password_kept_until_the_console_has_started(tmp_path):
    r = _run(tmp_path, 'write_env >/dev/null; admin_password_hint; echo "PW=$FIRST_ADMIN_PW"')
    pw = re.search(r"PW=(\S+)", r.stdout).group(1)
    assert pw in (tmp_path / "deploy/.env").read_text(encoding="utf-8")           # first boot still needs it
    assert "until the console first starts" in r.stdout


def test_rerun_reuses_env_and_never_reveals_a_password(tmp_path):
    first = _run(tmp_path, 'write_env >/dev/null; consume_admin_password; echo "PW=$FIRST_ADMIN_PW"')
    pw = re.search(r"PW=(\S+)", first.stdout).group(1)
    r = _run(tmp_path, 'write_env; consume_admin_password; admin_password_hint')
    assert "Reusing existing secrets" in r.stdout                 # the env file is kept
    assert pw not in r.stdout and "shown only this once" not in r.stdout
    assert "your existing password" in r.stdout


def test_legacy_env_file_with_old_default_is_flagged(tmp_path):
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy/.env").write_text("CORVEX_ADMIN_USER=corvex\nCORVEX_ADMIN_PASSWORD=corvex\n", encoding="utf-8")
    r = _run(tmp_path, "admin_password_hint")
    assert "still contains the old default password" in r.stdout


def test_docs_no_longer_advertise_a_default_login():
    for name in ("README.md", "INSTALL.md", "install.sh"):
        text = (ROOT / name).read_text(encoding="utf-8")
        assert "corvex / corvex" not in text and "`corvex` / `corvex`" not in text, name

"""The image and the native install build from a checkout whatever its file permissions, and a
cleanup hiccup after a successful dependency install is never reported as a failed install.

A checkout with private files (mode 600, directories 700) used to build an image whose console,
running as an unprivileged user, could not import its own code. The native fallback then built
fine but reported failure, because pip (as root) left files in the staged copy that the
installing user could not delete."""
import os
import re
import stat
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")
_GUARD = ('docker(){ return 1; }; systemctl(){ return 1; }; sudo(){ return 1; }; runuser(){ return 1; }; ')

posix_only = pytest.mark.skipif(sys.platform == "win32",
                                reason="drives install.sh / a find command through a POSIX shell")


def _image_permission_fix() -> str:
    m = re.search(r"^RUN (find /app .*?chmod a\+rX \{\} \+)", DOCKERFILE, re.M)
    assert m, "the Dockerfile no longer makes /app readable for the unprivileged user"
    return m.group(1)


def test_the_image_fixes_permissions_after_copying_the_code_and_before_dropping_root():
    copy = DOCKERFILE.index("COPY . /app")
    fix = DOCKERFILE.index(_image_permission_fix())
    user = DOCKERFILE.index("\nUSER ")
    assert copy < fix < user


@posix_only
def test_a_private_checkout_becomes_readable_and_readable_files_are_left_alone(tmp_path):
    app = tmp_path / "app"
    (app / "pkg" / "models").mkdir(parents=True)
    private = app / "pkg" / "models" / "enums.py"
    private.write_text("X = 1\n")
    private.chmod(0o600)
    (app / "pkg" / "models").chmod(0o700)
    shared = app / "pkg" / "cli.py"
    shared.write_text("print()\n")
    shared.chmod(0o664)
    before = shared.stat().st_ctime_ns

    cmd = _image_permission_fix().replace("/app", str(app), 1)
    subprocess.run(["sh", "-c", cmd], check=True, timeout=30)

    assert stat.S_IMODE(private.stat().st_mode) & 0o444 == 0o444
    assert stat.S_IMODE((app / "pkg" / "models").stat().st_mode) & 0o555 == 0o555
    assert stat.S_IMODE(private.stat().st_mode) & 0o111 == 0      # no file turned executable
    assert shared.stat().st_ctime_ns == before                    # untouched: no copied-up layer


def _native_pip(tmp_path, python_body: str, extra: str = ""):
    venv = tmp_path / "venv" / "bin"
    venv.mkdir(parents=True)
    for tool in ("python", "playwright"):
        exe = venv / tool
        exe.write_text("#!/bin/sh\n" + python_body)
        exe.chmod(0o755)
    blog = tmp_path / "build.log"
    script = (f'source "{ROOT}/install.sh"; {_GUARD}SUDO=""; native_layout; '
              f'NATIVE_VENV="{tmp_path}/venv"; NATIVE_PREFIX="{tmp_path}/prefix"; '
              f'stage_source(){{ d="$(mktemp -d)"; printf %s "$d"; }}; {extra} '
              f'native_pip_install "{blog}"; echo "rc=$?"')
    env = {**os.environ, "CORVEX_INSTALL_SOURCE_ONLY": "1", "NO_COLOR": "1", "TMPDIR": str(tmp_path)}
    return subprocess.run(["bash", "-c", script], capture_output=True, text=True, env=env, timeout=60)


@posix_only
def test_dependencies_that_installed_are_not_reported_failed_when_cleanup_is_denied(tmp_path):
    # rm always fails, as it did for files root's pip left in the staged copy
    r = _native_pip(tmp_path, "exit 0\n", extra='rm(){ return 1; };')
    assert "rc=0" in r.stdout, r.stdout + r.stderr


@posix_only
def test_a_real_dependency_failure_is_still_reported(tmp_path):
    body = 'case "$*" in *"[api,reports]"*) exit 1;; esac\nexit 0\n'
    r = _native_pip(tmp_path, body)
    assert "rc=1" in r.stdout, r.stdout + r.stderr


def test_migrated_volumes_carry_the_labels_compose_expects():
    sh = (ROOT / "install.sh").read_text(encoding="utf-8")
    compose = yaml.safe_load((ROOT / "deploy" / "docker-compose.yml").read_text(encoding="utf-8"))
    project = compose["name"]
    assert f"--label com.docker.compose.project={project}" in sh
    assert '--label "com.docker.compose.volume=${new#' + project + '-}"' in sh
    # the label derives the compose key from the volume name, so every name must be <project>-<key>
    for key, spec in compose["volumes"].items():
        assert spec["name"] == f"{project}-{key}"

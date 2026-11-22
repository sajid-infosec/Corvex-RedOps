"""install.sh never fails halfway: a read-only preflight (platform, memory, disk, Docker, every
host port) before any change; a busy port is named (or the next free one is used when the user
didn't choose one); a stack that doesn't come up healthy is taken down; the only DNS change is a
docker.service drop-in; the native console runs as an unprivileged user with its own venv and
data outside the checkout; the image pins its scanners and runs as a non-root user."""
import os
import re
import socket
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


def _sh(tmp_path, script, args="", extra_env=None):
    env = {**os.environ, "CORVEX_INSTALL_SOURCE_ONLY": "1", "NO_COLOR": "1",
           "CORVEX_NATIVE_HOME": str(tmp_path / "var-lib"), "CORVEX_NATIVE_PREFIX": str(tmp_path / "opt"),
           "CORVEX_NATIVE_ETC": str(tmp_path / "etc"), "CORVEX_UNIT_DIR": str(tmp_path / "units"),
           "CORVEX_DOCKER_DROPIN_DIR": str(tmp_path / "docker.service.d"), **(extra_env or {})}
    # SUDO="" and a Docker that looks absent: nothing here may touch this machine's services
    cmd = (f'source "{ROOT}/install.sh"; {_GUARD}SUDO=""; ENV_FILE="{tmp_path}/deploy/.env"; '
           f'docker_state(){{ echo missing; }}; detect_distro; parse_args {args}; {script}')
    return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=env, timeout=120,
                          encoding="utf-8", errors="replace")


@pytest.fixture
def listener():
    """A real TCP listener on 127.0.0.1 held by this test process (python)."""
    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
    s.bind(("127.0.0.1", 0)); s.listen(1)
    yield s.getsockname()[1]
    s.close()


def _free_port():
    s = socket.socket(); s.bind(("127.0.0.1", 0)); p = s.getsockname()[1]; s.close()
    return p


# ---- ports -------------------------------------------------------------------------------
def test_a_busy_port_is_named(tmp_path, listener):
    r = _sh(tmp_path, f'port_holder {listener}; echo; port_holder {_free_port()}; echo "<free>"')
    first, second = r.stdout.split("\n", 1)
    assert re.search(rf"python[0-9.]* \(pid {os.getpid()}", first), first
    assert second.strip() == "<free>"


def test_a_busy_port_the_user_chose_stops_the_install_naming_the_holder(tmp_path, listener):
    r = _sh(tmp_path, 'resolve_port "$PORT" "$PORT_SET" --port; echo SHOULD-NOT-RUN', args=f"--port {listener}")
    assert r.returncode != 0 and "SHOULD-NOT-RUN" not in r.stdout
    assert f"port {listener} is in use by python" in r.stderr and f"pid {os.getpid()}" in r.stderr
    assert "choose another port with --port N" in r.stderr


def test_a_busy_default_port_moves_to_the_next_free_one(tmp_path, listener):
    r = _sh(tmp_path, f'PORT={listener}; PORT_SET=0; echo "CHOSEN=$(resolve_port "$PORT" "$PORT_SET" --port)"')
    chosen = int(re.search(r"CHOSEN=(\d+)", r.stdout).group(1))
    assert chosen > listener and f"Port {listener} is in use by python" in r.stderr and f"using {chosen}" in r.stderr


def test_a_port_held_by_our_own_previous_console_is_not_a_conflict(tmp_path):
    assert _sh(tmp_path, 'is_ours "Docker container x|123|corvex-redops-console" && echo OURS').stdout.strip() == "OURS"
    assert _sh(tmp_path, 'is_ours "Docker container x|123|someone-elses-app" || echo THEIRS').stdout.strip() == "THEIRS"


def test_preflight_checks_every_published_port(tmp_path, listener):
    r = _sh(tmp_path, "preflight", args=f"--port {_free_port()} --publish-mobile {listener}",
            extra_env={"CORVEX_TEST_MEM_MB": "4096", "CORVEX_TEST_DISK_MB": "50000"})
    assert r.returncode != 0 and f"port {listener} is in use by python" in r.stderr
    assert "--publish-mobile N" in r.stderr


# ---- memory / disk / platform -------------------------------------------------------------
def test_preflight_stops_before_any_change_when_memory_is_short(tmp_path):
    r = _sh(tmp_path, 'preflight; echo CHANGED-SOMETHING', extra_env={"CORVEX_TEST_MEM_MB": "300", "CORVEX_TEST_DISK_MB": "50000"})
    assert r.returncode != 0 and "CHANGED-SOMETHING" not in r.stdout
    assert "only 300 MB of memory is free" in r.stderr
    assert not (tmp_path / "deploy").exists() and not (tmp_path / "var-lib").exists()


def test_short_disk_for_docker_falls_back_to_native_on_auto_and_stops_on_docker(tmp_path):
    env = {"CORVEX_TEST_MEM_MB": "4096", "CORVEX_TEST_DISK_MB": "3000"}
    r = _sh(tmp_path, 'native_layout; preflight; echo "ENGINE=$ENGINE"', args=f"--port {_free_port()}", extra_env=env)
    assert r.returncode == 0, r.stderr
    assert "ENGINE=native" in r.stdout and "using the native install instead" in r.stdout
    r = _sh(tmp_path, "native_layout; preflight", args=f"--docker --port {_free_port()}", extra_env=env)
    assert r.returncode != 0 and "the images need at least 8192 MB" in r.stderr


def test_preflight_reports_platform_memory_disk_docker_and_port(tmp_path):
    r = _sh(tmp_path, "native_layout; preflight", args=f"--port {_free_port()}",
            extra_env={"CORVEX_TEST_MEM_MB": "4096", "CORVEX_TEST_DISK_MB": "50000"})
    assert r.returncode == 0, r.stderr
    for part in ("Platform:", "Memory: 4096 MB free", "Docker: not installed", "Disk: 50000 MB free", "Console port:", "Preflight passed"):
        assert part in r.stdout, part


def test_preflight_runs_before_anything_is_installed():
    main = SH[SH.index("main() {"):]
    assert main.index("preflight") < main.index("install_base") < main.index("try_docker")


# ---- never half-started ------------------------------------------------------------------
@pytest.mark.parametrize("fail_at", ["up", "health"])
def test_a_stack_that_does_not_come_up_is_taken_down(tmp_path, fail_at):
    (tmp_path / "deploy").mkdir(); (tmp_path / "deploy/.env").write_text("X=1\n")
    up_rc = 1 if fail_at == "up" else 0
    health_rc = 1 if fail_at == "health" else 0
    r = _sh(tmp_path, f'''COMPOSE_FILE="{tmp_path}/deploy/c.yml"; : > "$COMPOSE_FILE"
      compose(){{ echo "compose $*" >> "{tmp_path}/calls"; case "$1" in up) return {up_rc};; esac; return 0; }}
      wait_healthy(){{ return {health_rc}; }}; stop_native_instances(){{ :; }}
      deploy_docker; echo "RC=$? STARTED=$STACK_STARTED"''')
    calls = (tmp_path / "calls").read_text().splitlines()
    assert "RC=1 STARTED=" in r.stdout
    assert calls[0] == "compose build" and any(c.startswith("compose up -d") for c in calls)
    assert calls[-1] == "compose down --remove-orphans"
    assert "nothing is left half-started" in r.stdout + r.stderr


def test_a_failed_image_build_touches_nothing(tmp_path):
    (tmp_path / "deploy").mkdir(); (tmp_path / "deploy/.env").write_text("X=1\n")
    r = _sh(tmp_path, f'''COMPOSE_FILE="{tmp_path}/deploy/c.yml"; : > "$COMPOSE_FILE"
      compose(){{ echo "compose $*" >> "{tmp_path}/calls"; [ "$1" = build ] && return 1; return 0; }}
      deploy_docker; echo "RC=$?"''')
    assert "RC=1" in r.stdout and (tmp_path / "calls").read_text().splitlines() == ["compose build"]


def test_ctrl_c_rolls_back_what_this_run_started():
    assert "trap on_abort INT TERM" in SH
    body = SH[SH.index("on_abort() {"):SH.index("# ----", SH.index("on_abort() {"))]
    assert "docker) rollback_docker" in body and "native) rollback_native" in body


# ---- Docker DNS ---------------------------------------------------------------------------
def test_go_resolver_symptom_is_recognised_only_when_the_host_resolves(tmp_path):
    msg = ('Error response from daemon: Get "https://registry-1.docker.io/v2/": dial tcp: lookup '
           'registry-1.docker.io on 172.16.80.2:53: no such host')
    ok = _sh(tmp_path, f"getent(){{ return 0; }}; go_resolver_symptom '{msg}' && echo YES")
    assert ok.stdout.strip() == "YES"
    no = _sh(tmp_path, f"getent(){{ return 2; }}; go_resolver_symptom '{msg}' || echo NO")
    assert no.stdout.strip() == "NO"
    other = _sh(tmp_path, "getent(){ return 0; }; go_resolver_symptom 'toomanyrequests: rate limit' || echo NO")
    assert other.stdout.strip() == "NO"


def test_the_dns_fix_is_only_a_docker_service_drop_in_and_says_so(tmp_path):
    r = _sh(tmp_path, f'''systemctl(){{ echo "systemctl $*" >> "{tmp_path}/calls"; }}; docker(){{ return 0; }}
      docker_dns_dropin''')
    dropin = tmp_path / "docker.service.d/corvex-dns.conf"
    assert dropin.read_text() == "[Service]\nEnvironment=GODEBUG=netdns=cgo\n"
    assert (tmp_path / "calls").read_text().splitlines() == ["systemctl daemon-reload", "systemctl restart docker"]
    assert f"Changed: added {dropin}" in r.stdout and "restarted Docker" in r.stdout and "To undo" in r.stdout
    # no system-wide resolver change is left anywhere in the installer
    for gone in ("resolved.conf", "/etc/resolv.conf", "daemon.json", "8.8.8.8", "1.1.1.1"):
        assert gone not in SH, gone


# ---- native: unprivileged service, own venv, data outside the checkout ------------------
def test_native_system_service_never_runs_as_root_and_stays_out_of_the_checkout(tmp_path):
    r = _sh(tmp_path, 'privileged(){ return 0; }; native_layout; unit_file_text; echo "DATA=$NATIVE_DATA VENV=$NATIVE_VENV"')
    unit = r.stdout
    assert "User=corvex-redops" in unit and "Group=corvex-redops" in unit and "User=root" not in unit
    data = re.search(r"DATA=(\S+)", unit).group(1); venv = re.search(r"VENV=(\S+)", unit).group(1)
    for p in (data, venv):
        assert not p.startswith(str(ROOT)), p
    assert f"ExecStart={venv}/bin/corvex serve" in unit and "/.venv/" not in unit
    assert f"CORVEX_DATA_DIR" not in unit or data in unit
    assert "NoNewPrivileges=yes" in unit and "ReadWritePaths=" in unit


def test_native_defaults_are_system_paths_outside_the_checkout():
    assert 'NATIVE_HOME="${CORVEX_NATIVE_HOME:-/var/lib/corvex-redops}"' in SH
    assert 'NATIVE_PREFIX="${CORVEX_NATIVE_PREFIX:-/opt/corvex-redops}"' in SH
    assert "$REPO_DIR/.venv" not in SH.replace("$REPO_DIR)/(venv|\\\\.venv)", "")


def test_native_settings_file_holds_the_data_dir_and_is_private(tmp_path):
    r = _sh(tmp_path, 'privileged(){ return 1; }; native_layout; write_native_env && cat "$NATIVE_ENV"; stat -c %a "$NATIVE_ENV"')
    assert f"CORVEX_DATA_DIR={tmp_path}/var-lib/data" in r.stdout and "CORVEX_LISTEN=127.0.0.1" in r.stdout
    assert re.search(r"CORVEX_SECRET_KEY=[0-9a-f]{64}", r.stdout) and r.stdout.strip().endswith("600")


def test_the_console_is_never_started_as_root_without_a_service_user(tmp_path):
    r = _sh(tmp_path, 'privileged(){ return 1; }; native_layout; id(){ [ "$1" = -u ] && echo 0 || command id "$@"; }; start_native; echo "RC=$?"')
    assert "RC=1" in r.stdout and "refusing to run the console as root" in r.stdout


def test_the_source_copy_leaves_venv_data_and_secrets_behind(tmp_path):
    r = _sh(tmp_path, 'src="$(stage_source)"; ls -A "$src"; echo ---; ls "$src/pentestiq/intel/data" | head -1; rm -rf "$src"')
    top, intel = r.stdout.split("---")
    names = top.split()
    for gone in (".git", ".venv", "data"):
        assert gone not in names, gone
    assert "pyproject.toml" in names and "pentestiq" in names
    assert intel.strip(), "package data (pentestiq/intel/data) must be copied"


def test_old_native_data_is_copied_once_and_never_deleted(tmp_path):
    legacy = tmp_path / "checkout-data"; legacy.mkdir()
    (legacy / "pentestiq.db").write_text("old")
    script = (f'privileged(){{ return 1; }}; native_layout; LEGACY_DATA="{legacy}"; mkdir -p "$NATIVE_DATA"; '
              'migrate_legacy_native_data; echo "COPIED=$LEGACY_DATA_COPIED"; cat "$NATIVE_DATA/pentestiq.db"')
    r = _sh(tmp_path, script)
    assert "COPIED=1" in r.stdout and r.stdout.strip().endswith("old")
    assert (legacy / "pentestiq.db").read_text() == "old"                       # left in place
    (tmp_path / "var-lib/data/pentestiq.db").write_text("new")
    r = _sh(tmp_path, script)
    assert "COPIED=0" in r.stdout and r.stdout.strip().endswith("new")          # never overwrites


# ---- image --------------------------------------------------------------------------------
DOCKERFILE = (ROOT / "Dockerfile").read_text(encoding="utf-8")


def test_libatomic_is_installed_before_the_headless_browser():
    assert DOCKERFILE.index("libatomic1") < DOCKERFILE.index("playwright install")


def test_scanners_are_pinned_with_sha256_for_both_architectures():
    for tool in ("NUCLEI", "SUBFINDER"):
        assert re.search(rf"ARG {tool}_VERSION=\d+\.\d+\.\d+\n", DOCKERFILE), tool
        for arch in ("AMD64", "ARM64"):
            assert re.search(rf"ARG {tool}_SHA256_{arch}=[0-9a-f]{{64}}\n", DOCKERFILE), (tool, arch)
    assert 'sha256sum -c -' in DOCKERFILE and "SHA-256 mismatch" in DOCKERFILE
    assert "releases/latest" not in DOCKERFILE and "api.github.com" not in DOCKERFILE


def test_the_app_runs_as_an_unprivileged_user():
    users = re.findall(r"^USER (\S+)", DOCKERFILE, re.M)
    assert users and users[-1] not in ("root", "0")
    assert DOCKERFILE.rindex("USER ") < DOCKERFILE.index("CMD [")
    assert "--uid 10001" in DOCKERFILE and "-R 10001:10001 /app/data" in SH


def test_secrets_and_local_data_never_enter_the_image():
    ignore = (ROOT / ".dockerignore").read_text(encoding="utf-8").split()
    for p in ("deploy/.env", "data/", ".venv/", ".git/"):
        assert p in ignore, p


def test_install_ps1_has_the_same_preflight_and_cleanup():
    ps1 = (ROOT / "install.ps1").read_text(encoding="utf-8")
    for part in ("function Invoke-Preflight", "Get-NetTCPConnection -State Listen", "function Resolve-Port",
                 "Stop it, or choose another port with", "Get-FreeMemMB", "Get-FreeDiskMB", "function Undo-Docker",
                 'Join-Path $env:LOCALAPPDATA "corvex-redops"', '"10001:10001"'):
        assert part in ps1, part
    assert ps1.index("Invoke-Preflight\n$Port") > ps1.index("function Invoke-Preflight")

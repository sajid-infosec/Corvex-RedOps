"""B5: network exposure — helper services on 127.0.0.1 only; the console's bind address is
install.sh --listen (default kept at 0.0.0.0) with a warning when it is reachable."""
import os
import re
import subprocess
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = (ROOT / "deploy/docker-compose.yml").read_text()


def test_helper_services_bound_to_loopback():
    assert '"127.0.0.1:8000:8000"' in COMPOSE          # mobile analysis
    assert '"127.0.0.1:11434:11434"' in COMPOSE        # local AI runtime
    assert '"8000:8000"' not in COMPOSE and '"11434:11434"' not in COMPOSE
    # the console still reaches them over the compose network
    assert "MOBSF_URL=http://mobsf:8000" in COMPOSE and "http://ollama:11434" in COMPOSE


def test_console_bind_address_is_configurable_with_todays_default():
    assert '"${PENTESTIQ_LISTEN:-0.0.0.0}:${PENTESTIQ_PORT:-8080}:8080"' in COMPOSE


def _sh(tmp_path, args, script):
    env = {**os.environ, "CORVEX_INSTALL_SOURCE_ONLY": "1"}
    cmd = f'source "{ROOT}/install.sh" {args}; ENV_FILE="{tmp_path}/deploy/.env"; {script}'
    return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=env, timeout=60)


def test_default_listen_warns_in_the_summary(tmp_path):
    r = _sh(tmp_path, "", 'echo "LISTEN=$LISTEN"; listen_warning')
    assert "LISTEN=0.0.0.0" in r.stdout
    assert "reachable from the network" in r.stdout and "--listen 127.0.0.1" in r.stdout


def test_loopback_listen_has_no_warning_and_reaches_env_and_native(tmp_path):
    r = _sh(tmp_path, "--listen 127.0.0.1", 'listen_warning; write_env >/dev/null; cat "$ENV_FILE"')
    assert "reachable from the network" not in r.stdout
    assert "PENTESTIQ_LISTEN=127.0.0.1" in r.stdout
    assert 'serve --host "$LISTEN"' in (ROOT / "install.sh").read_text()


def test_ipv6_is_bracketed_for_compose(tmp_path):
    r = _sh(tmp_path, "--listen ::1", 'write_env >/dev/null; cat "$ENV_FILE"; listen_warning')
    assert "PENTESTIQ_LISTEN=[::1]" in r.stdout and "reachable" not in r.stdout


def test_existing_env_file_follows_a_new_listen_value(tmp_path):
    _sh(tmp_path, "", "write_env >/dev/null")
    r = _sh(tmp_path, "--listen 127.0.0.1", 'set_listen_env; grep PENTESTIQ_LISTEN "$ENV_FILE"')
    assert r.stdout.strip() == "PENTESTIQ_LISTEN=127.0.0.1"


def test_invalid_listen_values_are_refused(tmp_path):
    for bad in ("1.2.3.4;id", "0.0.0.0/0", "$(id)", "example.com"):
        r = _sh(tmp_path, f"--listen '{bad}'", "echo SHOULD-NOT-RUN")
        assert r.returncode != 0 and "SHOULD-NOT-RUN" not in r.stdout, bad
        assert "invalid --listen" in r.stdout + r.stderr, bad


def test_docs_explain_listen_and_tls():
    for name in ("README.md", "INSTALL.md"):
        t = (ROOT / name).read_text()
        assert "--listen 127.0.0.1" in t and "Put TLS in front" in t, name

"""B5: network exposure — helper services on 127.0.0.1 only; the console's bind address is
install.sh --listen (default kept at 0.0.0.0) with a warning when it is reachable."""
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = (ROOT / "deploy/docker-compose.yml").read_text(encoding="utf-8")


def test_helper_services_bound_to_loopback():
    assert '"127.0.0.1:8000:8000"' in COMPOSE          # mobile analysis
    assert '"127.0.0.1:11434:11434"' in COMPOSE        # local AI runtime
    assert '"8000:8000"' not in COMPOSE and '"11434:11434"' not in COMPOSE
    # the console still reaches them over the compose network
    assert "MOBSF_URL=http://mobsf:8000" in COMPOSE and "http://ollama:11434" in COMPOSE


def test_console_bind_address_is_configurable_with_todays_default():
    assert '"${PENTESTIQ_LISTEN:-0.0.0.0}:${PENTESTIQ_PORT:-8080}:8080"' in COMPOSE


def _sh(tmp_path, args, script):
    if sys.platform == "win32":   # install.sh is the Linux/macOS installer; Windows uses install.ps1
        pytest.skip("drives install.sh through a POSIX bash (Windows installs with install.ps1)")
    env = {**os.environ, "CORVEX_INSTALL_SOURCE_ONLY": "1"}
    cmd = f'source "{ROOT}/install.sh" {args}; ENV_FILE="{tmp_path}/deploy/.env"; {script}'
    return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=env, timeout=60, encoding="utf-8", errors="replace")


def test_default_listen_warns_in_the_summary(tmp_path):
    r = _sh(tmp_path, "", 'echo "LISTEN=$LISTEN"; listen_warning')
    assert "LISTEN=0.0.0.0" in r.stdout
    assert "reachable from the network" in r.stdout and "--listen 127.0.0.1" in r.stdout


def test_loopback_listen_has_no_warning_and_reaches_env_and_native(tmp_path):
    r = _sh(tmp_path, "--listen 127.0.0.1", 'listen_warning; write_env >/dev/null; cat "$ENV_FILE"')
    assert "reachable from the network" not in r.stdout
    assert "PENTESTIQ_LISTEN=127.0.0.1" in r.stdout
    assert 'serve --host "$LISTEN"' in (ROOT / "install.sh").read_text(encoding="utf-8")


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
        t = (ROOT / name).read_text(encoding="utf-8")
        assert "--listen 127.0.0.1" in t and "Put TLS in front" in t, name


def test_trusted_proxy_flag_reaches_env_compose_and_native(tmp_path):
    r = _sh(tmp_path, "--trusted-proxy 172.18.0.1 --trusted-proxy 10.0.0.0/24", 'write_env >/dev/null; cat "$ENV_FILE"')
    assert "CORVEX_TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.1,10.0.0.0/24" in r.stdout
    assert "CORVEX_TRUSTED_PROXIES=${CORVEX_TRUSTED_PROXIES:-127.0.0.1,::1}" in COMPOSE
    assert "CORVEX_TRUSTED_PROXIES=$tpx" in (ROOT / "install.sh").read_text(encoding="utf-8")


def test_existing_env_file_follows_a_new_trusted_proxy(tmp_path):
    _sh(tmp_path, "", "write_env >/dev/null")
    r = _sh(tmp_path, "--trusted-proxy 172.18.0.1", 'set_trusted_env; grep CORVEX_TRUSTED_PROXIES "$ENV_FILE"')
    assert r.stdout.strip() == "CORVEX_TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.1"


def test_invalid_trusted_proxy_values_are_refused(tmp_path):
    for bad in ("*", "10.0.0.0/8;id", "proxy.example.com", "/24", "10.0.0.0/"):
        r = _sh(tmp_path, f"--trusted-proxy '{bad}'", "echo SHOULD-NOT-RUN")
        assert r.returncode != 0 and "SHOULD-NOT-RUN" not in r.stdout, bad
        assert "invalid --trusted-proxy" in r.stdout + r.stderr, bad


def test_docs_explain_the_gateway_and_never_star():
    for name in ("README.md", "INSTALL.md"):
        t = (ROOT / name).read_text(encoding="utf-8")
        assert "docker network inspect deploy_default" in t and "Never `*`" in t, name


def test_trusted_proxy_with_a_network_listen_warns(tmp_path):
    r = _sh(tmp_path, "--trusted-proxy 172.18.0.1", "proxy_trust_warning")
    assert "Trusted proxy 172.18.0.1 is set while the console listens on 0.0.0.0" in r.stdout
    assert "--listen 127.0.0.1" in r.stdout
    assert _sh(tmp_path, "--trusted-proxy 172.18.0.1 --listen 127.0.0.1", "proxy_trust_warning").stdout == ""
    assert _sh(tmp_path, "", "proxy_trust_warning").stdout == ""          # nothing trusted beyond loopback


def test_trust_warning_also_reads_an_existing_env_file(tmp_path):
    _sh(tmp_path, "--trusted-proxy 10.0.0.0/24", "write_env >/dev/null")
    assert "Trusted proxy 10.0.0.0/24" in _sh(tmp_path, "", "proxy_trust_warning").stdout


PS1 = (ROOT / "install.ps1").read_text(encoding="utf-8")


def test_install_ps1_has_listen_and_trusted_proxy_with_the_same_rules():
    assert '[string]$Listen = "0.0.0.0"' in PS1 and "[string[]]$TrustedProxy = @()" in PS1
    # same validation as install.sh: IP or localhost; IP/CIDR, never "*"
    assert "$Listen -notmatch '^[0-9A-Fa-f.:]+$'" in PS1
    assert "$tp -notmatch '^[0-9A-Fa-f.:]+(/[0-9]{1,3})?$'" in PS1 and "never `\"*`\"" in PS1
    # written to the env file (compose) and used by the native server
    assert '"PENTESTIQ_LISTEN=$(Get-ComposeListen)`n"' in PS1 and '"CORVEX_TRUSTED_PROXIES=$(Get-TrustedList)`n"' in PS1
    assert "serve --host $Listen --port $Port" in PS1 and "--host 0.0.0.0" not in PS1
    assert "$env:CORVEX_TRUSTED_PROXIES = Get-TrustedList" in PS1
    # the same two warnings
    assert "reachable from the network" in PS1 and "could set their own X-Forwarded-For" in PS1
    assert "Update-NetworkEnv" in PS1                     # an existing env file follows the flags


def test_install_ps1_validation_regexes_behave_like_install_sh():
    import re
    listen = re.compile(r"^[0-9A-Fa-f.:]+$")
    proxy = re.compile(r"^[0-9A-Fa-f.:]+(/[0-9]{1,3})?$")
    for ok in ("127.0.0.1", "0.0.0.0", "::1"):
        assert listen.match(ok)
    for bad in ("1.2.3.4;id", "example.com", "*"):
        assert not listen.match(bad)
    for ok in ("172.18.0.1", "10.0.0.0/24", "fd00::/64"):
        assert proxy.match(ok)
    for bad in ("*", "10.0.0.0/8;id", "proxy.example.com", "/24", "10.0.0.0/"):
        assert not proxy.match(bad)


def test_docs_pair_the_gateway_with_loopback():
    for name in ("README.md", "INSTALL.md"):
        t = (ROOT / name).read_text(encoding="utf-8")
        assert "Trust the gateway only together with `--listen 127.0.0.1`" in t, name
        assert "one-time warning" in t, name

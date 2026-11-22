"""Network exposure: only the console publishes a host port, on 127.0.0.1 unless install.sh
--listen says otherwise (one-line warning). The mobile-analysis engine and the AI runtime have
no host port; the mobile engine is published (on 127.0.0.1) only behind --publish-mobile."""
import os
import re
import subprocess
import sys
from pathlib import Path

import pytest
import yaml

ROOT = Path(__file__).resolve().parents[1]
COMPOSE = (ROOT / "deploy/docker-compose.yml").read_text(encoding="utf-8")
SERVICES = yaml.safe_load(COMPOSE)["services"]


def _console_service():
    return next(s for s in SERVICES.values() if s.get("build"))


def test_only_the_console_publishes_a_port():
    published = {name: s.get("ports") for name, s in SERVICES.items() if s.get("ports")}
    assert list(published.values()) == [_console_service()["ports"]]
    # the console still reaches the helpers over the compose network
    assert "MOBSF_URL=http://mobsf:8000" in COMPOSE and "http://ollama:11434" in COMPOSE


def test_console_defaults_to_this_host_only():
    assert _console_service()["ports"] == ["${PENTESTIQ_LISTEN:-127.0.0.1}:${PENTESTIQ_PORT:-8080}:8080"]
    assert "0.0.0.0" not in str(_console_service()["ports"])


def test_mobile_engine_is_published_only_by_the_override_and_on_loopback():
    over = yaml.safe_load((ROOT / "deploy/docker-compose.publish-mobile.yml").read_text(encoding="utf-8"))
    (name, svc), = over["services"].items()
    assert name in SERVICES and SERVICES[name].get("image", "").startswith("opensecurity/")
    assert svc["ports"] == ["127.0.0.1:${CORVEX_MOBILE_PORT:-8000}:8000"]


def _sh(tmp_path, args, script):
    if sys.platform == "win32":   # install.sh is the Linux/macOS installer; Windows uses install.ps1
        pytest.skip("drives install.sh through a POSIX bash (Windows installs with install.ps1)")
    env = {**os.environ, "CORVEX_INSTALL_SOURCE_ONLY": "1", "NO_COLOR": "1"}
    cmd = (f'source "{ROOT}/install.sh"; SUDO=""; ENV_FILE="{tmp_path}/deploy/.env"; '
           f'parse_args {args}; {script}')
    return subprocess.run(["bash", "-c", cmd], capture_output=True, text=True, env=env, timeout=60,
                          encoding="utf-8", errors="replace")


def test_default_listen_is_loopback_without_a_warning(tmp_path):
    r = _sh(tmp_path, "", 'echo "LISTEN=$LISTEN"; listen_warning; write_env >/dev/null; cat "$ENV_FILE"')
    assert "LISTEN=127.0.0.1" in r.stdout and "PENTESTIQ_LISTEN=127.0.0.1" in r.stdout
    assert "plain HTTP" not in r.stdout


def test_network_listen_is_opt_in_with_a_one_line_warning(tmp_path):
    r = _sh(tmp_path, "--listen 0.0.0.0", "listen_warning")
    lines = [l for l in r.stdout.splitlines() if l.strip()]
    assert len(lines) == 1 and "0.0.0.0" in lines[0] and "plain HTTP" in lines[0] and "TLS" in lines[0]


def test_ipv6_is_bracketed_for_compose(tmp_path):
    r = _sh(tmp_path, "--listen ::1", 'write_env >/dev/null; cat "$ENV_FILE"; listen_warning')
    assert "PENTESTIQ_LISTEN=[::1]" in r.stdout and "plain HTTP" not in r.stdout


def test_an_old_0000_install_moves_to_loopback_and_says_so(tmp_path):
    (tmp_path / "deploy").mkdir()
    (tmp_path / "deploy/.env").write_text("PENTESTIQ_PORT=9090\nPENTESTIQ_LISTEN=0.0.0.0\n", encoding="utf-8")
    r = _sh(tmp_path, "", 'load_existing_settings; echo "PORT=$PORT LISTEN=$LISTEN FROM=$LISTEN_CHANGED_FROM"')
    assert "PORT=9090 LISTEN=127.0.0.1 FROM=0.0.0.0" in r.stdout
    # an explicit --listen keeps it, and so does an address the user chose on purpose
    assert "LISTEN=0.0.0.0" in _sh(tmp_path, "--listen 0.0.0.0", 'load_existing_settings; echo "LISTEN=$LISTEN"').stdout
    (tmp_path / "deploy/.env").write_text("PENTESTIQ_LISTEN=192.0.2.7\n", encoding="utf-8")
    assert "LISTEN=192.0.2.7 FROM=" in _sh(tmp_path, "", 'load_existing_settings; echo "LISTEN=$LISTEN FROM=$LISTEN_CHANGED_FROM"').stdout


def test_existing_env_file_follows_this_runs_settings(tmp_path):
    _sh(tmp_path, "", "write_env >/dev/null")
    r = _sh(tmp_path, "--listen 192.0.2.7 --port 9191 --trusted-proxy 172.18.0.1",
            'sync_env; grep -E "^(PENTESTIQ_LISTEN|PENTESTIQ_PORT|CORVEX_TRUSTED_PROXIES)=" "$ENV_FILE" | sort')
    assert r.stdout.split() == ["CORVEX_TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.1",
                                "PENTESTIQ_LISTEN=192.0.2.7", "PENTESTIQ_PORT=9191"]
    assert oct((tmp_path / "deploy/.env").stat().st_mode)[-3:] == "600"


def test_invalid_listen_and_port_values_are_refused(tmp_path):
    for args in ("--listen '1.2.3.4;id'", "--listen 0.0.0.0/0", "--listen '$(id)'", "--listen example.com",
                 "--port 0", "--port 70000", "--port abc"):
        r = _sh(tmp_path, args, "echo SHOULD-NOT-RUN")
        assert r.returncode != 0 and "SHOULD-NOT-RUN" not in r.stdout, args
        assert "invalid --" in r.stdout + r.stderr, args


def test_docs_explain_listen_and_tls():
    for name in ("README.md", "INSTALL.md"):
        t = (ROOT / name).read_text(encoding="utf-8")
        assert "--listen 0.0.0.0" in t and "TLS" in t and "127.0.0.1" in t, name


def test_trusted_proxy_flag_reaches_env_compose_and_native(tmp_path):
    r = _sh(tmp_path, "--trusted-proxy 172.18.0.1 --trusted-proxy 10.0.0.0/24", 'write_env >/dev/null; cat "$ENV_FILE"')
    assert "CORVEX_TRUSTED_PROXIES=127.0.0.1,::1,172.18.0.1,10.0.0.0/24" in r.stdout
    assert "CORVEX_TRUSTED_PROXIES=${CORVEX_TRUSTED_PROXIES:-127.0.0.1,::1}" in COMPOSE
    assert "CORVEX_TRUSTED_PROXIES=$tp" in (ROOT / "install.sh").read_text(encoding="utf-8")


def test_invalid_trusted_proxy_values_are_refused(tmp_path):
    for bad in ("*", "10.0.0.0/8;id", "proxy.example.com", "/24", "10.0.0.0/"):
        r = _sh(tmp_path, f"--trusted-proxy '{bad}'", "echo SHOULD-NOT-RUN")
        assert r.returncode != 0 and "SHOULD-NOT-RUN" not in r.stdout, bad
        assert "invalid --trusted-proxy" in r.stdout + r.stderr, bad


def test_docs_explain_the_gateway_and_never_star():
    for name in ("README.md", "INSTALL.md"):
        t = (ROOT / name).read_text(encoding="utf-8")
        assert "docker network inspect" in t and "Never `*`" in t, name


def test_trusted_proxy_with_a_network_listen_warns(tmp_path):
    r = _sh(tmp_path, "--trusted-proxy 172.18.0.1 --listen 0.0.0.0", "proxy_trust_warning")
    assert "Trusted proxy 172.18.0.1 is set while the console listens on 0.0.0.0" in r.stdout
    assert "--listen 127.0.0.1" in r.stdout
    assert _sh(tmp_path, "--trusted-proxy 172.18.0.1", "proxy_trust_warning").stdout == ""   # loopback default
    assert _sh(tmp_path, "--listen 0.0.0.0", "proxy_trust_warning").stdout == ""             # nothing beyond loopback


def test_trust_warning_also_reads_an_existing_env_file(tmp_path):
    _sh(tmp_path, "--trusted-proxy 10.0.0.0/24", "write_env >/dev/null")
    assert "Trusted proxy 10.0.0.0/24" in _sh(tmp_path, "--listen 0.0.0.0", "proxy_trust_warning").stdout


PS1 = (ROOT / "install.ps1").read_text(encoding="utf-8")


def test_install_ps1_has_the_same_listen_rules():
    assert '[string]$Listen = ""' in PS1 and 'if (-not $ListenSet) { $Listen = "127.0.0.1" }' in PS1
    assert "[string[]]$TrustedProxy = @()" in PS1 and "[switch]$PublishMobile" in PS1
    # same validation as install.sh: IP or localhost; IP/CIDR, never "*"
    assert "$Listen -notmatch '^[0-9A-Fa-f.:]+$'" in PS1
    assert "$tp -notmatch '^[0-9A-Fa-f.:]+(/[0-9]{1,3})?$'" in PS1 and "never `\"*`\"" in PS1
    # written to the env file (compose) and used by the native server
    assert 'Set-EnvValue "PENTESTIQ_LISTEN" (Get-ComposeListen)' in PS1
    assert '"serve", "--host", $Listen, "--port", "$Port"' in PS1 and "--host 0.0.0.0" not in PS1
    assert "$env:CORVEX_TRUSTED_PROXIES = Get-TrustedList" in PS1
    assert "over plain HTTP" in PS1 and "choose their own X-Forwarded-For" in PS1
    assert 'if ($PublishMobile) { $a += @("-f", $MobileFile) }' in PS1


def test_install_ps1_validation_regexes_behave_like_install_sh():
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

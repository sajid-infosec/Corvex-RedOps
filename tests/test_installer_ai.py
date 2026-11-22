"""The local AI model, on request and proven: install.sh asks only in a terminal (Y installs,
Enter or anything else skips; no terminal = no AI unless --ai), checks memory and disk first,
skips the download when the model is already there, and prints "AI: ready" only after
`corvex ai-check` proved the status and a real narrative; on failure it says what failed and
switches AI off again (reports work without it)."""
import os
import pty
import re
import select
import subprocess
import sys
import time
from pathlib import Path

import pytest

ROOT = Path(__file__).resolve().parents[1]
# Never reach this machine's Docker, services or sudo from a test, whatever installer function runs.
_GUARD = ('docker(){ echo "docker $*" >> "${CORVEX_TEST_DOCKER_LOG:-/dev/null}"; return 1; }; '
          'systemctl(){ return 1; }; sudo(){ return 1; }; runuser(){ return 1; }; ')
SH = (ROOT / "install.sh").read_text(encoding="utf-8")
PROMPT = "Install the local AI model? About 5 GB download, needs 8 GB free memory. [y/N]"

pytestmark = pytest.mark.skipif(sys.platform == "win32",
                                reason="drives install.sh through a POSIX bash (Windows installs with install.ps1)")


def _cmd(tmp_path, args, script):
    return (f'source "{ROOT}/install.sh"; {_GUARD}SUDO=""; ENV_FILE="{tmp_path}/deploy/.env"; '
            f'docker_state(){{ echo missing; }}; detect_distro; parse_args {args}; {script}')


def _sh(tmp_path, script, args="", extra_env=None, stdin=subprocess.DEVNULL):
    env = {**os.environ, "CORVEX_INSTALL_SOURCE_ONLY": "1", "NO_COLOR": "1", **(extra_env or {})}
    return subprocess.run(["bash", "-c", _cmd(tmp_path, args, script)], capture_output=True, text=True,
                          env=env, timeout=60, stdin=stdin, encoding="utf-8", errors="replace")


def _in_terminal(tmp_path, script, answer, args=""):
    """Run in a pseudo-terminal (stdin and stdout are a tty) and type `answer` at the prompt."""
    env = {**os.environ, "CORVEX_INSTALL_SOURCE_ONLY": "1", "NO_COLOR": "1"}
    master, slave = pty.openpty()
    p = subprocess.Popen(["bash", "-c", _cmd(tmp_path, args, script)], stdin=slave, stdout=slave,
                         stderr=slave, env=env, close_fds=True)
    os.close(slave)
    out, sent, end = b"", False, time.time() + 30
    poller = select.poll()                 # not select(): fds above 1024 are fine in a long suite
    poller.register(master, select.POLLIN)
    while time.time() < end:
        r = poller.poll(200)
        if r:
            try:
                chunk = os.read(master, 4096)
            except OSError:
                break
            if not chunk:
                break
            out += chunk
        if not sent and PROMPT.encode() in out:
            os.write(master, answer.encode()); sent = True
        if p.poll() is not None and not r:
            break
    p.wait(10); os.close(master)
    return out.decode("utf-8", "replace")


@pytest.mark.parametrize("answer,expected", [("y\n", "1"), ("Y\n", "1"), ("yes\n", "1"),
                                             ("\n", "0"), ("n\n", "0"), ("maybe\n", "0")])
def test_a_terminal_is_asked_and_only_yes_installs(tmp_path, answer, expected):
    out = _in_terminal(tmp_path, 'decide_ai; echo "AI_CHOICE=$AI_CHOICE"', answer)
    assert PROMPT in out
    assert f"AI_CHOICE={expected}" in out


def test_no_terminal_means_no_ai_and_no_question(tmp_path):
    r = _sh(tmp_path, 'decide_ai; echo "AI_CHOICE=$AI_CHOICE"')
    assert "AI_CHOICE=0" in r.stdout and PROMPT not in r.stdout


def test_flags_decide_without_asking(tmp_path):
    assert "AI_CHOICE=1" in _in_terminal(tmp_path, 'decide_ai; echo "AI_CHOICE=$AI_CHOICE"', "n\n", args="--ai")
    out = _in_terminal(tmp_path, 'decide_ai; echo "AI_CHOICE=$AI_CHOICE"', "y\n", args="--no-ai")
    assert "AI_CHOICE=0" in out and PROMPT not in out


def test_an_install_that_already_runs_the_model_keeps_it(tmp_path):
    (tmp_path / "deploy").mkdir(); (tmp_path / "deploy/.env").write_text("CORVEX_AI=1\n")
    r = _sh(tmp_path, 'decide_ai; echo "AI_CHOICE=$AI_CHOICE"')
    assert "AI_CHOICE=1" in r.stdout and "Keeping the local AI model" in r.stdout


def test_native_installs_skip_the_model_and_say_how_to_add_it(tmp_path):
    r = _sh(tmp_path, 'decide_ai; echo "AI_CHOICE=$AI_CHOICE STATUS=$AI_STATUS"', args="--native --ai")
    assert "AI_CHOICE=0" in r.stdout and "needs Docker" in r.stdout and "--docker --ai" in r.stdout


def test_short_memory_or_disk_skips_with_an_explanation(tmp_path):
    r = _sh(tmp_path, 'ai_resources_ok || echo "SKIP: $AI_STATUS"', extra_env={"CORVEX_TEST_MEM_MB": "4000"})
    assert "SKIP: skipped: only 4000 MB of memory is free; the local model needs 8192 MB" in r.stdout
    r = _sh(tmp_path, 'ai_resources_ok || echo "SKIP: $AI_STATUS"',
            extra_env={"CORVEX_TEST_MEM_MB": "16000", "CORVEX_TEST_DISK_MB": "3000"})
    assert "SKIP: skipped: only 3000 MB of disk is free" in r.stdout


def _install_ai(tmp_path, present, check_ok, pull_ok=True):
    (tmp_path / "deploy").mkdir(exist_ok=True)
    (tmp_path / "deploy/.env").write_text("CORVEX_AI=0\nCORVEX_AI_MODEL=qwen2.5:7b-instruct\n")
    log = tmp_path / "calls"
    script = f'''
      ENGINE_USED=docker; AI_CHOICE=1; AI_MODEL=qwen2.5:0.5b
      wait_healthy(){{ return 0; }}
      compose(){{ echo "compose $*" >> "{log}"
        case "$*" in
          "exec -T ai ollama list") printf 'NAME ID SIZE\\n{"qwen2.5:0.5b" if present else "other:1b"} abc 1GB\\n';;
          "exec -T ai ollama pull "*) return {0 if pull_ok else 1};;
          "exec -T console corvex ai-check") {"echo 'AI: ready'" if check_ok else "echo 'AI check failed: the model qwen2.5:0.5b returned no narrative for a sample finding (no answer within 300 s)'; return 1"};;
        esac; return 0; }}
      install_ai; echo "STATUS=$AI_STATUS"; grep CORVEX_AI= "$ENV_FILE"'''
    r = _sh(tmp_path, script, extra_env={"CORVEX_TEST_MEM_MB": "16000", "CORVEX_TEST_DISK_MB": "50000"})
    return r, log.read_text().splitlines()


def test_model_already_present_skips_the_download_and_is_proven(tmp_path):
    r, calls = _install_ai(tmp_path, present=True, check_ok=True)
    assert not any("ollama pull" in c for c in calls)
    assert "already downloaded — skipping the download" in r.stdout
    assert "STATUS=ready" in r.stdout and "CORVEX_AI=1" in r.stdout
    # order: runtime up, AI switched on + console restarted, then the end-to-end check
    up_console = calls.index("compose up -d --no-deps console")
    assert calls.index("compose up -d ai") < up_console < calls.index("compose exec -T console corvex ai-check")
    assert r.stdout.index("AI: ready") > r.stdout.index("Checking the AI end to end")


def test_missing_model_is_downloaded_with_visible_progress(tmp_path):
    r, calls = _install_ai(tmp_path, present=False, check_ok=True)
    assert "compose exec -T ai ollama pull qwen2.5:0.5b" in calls       # no output capture: progress shows
    assert "STATUS=ready" in r.stdout


def test_a_failed_check_says_what_failed_and_switches_ai_off(tmp_path):
    r, calls = _install_ai(tmp_path, present=True, check_ok=False)
    assert "STATUS=failed: the model qwen2.5:0.5b returned no narrative" in r.stdout
    assert "Reports still work without AI" in r.stdout + r.stderr and "AI: ready" not in r.stdout
    assert "CORVEX_AI=0" in r.stdout and "compose stop ai" in calls


def test_a_failed_download_is_reported_too(tmp_path):
    r, _ = _install_ai(tmp_path, present=False, check_ok=True, pull_ok=False)
    assert "STATUS=failed: the model qwen2.5:0.5b could not be downloaded" in r.stdout and "CORVEX_AI=0" in r.stdout


def test_ai_is_decided_before_anything_changes_and_installed_after_the_stack_is_healthy():
    main = SH[SH.index("main() {"):]
    assert main.index("preflight") < main.index("decide_ai") < main.index("install_base") < main.index("install_ai")
    assert 'AI_MODEL="${CORVEX_AI_MODEL:-' in SH              # tiny model override (CI)


def test_install_ps1_asks_the_same_question_and_explains_native():
    ps1 = (ROOT / "install.ps1").read_text(encoding="utf-8")
    assert PROMPT in ps1 and "[Environment]::UserInteractive" in ps1
    assert "needs Docker" in ps1 and "-Docker -Ai" in ps1
    assert "corvex ai-check" in ps1 and "AI: ready" in ps1

"""`corvex ai-check` (what the installer runs before printing "AI: ready"): it passes only when
the runtime is reachable, the exact model is pulled, and the model itself writes a narrative for
a sample finding; otherwise it says which step failed."""
import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from typer.testing import CliRunner

from pentestiq.ai.provider import model_matches
from pentestiq.cli import app


def _fake_runtime(models, answer):
    class H(BaseHTTPRequestHandler):
        def _send(self, obj):
            body = json.dumps(obj).encode()
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.send_header("Content-Length", str(len(body))); self.end_headers(); self.wfile.write(body)

        def do_GET(self):
            self._send({"models": [{"name": m} for m in models]})

        def do_POST(self):
            self.rfile.read(int(self.headers.get("Content-Length") or 0))
            self._send({"message": {"role": "assistant", "content": answer}})

        def log_message(self, *a):
            pass
    srv = ThreadingHTTPServer(("127.0.0.1", 0), H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    return srv


@pytest.fixture
def runtime(monkeypatch):
    servers = []

    def start(models, answer, model="qwen2.5:0.5b"):
        srv = _fake_runtime(models, answer); servers.append(srv)
        monkeypatch.setenv("PENTESTIQ_AI", "1")
        monkeypatch.setenv("OLLAMA_URL", f"http://127.0.0.1:{srv.server_address[1]}")
        monkeypatch.setenv("PENTESTIQ_AI_MODEL", model)
        return srv
    yield start
    for s in servers:
        s.shutdown()


def _check():
    return CliRunner().invoke(app, ["ai-check", "--timeout", "10"])


def test_ready_only_with_a_real_narrative_from_the_model(runtime):
    runtime(["qwen2.5:0.5b"], "The assessment found a high-risk SQL injection in the search feature.")
    r = _check()
    assert r.exit_code == 0, r.output
    assert "available=True" in r.output and "model_present=True" in r.output
    assert "high-risk SQL injection" in r.output and r.output.rstrip().endswith("AI: ready")


def test_a_model_that_is_not_pulled_fails_and_says_so(runtime):
    runtime(["qwen2.5:0.5b"], "x", model="qwen2.5:7b-instruct")
    r = _check()
    assert r.exit_code == 1 and "AI check failed: the model qwen2.5:7b-instruct is not downloaded" in r.output
    assert "AI: ready" not in r.output


def test_an_empty_answer_is_not_a_narrative(runtime):
    runtime(["qwen2.5:0.5b"], "")
    r = _check()
    assert r.exit_code == 1 and "returned no narrative for a sample finding" in r.output


def test_ai_off_and_no_runtime_say_exactly_what_failed(monkeypatch):
    monkeypatch.setenv("PENTESTIQ_AI", "0")
    assert "AI check failed: AI is switched off" in _check().output
    monkeypatch.setenv("PENTESTIQ_AI", "1"); monkeypatch.setenv("OLLAMA_URL", "http://127.0.0.1:9")
    assert "AI check failed: the AI runtime is not reachable at http://127.0.0.1:9" in _check().output


def test_model_names_match_exactly():
    assert model_matches("qwen2.5:0.5b", ["qwen2.5:0.5b"])
    assert not model_matches("qwen2.5:7b-instruct", ["qwen2.5:0.5b"])     # used to count as present
    assert model_matches("llama3", ["llama3:latest"]) and not model_matches("llama3:8b", ["llama3:latest"])

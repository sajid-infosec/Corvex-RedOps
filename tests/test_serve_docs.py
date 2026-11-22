"""The docs give `serve` (and the single-file binary) its real default address, 127.0.0.1:8000;
the Docker / installer console stays on 8080."""
import inspect
import re
from pathlib import Path

from pentestiq import cli

ROOT = Path(__file__).resolve().parents[1]


def test_serve_defaults_are_127_0_0_1_and_8000():
    p = inspect.signature(cli.serve).parameters
    assert (p["host"].default.default, p["port"].default.default) == ("127.0.0.1", 8000)


def test_docs_never_put_serve_on_8080_unless_the_port_is_given():
    for name in ("README.md", "INSTALL.md", "docs/QA_GUIDE.md"):
        for n, line in enumerate((ROOT / name).read_text(encoding="utf-8").splitlines(), 1):
            if re.search(r"\bserve\b", line) and "8080" in line:
                assert "--port 8080" in line, f"{name}:{n}: {line.strip()}"
    install = (ROOT / "INSTALL.md").read_text(encoding="utf-8")
    assert "`pentestiq serve` → http://127.0.0.1:8000" in install
    assert "serve          # console at http://127.0.0.1:8000" in install
    assert "docker compose up -d --build         # console on 127.0.0.1:8080" in install       # Docker unchanged

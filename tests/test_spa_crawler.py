"""Headless SPA crawler test — renders JS DOM and captures XHR endpoints.

Skips automatically where Playwright / a browser isn't installed (e.g. CI without
the optional dep), like any other optional-tool integration.
"""
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest

# Needs a real headless browser — opt-in (run with `pytest -m live`), and re-enables
# SPA crawling that the default test env disables via CORVEX_SPA_CRAWL=0.
pytestmark = pytest.mark.live

pytest.importorskip("playwright.sync_api")
from pentestiq.crawler import SpaCrawler

if not SpaCrawler.is_available():
    pytest.skip("Playwright browser not available", allow_module_level=True)


@pytest.fixture(autouse=True)
def _enable_spa(monkeypatch):
    # The default test env disables SPA crawling; these tests exercise it.
    monkeypatch.setenv("CORVEX_SPA_CRAWL", "1")


_SPA = (b"<html><body><div id=app></div><script>"
        b"document.getElementById('app').innerHTML="
        b"'<a href=\"/#/dashboard\">dash</a>"
        b"<form action=\"/api/login\" method=\"post\"><input name=\"user\"></form>';"
        b"fetch('/api/v1/profile');"
        b"</script></body></html>")


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        if self.path.startswith("/api/"):
            self.send_response(200); self.send_header("Content-Type", "application/json")
            self.end_headers(); self.wfile.write(b'{"ok":true}')
        else:
            self.send_response(200); self.send_header("Content-Type", "text/html")
            self.end_headers(); self.wfile.write(_SPA)


@pytest.fixture
def spa_server():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}/"
    srv.shutdown()


def test_spa_crawler_captures_rendered_dom_and_xhr(spa_server):
    result = SpaCrawler(max_pages=5, settle_ms=600).crawl(spa_server)
    # the XHR endpoint only exists after JS runs — proves headless rendering
    assert any(u.endswith("/api/v1/profile") for u in result.js_endpoints), \
        f"expected /api/v1/profile in {result.js_endpoints}"
    # a form rendered by JS was captured
    login = [f for f in result.forms if f.action.endswith("/api/login")]
    assert login and login[0].inputs == ["user"]
    assert result.stats["engine"] == "spa"

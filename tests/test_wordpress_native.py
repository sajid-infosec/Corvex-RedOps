"""Native WordPress checks — must find issues with no external tools (no WPScan)."""
from __future__ import annotations

from pentestiq.checks.base import HttpClient, Response
from pentestiq.checks.wordpress_checks import WordPressNativeChecks
from pentestiq.models import Asset, AssetType


class WpSite(HttpClient):
    """A canned vulnerable WordPress site."""
    def request(self, method, url, headers=None, data=None):
        from urllib.parse import urlsplit
        p = (urlsplit(url).path or "/")
        q = urlsplit(url).query
        if p == "/" and not q:
            return self._r(200, '<html><head><meta name="generator" content="WordPress 6.2.1">'
                                '</head><body>wp-content</body></html>')
        if p == "/wp-login.php":
            return self._r(200, '<form><input name="user_login"></form>')
        if p == "/wp-json/":
            return self._r(200, '{"namespaces":["wp/v2"]}', "application/json")
        if p == "/wp-json/wp/v2/users":
            return self._r(200, '[{"id":1,"slug":"admin"},{"id":2,"slug":"editor"}]', "application/json")
        if p == "/xmlrpc.php":
            return self._r(405, "XML-RPC server accepts POST requests only.")
        if p == "/wp-content/debug.log":
            return self._r(200, "[08-Sep-2026] PHP Notice: ... debug data")
        if p == "/readme.html":
            return self._r(200, "<html><body>Version 6.2.1</body></html>")
        return self._r(404, "not found")

    def get(self, url, headers=None):
        return self.request("GET", url, headers)

    @staticmethod
    def _r(status, text, ctype="text/html"):
        return Response(status=status, headers={"content-type": ctype}, text=text,
                        elapsed_ms=1.0, url="http://wp.test/")


class _Ctx:
    class _L:
        def info(self, *a, **k): pass
        def error(self, *a, **k): pass
        def warning(self, *a, **k): pass
    logger = _L()
    rate_limiter = None
    def __init__(self, http):
        self.extra = {"checks_http_client": http}


def _findings():
    asset = Asset(type=AssetType.WORDPRESS, identifier="http://wp.test/", metadata={})
    return WordPressNativeChecks().scan(asset, _Ctx(WpSite()))


def test_wordpress_native_detects_and_reports():
    fs = _findings()
    titles = " | ".join(f.title for f in fs)
    assert "WordPress detected" in titles
    assert "version 6.2.1" in titles.lower() or "6.2.1" in titles
    assert any("user enumeration" in f.title.lower() for f in fs)
    assert any("xml-rpc" in f.title.lower() for f in fs)
    assert any("debug log" in f.title.lower() for f in fs)


def test_wordpress_native_user_enum_severity_and_users():
    fs = _findings()
    enum = [f for f in fs if "user enumeration" in f.title.lower()][0]
    assert enum.severity.value == "medium"
    ev = " ".join(e.ref + (e.description or "") for e in enum.evidence)
    assert "admin" in ev and "editor" in ev


def test_wordpress_native_non_wp_site_is_quiet():
    class Empty(HttpClient):
        def request(self, m, url, headers=None, data=None):
            return Response(status=404, headers={}, text="", elapsed_ms=1.0, url=url)
        def get(self, url, headers=None):
            return self.request("GET", url, headers)
    asset = Asset(type=AssetType.WORDPRESS, identifier="http://plain.test/", metadata={})
    fs = WordPressNativeChecks().scan(asset, _Ctx(Empty()))
    # no WP signals, nothing exposed -> no findings (no false positives)
    assert fs == []

"""Tests for the native web crawler."""
from urllib.parse import urlsplit

from pentestiq.checks.base import HttpClient, Response
from pentestiq.crawler import Crawler
from pentestiq.crawler.model import templatize_path, normalize_url
from pentestiq.crawler.parser import parse_html, extract_js_endpoints


class SiteHttp(HttpClient):
    """Serves a canned multi-page site keyed by path."""
    def __init__(self, pages):
        self.pages = pages
        self.hits = []

    def request(self, method, url, headers=None, data=None):
        self.hits.append(url)
        path = urlsplit(url).path or "/"
        body, ctype = self.pages.get(path, (None, None))
        if body is None:
            return Response(status=404, headers={}, text="", elapsed_ms=1.0, url=url)
        return Response(status=200, headers={"content-type": ctype}, text=body,
                        elapsed_ms=1.0, url=url)

    def get(self, url, headers=None):
        return self.request("GET", url, headers)


SITE = {
    "/": ('<html><body>'
          '<a href="/about">about</a>'
          '<a href="/user/42">user</a>'
          '<a href="/search?q=x">search</a>'
          '<a href="http://evil.com/x">ext</a>'
          '<form action="/login" method="post">'
          '<input name="username"><input name="password"></form>'
          '<script src="/app.js"></script>'
          '</body></html>', "text/html"),
    "/about": ('<html><body><a href="/">home</a>'
               '<a href="/user/99">u99</a></body></html>', "text/html"),
    "/user/42": ('<html><body>user 42</body></html>', "text/html"),
    "/user/99": ('<html><body>user 99</body></html>', "text/html"),
    "/search": ('<html><body>results</body></html>', "text/html"),
    "/app.js": ('const a=fetch("/api/v1/users");'
                'const b="/api/v1/orders/{id}";'
                'const c="https://cdn.evil.com/x.js";'
                'img="/logo.png";', "application/javascript"),
}


def test_crawler_discovers_pages_forms_and_scope():
    http = SiteHttp(SITE)
    r = Crawler(http=http).crawl("http://app.test/")
    paths = sorted(urlsplit(u).path for u in r.urls)
    assert "/" in paths and "/about" in paths and "/user/42" in paths and "/search" in paths
    # external host is out of scope
    assert not any("evil.com" in u for u in r.urls)
    # form captured with inputs
    login = [f for f in r.forms if f.action.endswith("/login")]
    assert login and login[0].method == "POST"
    assert set(login[0].inputs) == {"username", "password"}
    # query params recorded
    assert any("q" in names for names in r.params.values())


def test_crawler_templatizes_ids_and_finds_idor():
    r = Crawler(http=SiteHttp(SITE)).crawl("http://app.test/")
    templates = r.endpoint_templates()
    assert "/user/{id}" in templates          # /user/42 and /user/99 collapse
    assert "/user/{id}" in r.idor_endpoints()
    assert "/about" in r.data_endpoints()


def test_crawler_extracts_js_endpoints():
    r = Crawler(http=SiteHttp(SITE)).crawl("http://app.test/")
    eps = [urlsplit(u).path for u in r.js_endpoints]
    assert "/api/v1/users" in eps
    assert "/api/v1/orders/{id}" in eps
    # asset noise (.png) is excluded from JS endpoints
    assert not any(p.endswith(".png") for p in eps)


def test_crawler_respects_page_limit():
    http = SiteHttp(SITE)
    r = Crawler(http=http, max_pages=2).crawl("http://app.test/")
    assert r.stats["pages_crawled"] <= 2


def test_crawler_respects_depth_limit():
    http = SiteHttp(SITE)
    r = Crawler(http=http, max_depth=0).crawl("http://app.test/")
    # depth 0 -> only the seed page is crawled
    assert r.stats["pages_crawled"] == 1


def test_parser_and_helpers():
    links, scripts, forms = parse_html(
        '<a href="/x">x</a><script src="/y.js"></script>'
        '<form action="/f"><input name="a"></form>', "http://h/")
    assert "http://h/x" in links and "http://h/y.js" in scripts
    assert forms[0].inputs == ["a"]
    assert templatize_path("/user/550e8400-e29b-41d4-a716-446655440000") == "/user/{id}"
    assert normalize_url("http://h/a/#frag") == "http://h/a"
    eps = extract_js_endpoints('x=fetch("/api/z");y="/img/a.png"', "http://h/")
    assert any(e.endswith("/api/z") for e in eps)

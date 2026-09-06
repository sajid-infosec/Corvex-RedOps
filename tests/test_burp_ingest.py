"""Burp Suite XML importer."""
import base64
from pentestiq.api.burp_ingest import build_burp_metadata


def _item(host, method, path, auth=None, proto="https"):
    req = f"{method} {path} HTTP/1.1\r\nHost: {host}\r\n"
    if auth:
        req += f"Authorization: {auth}\r\n"
    req += "\r\n"
    b64 = base64.b64encode(req.encode()).decode()
    return (f"<item><host>{host}</host><protocol>{proto}</protocol>"
            f"<method>{method}</method><path><![CDATA[{path}]]></path>"
            f'<request base64="true">{b64}</request></item>')


def _write(tmp_path, items):
    p = tmp_path / "burp.xml"
    p.write_text("<?xml version='1.0'?><items>" + "".join(items) + "</items>")
    return str(p)


def test_burp_extracts_endpoints_params_tokens(tmp_path):
    items = [
        _item("app.target.com", "GET", "/api/user/42?tab=profile",
              auth="Bearer tokAAA"),
        _item("app.target.com", "GET", "/api/user/99", auth="Bearer tokBBB"),
        _item("app.target.com", "GET", "/search?q=x&page=2"),
        _item("www.google-analytics.com", "POST", "/collect"),   # noise, filtered
    ]
    base, meta = build_burp_metadata(_write(tmp_path, items),
                                     scope_hosts=["target.com"], allow_active=True)
    assert base == "https://app.target.com"
    assert "/api/user/{id}" in meta["idor_endpoints"]
    assert meta["allow_active"] is True
    # two distinct bearer tokens -> two identities
    assert len(meta["identities"]) == 2
    assert meta["jwt"] == "tokAAA"
    # analytics host excluded
    assert all("google" not in u for u in meta["discovered_urls"])
    # query params captured
    assert any("q" in v for v in meta["params"].values())


def test_burp_auto_scope_picks_busiest_non_noise_host(tmp_path):
    items = [_item("mixpanel.com", "POST", "/track") for _ in range(3)]
    items += [_item("app.real.com", "GET", f"/p/{i}") for i in range(5)]
    base, meta = build_burp_metadata(_write(tmp_path, items))
    assert "real.com" in base

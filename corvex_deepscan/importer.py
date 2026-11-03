"""Import captured traffic from a HAR file into the flow store.

This gives the Deep Scan engine a proxy-independent ingestion path: traffic
exported from a browser's devtools, another proxy, or your existing capture can
be analyzed without running the interceptor.
"""
from __future__ import annotations

import json
from urllib.parse import urlsplit

from .models import CapturedRequest, CapturedResponse, Flow
from .store import FlowStore


def _headers(entries) -> list[tuple[str, str]]:
    return [(h.get("name", ""), h.get("value", "")) for h in entries or []]


def _port(url: str, scheme: str) -> int:
    parts = urlsplit(url)
    if parts.port:
        return parts.port
    return 443 if scheme == "https" else 80


def flow_from_har_entry(entry: dict) -> Flow:
    req = entry.get("request", {})
    resp = entry.get("response", {})
    url = req.get("url", "")
    parts = urlsplit(url)
    scheme = parts.scheme or "http"

    creq = CapturedRequest(
        method=req.get("method", "GET"),
        url=url,
        scheme=scheme,
        host=parts.hostname or "",
        port=_port(url, scheme),
        path=parts.path or "/",
        query=[(q.get("name", ""), q.get("value", ""))
               for q in req.get("queryString", [])],
        headers=_headers(req.get("headers")),
        body=(req.get("postData", {}) or {}).get("text", "") or "",
    )
    cresp = None
    if resp and resp.get("status"):
        content = resp.get("content", {}) or {}
        cresp = CapturedResponse(
            status_code=resp.get("status", 0),
            reason=resp.get("statusText", ""),
            headers=_headers(resp.get("headers")),
            body=content.get("text", "") or "",
            mime=content.get("mimeType", ""),
        )
    return Flow(request=creq, response=cresp,
                duration_ms=float(entry.get("time", 0) or 0))


def import_har(path: str, store: FlowStore) -> int:
    with open(path, "r", encoding="utf-8", errors="replace") as fh:
        data = json.load(fh)
    entries = data.get("log", {}).get("entries", [])
    n = 0
    for entry in entries:
        try:
            store.save_flow(flow_from_har_entry(entry))
            n += 1
        except Exception:
            continue
    return n

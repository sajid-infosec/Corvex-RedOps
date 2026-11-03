"""Serializable capture model, decoupled from any specific proxy backend.

The whole analysis layer consumes these objects, so flows can come from the
intercepting proxy, a HAR import, or any other source without the analyzers
knowing or caring.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field
from typing import Optional

from .utils import header_get, parse_cookie_header, parse_set_cookie


@dataclass
class CapturedRequest:
    method: str
    url: str
    scheme: str
    host: str
    port: int
    path: str
    query: list[tuple[str, str]] = field(default_factory=list)
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    body_truncated: bool = False
    timestamp: float = field(default_factory=time.time)

    @property
    def cookies(self) -> list[tuple[str, str]]:
        return parse_cookie_header(header_get(self.headers, "cookie") or "")

    @property
    def content_type(self) -> str:
        return (header_get(self.headers, "content-type") or "").split(";")[0].strip()

    @property
    def endpoint(self) -> str:
        """Stable key for grouping: METHOD scheme://host[:port]/path (no query)."""
        return f"{self.method} {self.scheme}://{self.host}:{self.port}{self.path}"


@dataclass
class CapturedResponse:
    status_code: int
    reason: str = ""
    headers: list[tuple[str, str]] = field(default_factory=list)
    body: str = ""
    body_truncated: bool = False
    mime: str = ""
    timestamp: float = field(default_factory=time.time)

    @property
    def set_cookies(self) -> list[dict]:
        from .utils import header_all
        return [parse_set_cookie(v) for v in header_all(self.headers, "set-cookie")]


@dataclass
class Flow:
    request: CapturedRequest
    response: Optional[CapturedResponse] = None
    id: Optional[int] = None
    duration_ms: float = 0.0

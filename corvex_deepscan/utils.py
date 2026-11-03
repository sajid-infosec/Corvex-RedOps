"""Low-level helpers shared across the engine (no third-party deps)."""
from __future__ import annotations

import base64
import json
import math
import re
from collections import Counter
from typing import Iterable, Optional

# ----------------------------------------------------------------------------
# Headers / cookies
# ----------------------------------------------------------------------------

def header_get(headers: Iterable[tuple[str, str]], name: str) -> Optional[str]:
    """Case-insensitive single header lookup. Returns the first match."""
    name_l = name.lower()
    for k, v in headers:
        if k.lower() == name_l:
            return v
    return None


def header_all(headers: Iterable[tuple[str, str]], name: str) -> list[str]:
    name_l = name.lower()
    return [v for k, v in headers if k.lower() == name_l]


def parse_cookie_header(value: str) -> list[tuple[str, str]]:
    """Parse a `Cookie:` request header into (name, value) pairs."""
    out: list[tuple[str, str]] = []
    if not value:
        return out
    for part in value.split(";"):
        part = part.strip()
        if not part:
            continue
        if "=" in part:
            k, v = part.split("=", 1)
            out.append((k.strip(), v.strip()))
        else:
            out.append((part, ""))
    return out


def parse_set_cookie(value: str) -> dict:
    """Parse a single Set-Cookie header into name/value + attribute flags."""
    pieces = [p.strip() for p in value.split(";") if p.strip()]
    if not pieces:
        return {}
    name, _, val = pieces[0].partition("=")
    attrs = {p.split("=", 1)[0].lower(): (p.split("=", 1)[1] if "=" in p else True)
             for p in pieces[1:]}
    return {
        "name": name.strip(),
        "value": val.strip(),
        "httponly": "httponly" in attrs,
        "secure": "secure" in attrs,
        "samesite": attrs.get("samesite"),
        "domain": attrs.get("domain"),
        "path": attrs.get("path"),
        "expires": attrs.get("expires"),
        "raw": value,
    }


# ----------------------------------------------------------------------------
# Entropy / secret handling
# ----------------------------------------------------------------------------

def shannon_entropy(s: str) -> float:
    if not s:
        return 0.0
    counts = Counter(s)
    length = len(s)
    return -sum((c / length) * math.log2(c / length) for c in counts.values())


def mask_secret(s: str, keep: int = 4) -> str:
    """Mask the middle of a secret so reports can be shared safely."""
    if s is None:
        return ""
    s = str(s)
    if len(s) <= keep * 2:
        return "*" * len(s)
    return f"{s[:keep]}{'*' * (len(s) - keep * 2)}{s[-keep:]}"


# ----------------------------------------------------------------------------
# JWT
# ----------------------------------------------------------------------------

JWT_RE = re.compile(r"eyJ[A-Za-z0-9_-]{4,}\.eyJ[A-Za-z0-9_-]{4,}\.[A-Za-z0-9_-]*")


def _b64url_decode(seg: str) -> bytes:
    pad = "=" * (-len(seg) % 4)
    return base64.urlsafe_b64decode(seg + pad)


def decode_jwt(token: str) -> Optional[dict]:
    """Decode a JWT's header + payload without verifying the signature."""
    parts = token.split(".")
    if len(parts) < 2:
        return None
    try:
        header = json.loads(_b64url_decode(parts[0]))
        payload = json.loads(_b64url_decode(parts[1]))
    except Exception:
        return None
    return {"header": header, "payload": payload,
            "alg": header.get("alg"), "has_signature": len(parts) == 3 and bool(parts[2])}


# ----------------------------------------------------------------------------
# Content helpers
# ----------------------------------------------------------------------------

_TEXTUAL_HINTS = ("text/", "json", "xml", "html", "javascript", "x-www-form",
                  "csv", "yaml", "graphql")


def is_textual(mime: str) -> bool:
    if not mime:
        return True
    m = mime.lower()
    return any(h in m for h in _TEXTUAL_HINTS)


def safe_json(text: str):
    try:
        return json.loads(text)
    except Exception:
        return None


def flatten_json(obj, prefix: str = "") -> list[tuple[str, str]]:
    """Flatten a JSON structure into (dotted.key, value) string pairs."""
    out: list[tuple[str, str]] = []
    if isinstance(obj, dict):
        for k, v in obj.items():
            key = f"{prefix}.{k}" if prefix else str(k)
            out.extend(flatten_json(v, key))
    elif isinstance(obj, list):
        for i, v in enumerate(obj):
            out.extend(flatten_json(v, f"{prefix}[{i}]"))
    else:
        out.append((prefix, "" if obj is None else str(obj)))
    return out

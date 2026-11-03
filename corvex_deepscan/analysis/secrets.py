"""Detect secrets, tokens and credentials in captured traffic.

Everything here is passive: it only reads what the proxy already captured from
the tester's own authorized session. Values are masked in the returned records;
the full value stays in the flow store if the operator needs it for replay.
"""
from __future__ import annotations

import base64
import re
from dataclasses import dataclass, field

from ..models import Flow
from ..utils import (JWT_RE, decode_jwt, flatten_json, header_all, header_get,
                     is_textual, mask_secret, safe_json, shannon_entropy)

# High-signal provider patterns (name -> compiled regex)
PROVIDER_PATTERNS = {
    "aws_access_key": re.compile(r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA)[A-Z0-9]{16}\b"),
    "google_api_key": re.compile(r"\bAIza[0-9A-Za-z\-_]{35}\b"),
    "github_token": re.compile(r"\bgh[pousr]_[A-Za-z0-9]{36,255}\b"),
    "slack_token": re.compile(r"\bxox[baprs]-[0-9A-Za-z-]{10,}\b"),
    "stripe_key": re.compile(r"\b[sr]k_live_[0-9A-Za-z]{20,}\b"),
    "google_oauth": re.compile(r"\bya29\.[0-9A-Za-z\-_]+\b"),
    "private_key": re.compile(r"-----BEGIN (?:RSA |EC |OPENSSH |DSA |PGP )?PRIVATE KEY-----"),
    "twilio_sid": re.compile(r"\bAC[0-9a-fA-F]{32}\b"),
}

# Parameter / header names that indicate a credential by role
CREDENTIAL_NAMES = {"password", "passwd", "pwd", "pass", "passphrase",
                    "secret", "client_secret", "apikey", "api_key", "api-key",
                    "access_token", "refresh_token", "auth_token", "id_token",
                    "token", "sessionid", "session_id"}
USERNAME_NAMES = {"username", "user", "uname", "login", "email", "userid", "user_id"}
SENSITIVE_HEADERS = {"authorization", "x-api-key", "x-auth-token", "api-key",
                     "x-access-token", "cookie", "x-csrf-token", "proxy-authorization"}

SEVERITY = "critical"


@dataclass
class SecretHit:
    kind: str                 # jwt, bearer, basic-auth, provider:<name>, credential-field, high-entropy
    name: str                 # param/header/cookie name or token label
    masked_value: str
    location: str             # method + url
    where: str                # req-header / req-body / resp-header / resp-body / cookie
    severity: str = SEVERITY
    detail: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {"kind": self.kind, "name": self.name, "masked_value": self.masked_value,
                "location": self.location, "where": self.where,
                "severity": self.severity, "detail": self.detail}


def _scan_text_blob(text: str, location: str, where: str) -> list[SecretHit]:
    hits: list[SecretHit] = []
    if not text:
        return hits
    for name, rx in PROVIDER_PATTERNS.items():
        for m in rx.findall(text):
            val = m if isinstance(m, str) else m[0]
            hits.append(SecretHit(kind=f"provider:{name}", name=name,
                                   masked_value=mask_secret(val),
                                   location=location, where=where))
    for jwt in JWT_RE.findall(text):
        dec = decode_jwt(jwt)
        detail = {}
        if dec:
            detail = {"alg": dec.get("alg"), "claims": list(dec["payload"].keys())[:12]}
            for tc in ("exp", "iat", "sub", "iss", "aud", "role", "roles", "scope"):
                if tc in dec["payload"]:
                    detail[tc] = dec["payload"][tc]
        hits.append(SecretHit(kind="jwt", name="jwt", masked_value=mask_secret(jwt),
                              location=location, where=where, detail=detail))
    return hits


def _scan_headers(headers, location, where) -> list[SecretHit]:
    hits: list[SecretHit] = []
    for k, v in headers:
        kl = k.lower()
        if kl == "authorization":
            scheme, _, rest = v.partition(" ")
            sl = scheme.lower()
            if sl == "basic" and rest:
                try:
                    user, _, pw = base64.b64decode(rest).decode("utf-8", "replace").partition(":")
                    hits.append(SecretHit(kind="basic-auth", name="authorization",
                                          masked_value=f"{user}:{mask_secret(pw)}",
                                          location=location, where=where,
                                          detail={"username": user}))
                except Exception:
                    pass
            elif sl == "bearer" and rest:
                dec = decode_jwt(rest)
                kind = "jwt" if dec else "bearer"
                detail = {"alg": dec["alg"]} if dec else {}
                hits.append(SecretHit(kind=kind, name="authorization",
                                      masked_value=mask_secret(rest),
                                      location=location, where=where, detail=detail))
        elif kl in SENSITIVE_HEADERS and kl != "cookie" and v:
            hits.append(SecretHit(kind="credential-field", name=kl,
                                  masked_value=mask_secret(v),
                                  location=location, where=where))
    return hits


def _scan_named_pairs(pairs, location, where) -> list[SecretHit]:
    """Scan (name, value) pairs (query/form/json/cookie) for credential fields."""
    hits: list[SecretHit] = []
    for name, value in pairs:
        nl = str(name).lower().split(".")[-1].split("[")[0]
        if not value:
            continue
        if nl in CREDENTIAL_NAMES:
            hits.append(SecretHit(kind="credential-field", name=name,
                                  masked_value=mask_secret(value),
                                  location=location, where=where))
        elif nl in USERNAME_NAMES:
            hits.append(SecretHit(kind="username-field", name=name,
                                  masked_value=value if "@" not in value else
                                  mask_secret(value, keep=2),
                                  location=location, where=where, severity="low"))
        elif len(value) >= 20 and shannon_entropy(value) >= 4.0 and \
                re.fullmatch(r"[A-Za-z0-9+/_\-=.]+", value or ""):
            hits.append(SecretHit(kind="high-entropy", name=name,
                                  masked_value=mask_secret(value),
                                  location=location, where=where, severity="medium",
                                  detail={"entropy": round(shannon_entropy(value), 2)}))
    return hits


def _body_pairs(req) -> list[tuple[str, str]]:
    ct = req.content_type
    if "json" in ct:
        obj = safe_json(req.body)
        return flatten_json(obj) if obj is not None else []
    if "x-www-form-urlencoded" in ct and req.body:
        from urllib.parse import parse_qsl
        return parse_qsl(req.body, keep_blank_values=True)
    return []


def scan_flow(flow: Flow) -> list[SecretHit]:
    req, resp = flow.request, flow.response
    loc = f"{req.method} {req.url}"
    hits: list[SecretHit] = []

    hits += _scan_headers(req.headers, loc, "req-header")
    hits += _scan_named_pairs(req.query, loc, "req-query")
    hits += _scan_named_pairs(req.cookies, loc, "cookie")
    hits += _scan_named_pairs(_body_pairs(req), loc, "req-body")
    if is_textual(req.content_type):
        hits += _scan_text_blob(req.body, loc, "req-body")

    if resp:
        hits += _scan_headers(resp.headers, loc, "resp-header")
        if is_textual(resp.mime):
            hits += _scan_text_blob(resp.body, loc, "resp-body")
            obj = safe_json(resp.body)
            if obj is not None:
                hits += _scan_named_pairs(flatten_json(obj), loc, "resp-body")
    return hits


def scan_all(flows) -> list[SecretHit]:
    out: list[SecretHit] = []
    for f in flows:
        out.extend(scan_flow(f))
    # de-duplicate identical (kind, name, masked, location, where)
    seen = set()
    deduped = []
    for h in out:
        key = (h.kind, h.name, h.masked_value, h.location, h.where)
        if key not in seen:
            seen.add(key)
            deduped.append(h)
    return deduped

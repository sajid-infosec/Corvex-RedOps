"""Passive security checks.

These inspect responses already captured and raise findings without sending a
single crafted request. This is the safe, always-on layer; active probing is a
separate module that must be gated on explicit authorized scope.
"""
from __future__ import annotations

import re

from ..findings import Finding
from ..models import Flow
from ..utils import header_all, header_get, is_textual

ERROR_SIGNATURES = [
    (re.compile(r"Traceback \(most recent call last\)"), "Python traceback"),
    (re.compile(r"\bat [\w.$]+\([\w.]+\.java:\d+\)"), "Java stack trace"),
    (re.compile(r"You have an error in your SQL syntax"), "MySQL error"),
    (re.compile(r"\bORA-\d{5}\b"), "Oracle error"),
    (re.compile(r"PostgreSQL.*ERROR"), "PostgreSQL error"),
    (re.compile(r"System\.(?:Web|Data|NullReference)"), ".NET exception"),
    (re.compile(r"Warning: \w+\(\) \[<a href"), "PHP warning"),
    (re.compile(r"Microsoft OLE DB Provider"), "MSSQL/OLEDB error"),
    (re.compile(r"Index of /"), "Directory listing"),
]

SECURITY_HEADERS = {
    "strict-transport-security": ("missing-hsts", "Missing HSTS header", "low",
        "Set Strict-Transport-Security with a long max-age on HTTPS responses."),
    "content-security-policy": ("missing-csp", "Missing Content-Security-Policy", "low",
        "Define a Content-Security-Policy to mitigate XSS and data injection."),
    "x-content-type-options": ("missing-xcto", "Missing X-Content-Type-Options", "info",
        "Add 'X-Content-Type-Options: nosniff'."),
    "x-frame-options": ("missing-xfo", "Missing X-Frame-Options / frame-ancestors", "low",
        "Set X-Frame-Options: DENY or a CSP frame-ancestors directive."),
    "referrer-policy": ("missing-referrer-policy", "Missing Referrer-Policy", "info",
        "Set a Referrer-Policy such as 'strict-origin-when-cross-origin'."),
}


def _is_html_or_api(resp) -> bool:
    return is_textual(resp.mime) and resp.status_code and 200 <= resp.status_code < 400


def check_flow(flow: Flow) -> list[Finding]:
    req, resp = flow.request, flow.response
    out: list[Finding] = []
    if not resp:
        return out
    loc = f"{req.method} {req.url}"

    # --- security headers (only on substantive HTML/API responses) ---
    if _is_html_or_api(resp):
        present = {k.lower() for k, _ in resp.headers}
        for hdr, (fid, title, sev, remed) in SECURITY_HEADERS.items():
            if hdr == "strict-transport-security" and req.scheme != "https":
                continue
            if hdr not in present:
                out.append(Finding(id=fid, title=title, severity=sev, confidence="firm",
                                   category="config", location=loc, remediation=remed,
                                   evidence=f"Header '{hdr}' absent on {resp.status_code} response"))

    # --- cookie flags ---
    for sc in header_all(resp.headers, "set-cookie"):
        from ..utils import parse_set_cookie
        c = parse_set_cookie(sc)
        missing = [flag for flag, ok in
                   (("HttpOnly", c.get("httponly")), ("Secure", c.get("secure")),
                    ("SameSite", c.get("samesite"))) if not ok]
        if missing:
            out.append(Finding(id="weak-cookie-flags",
                               title=f"Cookie '{c.get('name')}' missing {', '.join(missing)}",
                               severity="low" if "HttpOnly" in missing else "info",
                               confidence="firm", category="config", location=loc,
                               evidence=f"Set-Cookie: {c.get('name')}=…; missing {', '.join(missing)}",
                               remediation="Set HttpOnly, Secure and SameSite on session cookies."))

    # --- CORS misconfiguration ---
    acao = header_get(resp.headers, "access-control-allow-origin")
    acac = header_get(resp.headers, "access-control-allow-credentials")
    origin = header_get(req.headers, "origin")
    if acao == "*" and acac and acac.lower() == "true":
        out.append(Finding(id="cors-wildcard-credentials",
                           title="CORS allows any origin with credentials",
                           severity="high", confidence="firm", category="config",
                           location=loc, evidence="ACAO: * with ACA-Credentials: true",
                           remediation="Never combine a wildcard ACAO with credentialed CORS."))
    elif origin and acao == origin and acac and acac.lower() == "true":
        out.append(Finding(id="cors-reflects-origin",
                           title="CORS reflects arbitrary Origin with credentials",
                           severity="medium", confidence="tentative", category="config",
                           location=loc, evidence=f"ACAO reflected request Origin '{origin}'",
                           remediation="Validate Origin against an allow-list before reflecting."))

    # --- version / tech disclosure ---
    for hk in ("server", "x-powered-by", "x-aspnet-version", "x-generator"):
        v = header_get(resp.headers, hk)
        if v and re.search(r"\d", v):
            out.append(Finding(id="version-disclosure",
                               title=f"Technology/version disclosure via '{hk}'",
                               severity="info", confidence="firm", category="config",
                               location=loc, evidence=f"{hk}: {v}",
                               remediation="Suppress or genericize version banners."))

    # --- verbose errors / listings in body ---
    if is_textual(resp.mime) and resp.body:
        head = resp.body[:8000]
        for rx, label in ERROR_SIGNATURES:
            if rx.search(head):
                out.append(Finding(id="verbose-error",
                                   title=f"Information disclosure: {label}",
                                   severity="medium", confidence="firm", category="config",
                                   location=loc, evidence=f"{label} present in response body",
                                   remediation="Return generic errors; disable debug output in production."))
                break

    # --- secrets in URL query string ---
    for k, _ in req.query:
        if k.lower() in {"password", "passwd", "pwd", "token", "access_token",
                         "api_key", "apikey", "secret"}:
            out.append(Finding(id="secret-in-url",
                               title=f"Sensitive parameter '{k}' sent in URL query string",
                               severity="medium", confidence="firm", category="config",
                               location=loc, evidence=f"Query parameter '{k}' in request URL",
                               remediation="Move credentials/tokens to headers or request body; URLs are logged."))
    return out


def check_all(flows: list[Flow]) -> list[Finding]:
    out: list[Finding] = []
    for f in flows:
        out.extend(check_flow(f))
    return out

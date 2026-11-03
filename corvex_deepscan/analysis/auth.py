"""Identify authentication mechanisms, locate auth endpoints, and reconstruct
sessions by grouping flows under the credential that carried them.

All passive: derived purely from captured headers/cookies/bodies.
"""
from __future__ import annotations

from collections import defaultdict
from dataclasses import dataclass, field

from ..models import Flow
from ..utils import decode_jwt, header_get, mask_secret

LOGIN_HINTS = ("login", "signin", "sign-in", "auth", "token", "oauth", "session",
               "authenticate", "connect/token")
SESSION_COOKIE_HINTS = ("session", "sess", "sid", "phpsessid", "jsessionid",
                        "asp.net_sessionid", "connect.sid", "auth", "token")
CREDENTIAL_BODY_HINTS = ("password", "passwd", "pwd", "client_secret")


@dataclass
class AuthSummary:
    schemes: dict = field(default_factory=dict)       # host -> set(schemes)
    login_endpoints: list = field(default_factory=list)
    sessions: list = field(default_factory=list)      # reconstructed sessions

    def to_dict(self) -> dict:
        return {
            "schemes": {h: sorted(s) for h, s in self.schemes.items()},
            "login_endpoints": self.login_endpoints,
            "sessions": self.sessions,
        }


def _detect_scheme(flow: Flow) -> set[str]:
    req = flow.request
    schemes: set[str] = set()
    auth = header_get(req.headers, "authorization")
    if auth:
        s = auth.split(" ", 1)[0].lower()
        if s == "bearer":
            rest = auth.split(" ", 1)[1] if " " in auth else ""
            schemes.add("jwt-bearer" if decode_jwt(rest) else "bearer-token")
        elif s == "basic":
            schemes.add("http-basic")
        else:
            schemes.add(f"authorization:{s}")
    for hk in ("x-api-key", "api-key", "x-auth-token", "x-access-token"):
        if header_get(req.headers, hk):
            schemes.add("api-key-header")
    for name, _ in req.cookies:
        if any(h in name.lower() for h in SESSION_COOKIE_HINTS):
            schemes.add("cookie-session")
            break
    return schemes


def _credential_token(flow: Flow) -> str | None:
    """Return a stable identifier of the credential used in this request, so
    requests sharing a credential can be grouped into a session."""
    req = flow.request
    auth = header_get(req.headers, "authorization")
    if auth and " " in auth:
        return "auth:" + auth.split(" ", 1)[1][:48]
    for hk in ("x-api-key", "api-key", "x-auth-token", "x-access-token"):
        v = header_get(req.headers, hk)
        if v:
            return f"{hk}:{v[:48]}"
    for name, value in req.cookies:
        if any(h in name.lower() for h in SESSION_COOKIE_HINTS) and value:
            return f"cookie:{name}:{value[:48]}"
    return None


def _looks_like_login(flow: Flow) -> bool:
    req, resp = flow.request, flow.response
    path = req.path.lower()
    path_hit = any(h in path for h in LOGIN_HINTS)
    body_hit = any(h in (req.body or "").lower() for h in CREDENTIAL_BODY_HINTS)
    issues_token = False
    if resp:
        if any(k.lower() == "set-cookie" for k, _ in resp.headers):
            issues_token = True
        if "token" in (resp.body or "")[:2000].lower():
            issues_token = True
    return (path_hit and (body_hit or issues_token)) or (body_hit and issues_token)


def analyze(flows: list[Flow]) -> AuthSummary:
    summary = AuthSummary()
    schemes: dict[str, set] = defaultdict(set)
    sessions: dict[str, dict] = {}

    for flow in flows:
        req = flow.request
        for s in _detect_scheme(flow):
            schemes[req.host].add(s)

        if _looks_like_login(flow):
            summary.login_endpoints.append({
                "endpoint": req.endpoint,
                "status": flow.response.status_code if flow.response else None,
            })

        cred = _credential_token(flow)
        if cred:
            sess = sessions.setdefault(cred, {
                "credential": cred.split(":", 1)[0] + ":" + mask_secret(cred.split(":", 1)[1]),
                "hosts": set(), "requests": 0,
                "first_ts": req.timestamp, "last_ts": req.timestamp,
            })
            sess["hosts"].add(req.host)
            sess["requests"] += 1
            sess["first_ts"] = min(sess["first_ts"], req.timestamp)
            sess["last_ts"] = max(sess["last_ts"], req.timestamp)

    summary.schemes = dict(schemes)
    # de-dupe login endpoints
    seen = set()
    uniq = []
    for e in summary.login_endpoints:
        if e["endpoint"] not in seen:
            seen.add(e["endpoint"])
            uniq.append(e)
    summary.login_endpoints = uniq
    summary.sessions = [
        {**s, "hosts": sorted(s["hosts"])} for s in sessions.values()
    ]
    return summary

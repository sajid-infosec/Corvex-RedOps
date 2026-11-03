"""Build a parameter catalog across all flows and flag reflected inputs.

Reflection is a passive indicator only: if a submitted parameter value appears
verbatim in the response body, that endpoint/param is worth active testing for
XSS / injection. The engine never sends a payload here.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from urllib.parse import parse_qsl

from ..models import Flow
from ..utils import flatten_json, is_textual, safe_json


@dataclass
class ParamRecord:
    name: str
    sources: set = field(default_factory=set)      # query / body-form / body-json / cookie
    endpoints: set = field(default_factory=set)    # endpoints where it appears
    example: str = ""
    reflected_at: set = field(default_factory=set)  # endpoints where value reflected

    def to_dict(self) -> dict:
        return {
            "name": self.name,
            "sources": sorted(self.sources),
            "endpoints": sorted(self.endpoints),
            "example": self.example,
            "reflected": sorted(self.reflected_at),
        }


def _request_params(req) -> list[tuple[str, str, str]]:
    """Return (name, value, source) across query, form body and json body."""
    out = [(k, v, "query") for k, v in req.query]
    ct = req.content_type
    if "json" in ct:
        obj = safe_json(req.body)
        if obj is not None:
            out += [(k, v, "body-json") for k, v in flatten_json(obj)]
    elif "x-www-form-urlencoded" in ct and req.body:
        out += [(k, v, "body-form") for k, v in parse_qsl(req.body, keep_blank_values=True)]
    out += [(k, v, "cookie") for k, v in req.cookies]
    return out


def build_catalog(flows: list[Flow]) -> dict[str, ParamRecord]:
    catalog: dict[str, ParamRecord] = {}
    for flow in flows:
        req, resp = flow.request, flow.response
        ep = req.endpoint
        body = resp.body if (resp and is_textual(resp.mime)) else ""
        for name, value, source in _request_params(req):
            leaf = str(name).split(".")[-1].split("[")[0]
            rec = catalog.setdefault(leaf, ParamRecord(name=leaf))
            rec.sources.add(source)
            rec.endpoints.add(ep)
            if value and not rec.example:
                rec.example = value[:80]
            # passive reflection check
            if value and len(value) >= 4 and body and value in body:
                rec.reflected_at.add(ep)
    return catalog


def reflected_params(catalog: dict[str, ParamRecord]) -> list[ParamRecord]:
    return [r for r in catalog.values() if r.reflected_at]

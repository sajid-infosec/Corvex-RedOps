"""Build a Burp-style site map / attack-surface tree from captured flows."""
from __future__ import annotations

from dataclasses import dataclass, field

from ..models import Flow


@dataclass
class EndpointNode:
    path: str
    methods: dict = field(default_factory=dict)   # method -> set(status codes)
    params: set = field(default_factory=set)
    content_types: set = field(default_factory=set)

    def to_dict(self) -> dict:
        return {
            "path": self.path,
            "methods": {m: sorted(s) for m, s in self.methods.items()},
            "params": sorted(self.params),
            "content_types": sorted(self.content_types),
        }


def build(flows: list[Flow]) -> dict:
    """Return {host: {"endpoints": [EndpointNode...], "count": n}}."""
    hosts: dict[str, dict[str, EndpointNode]] = {}
    for flow in flows:
        req, resp = flow.request, flow.response
        node = hosts.setdefault(req.host, {}).setdefault(
            req.path, EndpointNode(path=req.path))
        node.methods.setdefault(req.method, set())
        if resp:
            node.methods[req.method].add(resp.status_code)
            if resp.mime:
                node.content_types.add(resp.mime.split(";")[0])
        for k, _ in req.query:
            node.params.add(k)

    out = {}
    for host, nodes in hosts.items():
        eps = sorted(nodes.values(), key=lambda n: n.path)
        out[host] = {"count": len(eps), "endpoints": [n.to_dict() for n in eps]}
    return out


def render_tree(sitemap: dict) -> str:
    """ASCII tree for console output."""
    lines: list[str] = []
    for host in sorted(sitemap):
        lines.append(host)
        eps = sitemap[host]["endpoints"]
        for i, ep in enumerate(eps):
            branch = "└──" if i == len(eps) - 1 else "├──"
            methods = ",".join(sorted(ep["methods"]))
            lines.append(f"  {branch} [{methods}] {ep['path']}")
    return "\n".join(lines)

"""Deep Scan orchestrator.

Runs every passive analyzer over the captured flow store and assembles a single
structured report: attack surface, site map, parameter catalog, discovered
secrets/credentials, auth/session reconstruction, and passive security findings.

This is the "custom differentiating logic" layer — it correlates what the
capture engine collected into operator-ready intelligence. It sends no traffic.
"""
from __future__ import annotations

import time
from dataclasses import dataclass, field

from ..findings import Finding, SEVERITY_ORDER, dedupe
from ..models import Flow
from . import auth, params, passive, secrets, sitemap

ENGINE_NAME = "Attack Surface Deep Scan"
ENGINE_VERSION = "1.0.0"


@dataclass
class DeepScanReport:
    engine: str = ENGINE_NAME
    engine_version: str = ENGINE_VERSION
    generated_at: float = field(default_factory=time.time)
    scope_hosts: list = field(default_factory=list)
    flow_count: int = 0
    attack_surface: dict = field(default_factory=dict)
    sitemap: dict = field(default_factory=dict)
    parameters: list = field(default_factory=list)
    reflected_parameters: list = field(default_factory=list)
    secrets: list = field(default_factory=list)
    auth: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    severity_counts: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        return {
            "engine": self.engine,
            "engine_version": self.engine_version,
            "generated_at": self.generated_at,
            "scope_hosts": self.scope_hosts,
            "flow_count": self.flow_count,
            "attack_surface": self.attack_surface,
            "sitemap": self.sitemap,
            "parameters": self.parameters,
            "reflected_parameters": self.reflected_parameters,
            "secrets": self.secrets,
            "auth": self.auth,
            "findings": self.findings,
            "severity_counts": self.severity_counts,
        }


def _secret_findings(hits) -> list[Finding]:
    """Promote notable secret hits into findings for the scored list."""
    out = []
    label = {
        "jwt": ("Exposed JSON Web Token in traffic", "high"),
        "bearer": ("Bearer token present in traffic", "medium"),
        "basic-auth": ("HTTP Basic credentials transmitted", "high"),
        "credential-field": ("Credential-bearing field captured", "high"),
        "high-entropy": ("High-entropy secret-like value captured", "medium"),
    }
    for h in hits:
        if h.kind.startswith("provider:"):
            prov = h.kind.split(":", 1)[1]
            out.append(Finding(id=f"exposed-secret-{prov}",
                               title=f"Exposed {prov.replace('_', ' ')} in traffic",
                               severity="critical", confidence="firm", category="secret",
                               location=h.location,
                               evidence=f"{h.name}={h.masked_value} ({h.where})",
                               remediation="Rotate the exposed credential; stop transmitting it in this location."))
        elif h.kind in label:
            title, sev = label[h.kind]
            out.append(Finding(id=f"exposed-{h.kind}", title=title, severity=sev,
                               confidence="firm", category="secret", location=h.location,
                               evidence=f"{h.name}={h.masked_value} ({h.where})",
                               remediation="Verify this credential is scoped, short-lived and transmitted only where required."))
    return out


def _reflection_findings(reflected) -> list[Finding]:
    out = []
    for rec in reflected:
        for ep in rec.reflected_at:
            out.append(Finding(id="reflected-parameter",
                               title=f"Parameter '{rec.name}' reflected in response",
                               severity="low", confidence="tentative", category="surface",
                               location=ep, passive=True,
                               evidence=f"Value of '{rec.name}' echoed in response body",
                               remediation="Passive indicator only — actively test this input for XSS/injection."))
    return out


def run(flows, scope_hosts=None) -> DeepScanReport:
    """Run a full Deep Scan over an iterable of Flow objects."""
    flows = list(flows)
    report = DeepScanReport(flow_count=len(flows))

    # attack surface + site map
    smap = sitemap.build(flows)
    report.sitemap = smap
    report.scope_hosts = scope_hosts or sorted(smap.keys())
    report.attack_surface = {
        "hosts": len(smap),
        "endpoints": sum(h["count"] for h in smap.values()),
    }

    # parameters + reflection
    catalog = params.build_catalog(flows)
    report.parameters = [r.to_dict() for r in
                         sorted(catalog.values(), key=lambda r: r.name)]
    reflected = params.reflected_params(catalog)
    report.reflected_parameters = [r.to_dict() for r in reflected]
    report.attack_surface["parameters"] = len(catalog)

    # secrets / credentials
    hits = secrets.scan_all(flows)
    report.secrets = [h.to_dict() for h in hits]

    # auth / sessions
    auth_summary = auth.analyze(flows)
    report.auth = auth_summary.to_dict()

    # findings: passive checks + promoted secrets + reflection
    all_findings = passive.check_all(flows)
    all_findings += _secret_findings(hits)
    all_findings += _reflection_findings(reflected)
    findings = dedupe(all_findings)
    report.findings = [f.to_dict() for f in findings]

    counts = {k: 0 for k in SEVERITY_ORDER}
    for f in findings:
        counts[f.severity] = counts.get(f.severity, 0) + 1
    report.severity_counts = counts
    return report

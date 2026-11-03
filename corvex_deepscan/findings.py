"""Normalized finding model used by every analyzer so the orchestrator can
aggregate, de-duplicate and score consistently."""
from __future__ import annotations

from dataclasses import dataclass, field, asdict

SEVERITY_ORDER = {"info": 0, "low": 1, "medium": 2, "high": 3, "critical": 4}
CONFIDENCE_ORDER = {"tentative": 0, "firm": 1, "certain": 2}


@dataclass
class Finding:
    id: str                       # stable slug, e.g. "missing-hsts"
    title: str
    severity: str                 # info | low | medium | high | critical
    confidence: str = "firm"      # tentative | firm | certain
    category: str = "passive"     # passive | secret | auth | surface | config
    location: str = ""            # url / endpoint / where it was seen
    evidence: str = ""            # short, redacted evidence snippet
    remediation: str = ""
    passive: bool = True          # True = detected without sending payloads
    extra: dict = field(default_factory=dict)

    @property
    def rank(self) -> tuple[int, int]:
        return (SEVERITY_ORDER.get(self.severity, 0),
                CONFIDENCE_ORDER.get(self.confidence, 0))

    def to_dict(self) -> dict:
        return asdict(self)


def dedupe(findings: list[Finding]) -> list[Finding]:
    """Collapse identical (id, location) findings, keeping the strongest."""
    best: dict[tuple[str, str], Finding] = {}
    for f in findings:
        key = (f.id, f.location)
        if key not in best or f.rank > best[key].rank:
            best[key] = f
    return sorted(best.values(), key=lambda f: f.rank, reverse=True)

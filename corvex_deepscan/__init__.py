"""Corvex Deep Scan engine — vendored core.

Capture-independent, passive attack-surface analysis over recorded HTTP traffic.
Flows are ingested from a HAR export (browser devtools, another proxy, or an
upstream capture) into a local flow store, then a passive deep scan correlates
them into operator-ready intelligence: attack surface, site map, parameter
catalog, exposed secrets/credentials, auth/session reconstruction, and passive
security findings. It sends no traffic of its own.

This is the free-core subset. The live capture proxy and the active operator
tooling (traffic replay, injection fuzzing, credentialed infra audit) ship in
the premium build.
"""
from __future__ import annotations

from .analysis import deepscan as _deepscan
from .importer import import_har as _import_har
from .models import CapturedRequest, CapturedResponse, Flow
from .store import FlowStore

__version__ = "1.8.0"
__all__ = [
    "DeepScanEngine",
    "FlowStore",
    "Flow",
    "CapturedRequest",
    "CapturedResponse",
    "import_har",
    "__version__",
]


def import_har(path: str, store: "FlowStore") -> int:
    """Load a HAR capture into ``store``; returns the number of flows imported."""
    return _import_har(path, store)


class DeepScanEngine:
    """Facade over the free-core deep-scan pipeline.

    Typical use::

        eng = DeepScanEngine()              # in-memory store
        eng.import_har("capture.har")       # or add_flow(flow) one at a time
        report = eng.deep_scan(scope_hosts=["app.example.com"])
        eng.close()
    """

    name = "Attack Surface Deep Scan"
    version = __version__

    def __init__(self, store_path: str = ":memory:"):
        self.store = FlowStore(store_path)

    def import_har(self, path: str) -> int:
        """Ingest a HAR file into the flow store; returns flows imported."""
        return _import_har(path, self.store)

    def add_flow(self, flow: "Flow") -> int:
        """Add a single captured flow to the store."""
        return self.store.save_flow(flow)

    def flow_count(self) -> int:
        return self.store.count()

    def deep_scan(self, scope_hosts=None):
        """Run the passive deep scan over every stored flow."""
        return _deepscan.run(self.store.iter_flows(), scope_hosts=scope_hosts)

    def close(self) -> None:
        self.store.close()

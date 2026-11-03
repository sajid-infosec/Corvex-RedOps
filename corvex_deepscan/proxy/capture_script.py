"""mitmdump addon-script entrypoint for the capture proxy.

Point the proxy backend at this file to persist intercepted flows to a store::

    CORVEX_DEEPSCAN_DB=flows.db \
    mitmdump --set confdir=~/.corvex-deepscan \
             -s corvex_deepscan/proxy/capture_script.py -p 8083

The store path comes from ``CORVEX_DEEPSCAN_DB`` (default ``corvex_flows.db``
in the current directory). This module intentionally performs the store
side-effect at import — that is what an addon script is for. ``addon.py``
itself stays import-safe.
"""
from __future__ import annotations

import os

from ..store import FlowStore
from .addon import CaptureAddon

_DB = os.environ.get("CORVEX_DEEPSCAN_DB", "corvex_flows.db")

# the proxy backend collects this module-level ``addons`` list when loaded via -s
addons = [CaptureAddon(FlowStore(_DB))]

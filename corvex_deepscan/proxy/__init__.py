"""Intercepting-proxy capture layer (optional; needs the ``proxy`` extra).

Import-safe: importing this package opens no files and binds no port. The CA
helpers are stdlib-only; the live proxy runner needs the ``proxy`` extra.
"""
from __future__ import annotations

from . import ca  # noqa: F401
from .addon import CaptureAddon, PROXY_INSTALL_HINT, proxy_available, run_proxy

__all__ = ["ca", "CaptureAddon", "run_proxy", "proxy_available", "PROXY_INSTALL_HINT"]

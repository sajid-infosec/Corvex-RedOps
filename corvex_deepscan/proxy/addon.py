"""Intercepting-proxy capture layer.

A thin capture addon on top of the proxy backend that maps intercepted HTTP
flows into the engine's capture model and persists them to the flow store. The
proxy backend is used only as the TLS/HTTP substrate (cert generation,
HTTP/1.1+2, WebSocket); all engine value lives in the proxy-independent
analysis layer.

Two ways to run it:

  1. As an addon script (most robust, version-stable):
         CORVEX_DEEPSCAN_DB=flows.db \
         mitmdump --set confdir=~/.corvex-deepscan \
                  -s corvex_deepscan/proxy/capture_script.py -p 8083

  2. Programmatically (or via `corvex deepscan-capture`):
         from corvex_deepscan.proxy.addon import run_proxy
         run_proxy(store_path="flows.db", port=8083)

This module is import-safe: importing it opens no files and binds no port. The
``mitmdump -s`` entrypoint lives in ``capture_script.py``.

NOTE: the Corvex-RedOps API binds :8000/:8080 by convention. Run the capture
proxy on another port (e.g. 8083) when co-locating.
"""
from __future__ import annotations

from ..models import CapturedRequest, CapturedResponse, Flow
from ..store import FlowStore

#: install hint surfaced wherever the proxy backend is missing.
PROXY_INSTALL_HINT = "pip install 'corvex-redops[proxy]'"


def _headers(fields) -> list[tuple[str, str]]:
    # the proxy backend's Headers is a multidict of bytes; .fields gives raw pairs
    out = []
    try:
        for k, v in fields.fields:
            out.append((k.decode("latin-1"), v.decode("latin-1")))
    except Exception:
        for k, v in fields.items(multi=True):
            out.append((k, v))
    return out


class CaptureAddon:
    """Proxy addon: persists each completed flow to a FlowStore."""

    def __init__(self, store: FlowStore):
        self.store = store
        self.saved = 0

    def _to_flow(self, flow) -> Flow:
        r = flow.request
        creq = CapturedRequest(
            method=r.method, url=r.url, scheme=r.scheme, host=r.host,
            port=r.port, path=r.path.split("?")[0] if r.path else "/",
            query=list(r.query.items(multi=True)) if r.query else [],
            headers=_headers(r.headers),
            body=r.get_text(strict=False) or "",
            timestamp=getattr(r, "timestamp_start", 0.0) or 0.0,
        )
        cresp = None
        resp = flow.response
        if resp is not None:
            mime = ""
            ct = resp.headers.get("content-type", "")
            if ct:
                mime = ct.split(";")[0].strip()
            cresp = CapturedResponse(
                status_code=resp.status_code, reason=resp.reason or "",
                headers=_headers(resp.headers),
                body=resp.get_text(strict=False) or "",
                mime=mime,
                timestamp=getattr(resp, "timestamp_end", 0.0) or 0.0,
            )
        dur = 0.0
        try:
            if resp and r.timestamp_start and resp.timestamp_end:
                dur = (resp.timestamp_end - r.timestamp_start) * 1000.0
        except Exception:
            pass
        return Flow(request=creq, response=cresp, duration_ms=dur)

    def response(self, flow) -> None:  # proxy hook: full flow available
        try:
            self.store.save_flow(self._to_flow(flow))
            self.saved += 1
        except Exception as exc:  # never let capture crash the proxy
            import sys
            print(f"[deepscan] capture error: {exc}", file=sys.stderr)


def run_proxy(store_path: str = "corvex_flows.db", host: str = "127.0.0.1",
              port: int = 8083, confdir: str | None = None) -> None:
    """Start the capture proxy in-process. Requires the ``proxy`` extra
    (``pip install 'corvex-redops[proxy]'``). Blocks until interrupted.

    Raises :class:`RuntimeError` with an install hint if the proxy backend is
    not installed — the rest of Deep Scan (HAR import + analysis) works without
    it.
    """
    import asyncio

    try:
        from mitmproxy.options import Options
        from mitmproxy.tools.dump import DumpMaster
    except ImportError as exc:  # pragma: no cover
        raise RuntimeError(
            "the capture proxy backend is not installed. "
            f"Install it with: {PROXY_INSTALL_HINT}") from exc

    from .ca import DEFAULT_CONFDIR
    cdir = confdir or str(DEFAULT_CONFDIR)
    opts = Options(listen_host=host, listen_port=port, confdir=cdir)
    master = DumpMaster(opts, with_termlog=True, with_dumper=False)
    master.addons.add(CaptureAddon(FlowStore(store_path)))

    async def _run():  # pragma: no cover
        await master.run()

    try:  # pragma: no cover
        asyncio.run(_run())
    except KeyboardInterrupt:  # pragma: no cover
        master.shutdown()


def proxy_available() -> bool:
    """True if the proxy backend is importable (the ``proxy`` extra is installed)."""
    import importlib.util
    return importlib.util.find_spec("mitmproxy") is not None

"""Live streaming: the check engine reports findings to RunControl as they are
confirmed, honours pause/stop, and never hangs (bounded)."""
import threading, time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

import pytest
from pentestiq.models import Asset, AssetType
from pentestiq.checks.base import RealHttpClient
from pentestiq.checks.engine import CheckEngine, build_context
from pentestiq.core.runcontrol import RunControl, ScanCancelled


class _H(BaseHTTPRequestHandler):
    def log_message(self, *a): pass
    def do_GET(self):
        # no security headers -> SecurityHeadersCheck + clickjacking fire
        self.send_response(200); self.send_header("Content-Type", "text/html")
        self.end_headers(); self.wfile.write(b"<html><body>hi</body></html>")


@pytest.fixture(scope="module")
def base():
    srv = ThreadingHTTPServer(("127.0.0.1", 0), _H)
    threading.Thread(target=srv.serve_forever, daemon=True).start()
    yield f"http://127.0.0.1:{srv.server_address[1]}"
    srv.shutdown()


def test_findings_stream_to_control(base):
    ctrl = RunControl("live1", deadline_s=30)
    asset = Asset(type=AssetType.WEB, identifier=base, metadata={"base_url": base})
    cx = build_context(asset, http=RealHttpClient(), control=ctrl)
    found = CheckEngine().run(cx)
    assert found, "expected passive findings on a header-less page"
    # each finding was streamed to the control as it was confirmed
    assert ctrl.findings_total == len(found)
    snap = ctrl.snapshot()
    assert snap["findings"] == len(found)
    assert any(e.get("f") for e in snap["log"])       # live finding feed populated


def test_stop_cancels_mid_run(base):
    ctrl = RunControl("live2", deadline_s=30)
    ctrl.stop()                                        # request stop up front
    asset = Asset(type=AssetType.WEB, identifier=base, metadata={"base_url": base})
    cx = build_context(asset, http=RealHttpClient(), control=ctrl)
    with pytest.raises(ScanCancelled):
        CheckEngine().run(cx)

"""Helpers to locate and export the interception CA.

The proxy backend generates a CA on first run under its confdir. To decrypt
TLS you must install this CA in the trust store of the browser / device whose
traffic you are *authorized* to test — the same trust step any intercepting
proxy requires. That trust step is the deliberate, operator-controlled gate on
interception.
"""
from __future__ import annotations

import shutil
from pathlib import Path

DEFAULT_CONFDIR = Path.home() / ".corvex-deepscan"
CA_FILENAMES = ("mitmproxy-ca-cert.pem", "mitmproxy-ca-cert.cer",
                "mitmproxy-ca-cert.p12", "mitmproxy-ca.pem")


def ca_dir(confdir: str | None = None) -> Path:
    return Path(confdir) if confdir else DEFAULT_CONFDIR


def find_ca(confdir: str | None = None) -> Path | None:
    d = ca_dir(confdir)
    for name in CA_FILENAMES:
        p = d / name
        if p.exists():
            return p
    return None


def export_ca(dest: str, confdir: str | None = None) -> Path:
    """Copy the PEM CA to `dest` for installation in a trust store."""
    src = find_ca(confdir)
    if not src:
        raise FileNotFoundError(
            f"CA not found in {ca_dir(confdir)}. Start the capture proxy once to generate it.")
    pem = src.with_suffix(".pem") if src.suffix != ".pem" else src
    out = Path(dest)
    out.parent.mkdir(parents=True, exist_ok=True)
    shutil.copyfile(pem if pem.exists() else src, out)
    return out

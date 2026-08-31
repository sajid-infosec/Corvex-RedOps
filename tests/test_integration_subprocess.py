"""End-to-end test of the real subprocess path (is_available -> run -> parse)
using a stub binary on PATH. Proves the plumbing without needing the real tool;
live validation against the tools happens on an operator's Kali/lab.
"""
import os
from pathlib import Path
from pentestiq.integrations.nmap_tool import NmapIntegration
from pentestiq.integrations.nuclei_tool import NucleiIntegration
from pentestiq.models import Asset, AssetType

FIX = Path(__file__).parent / "fixtures"


def _install_stub(tmp_path, name, fixture_env, monkeypatch):
    stub = tmp_path / name
    stub.write_text('#!/bin/sh\ncat "$STUB_FIXTURE"\n')
    stub.chmod(0o755)
    monkeypatch.setenv("PATH", f"{tmp_path}:{os.environ['PATH']}")
    monkeypatch.setenv("STUB_FIXTURE", str(fixture_env))


def test_nmap_scan_end_to_end_subprocess(tmp_path, monkeypatch):
    _install_stub(tmp_path, "nmap", FIX / "nmap_sample.xml", monkeypatch)
    nmap = NmapIntegration()
    assert nmap.is_available() is True
    findings = nmap.scan(Asset(type=AssetType.INFRA, identifier="10.0.0.5"))
    assert len(findings) == 3
    assert all(f.source_tools == ["nmap"] for f in findings)


def test_nuclei_scan_end_to_end_subprocess(tmp_path, monkeypatch):
    _install_stub(tmp_path, "nuclei", FIX / "nuclei_sample.jsonl", monkeypatch)
    nuclei = NucleiIntegration()
    assert nuclei.is_available() is True
    findings = nuclei.scan(Asset(type=AssetType.INFRA, identifier="http://10.0.0.5"))
    assert len(findings) == 3

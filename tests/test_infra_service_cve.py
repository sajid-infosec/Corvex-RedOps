"""Infra service→CVE auto-enrichment: nmap banners become ranked CVE findings."""
from __future__ import annotations

import logging
import types

from pentestiq.intel import ServiceCVEMatcher, service_findings_from
from pentestiq.modules.infra import InfraModule
from pentestiq.models import Asset, AssetType, Finding, Severity, Evidence


def _asset():
    return Asset(type=AssetType.INFRA, identifier="10.0.0.5")


def test_service_findings_from_banner():
    a = _asset()
    nmap = Finding(asset=a, title="Open port 22/tcp — ssh (OpenSSH 7.6p1)",
                   severity=Severity.INFO, location="22/tcp",
                   evidence=[Evidence(type="service", ref="10.0.0.5:22", description="OpenSSH 7.6p1")])
    out = service_findings_from(a, [nmap], ServiceCVEMatcher())
    assert out and "Outdated openssh 7.6p1" in out[0].title
    assert any(r.startswith("CVE-") for r in out[0].references)


def test_no_findings_for_patched_service():
    a = _asset()
    nmap = Finding(asset=a, title="Open port 22/tcp — ssh (OpenSSH 9.6p1)",
                   severity=Severity.INFO,
                   evidence=[Evidence(type="service", ref="x", description="OpenSSH 9.6p1")])
    assert service_findings_from(a, [nmap], ServiceCVEMatcher()) == []


def test_deduped_per_service():
    a = _asset()
    fs = [Finding(asset=a, title=f"Open port {p} — http (Apache/2.4.29)", severity=Severity.INFO,
                  evidence=[Evidence(type="service", ref="x", description="Apache 2.4.29")])
          for p in ("80/tcp", "8080/tcp")]
    out = service_findings_from(a, fs, ServiceCVEMatcher())
    assert len(out) == 1                     # apache 2.4.29 reported once, not twice


def test_infra_module_enriches(monkeypatch):
    a = _asset()
    # a fake nmap tool that returns a banner finding; no real nmap needed
    class _FakeTool:
        tool_name = "nmap"
        def scan(self, asset, ctx):
            return [Finding(asset=asset, title="Open port 21/tcp — ftp (vsftpd 2.3.4)",
                            severity=Severity.INFO,
                            evidence=[Evidence(type="service", ref="x", description="vsftpd 2.3.4")])]
    m = InfraModule()
    m.tools = [_FakeTool()]
    ctx = types.SimpleNamespace(asset=a, logger=logging.getLogger("t"),
                                rate_limiter=None, config=None, control=None)
    findings = m.assess(ctx)
    titles = " | ".join(f.title for f in findings)
    assert "Outdated vsftpd 2.3.4" in titles                 # CVE-2011-2523 backdoor
    assert any(f.severity == Severity.CRITICAL for f in findings)

from pathlib import Path
from pentestiq.integrations.nmap_tool import NmapIntegration
from pentestiq.integrations.nuclei_tool import NucleiIntegration
from pentestiq.models import Asset, AssetType, Severity

FIX = Path(__file__).parent / "fixtures"


def _infra_asset():
    return Asset(type=AssetType.INFRA, identifier="10.0.0.5")


def test_nmap_parse_open_ports():
    raw = (FIX / "nmap_sample.xml").read_text()
    findings = NmapIntegration().parse(raw, _infra_asset())
    # only the 3 OPEN ports (443 is closed -> excluded)
    assert len(findings) == 3
    titles = " ".join(f.title for f in findings)
    assert "22/tcp" in titles and "80/tcp" in titles and "443" not in titles
    # telnet is raised to LOW, others INFO
    sev = {f.title.split("—")[1].strip().split()[0]: f.severity for f in findings}
    assert all(f.source_tools == ["nmap"] and f.category == "open-port" for f in findings)
    telnet = [f for f in findings if "telnet" in f.title][0]
    assert telnet.severity == Severity.LOW
    http = [f for f in findings if "http" in f.title][0]
    assert http.severity == Severity.INFO


def test_nuclei_parse_jsonl():
    raw = (FIX / "nuclei_sample.jsonl").read_text()
    findings = NucleiIntegration().parse(raw, _infra_asset())
    assert len(findings) == 3
    crit = [f for f in findings if f.category == "CVE-2021-1234"][0]
    assert crit.severity == Severity.CRITICAL
    assert crit.references == ["https://nvd.nist.gov/vuln/detail/CVE-2021-1234"]
    assert crit.source_tools == ["nuclei"]
    med = [f for f in findings if f.category == "weak-tls"][0]
    assert med.severity == Severity.MEDIUM


def test_missing_tool_scans_gracefully():
    # neither binary is installed in CI/dev -> scan returns [] without raising
    nmap = NmapIntegration()
    if not nmap.is_available():
        assert nmap.scan(_infra_asset()) == []

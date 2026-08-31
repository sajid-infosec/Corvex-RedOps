from pathlib import Path
from pentestiq.integrations.firewall_tool import FirewallConfigAnalyzer
from pentestiq.models import Asset, AssetType, Severity

FIX = Path(__file__).parent / "fixtures"


def _fw(path):
    return Asset(type=AssetType.FIREWALL, identifier=path)


def test_iptables_audit():
    p = str(FIX / "iptables_save.txt")
    findings = FirewallConfigAnalyzer().parse(p, _fw(p))
    cats = [f.category for f in findings]
    assert cats.count("fw-default-allow") == 2          # INPUT + FORWARD ACCEPT
    assert "fw-any-any" in cats                          # -A INPUT -j ACCEPT
    dsvc = [f for f in findings if f.category == "fw-dangerous-service"]
    titles = " ".join(f.title for f in dsvc)
    assert "Telnet" in titles and "RDP" in titles
    assert all(f.severity == Severity.HIGH for f in dsvc)
    info = [f for f in findings if f.category == "firewall-info"][0]
    assert "iptables" in info.title


def test_asa_audit():
    p = str(FIX / "asa_config.txt")
    findings = FirewallConfigAnalyzer().parse(p, _fw(p))
    cats = [f.category for f in findings]
    assert "fw-any-any" in cats                          # permit ip any any
    assert "fw-dangerous-service" in cats                # telnet + rdp
    assert "fw-no-explicit-deny" in cats                 # no deny ip any any
    info = [f for f in findings if f.category == "firewall-info"][0]
    assert "ASA" in info.title


def test_clean_firewall_quiet(tmp_path):
    cfg = tmp_path / "good.rules"
    cfg.write_text("*filter\n:INPUT DROP [0:0]\n:FORWARD DROP [0:0]\n"
                   "-A INPUT -s 10.0.0.0/8 -p tcp --dport 443 -j ACCEPT\nCOMMIT\n")
    findings = FirewallConfigAnalyzer().parse(str(cfg), _fw(str(cfg)))
    cats = {f.category for f in findings}
    assert "fw-default-allow" not in cats and "fw-any-any" not in cats
    assert "fw-dangerous-service" not in cats


def test_firewall_module_registered():
    from pentestiq.core.registry import registry
    import pentestiq.modules  # noqa
    assert "firewall" in [m.name for m in registry.for_asset_type(AssetType.FIREWALL)]

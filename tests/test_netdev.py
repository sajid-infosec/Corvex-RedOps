from pathlib import Path
from pentestiq.integrations.netdev_tool import NetworkConfigAnalyzer
from pentestiq.models import Asset, AssetType, Severity

FIX = Path(__file__).parent / "fixtures"


def _dev(path):
    return Asset(type=AssetType.NETWORK_DEVICE, identifier=path)


def test_cisco_config_audit():
    findings = NetworkConfigAnalyzer().parse(str(FIX / "cisco_config.txt"),
                                             _dev(str(FIX / "cisco_config.txt")))
    cats = {f.category for f in findings}
    assert "netdev-telnet" in cats               # transport input telnet
    assert "netdev-enable-pw" in cats            # enable password (no secret)
    assert "netdev-type7" in cats                # password 7
    assert "netdev-snmp-default" in cats         # community public
    assert "netdev-snmp-rw" in cats              # private RW
    assert "netdev-http" in cats                 # ip http server (no secure)
    assert "netdev-aaa" in cats                  # no aaa new-model
    assert "netdev-ntp" in cats                  # no ntp
    telnet = [f for f in findings if f.category == "netdev-telnet"][0]
    assert telnet.severity == Severity.HIGH
    snmp = [f for f in findings if f.category == "netdev-snmp-default"][0]
    assert "public" in snmp.title


def test_hardened_config_is_quiet(tmp_path):
    cfg = tmp_path / "good.cfg"
    cfg.write_text(
        "hostname core\naaa new-model\nservice password-encryption\n"
        "enable secret 9 $9$abc\nip http secure-server\n"
        "logging host 10.0.0.5\nntp server 10.0.0.1\n"
        "snmp-server group v3grp v3 priv\n"
        "line vty 0 4\n transport input ssh\n")
    findings = NetworkConfigAnalyzer().parse(str(cfg), _dev(str(cfg)))
    cats = {f.category for f in findings}
    assert "netdev-telnet" not in cats and "netdev-http" not in cats
    assert "netdev-aaa" not in cats and "netdev-ntp" not in cats


def test_netdev_module_registered():
    from pentestiq.core.registry import registry
    import pentestiq.modules  # noqa
    assert "network-device" in [m.name for m in registry.for_asset_type(AssetType.NETWORK_DEVICE)]

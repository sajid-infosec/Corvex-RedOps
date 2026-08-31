from pathlib import Path
from pentestiq.integrations.hardening_tool import HardeningAnalyzer
from pentestiq.models import Asset, AssetType, Severity

FIX = Path(__file__).parent / "fixtures"


def _h(path):
    return Asset(type=AssetType.HARDENING, identifier=path)


def test_sshd_hardening_audit():
    p = str(FIX / "sshd_config.txt")
    findings = HardeningAnalyzer().parse(p, _h(p))
    cats = {f.category for f in findings}
    assert "hard-ssh-root" in cats and "hard-ssh-empty" in cats
    assert "hard-ssh-passauth" in cats and "hard-ssh-x11" in cats
    assert "hard-ssh-crypto" in cats                      # cbc/3des ciphers
    root = [f for f in findings if f.category == "hard-ssh-root"][0]
    assert root.severity == Severity.HIGH


def test_lynis_report_ingest():
    p = str(FIX / "lynis_report.dat")
    findings = HardeningAnalyzer().parse(p, _h(p))
    cats = [f.category for f in findings]
    assert "hard-lynis-index" in cats
    assert cats.count("hard-lynis-warning") == 1
    assert cats.count("hard-lynis-suggestion") == 2
    idx = [f for f in findings if f.category == "hard-lynis-index"][0]
    assert "56" in idx.title


def test_sysctl_hardening(tmp_path):
    p = tmp_path / "sysctl.conf"
    p.write_text("kernel.randomize_va_space = 0\n"
                 "net.ipv4.ip_forward = 1\n"
                 "net.ipv4.tcp_syncookies = 0\n")
    findings = HardeningAnalyzer().parse(str(p), _h(str(p)))
    cats = {f.category for f in findings}
    assert "hard-aslr" in cats and "hard-ipforward" in cats and "hard-syncookies" in cats
    aslr = [f for f in findings if f.category == "hard-aslr"][0]
    assert aslr.severity == Severity.MEDIUM


def test_hardening_module_registered():
    from pentestiq.core.registry import registry
    import pentestiq.modules  # noqa
    assert "hardening" in [m.name for m in registry.for_asset_type(AssetType.HARDENING)]

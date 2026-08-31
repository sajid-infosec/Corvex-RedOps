import os
import sys
from pentestiq.integrations.binary_tool import SecretsScanner, BinaryHardeningAnalyzer
from pentestiq.models import Asset, AssetType, Severity


def _desktop(path):
    return Asset(type=AssetType.DESKTOP, identifier=path)


def test_secrets_scanner_finds_planted_secrets(tmp_path):
    blob = (b"\x00\x01random binary\x00"
            b"AKIAIOSFODNN7EXAMPLE\x00"
            b"-----BEGIN RSA PRIVATE KEY-----\x00"
            b"password = 'Sup3rSecret!'\x00"
            b"connect http://internal.example.com/api\x00"
            b"\xff\xfe padding")
    p = tmp_path / "app.bin"
    p.write_bytes(blob)
    findings = SecretsScanner().parse(str(p), _desktop(str(p)))
    cats = {f.category for f in findings}
    assert "secret-aws-access-key" in cats
    assert "secret-private-key" in cats
    assert "secret-generic-secret" in cats
    assert "insecure-url" in cats
    pk = [f for f in findings if f.category == "secret-private-key"][0]
    assert pk.severity == Severity.CRITICAL


def test_secrets_scanner_clean_file(tmp_path):
    p = tmp_path / "clean.bin"
    p.write_bytes(b"just some ordinary strings here nothing secret at all")
    assert SecretsScanner().parse(str(p), _desktop(str(p))) == []


def test_hardening_analyzer_on_real_elf():
    ha = BinaryHardeningAnalyzer()
    assert ha.is_available() is True                 # lief installed
    elf = os.path.realpath(sys.executable)           # a real ELF on this host
    findings = ha.parse(elf, _desktop(elf))
    assert findings                                   # at least a binary-info finding
    info = [f for f in findings if f.category == "binary-info"][0]
    assert "ELF" in info.title
    # all findings carry the tool + a category
    assert all(f.source_tools == ["binary-hardening"] for f in findings)


def test_hardening_scan_handles_non_binary(tmp_path):
    p = tmp_path / "notbinary.txt"
    p.write_text("hello world")
    # lief returns None for a non-binary -> graceful empty
    assert BinaryHardeningAnalyzer().parse(str(p), _desktop(str(p))) == []


def test_desktop_module_registered_and_typing():
    from pentestiq.core.registry import registry
    from pentestiq.engine import infer_asset_type
    import pentestiq.modules  # noqa
    assert "desktop" in [m.name for m in registry.for_asset_type(AssetType.DESKTOP)]
    assert infer_asset_type("setup.exe") == AssetType.DESKTOP
    assert infer_asset_type("App.dmg") == AssetType.DESKTOP

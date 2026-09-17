"""Native desktop analysis — PE/ELF/Mach-O hardening, Electron .asar, containers."""
from __future__ import annotations

import io
import json
import struct
import zipfile

from pentestiq.integrations.desktop_native import (
    parse_pe_hardening, parse_elf_hardening, parse_macho_hardening,
    analyze_electron, analyze_desktop, _hardening_findings)
from pentestiq.models import Asset, AssetType, Severity


def _asset(name="app"):
    return Asset(type=AssetType.DESKTOP, identifier=name)


# ---------------------------------------------------------------- PE
def _make_pe(dll_chars=0, cert_size=0):
    pe_off = 0x80
    buf = bytearray(512)
    buf[0:2] = b"MZ"
    struct.pack_into("<I", buf, 0x3C, pe_off)
    buf[pe_off:pe_off + 4] = b"PE\x00\x00"
    struct.pack_into("<H", buf, pe_off + 4, 0x14C)          # machine x86
    opt = pe_off + 24
    struct.pack_into("<H", buf, opt, 0x10B)                 # PE32
    struct.pack_into("<H", buf, opt + 70, dll_chars)
    dd = opt + 96                                           # data dirs (PE32)
    struct.pack_into("<II", buf, dd + 4 * 8, 0x1000, cert_size)   # cert table entry 4
    return bytes(buf)


def test_pe_no_mitigations_unsigned():
    h = parse_pe_hardening(_make_pe(dll_chars=0, cert_size=0))
    assert h and h["format"] == "PE"
    assert not h["aslr"] and not h["dep"] and not h["cfg"] and not h["signed"]
    fs = _hardening_findings(_asset(), h, "app.exe")
    titles = " | ".join(f.title for f in fs)
    assert "no ASLR" in titles and "no DEP" in titles and "not Authenticode-signed" in titles


def test_pe_fully_hardened_signed():
    h = parse_pe_hardening(_make_pe(dll_chars=0x40 | 0x100 | 0x4000, cert_size=2048))
    assert h["aslr"] and h["dep"] and h["cfg"] and h["signed"]
    assert _hardening_findings(_asset(), h, "app.exe") == []


# ---------------------------------------------------------------- ELF
def _make_elf(exec_stack=True, et_exec=True):
    buf = bytearray(0x34 + 32)
    buf[0:4] = b"\x7fELF"
    buf[4] = 1          # 32-bit
    buf[5] = 1          # LE
    buf[6] = 1
    struct.pack_into("<H", buf, 0x10, 2 if et_exec else 3)   # ET_EXEC / ET_DYN
    struct.pack_into("<I", buf, 0x1C, 0x34)                  # e_phoff
    struct.pack_into("<H", buf, 0x2A, 32)                    # e_phentsize
    struct.pack_into("<H", buf, 0x2C, 1)                     # e_phnum
    ph = 0x34
    struct.pack_into("<I", buf, ph, 0x6474E551)             # PT_GNU_STACK
    struct.pack_into("<I", buf, ph + 24, 0x7 if exec_stack else 0x6)   # p_flags RWE/RW
    return bytes(buf)


def test_elf_exec_stack_no_pie():
    h = parse_elf_hardening(_make_elf(exec_stack=True, et_exec=True))
    assert h and h["format"] == "ELF"
    assert h["nx"] is False and h["pie"] is False and h["canary"] is False
    titles = " | ".join(f.title for f in _hardening_findings(_asset(), h, "bin"))
    assert "executable stack" in titles and "not position-independent" in titles
    assert "no stack canary" in titles


def test_elf_pie_when_dyn():
    h = parse_elf_hardening(_make_elf(exec_stack=False, et_exec=False))
    assert h["pie"] is True and h["nx"] is True


# ---------------------------------------------------------------- Mach-O
def _make_macho(flags=0, ncmds=0):
    buf = bytearray(64)
    buf[0:4] = b"\xce\xfa\xed\xfe"      # 32-bit LE
    struct.pack_into("<I", buf, 16, ncmds)
    struct.pack_into("<I", buf, 20, 0)
    struct.pack_into("<I", buf, 24, flags)
    return bytes(buf)


def test_macho_no_pie_unsigned():
    h = parse_macho_hardening(_make_macho(flags=0, ncmds=0))
    assert h and h["format"] == "Mach-O" and not h["pie"] and not h["signed"]
    titles = " | ".join(f.title for f in _hardening_findings(_asset(), h, "app"))
    assert "not position-independent" in titles and "not code-signed" in titles


def test_non_binary_returns_none():
    assert parse_pe_hardening(b"hello") is None
    assert parse_elf_hardening(b"hello") is None
    assert parse_macho_hardening(b"hello") is None


# ---------------------------------------------------------------- Electron .asar
def _make_asar(files: dict):
    """files: {name: bytes}. Builds a minimal but valid asar archive."""
    content = b""
    entries = {}
    for name, blob in files.items():
        entries[name] = {"offset": str(len(content)), "size": len(blob)}
        content += blob
    header = json.dumps({"files": entries}).encode("utf-8")
    padded = header + b"\x00" * ((4 - len(header) % 4) % 4)
    hdr_size = 8 + len(padded)
    out = struct.pack("<IIII", 4, hdr_size, 4 + len(header), len(header)) + padded + content
    return out


def test_electron_asar_misconfig_and_secret(tmp_path):
    main_js = (b"const win = new BrowserWindow({webPreferences:{"
               b"nodeIntegration:true, contextIsolation:false, webSecurity:false}});\n"
               b"win.loadURL('http://updates.example.com/app');\n"
               b"const KEY='AKIAIOSFODNN7EXAMPLE';\n")
    pkg = b'{"name":"app","dependencies":{"electron":"^11.0.0"}}'
    p = tmp_path / "app.asar"
    p.write_bytes(_make_asar({"main.js": main_js, "package.json": pkg}))
    fs = analyze_electron(_asset(str(p)), str(p))
    titles = " | ".join(f.title for f in fs)
    assert "nodeIntegration" in titles
    assert "contextIsolation" in titles
    assert "webSecurity" in titles
    assert "loads a remote page over HTTP" in titles
    assert "Hardcoded secret" in titles
    assert "version 11.0.0" in titles
    assert any(f.severity == Severity.HIGH for f in fs)
    # secret redacted
    assert all("AKIAIOSFODNN7EXAMPLE" not in (e.description or "")
               for f in fs for e in f.evidence)


def test_electron_clean_asar(tmp_path):
    p = tmp_path / "clean.asar"
    p.write_bytes(_make_asar({"main.js": b"console.log('hello world, nothing bad here');"}))
    assert analyze_electron(_asset(str(p)), str(p)) == []


def test_analyze_desktop_dispatch_binary(tmp_path):
    p = tmp_path / "app.exe"
    p.write_bytes(_make_pe(dll_chars=0, cert_size=0))
    fs = analyze_desktop(_asset(str(p)), str(p))
    assert any("no ASLR" in f.title or "no DEP" in f.title for f in fs)


def test_analyze_desktop_zip_container_with_secret(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("config.env", b"AWS_SECRET=AKIAIOSFODNN7EXAMPLE\n")
        z.writestr("bin/app", _make_elf(exec_stack=True))
    p = tmp_path / "installer.zip"
    p.write_bytes(buf.getvalue())
    fs = analyze_desktop(_asset(str(p)), str(p))
    titles = " | ".join(f.title for f in fs)
    assert "Hardcoded secret" in titles
    assert "executable stack" in titles

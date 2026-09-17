"""Native APK/IPA static analysis — real crafted archives, no MobSF, no tools."""
from __future__ import annotations

import io
import plistlib
import struct
import zipfile

from pentestiq.integrations.mobile_native import (
    analyze_apk, analyze_ipa, analyze_mobile, parse_axml,
    _apk_manifest_findings, _attr_name)
from pentestiq.models import Asset, AssetType, Severity


def _asset(name="app.apk"):
    return Asset(type=AssetType.MOBILE, identifier=name)


# ------------------------------------------------------------------ AXML parser
def _axml(elements):
    """Minimal AXML encoder (UTF-16 string pool, named attrs) for round-trip tests.
    elements: list of ('start'|'end', name, [(attr, type, data)]) where type is
    'bool'|'str' and data is python value. Enough to exercise the parser."""
    # collect strings
    pool = []
    def sidx(s):
        if s not in pool:
            pool.append(s)
        return pool.index(s)
    # pre-register all strings
    encoded = []
    for kind, name, attrs in elements:
        sidx(name)
        for a, t, d in attrs:
            sidx(a)
            if t == "str":
                sidx(str(d))
    # string pool chunk (UTF-16)
    offsets = b""; strdata = b""
    for s in pool:
        offsets += struct.pack("<I", len(strdata))
        b = s.encode("utf-16-le")
        n = len(s)
        strdata += struct.pack("<H", n) + b + b"\x00\x00"
    while len(strdata) % 4:
        strdata += b"\x00"
    sp_header = 28
    strings_start = sp_header + len(offsets)
    sp_size = strings_start + len(strdata)
    sp = struct.pack("<HHIIIIII", 0x0001, sp_header, sp_size, len(pool), 0, 0,
                     strings_start, 0) + offsets + strdata
    # body chunks
    body = b""
    for kind, name, attrs in elements:
        if kind == "start":
            attr_blob = b""
            for a, t, d in attrs:
                if t == "bool":
                    dtype, dval, raw = 0x12, (0xFFFFFFFF if d else 0), 0xFFFFFFFF
                else:
                    dtype, dval, raw = 0x03, sidx(str(d)), sidx(str(d))
                attr_blob += struct.pack("<IIIHBBI", 0xFFFFFFFF, sidx(a), raw,
                                         8, 0, dtype, dval)
            hsize = 16
            chunk = struct.pack("<HHI", 0x0102, hsize, hsize + 20 + len(attr_blob))
            chunk += struct.pack("<II", 0, 0xFFFFFFFF)          # line, comment
            chunk += struct.pack("<II", 0xFFFFFFFF, sidx(name))  # ns, name
            chunk += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0)
            chunk += attr_blob
            body += chunk
        else:
            chunk = struct.pack("<HHI", 0x0103, 16, 16 + 8)
            chunk += struct.pack("<II", 0, 0xFFFFFFFF)
            chunk += struct.pack("<II", 0xFFFFFFFF, sidx(name))
            body += chunk
    total = 8 + len(sp) + len(body)
    return struct.pack("<HHI", 0x0003, 8, total) + sp + body


def test_parse_axml_roundtrip():
    blob = _axml([
        ("start", "manifest", []),
        ("start", "application", [("debuggable", "bool", True), ("name", "str", "MyApp")]),
        ("start", "activity", [("exported", "bool", True), ("name", "str", ".Main")]),
        ("end", "activity", []),
        ("end", "application", []),
        ("end", "manifest", []),
    ])
    events = parse_axml(blob)
    starts = {name: attrs for kind, name, attrs in events if kind == "start"}
    assert starts["application"]["debuggable"] == "true"
    assert starts["application"]["name"] == "MyApp"
    assert starts["activity"]["exported"] == "true"


def test_parse_axml_rejects_garbage():
    assert parse_axml(b"not axml at all") == []


def test_attr_name_resolves_resource_id():
    # empty string name + resource map entry -> android attr name
    assert _attr_name(0, [""], [0x0101000F]) == "debuggable"
    assert _attr_name(0, [""], [0x01010010]) == "exported"


# ------------------------------------------------------------- manifest findings
def test_manifest_findings_flags():
    events = [
        ("start", "application", {"debuggable": "true", "allowBackup": "true",
                                  "usesCleartextTraffic": "true"}),
        ("start", "provider", {"name": ".Leaky", "exported": "true"}),
        ("end", "provider", {}),
    ]
    fs = _apk_manifest_findings(_asset(), events)
    titles = " | ".join(f.title for f in fs)
    assert "debuggable" in titles
    assert "backup-enabled" in titles
    assert "Cleartext traffic" in titles
    assert "Exported provider" in titles
    assert any(f.severity == Severity.HIGH for f in fs)
    assert all(any("MASVS" in r for r in f.references) for f in fs)


# --------------------------------------------------------------- APK end-to-end
def _make_apk(with_manifest=True):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        if with_manifest:
            z.writestr("AndroidManifest.xml", _axml([
                ("start", "manifest", []),
                ("start", "application", [("debuggable", "bool", True)]),
                ("end", "application", []),
                ("end", "manifest", []),
            ]))
        # a DEX-like blob carrying a hardcoded AWS key + cleartext URL
        z.writestr("classes.dex", b"dex\n035\x00" +
                   b"AKIAIOSFODNN7EXAMPLE some junk http://api.internal.example/v1 more")
        z.writestr("META-INF/CERT.RSA", b"....CN=Android Debug, O=Android....")
    return buf.getvalue()


def test_analyze_apk_end_to_end(tmp_path):
    p = tmp_path / "app.apk"
    p.write_bytes(_make_apk())
    fs = analyze_apk(_asset(str(p)), str(p))
    titles = " | ".join(f.title for f in fs)
    assert "debuggable" in titles                      # from AXML manifest
    assert "Hardcoded secret" in titles                # AWS key in dex
    assert "Cleartext (HTTP) endpoints" in titles      # http:// url
    assert "debug certificate" in titles               # debug-signed
    # secrets are redacted, never echoed in full
    assert all("AKIAIOSFODNN7EXAMPLE" not in (e.description or "")
               for f in fs for e in f.evidence)


def test_analyze_apk_no_findings_on_clean(tmp_path):
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("classes.dex", b"dex\n035\x00 nothing interesting here at all")
    p = tmp_path / "clean.apk"; p.write_bytes(buf.getvalue())
    assert analyze_apk(_asset(str(p)), str(p)) == []


# --------------------------------------------------------------- IPA end-to-end
def _make_ipa():
    info = {
        "CFBundleIdentifier": "com.example.app",
        "NSAppTransportSecurity": {
            "NSAllowsArbitraryLoads": True,
            "NSExceptionDomains": {"insecure.example.com": {
                "NSExceptionAllowsInsecureHTTPLoads": True}},
        },
        "UIFileSharingEnabled": True,
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["myapp", "myapp-oauth"]}],
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("Payload/App.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        z.writestr("Payload/App.app/App", b"MachO... AIzaSyA1234567890123456789012345678901 http://tracker.example/x")
        z.writestr("embedded.mobileprovision",
                   b"<plist><dict><key>get-task-allow</key><true/>"
                   b"<key>ProvisionedDevices</key><array></array></dict></plist>")
    return buf.getvalue()


def test_analyze_ipa_end_to_end(tmp_path):
    p = tmp_path / "app.ipa"
    p.write_bytes(_make_ipa())
    fs = analyze_ipa(_asset(str(p)), str(p))
    titles = " | ".join(f.title for f in fs)
    assert "App Transport Security disabled" in titles
    assert "insecure-HTTP exceptions" in titles
    assert "file sharing enabled" in titles
    assert "Custom URL scheme" in titles
    assert "debuggable (get-task-allow" in titles
    assert "development (ad-hoc) build" in titles
    assert "Hardcoded secret" in titles or "Cleartext" in titles
    assert any(f.severity == Severity.HIGH for f in fs)


def test_analyze_mobile_dispatch(tmp_path):
    a = tmp_path / "x.apk"; a.write_bytes(_make_apk(with_manifest=False))
    assert isinstance(analyze_mobile(_asset(str(a)), str(a)), list)
    assert analyze_mobile(_asset("x.txt"), "x.txt") == []

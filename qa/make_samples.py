#!/usr/bin/env python3
"""Generate deliberately-vulnerable sample inputs for manual QA of Corvex.

Run:  python qa/make_samples.py
Outputs land in qa/samples/. Every file is synthetic and safe — no real
credentials, no real malware — but each is crafted to trigger specific Corvex
findings so you can verify detection end-to-end. See docs/QA_GUIDE.md for the
expected results per file.
"""
from __future__ import annotations

import io
import json
import os
import plistlib
import struct
import zipfile

OUT = os.path.join(os.path.dirname(__file__), "samples")
os.makedirs(OUT, exist_ok=True)

# a fake-but-realistic AWS key shape (example key from AWS docs — not a real secret)
FAKE_AWS = "AKIAIOSFODNN7EXAMPLE"


# ---------------------------------------------------------------- APK
def _axml(elements):
    pool = []
    def sidx(s):
        if s not in pool:
            pool.append(s)
        return pool.index(s)
    for _, name, attrs in elements:
        sidx(name)
        for a, t, d in attrs:
            sidx(a)
            if t == "str":
                sidx(str(d))
    offsets = b""; strdata = b""
    for s in pool:
        offsets += struct.pack("<I", len(strdata))
        strdata += struct.pack("<H", len(s)) + s.encode("utf-16-le") + b"\x00\x00"
    while len(strdata) % 4:
        strdata += b"\x00"
    strings_start = 28 + len(offsets)
    sp = struct.pack("<HHIIIIII", 0x0001, 28, strings_start + len(strdata),
                     len(pool), 0, 0, strings_start, 0) + offsets + strdata
    body = b""
    for kind, name, attrs in elements:
        if kind == "start":
            ab = b""
            for a, t, d in attrs:
                if t == "bool":
                    dtype, dval, raw = 0x12, (0xFFFFFFFF if d else 0), 0xFFFFFFFF
                else:
                    dtype, dval, raw = 0x03, sidx(str(d)), sidx(str(d))
                ab += struct.pack("<IIIHBBI", 0xFFFFFFFF, sidx(a), raw, 8, 0, dtype, dval)
            chunk = struct.pack("<HHI", 0x0102, 16, 16 + 20 + len(ab))
            chunk += struct.pack("<IIII", 0, 0xFFFFFFFF, 0xFFFFFFFF, sidx(name))
            chunk += struct.pack("<HHHHHH", 20, 20, len(attrs), 0, 0, 0) + ab
            body += chunk
        else:
            chunk = struct.pack("<HHI", 0x0103, 16, 24)
            chunk += struct.pack("<IIII", 0, 0xFFFFFFFF, 0xFFFFFFFF, sidx(name))
            body += chunk
    return struct.pack("<HHI", 0x0003, 8, 8 + len(sp) + len(body)) + sp + body


def make_apk():
    manifest = _axml([
        ("start", "manifest", []),
        ("start", "application", [("debuggable", "bool", True),
                                  ("allowBackup", "bool", True),
                                  ("usesCleartextTraffic", "bool", True)]),
        ("start", "provider", [("name", "str", ".ExportedProvider"),
                               ("exported", "bool", True)]),
        ("end", "provider", []),
        ("end", "application", []),
        ("end", "manifest", []),
    ])
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("AndroidManifest.xml", manifest)
        z.writestr("classes.dex", b"dex\n035\x00 secret " + FAKE_AWS.encode() +
                   b" endpoint http://api.internal.example/v1/login token")
        z.writestr("META-INF/CERT.RSA", b"....CN=Android Debug, O=Android, C=US....")
    open(os.path.join(OUT, "vulnerable.apk"), "wb").write(buf.getvalue())


# ---------------------------------------------------------------- IPA
def make_ipa():
    info = {
        "CFBundleIdentifier": "com.example.vulnapp",
        "NSAppTransportSecurity": {"NSAllowsArbitraryLoads": True,
            "NSExceptionDomains": {"insecure.example.com": {
                "NSExceptionAllowsInsecureHTTPLoads": True}}},
        "UIFileSharingEnabled": True,
        "CFBundleURLTypes": [{"CFBundleURLSchemes": ["vulnapp", "vulnapp-oauth"]}],
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("Payload/VulnApp.app/Info.plist", plistlib.dumps(info, fmt=plistlib.FMT_BINARY))
        z.writestr("Payload/VulnApp.app/VulnApp",
                   b"MachO body AIzaSyA1234567890123456789012345678901 http://tracker.example/beacon")
        z.writestr("embedded.mobileprovision",
                   b"<plist><dict><key>get-task-allow</key><true/>"
                   b"<key>ProvisionedDevices</key><array></array></dict></plist>")
    open(os.path.join(OUT, "vulnerable.ipa"), "wb").write(buf.getvalue())


# ---------------------------------------------------------------- Electron .asar
def make_asar():
    main_js = (b"const {BrowserWindow} = require('electron');\n"
               b"const win = new BrowserWindow({webPreferences:{"
               b"nodeIntegration:true, contextIsolation:false, webSecurity:false}});\n"
               b"win.loadURL('http://updates.example.com/app');\n"
               b"const API_KEY='" + FAKE_AWS.encode() + b"';\n"
               b"eval(userInput);\n")
    pkg = b'{"name":"vulnapp","dependencies":{"electron":"^11.0.0"}}'
    files = {"main.js": main_js, "package.json": pkg}
    content = b""; entries = {}
    for name, blob in files.items():
        entries[name] = {"offset": str(len(content)), "size": len(blob)}
        content += blob
    header = json.dumps({"files": entries}).encode()
    padded = header + b"\x00" * ((4 - len(header) % 4) % 4)
    data = struct.pack("<IIII", 4, 8 + len(padded), 4 + len(header), len(header)) + padded + content
    open(os.path.join(OUT, "vulnerable-electron.asar"), "wb").write(data)


# ---------------------------------------------------------------- desktop ELF
def make_elf():
    buf = bytearray(0x34 + 32)
    buf[0:4] = b"\x7fELF"; buf[4] = 1; buf[5] = 1; buf[6] = 1
    struct.pack_into("<H", buf, 0x10, 2)          # ET_EXEC (no PIE)
    struct.pack_into("<I", buf, 0x1C, 0x34)
    struct.pack_into("<H", buf, 0x2A, 32)
    struct.pack_into("<H", buf, 0x2C, 1)
    struct.pack_into("<I", buf, 0x34, 0x6474E551)  # PT_GNU_STACK
    struct.pack_into("<I", buf, 0x34 + 24, 0x7)    # RWE -> exec stack
    open(os.path.join(OUT, "vulnerable-linux-binary"), "wb").write(bytes(buf))


# ---------------------------------------------------------------- BloodHound
def make_bloodhound():
    DOM = "S-1-5-21-1111-2222-3333"
    users = {"meta": {"type": "users"}, "data": [
        {"Properties": {"name": "SQLSVC@CORP.LOCAL", "enabled": True, "hasspn": True,
                        "serviceprincipalnames": ["MSSQLSvc/db01.corp.local"]},
         "ObjectIdentifier": DOM + "-1105", "Aces": []},
        {"Properties": {"name": "HELPDESK@CORP.LOCAL", "enabled": True, "dontreqpreauth": True},
         "ObjectIdentifier": DOM + "-1106", "Aces": []},
        {"Properties": {"name": "KRBTGT@CORP.LOCAL", "pwdlastset": 1500000000},
         "ObjectIdentifier": DOM + "-502", "Aces": []},
    ]}
    groups = {"meta": {"type": "groups"}, "data": [
        {"Properties": {"name": "DOMAIN ADMINS@CORP.LOCAL", "admincount": True},
         "ObjectIdentifier": DOM + "-512", "Members": [],
         "Aces": [{"PrincipalSID": DOM + "-1105", "RightName": "GenericAll", "IsInherited": False}]}]}
    computers = {"meta": {"type": "computers"}, "data": [
        {"Properties": {"name": "WS01.CORP.LOCAL", "enabled": True, "haslaps": False,
                        "unconstraineddelegation": True,
                        "operatingsystem": "Windows Server 2008 R2"},
         "ObjectIdentifier": DOM + "-2101", "Aces": [], "AllowedToDelegate": []}]}
    domains = {"meta": {"type": "domains"}, "data": [
        {"Properties": {"name": "CORP.LOCAL"}, "ObjectIdentifier": DOM, "Aces": [
            {"PrincipalSID": DOM + "-1105", "RightName": "GetChanges"},
            {"PrincipalSID": DOM + "-1105", "RightName": "GetChangesAll"}]}]}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("20260101000000_users.json", json.dumps(users))
        z.writestr("20260101000000_groups.json", json.dumps(groups))
        z.writestr("20260101000000_computers.json", json.dumps(computers))
        z.writestr("20260101000000_domains.json", json.dumps(domains))
    open(os.path.join(OUT, "bloodhound-sample.zip"), "wb").write(buf.getvalue())


# ---------------------------------------------------------------- IaC / secrets / config
def make_text_samples():
    open(os.path.join(OUT, "Dockerfile"), "w").write(
        "FROM ubuntu:latest\nUSER root\nRUN curl http://get.example.com/install | bash\n"
        "ADD https://x/y /app\nEXPOSE 22\nENV AWS_SECRET_ACCESS_KEY=" + FAKE_AWS + "\n")
    # a source archive with a committed secret (for the Secret-scan template)
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("app/config.py", "AWS_ACCESS_KEY = '" + FAKE_AWS + "'\nDEBUG = True\n")
        z.writestr("app/main.py", "import os\napi='sk_live_4eC39HqLyjWDarjtT1zdp7dcABCDEF'\n")
    open(os.path.join(OUT, "leaky-source.zip"), "wb").write(buf.getvalue())
    # a weak Windows security policy export
    open(os.path.join(OUT, "secpol-weak.inf"), "w").write(
        "[System Access]\nMinimumPasswordLength = 4\nPasswordComplexity = 0\n"
        "LockoutBadCount = 0\n[Kerberos Policy]\nMaxTicketAge = 24\n"
        "; DONT_REQ_PREAUTH accounts present; unconstrained delegation configured\n")


def main():
    make_apk(); make_ipa(); make_asar(); make_elf(); make_bloodhound(); make_text_samples()
    print("Wrote sample inputs to", OUT)
    for fn in sorted(os.listdir(OUT)):
        print("  -", fn)


if __name__ == "__main__":
    main()

"""AD attack-surface analysis from a synthetic BloodHound/SharpHound collection."""
from __future__ import annotations

import io
import json
import time
import zipfile

from pentestiq.integrations.ad_bloodhound import analyze_ad_bloodhound, load_bloodhound
from pentestiq.models import Asset, AssetType, Severity

DOM = "S-1-5-21-111-222-333"


def _asset(p):
    return Asset(type=AssetType.ACTIVE_DIRECTORY, identifier=p)


def _user(name, sid, **props):
    p = {"name": name, "enabled": True}
    p.update(props)
    return {"Properties": p, "ObjectIdentifier": sid, "Aces": props.pop("_aces", []) or []}


def _bh_zip(tmp_path):
    old = time.time() - 400 * 86400
    users = {"meta": {"type": "users"}, "data": [
        _user("SQLSVC@CORP", f"{DOM}-1105", hasspn=True,
              serviceprincipalnames=["MSSQL/db01"]),
        _user("NOPREAUTH@CORP", f"{DOM}-1106", dontreqpreauth=True),
        _user("KRBTGT@CORP", f"{DOM}-502", pwdlastset=old),
        _user("ADMIN@CORP", f"{DOM}-1107", admincount=True, pwdneverexpires=True),
        # SQLSVC has GenericAll over the Domain Admins group -> attack path
    ]}
    # give SQLSVC a control edge to Domain Admins group via the group's Aces
    da_group = {"Properties": {"name": "DOMAIN ADMINS@CORP", "admincount": True},
                "ObjectIdentifier": f"{DOM}-512",
                "Members": [{"ObjectIdentifier": f"{DOM}-1107", "ObjectType": "User"}],
                "Aces": [{"PrincipalSID": f"{DOM}-1105", "PrincipalType": "User",
                          "RightName": "GenericAll", "IsInherited": False}]}
    groups = {"meta": {"type": "groups"}, "data": [da_group]}
    computers = {"meta": {"type": "computers"}, "data": [
        {"Properties": {"name": "WS01@CORP", "unconstraineddelegation": True,
                        "enabled": True, "haslaps": False,
                        "operatingsystem": "Windows Server 2008 R2"},
         "ObjectIdentifier": f"{DOM}-2101", "Aces": [], "AllowedToDelegate": []},
    ]}
    # DCSync: a non-default principal with both GetChanges + GetChangesAll on the domain
    domains = {"meta": {"type": "domains"}, "data": [
        {"Properties": {"name": "CORP"}, "ObjectIdentifier": DOM, "Aces": [
            {"PrincipalSID": f"{DOM}-1105", "RightName": "GetChanges"},
            {"PrincipalSID": f"{DOM}-1105", "RightName": "GetChangesAll"},
        ]}]}
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as z:
        z.writestr("20260101_users.json", json.dumps(users))
        z.writestr("20260101_groups.json", json.dumps(groups))
        z.writestr("20260101_computers.json", json.dumps(computers))
        z.writestr("20260101_domains.json", json.dumps(domains))
    p = tmp_path / "bh.zip"
    p.write_bytes(buf.getvalue())
    return str(p)


def test_load_bloodhound(tmp_path):
    data = load_bloodhound(_bh_zip(tmp_path))
    assert len(data["users"]) == 4 and len(data["groups"]) == 1
    assert len(data["computers"]) == 1 and len(data["domains"]) == 1


def test_full_attack_surface(tmp_path):
    fs = analyze_ad_bloodhound(_asset(_bh_zip(tmp_path)), _bh_zip(tmp_path))
    titles = " | ".join(f.title for f in fs)
    assert "Kerberoastable accounts (1)" in titles
    assert "AS-REP roastable accounts (1)" in titles
    assert "Unconstrained delegation" in titles
    assert "DCSync rights" in titles
    assert "Dangerous ACLs over high-value" in titles
    assert "Attack path to Domain/Enterprise Admins" in titles
    assert "krbtgt password not rotated" in titles
    assert "non-expiring password" in titles
    assert "End-of-life Windows OS" in titles
    assert "LAPS not deployed" in titles
    # criticality present and ATT&CK-mapped
    assert any(f.severity == Severity.CRITICAL for f in fs)
    assert all(f.references for f in fs)


def test_attack_path_names_the_route(tmp_path):
    fs = analyze_ad_bloodhound(_asset(_bh_zip(tmp_path)), _bh_zip(tmp_path))
    path_f = next(f for f in fs if "Attack path" in f.title)
    detail = " ".join(e.description or "" for e in path_f.evidence)
    assert "SQLSVC@CORP" in detail and "DOMAIN ADMINS@CORP" in detail
    assert "→" in detail


def test_empty_on_non_bloodhound(tmp_path):
    p = tmp_path / "x.inf"
    p.write_text("[System Access]\nMinimumPasswordLength = 8\n")
    assert analyze_ad_bloodhound(_asset(str(p)), str(p)) == []


def test_single_json_file(tmp_path):
    users = {"meta": {"type": "users"}, "data": [
        _user("SVC@CORP", f"{DOM}-1200", hasspn=True, serviceprincipalnames=["HTTP/x"])]}
    p = tmp_path / "users.json"
    p.write_text(json.dumps(users))
    fs = analyze_ad_bloodhound(_asset(str(p)), str(p))
    assert any("Kerberoastable" in f.title for f in fs)

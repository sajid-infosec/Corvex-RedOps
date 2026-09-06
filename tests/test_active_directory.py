"""Active Directory posture analyzer tests."""
from pentestiq.integrations.ad_tool import ActiveDirectoryAnalyzer, _ini
from pentestiq.models import Asset, AssetType
from pentestiq.engine import parse_scope_entry
from pentestiq.core.registry import registry
import pentestiq.modules  # noqa


SECPOL = """[System Access]
MinimumPasswordLength = 7
PasswordComplexity = 0
ClearTextPassword = 1
LockoutBadCount = 0
MaximumPasswordAge = -1
[Kerberos Policy]
MaxTicketAge = 24
; DONT_REQ_PREAUTH set on jdoe
; svc_sql has servicePrincipalName MSSQLSvc/db01
; DC01 TRUSTED_FOR_DELEGATION = TRUE
; groups.xml cpassword in SYSVOL
; SMBv1 enabled
; ms-DS-MachineAccountQuota = 10
; Domain Admins group has 24 members
"""


def _run(tmp_path, text=SECPOL):
    f = tmp_path / "secpol.inf"; f.write_text(text)
    a = Asset(type=AssetType.ACTIVE_DIRECTORY, identifier=str(f))
    return {x.title: x for x in ActiveDirectoryAnalyzer().parse(str(f), a)}


def test_ini_parser():
    d = _ini(SECPOL)
    assert d["System Access"]["MinimumPasswordLength"] == "7"
    assert d["Kerberos Policy"]["MaxTicketAge"] == "24"


def test_password_policy_findings(tmp_path):
    t = _run(tmp_path)
    assert any("minimum password length" in k.lower() for k in t)
    assert any("complexity disabled" in k.lower() for k in t)
    assert any("reversible" in k.lower() for k in t)               # critical
    assert any("lockout" in k.lower() for k in t)


def test_attack_path_findings(tmp_path):
    t = _run(tmp_path)
    titles = " | ".join(t).lower()
    for expect in ("as-rep", "kerberoast", "unconstrained", "cpassword",
                   "smbv1", "machineaccountquota", "domain admins"):
        assert expect in titles, f"missing AD check: {expect}"


def test_severities(tmp_path):
    t = _run(tmp_path)
    sevs = {v.severity.value for v in t.values()}
    assert "critical" in sevs and "high" in sevs


def test_clean_policy_few_findings(tmp_path):
    good = ("[System Access]\nMinimumPasswordLength = 15\nPasswordComplexity = 1\n"
            "ClearTextPassword = 0\nLockoutBadCount = 5\nMaximumPasswordAge = 90\n"
            "PasswordHistorySize = 24\n[Kerberos Policy]\nMaxTicketAge = 10\n")
    t = _run(tmp_path, good)
    assert len(t) == 0


def test_scope_prefix_and_registration():
    at, target = parse_scope_entry("ad=/path/secpol.inf")
    assert at == AssetType.ACTIVE_DIRECTORY and target == "/path/secpol.inf"
    at2, _ = parse_scope_entry("active_directory=/x")
    assert at2 == AssetType.ACTIVE_DIRECTORY
    assert registry.for_asset_type(AssetType.ACTIVE_DIRECTORY), "AD module not registered"

"""Score PentestIQ's native engine against the local vulnerable target.

Run from the repo root:  python bench/run_benchmark.py
"""
import os, sys, time

sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import vuln_target as vt
from pentestiq.models import Asset, AssetType
from pentestiq.checks.engine import CheckEngine
from pentestiq.checks.owasp import coverage_report

BASE = "http://127.0.0.1:8099"

PLANTED = {
    "Missing HSTS": "HSTS",
    "Missing CSP": "Content-Security-Policy",
    "Clickjacking (no XFO)": "framable",
    "CORS reflect + credentials": "CORS reflects",
    "Cookie missing flags": "cookie missing",
    "Dangerous HTTP methods": "dangerous HTTP methods",
    "Stack-trace leakage": "leaks Java",
    "JWT weak secret": "weak/guessable",
    "JWT embedded sensitive claim": "sensitive claim",
    "JWT long TTL": "lifetime is long",
    "BOLA cross-identity": "BOLA",
    "Excessive data exposure": "sensitive data",
    "Account enumeration": "enumeration",
}


def main():
    vt.serve(); time.sleep(0.4)
    meta = {
        "base_url": BASE, "jwt": vt.TOKEN_A,
        "identities": [
            {"name": "orgA", "headers": {"Authorization": f"Bearer {vt.TOKEN_A}"},
             "token": vt.TOKEN_A, "object_ids": ["user-a1"], "org_id": "orgA"},
            {"name": "orgB", "headers": {"Authorization": f"Bearer {vt.TOKEN_B}"},
             "token": vt.TOKEN_B, "object_ids": ["user-b1"], "org_id": "orgB"},
        ],
        "idor_endpoints": ["/api/user/{id}"],
        "data_endpoints": ["/api/user/me"],
        "login": {"url": "/auth/forgot", "field": "email",
                  "valid_user": "alice@x.com", "invalid_user": "nobody@x.com"},
        "allow_active": True, "rate_limit_attempts": 6,
    }
    findings = CheckEngine().run_asset(Asset(type=AssetType.API, identifier=BASE, metadata=meta))

    print("\n" + "=" * 74)
    print(f" PentestIQ benchmark — target {BASE} ({len(findings)} findings)")
    print("=" * 74)
    detected = 0
    for name, sig in PLANTED.items():
        hit = next((f for f in findings if sig.lower() in f.title.lower()), None)
        detected += bool(hit)
        sev = hit.severity.value.upper() if hit else "-"
        cat = hit.category if hit else "-"
        print(f"  [{'PASS' if hit else 'MISS'}] {name:<34} {sev:<9} {cat}")
    print("-" * 74)
    pct = detected * 100 // len(PLANTED)
    print(f"  DETECTED {detected}/{len(PLANTED)} planted vulnerabilities ({pct}%)")
    print("=" * 74)

    cov = coverage_report(findings)
    print("\n OWASP category coverage:")
    for edition in ("web-2021", "api-2023"):
        hits = [c for c in cov[edition] if c["findings"]]
        if hits:
            print(f"  {edition}: " + ", ".join(
                f"{c['id'].split(':')[0]}({c['findings']})" for c in hits))
    return 0 if detected == len(PLANTED) else 1


if __name__ == "__main__":
    sys.exit(main())

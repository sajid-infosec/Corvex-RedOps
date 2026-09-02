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
    "Blind SSRF (out-of-band)": "Blind SSRF",
    "Reflected XSS": "Reflected XSS",
    "SQL injection": "SQL injection",
    "Path traversal / LFI": "Path traversal",
    "SSTI (template injection)": "template injection",
    "OS command injection": "command injection",
}


def main():
    from pentestiq.crawler import Crawler
    vt.serve(); time.sleep(0.4)

    # 1) CRAWL — discover the surface (endpoints NOT supplied by hand)
    crawl = Crawler(max_pages=50).crawl(BASE)
    print(f"\n crawler: {crawl.stats}")
    print(f" crawler discovered IDOR candidates: {crawl.idor_endpoints()}")
    print(f" crawler discovered data endpoints:  {crawl.data_endpoints()}")

    # 2) tokens/login must be supplied (not discoverable); endpoints come from the crawl
    meta = {
        "base_url": BASE, "jwt": vt.TOKEN_A,
        "identities": [
            {"name": "orgA", "headers": {"Authorization": f"Bearer {vt.TOKEN_A}"},
             "token": vt.TOKEN_A, "object_ids": ["user-a1"], "org_id": "orgA"},
            {"name": "orgB", "headers": {"Authorization": f"Bearer {vt.TOKEN_B}"},
             "token": vt.TOKEN_B, "object_ids": ["user-b1"], "org_id": "orgB"},
        ],
        "login": {"url": "/auth/forgot", "field": "email",
                  "valid_user": "alice@x.com", "invalid_user": "nobody@x.com"},
        "allow_active": True, "rate_limit_attempts": 6,
    }
    meta.update(crawl.to_check_metadata())     # <-- crawler feeds the check engine
    meta["oast_wait"] = 1.5                      # allow the out-of-band callback to arrive
    meta["fuzz_time_delay"] = 1                  # keep time-based probes quick in the demo

    # 3) OAST — stand up a collaborator and confirm blind vulns out-of-band
    from pentestiq.oast import OastServer, OastClient
    collab = OastServer().start()
    oast = OastClient.local(collab)
    print(f" oast collaborator: {collab.base_url}")
    try:
        findings = CheckEngine().run_asset(
            Asset(type=AssetType.API, identifier=BASE, metadata=meta), oast=oast)
    finally:
        collab.stop()

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

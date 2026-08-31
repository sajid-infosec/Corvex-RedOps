# VAPT Report — Example Corp — External Web & Infra Assessment
*Prepared by PentestIQ · 2026-08-31 09:59 UTC*

## Executive Summary

PentestIQ assessed 2 assets for engagement "Example Corp — External Web & Infra Assessment" and identified 8 findings (overall risk rating: Critical). By severity: 1 critical, 1 high, 1 medium, 2 low. 1 finding was safely validated as exploitable through non-destructive checks (including: SQL Injection), removing false-positive doubt. The highest-priority item is "SQL Injection" (high, risk 95) on web:http://10.0.0.5:80.

**Overall risk rating: Critical**

| Severity | Count |
|---|---|
| Critical | 1 |
| High | 1 |
| Medium | 1 |
| Low | 2 |
| Info | 3 |

Assets: 2 · Findings: 8 · Validated: 1 · False positives dismissed: 0 · Attack chains: 4

## Scope

- Authorized by: Example Corp CISO (demonstration data)
- 10.0.0.5
- http://10.0.0.5:80

## Methodology

PentestIQ performed automated vulnerability assessment by orchestrating industry-standard tools (e.g. Nmap, Nuclei, OWASP ZAP), normalized and deduplicated results into a single findings model, then applied non-destructive safe-mode validation to confirm exploitability and remove false positives. Findings are prioritized by a blended risk score and correlated into attack chains.

## Findings

### 1. SQL Injection  

- **Severity:** high  |  **Risk:** 95  |  **Status:** validated  |  **Confidence:** high
- **Asset:** web:http://10.0.0.5:80  |  **Category:** CWE-89  |  **Chain:** 10.0.0.5:80  |  **Tools:** zap
- **Validation:** safe → confirmed
- **Evidence:**
    - `http://10.0.0.5:80/login` — POST SQL error
    - `http://10.0.0.5:80/login` — Boolean-based inference: TRUE matched baseline, FALSE diverged (base=(200, 160), true=(200, 160), false=(200, 7))
- **Remediation:** Use parameterized queries.
- **References:** https://owasp.org/sqli, https://cwe.mitre.org/data/definitions/89.html, https://cwe.mitre.org/data/definitions/89.html

### 2. Example RCE  

- **Severity:** critical  |  **Risk:** 90  |  **Status:** detected  |  **Confidence:** medium
- **Asset:** infra:10.0.0.5  |  **Category:** CVE-2021-1234  |  **Chain:** 10.0.0.5:80  |  **Tools:** nuclei
- **Evidence:**
    - `http://10.0.0.5:80/vuln` — Remote code execution
- **References:** https://nvd.nist.gov/vuln/detail/CVE-2021-1234

### 3. Weak TLS  

- **Severity:** medium  |  **Risk:** 50  |  **Status:** detected  |  **Confidence:** medium
- **Asset:** infra:10.0.0.5  |  **Category:** weak-tls  |  **Chain:** 10.0.0.5:443  |  **Tools:** nuclei
- **Evidence:**
    - `https://10.0.0.5:443`
- **References:** https://example.com/tls

### 4. Open port 23/tcp — telnet  

- **Severity:** low  |  **Risk:** 28  |  **Status:** detected  |  **Confidence:** high
- **Asset:** infra:10.0.0.5  |  **Category:** open-port  |  **Chain:** 10.0.0.5:23  |  **Tools:** nmap
- **Evidence:**
    - `10.0.0.5:23/tcp` — telnet

### 5. X-Content-Type-Options Header Missing  

- **Severity:** low  |  **Risk:** 25  |  **Status:** detected  |  **Confidence:** medium
- **Asset:** web:http://10.0.0.5:80  |  **Category:** CWE-16  |  **Chain:** 10.0.0.5:80  |  **Tools:** zap
- **Evidence:**
    - `http://10.0.0.5:80/` — GET
- **Remediation:** Set the header.
- **References:** https://cwe.mitre.org/data/definitions/16.html

### 6. Open port 22/tcp — ssh (OpenSSH 8.2p1)  

- **Severity:** info  |  **Risk:** 6  |  **Status:** detected  |  **Confidence:** high
- **Asset:** infra:10.0.0.5  |  **Category:** open-port  |  **Chain:** 10.0.0.5:22  |  **Tools:** nmap
- **Evidence:**
    - `10.0.0.5:22/tcp` — OpenSSH 8.2p1

### 7. Open port 80/tcp — http (nginx 1.18.0)  

- **Severity:** info  |  **Risk:** 6  |  **Status:** detected  |  **Confidence:** high
- **Asset:** infra:10.0.0.5  |  **Category:** open-port  |  **Chain:** 10.0.0.5:80  |  **Tools:** nmap
- **Evidence:**
    - `10.0.0.5:80/tcp` — nginx 1.18.0

### 8. nginx detected  

- **Severity:** info  |  **Risk:** 5  |  **Status:** detected  |  **Confidence:** medium
- **Asset:** infra:10.0.0.5  |  **Category:** tech-detect  |  **Chain:** 10.0.0.5:80  |  **Tools:** nuclei
- **Evidence:**
    - `http://10.0.0.5:80`

## Compliance Mapping

6 of 8 findings map to a recognized framework control (indicative, not a certification).

- **OWASP Top 10:** A05: Security Misconfiguration (x4), A03: Injection (x1), A02: Cryptographic Failures (x1)
- **PCI-DSS:** 1.1.6 (x3), 6.5.1 (x1), 2.2 (x1), 4.1 (x1)
- **ISO 27001:** A.13.1.1 (x3), A.14.2.5 (x1), A.14.1.2 (x1), A.10.1.1 (x1)
- **MITRE ATT&CK:** T1046 (x3), T1190 (x1), T1590 (x1), T1040 (x1)

---
*Authorized use only. This report documents testing performed under an agreed engagement scope. Findings are confidential.*
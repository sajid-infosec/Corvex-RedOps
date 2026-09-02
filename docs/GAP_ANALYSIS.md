# PentestIQ Gap Analysis & OWASP Top 10 Coverage

**Benchmark:** the real, completed VAPT of **Convay/Synesis** (`convay2.0/`) — a
multi-tenant video-conferencing SaaS. 52 test cases mapped to OWASP WSTG +
API Security Top 10, ~35 confirmed findings across web, API, JWT, authorization,
business logic, real-time/chat, and infrastructure.

The question this answers: **what does a real VAPT of a modern SaaS require that a
VA orchestrator does not do?** — and how PentestIQ now closes that gap.

---

## 1. What the real engagement proved

The Convay engagement's confirmed findings were overwhelmingly **authorization,
JWT, and business-logic** issues — the exact classes that automated VA scanners
(ZAP/Nuclei/Nessus) structurally cannot find, because they need authenticated,
multi-identity, active probing:

| # | Confirmed finding (Convay) | OWASP | Scanner can find? |
|---|---|---|---|
| TC-C05 | App JWT embeds a cleartext Matrix `syt_` token → full Matrix takeover | API2 | No |
| TC-C06 | 24h token, no server-side revocation on logout | API2 | No |
| TC-D03 | BOLA: cross-tenant meeting/invitee read | API1 | No |
| TC-D05 | BFLA: low-priv user exports 350-user roster | API5 | No |
| TC-D06 | `downloadFile/{uuid}` served with no auth (IDOR) | API1 | Partial |
| TC-D07 | `userId` query param overrides token tenant scope | API1 | No |
| TC-F02 | Stored XSS in `firstName` (renders in meetings/admin) | A03 | Partial |
| TC-G01 | CORS reflects any `*.convay.com` origin with credentials | API8 | Partial |
| TC-G02 | No HSTS anywhere; CSP `frame-ancestors:*` | A05 | Yes |
| TC-H01 | Unrestricted upload (`.php`, SVG-XSS) | A05 | Partial |
| TC-I02 | Payment result manipulation (fake gateway sub-id accepted) | API6 | No |
| TC-I03 | Unauth invite-validate leaks full org roster | API5 | No |
| TC-I05 | bcrypt `userPass` hash returned in user profile JSON | API3 | No |
| TC-J02 | Excessive data exposure via `/user/export` | API3 | No |
| TC-J04 | Java stack traces on malformed input | A05 | Partial |
| TC-K01/K04 | Matrix open registration; LiveKit mints tokens for any room | API5 | No |
| TC-L02/L03 | nginx CVEs; Consul/Kafka/RabbitMQ/Zabbix internet-facing | A06/A05 | Yes |

**Roughly 70% of the real findings are logic/authz/JWT** — the differentiator of
a true VAPT platform (Burp Suite Enterprise / Acunetix class), not a VA scanner.

---

## 2. Gap: PentestIQ *before* this upgrade

PentestIQ was a strong **VA orchestrator** — it wraps nmap, Nessus-class output,
Nuclei, ZAP, WPScan, MobSF, and native analyzers for desktop/netdev/firewall/
hardening, normalizes everything into one `Finding` model, dedupes, risk-scores,
correlates, and reports. But for the *web/API* asset types it only ran ZAP +
Nuclei + an OpenAPI enumerator, and had just two exploit validators (reflected
XSS, SQLi).

That leaves the crown-jewel classes uncovered:

| Class | Convay cases | Covered before? |
|---|---|---|
| JWT security (alg confusion, weak secret, claim trust, embedded tokens, TTL) | TC-C01–C06 | ❌ none |
| BOLA / IDOR / tenant confusion (multi-identity diff) | TC-D01–D07 | ❌ none |
| Broken function-level authz (BFLA) | TC-D05 | ❌ none |
| Excessive data exposure / secrets-in-response | TC-J02, I05 | ❌ none |
| CORS credential reflection | TC-G01 | ⚠️ ZAP-partial |
| Security headers / clickjacking / cookies | TC-G02/G03/E01 | ⚠️ ZAP-partial |
| Auth logic: account enumeration, login rate-limit | TC-B01/B03 | ❌ none |
| Verbose errors / stack-trace leakage | TC-J04 | ❌ none |
| HTTP methods / OPTIONS surface | TC-A04 | ❌ none |
| OWASP Top 10 (2021) + API Top 10 (2023) coverage checklist | all | ❌ free-text only |

---

## 3. What this upgrade adds — the native active-checks engine

A new dependency-free, fully unit-tested **`pentestiq.checks`** package that runs
authenticated, multi-identity, active checks — the layer a VA orchestrator lacks.
It mirrors the validator design (injectable HTTP client → testable without a live
target) and is **safe by default**: every probe is GET/OPTIONS/read-only; any
state-generating probe (e.g. login brute-force) is gated behind `allow_active`.

| Check | Reproduces | OWASP |
|---|---|---|
| `JwtSecurityCheck` | alg:none, offline HMAC weak-secret crack, embedded-token/all-perms claims, long TTL, live none-alg accept probe | API2 / A02 / API1 |
| `BolaIdorCheck` | cross-identity object reads (two-identity diff) | API1 |
| `TenantConfusionCheck` | query param overrides token tenant scope | API1 |
| `ExcessiveDataExposureCheck` | password hashes / secrets / tokens in responses | API3 |
| `AccountEnumerationCheck` | valid-vs-invalid user response diff | A07 |
| `LoginRateLimitCheck` (gated) | missing lockout / 429 on failed logins | A07 |
| `SecurityHeadersCheck` | HSTS/CSP/XCTO/Referrer/Permissions + banner | A05 |
| `ClickjackingCheck` | `frame-ancestors:*` / missing XFO | A05 |
| `CorsCheck` | origin reflection with credentials | API8 |
| `CookieFlagsCheck` | HttpOnly/Secure/SameSite | A05 |
| `HttpMethodsCheck` | dangerous methods via OPTIONS | A05 |
| `ErrorHandlingCheck` | Java/Python/.NET/SQL stack-trace leakage | A05 |

**Coverage checklist.** `pentestiq.checks.owasp` is the canonical OWASP Top 10
2021 (A01–A10) + API Top 10 2023 (API1–API10) catalogue. The compliance report
now maps every finding to a canonical id and emits an **`owasp_coverage`**
matrix — the checklist that shows which categories a given engagement exercised
and which are still gaps.

**Wiring.** The `web` and `api` modules now run this engine in their `assess()`
phase alongside ZAP/Nuclei/OpenAPI, so findings flow through the same dedup /
risk-scoring / correlation / reporting pipeline. Authenticated testing is
configured per-asset via `asset.metadata` (identities, object IDs, endpoints,
login, JWT) — see `pentestiq/checks/engine.py`.

---

## 4. Coverage: before → after

| OWASP (2021 / API 2023) | Before | After |
|---|---|---|
| A01 / API1 Broken Access Control / BOLA | ❌ | ✅ BOLA, tenant-confusion, IDOR |
| A02 Cryptographic Failures | ⚠️ TLS via tools | ✅ + JWT weak-secret |
| A03 Injection | ✅ XSS/SQLi validators | ✅ (unchanged) |
| A05 / API8 Security Misconfiguration | ⚠️ partial | ✅ headers/CORS/cookies/methods/errors |
| A06 Vulnerable Components | ✅ nmap/nuclei/nessus | ✅ (unchanged) |
| A07 Auth Failures | ⚠️ enum via tools | ✅ + enumeration, rate-limit |
| API2 Broken Authentication | ❌ | ✅ full JWT analysis |
| API3 Data Exposure | ❌ | ✅ secrets-in-response |
| API5 Broken Function-Level Authz | ⚠️ OpenAPI-only | ✅ + BFLA surface |
| API4 Resource Consumption | ⚠️ | ✅ rate-limit (gated) |

---

## 5. Delivered since the first gap pass

- ✅ **Attack-surface crawler** (`pentestiq.crawler`) — BFS same-scope crawl,
  forms/params/JS-endpoint extraction, id-path templatizing → the check engine now
  runs app-wide instead of only on supplied endpoints. Benchmarked crawl-first:
  the crawler discovers the vulnerable endpoints itself and checks still detect
  **13/13** planted vulnerabilities (`bench/`).
- ✅ **Single-portal API VAPT** — upload an OpenAPI/Swagger spec + bearer token(s)
  like an APK; endpoints/identities are derived automatically.
- ✅ **Frida dynamic-analysis kit** served from the portal.

## 6. Still orchestrated / roadmap (honest gaps)

Some Convay findings remain best served by external tools (already orchestrated)
or are candidates for future native checks:

- **Mass assignment (TC-F05), SSRF (TC-F04), host-header (TC-F06)** — active
  write/OOB probes; planned as `allow_active`-gated checks.
- **Payment/business-logic (TC-I02)** — inherently app-specific; PentestIQ flags
  the surface, human confirms the write PoC (per rules-of-engagement).
- **Real-time/chat (Matrix/LiveKit/Firebase, TC-K)** — protocol-specific probes;
  candidate native module.
- **Infra service auth (Consul/Kafka/RabbitMQ guest, TC-L)** — nmap discovers the
  ports; service-specific auth checks are a roadmap module.
- **File-upload execution (TC-H01)** — partially covered; a dedicated upload
  check is planned.

---

## 7. Asset-type coverage (as tested on Convay's real assets)

| Convay asset | File | PentestIQ module |
|---|---|---|
| Web app (`app.convay.com` SPA) | JS bundles | `web` + native checks |
| REST API (218 endpoints, JWT) | Burp capture | `api` + native checks (BOLA/JWT/authz) |
| Mobile app | `convaychat-x-production.apk` (323 MB) | `mobile` (MobSF) |
| Desktop app | `convay-desktop-production…​.exe` (70 MB) | `desktop` (native PE/ELF/Mach-O) |
| Infrastructure | nmap + Nessus | `infra` (nmap/nuclei) |
| Firewall / hardening / network device | configs | `firewall` / `hardening` / `netdev` |

Every asset type in the real engagement maps to a PentestIQ module; the upgrade
closes the *depth* gap on the two hardest ones — web and API.

# Corvex — Manual QA Guide

A hands-on checklist to verify Corvex detection end-to-end, yourself. Every step
uses a **synthetic, safe** sample you generate locally — no real credentials, no
real targets required (a couple of optional live-web steps use public deliberately
vulnerable apps).

> This is the human-run companion to the automated suite (`pytest`, 480+ tests).
> Work top to bottom, or jump to the module you care about. Each section lists the
> **exact steps** and the **findings you should see**.

---

## 0. Setup (once)

```bash
# from the repo root
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev,api,reports]"

# generate the deliberately-vulnerable sample inputs → qa/samples/
python qa/make_samples.py

# start the server
corvex serve            # http://127.0.0.1:8000  (console + /docs)
```

On first run Corvex prints a **one-time admin password** to this terminal:

```
==================================================================
  Corvex first-run admin created.
    username: admin
    password: <copy-this>
==================================================================
```

Open **http://127.0.0.1:8000**, sign in as `admin` with that password (or set
`export CORVEX_ADMIN_PASSWORD=…` before starting to pin your own), and change it.

`qa/samples/` now contains:

| File | Feeds the… | Upload as template |
|---|---|---|
| `vulnerable.apk` | Mobile module | **Mobile / Desktop app** |
| `vulnerable.ipa` | Mobile module | **Mobile / Desktop app** |
| `vulnerable-electron.asar` | Desktop module | **Mobile / Desktop app** |
| `vulnerable-linux-binary` | Desktop module | **Mobile / Desktop app** |
| `bloodhound-sample.zip` | Active Directory module | **Active Directory** |
| `secpol-weak.inf` | Active Directory (config) | **Active Directory** |
| `leaky-source.zip` | Secret scan | **Secret scan** |
| `Dockerfile` | IaC scan (Trivy) | **Container / IaC** |

---

## 1. Mobile — APK (native, no MobSF)

**Do:** New scan → **Mobile / Desktop app** → upload `qa/samples/vulnerable.apk` → run.

**Expect (≈8 findings), all MASVS-mapped:**

- [ ] **HIGH** — Application is debuggable (`android:debuggable=true`)
- [ ] **MEDIUM** — Application data is backup-enabled (`allowBackup`)
- [ ] **MEDIUM** — Cleartext traffic explicitly allowed
- [ ] **LOW** — No network security config
- [ ] **HIGH** — Exported provider without permission guard (`.ExportedProvider`)
- [ ] **HIGH** — Hardcoded secret in app package (AWS key — value **redacted**)
- [ ] **MEDIUM** — Cleartext (HTTP) endpoints in app
- [ ] **HIGH** — APK signed with a debug certificate

✅ **Key check:** you get findings **without** a MobSF server running. The old
build returned zero here.

## 2. Mobile — IPA

**Do:** same template → upload `qa/samples/vulnerable.ipa`.

**Expect (≈7):**

- [ ] **HIGH** — App Transport Security disabled (`NSAllowsArbitraryLoads`)
- [ ] **MEDIUM** — ATS insecure-HTTP exceptions for 1 domain
- [ ] **MEDIUM** — iTunes/Files file sharing enabled
- [ ] **LOW** — Custom URL scheme(s) registered
- [ ] **HIGH** — iOS app is debuggable (`get-task-allow=true`)
- [ ] **LOW** — iOS app is a development (ad-hoc) build
- [ ] **HIGH/MEDIUM** — Hardcoded secret / Cleartext endpoint

## 3. Desktop — Electron app

**Do:** **Mobile / Desktop app** → upload `qa/samples/vulnerable-electron.asar`.

**Expect (≈7), CWE-mapped:**

- [ ] **HIGH** — Electron insecure config: `nodeIntegration`
- [ ] **HIGH** — Electron insecure config: `contextIsolation`
- [ ] **HIGH** — Electron insecure config: `webSecurity`
- [ ] **MEDIUM** — Electron loads a remote page over HTTP
- [ ] **LOW** — Electron main/renderer uses `eval()`
- [ ] **HIGH** — Hardcoded secret (redacted)
- [ ] **INFO** — Electron runtime version 11.0.0 bundled

## 4. Desktop — native binary hardening

**Do:** upload `qa/samples/vulnerable-linux-binary`.

**Expect:** **ELF has an executable stack (NX disabled)** · **not position-independent
(no PIE)** · **no stack canary** — all without `lief` installed.

## 5. Active Directory — BloodHound attack surface

**Do:** New scan → **Active Directory** → upload `qa/samples/bloodhound-sample.zip`.

**Expect (≈9), ATT&CK-mapped:**

- [ ] **HIGH** — Kerberoastable accounts (SQLSVC)
- [ ] **HIGH** — AS-REP roastable accounts (HELPDESK)
- [ ] **CRITICAL** — Unconstrained delegation on a non-DC host (WS01)
- [ ] **CRITICAL** — Non-default principals with DCSync rights
- [ ] **HIGH** — Dangerous ACLs over high-value objects
- [ ] **CRITICAL** — **Attack path to Domain Admins** from a crackable account
      (evidence names the route: `SQLSVC@… → DOMAIN ADMINS@…`)
- [ ] **HIGH** — krbtgt password not rotated in N days
- [ ] **MEDIUM** — End-of-life Windows OS (Server 2008 R2)
- [ ] **MEDIUM** — LAPS not deployed

✅ **Key check:** this is real attack-surface analysis (paths to DA), not just a
config checklist. To try config review too, upload `secpol-weak.inf`.

## 6. Secret scan (source archive)

**Do:** New scan → **Secret scan** → upload `qa/samples/leaky-source.zip`.

**Expect:** hardcoded **AWS key** and **Stripe live key** detected, mapped to
CWE-798 / OWASP A07, values **redacted** in the report.

## 7. Infra — service → CVE (optional, needs a target or nmap output)

The infra module maps discovered service banners to CVEs automatically. Two ways
to see it:

- **With nmap installed**, scan a host you own that runs an older service; an
  `OpenSSH 7.6p1` / `vsftpd 2.3.4` banner becomes an **Outdated … — N known CVE(s)**
  finding ranked by PRP.
- **Without a target**, import an existing Nessus/Nuclei file (**Import findings**)
  — banners in the import get the same enrichment.

Expected for `vsftpd 2.3.4`: **CRITICAL — Outdated vsftpd 2.3.4** (CVE-2011-2523).

## 8. Web / API (optional, live target)

Point the **Web** template at a deliberately vulnerable app you host locally, e.g.
[OWASP Juice Shop](https://github.com/juice-shop/juice-shop) (`docker run -p 3000:3000
bkimminich/juice-shop`) or DVWA. Expect crawl → OWASP checks → injection findings
(reflected XSS, SQLi) with **safe validation** flipping confirmed ones to *validated*.

> Only scan targets you own or are authorized to test.

---

## 9. Reports — verify the deliverable

For any completed engagement:

- [ ] Open **Reports → Full technical (HTML)**. Severity chips show the **correct
      colour** (Critical red, High orange, Medium amber, Low blue) — including in
      the *Risk Rating Methodology* table (this was a fixed bug).
- [ ] Scroll to the appendix sections: **MITRE ATT&CK Coverage**, **Attack Path
      Analysis** (SVG), **Cloud/Container findings**, **Compliance Mapping** appear
      when the engagement has that data.
- [ ] Export **PDF** and **DOCX** — same sections render as tables; headings read
      "MITRE ATT&CK Coverage" (not "ATT&CK;").
- [ ] Export the **Executive summary** — donut + gauge + top risks.

## 10. Analytics & alerts (CTEM)

- [ ] Overview → **Posture trend** card appears after a scan (or click *Snapshot now*).
- [ ] Settings → **Exposure alerts** → set a Slack webhook → **Send test alert**.

---

## Regression sign-off

- [ ] `pytest` runs clean (480+ passed, a few `live` tests deselected) in ~1 min.
- [ ] Sign-in uses the one-time logged password — **no default credentials** anywhere.
- [ ] Every module above produced findings from the sample inputs.

Found a gap or a wrong result? Note the module + sample file + what you expected,
and it goes straight onto the backlog.

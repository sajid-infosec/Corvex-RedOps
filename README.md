<div align="center">

# 🛡️ PentestIQ

### The orchestration-driven VAPT platform — every asset, one engine, client-ready in minutes.

*Vulnerability Assessment **and** validated Penetration Testing across infrastructure, web, WordPress, APIs, mobile, desktop, network devices, firewalls, and system hardening — normalized, risk-scored, correlated, and reported. Safely, with authorization built in.*

![CI](https://github.com/sajid-infosec/PentestIQ/actions/workflows/ci.yml/badge.svg)
![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg)
![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg)
![Tests](https://img.shields.io/badge/tests-118%20passing-brightgreen.svg)
![Modules](https://img.shields.io/badge/asset%20modules-9-8a2be2.svg)
![Status](https://img.shields.io/badge/status-active%20development-orange.svg)

[Features](#-features) · [Asset Coverage](#-asset-coverage) · [Installation](#-installation) · [Quick Start](#-quick-start) · [Deployment](#-deployment) · [User Manual](#-user-manual) · [API Reference](#-rest-api-reference)

</div>

---

> ⚠️ **Authorized use only.** PentestIQ performs active security testing, including safe, non-destructive exploit validation. Use it **only** against systems you own or are explicitly authorized to test. Scope enforcement, a safe-mode governor, and a full audit trail are **core, built-in features**. See [Legal & Ethics](docs/LEGAL_AND_ETHICS.md).

---

## 📖 Table of Contents

- [What is PentestIQ?](#-what-is-pentestiq)
- [Features](#-features)
- [Asset Coverage](#-asset-coverage)
- [How It Works](#-how-it-works)
- [Screens & Samples](#-screens--samples)
- [Installation](#-installation)
- [Quick Start](#-quick-start)
- [Deployment](#-deployment)
- [User Manual](#-user-manual)
  - [1. Scope files](#1-scope-files)
  - [2. CLI reference](#2-cli-reference)
  - [3. Scanning each asset type](#3-scanning-each-asset-type)
  - [4. Uploading apps & configs](#4-uploading-apps--configs)
  - [5. Reports](#5-reports)
  - [6. Continuous scanning & scheduling](#6-continuous-scanning--scheduling)
  - [7. Authentication, tenants & RBAC](#7-authentication-tenants--rbac)
  - [8. Configuration](#8-configuration)
- [REST API Reference](#-rest-api-reference)
- [Safety, Authorization & Legal](#-safety-authorization--legal)
- [Development & Testing](#-development--testing)
- [Roadmap](#-roadmap)
- [Contributing](#-contributing)
- [License](#-license)

---

## 🔍 What is PentestIQ?

Security teams run VAPT with a sprawl of disconnected point tools — each with its own output format and no shared model. The result is hours of glue work, false-positive overload, inconsistent methodology, and reporting that takes as long as the testing.

**PentestIQ unifies the entire VAPT lifecycle into one workflow-driven platform.** It orchestrates best-in-class tools behind a single engine, normalizes their output into one findings model, **safely validates** whether findings are actually exploitable, prioritizes by risk, correlates issues into attack chains, and produces **client-ready reports** — HTML, Markdown, PDF, or DOCX, with compliance mapping and white-label branding.

It does **both halves** of the job:

- **Vulnerability Assessment (VA)** — discover, enumerate, and prioritize weaknesses across the full asset surface.
- **Penetration Testing (PT)** — safely confirm real exploitability (non-destructively), cutting false positives and proving impact.

It ships as **both** a free, self-hostable open-source engine **and** a multi-tenant SaaS platform (REST API + web console + scheduling + reporting).

---

## ✨ Features

### Core engine
- **One normalized findings model** across every tool and asset type — deduplicate, correlate, and risk-score once.
- **9 asset modules** covering the complete attack surface (see [Asset Coverage](#-asset-coverage)).
- **Safe exploit validation** — non-destructive reflected-XSS and boolean-based SQLi confirmation that flips findings from *detected* to *validated* (with evidence) or dismisses false positives.
- **Risk scoring (0–100)** blending severity, CVSS, confidence, and validation state.
- **Attack-chain correlation** — links findings that share a host + service into one story.
- **AI-assisted reporting** with a pluggable LLM hook that degrades gracefully to a strong data-driven summary (works with zero budget / no API key).

### Safety & governance (built in, not bolted on)
- **Scope enforcement** — every engagement runs against a validated scope; out-of-scope targets are blocked (or warned) by policy.
- **Safe-mode governor** — non-destructive by default; intrusive/exploit actions require explicit, logged opt-in.
- **Append-only audit trail** (JSONL) — who ran what, against what, when, and what the policy decided.
- **Per-host rate limiting** — never accidentally DoS a target.

### Platform (SaaS layer)
- **REST API** (FastAPI) with auto-generated OpenAPI docs at `/docs`.
- **Web console** — create engagements, upload apps/configs, run scans, watch findings, open reports — served at `/`.
- **Authentication, multi-tenancy & RBAC** — user login (PBKDF2), session tokens, per-tenant API keys (hashed), and roles (`viewer` → `member` → `admin` → `owner`).
- **Continuous scanning** — recurring schedules with **diffing** (new / fixed / persisting) and **Slack/webhook notifications**.
- **Reporting at scale** — HTML / Markdown / PDF / DOCX, **compliance mapping** (OWASP / PCI-DSS / ISO 27001 / MITRE ATT&CK), and **per-tenant white-label branding**.

### Deployment
- **Self-hostable** — `pip install` for the engine; **Docker Compose** for the full stack with the integrated mobile-analysis service.
- **Postgres-ready** — SQLite by default, swappable behind clean storage interfaces.

---

## 🎯 Asset Coverage

Ten modules — the complete VAPT surface, driven by PentestIQ's own engines with additional deep-scan backends bundled in the platform (auto-detected; anything unavailable is skipped, never fatal).

| # | Module | Asset type | What PentestIQ does |
|---|---|---|---|
| 1 | `infra` | Infrastructure / network | Host & service discovery, port enumeration, network vulnerability scanning |
| 2 | `web` | Web applications | Crawl (static + headless SPA), OWASP Top-10 active checks (headers/CORS/JWT/authz/errors), injection fuzzing, out-of-band detection, safe exploit validation |
| 3 | `wordpress` | WordPress sites | Core/plugin/theme CVEs, user enumeration, weak-credential checks |
| 4 | `api` | REST / OpenAPI | Endpoint mapping + **authenticated access-control (BOLA/IDOR), token analysis, tenant confusion, excessive-data-exposure** (OWASP API Top 10) |
| 5 | `mobile` | Mobile apps (Android / iOS) | Static analysis of code, manifest, permissions, secrets & certificates (CWE/MASVS) + on-device dynamic kit |
| 6 | `desktop` | Desktop binaries (PE / ELF / Mach-O) | Hardcoded secrets/keys, insecure URLs, missing binary hardening (NX/PIE/RELRO/canary/DEP/CFG) |
| 7 | `network-device` | Routers / switches | Device config audit: telnet, default/RW SNMP, weak passwords, cleartext management |
| 8 | `firewall` | Firewall rulesets | *nipper-class* ruleset audit: any-any permits, exposed services, shadowed rules |
| 9 | `hardening` | System hardening | Host hardening gaps (SSH/kernel/CIS) + hardening-report ingestion |
| 10 | `active-directory` | Active Directory / domain | Domain security-posture review from a policy export: password policy, Kerberos (AS-REP roasting / Kerberoasting), unconstrained delegation, GPP cpassword, SMBv1/LLMNR, machine-account quota, privileged-group sprawl |

Plus **lab automation** — `lab/docker-compose.yml` stands up intentionally-vulnerable targets for testing and demos.

---

## 🕷️ Attack-surface crawler

PentestIQ ships a native, dependency-free **crawler** (`pentestiq.crawler`) that
discovers the app surface — like the commercial DAST engines — so the checks run
across the whole application instead of only the endpoints you supply:

- **BFS crawl**, same-scope (optional subdomains), depth- and page-bounded, rate-limited.
- Extracts **links, forms (action/method/inputs), query parameters**, and
  **endpoints mined from JavaScript bundles** (the recon that surfaced internal
  endpoints in the real Convay assessment).
- **Templatizes id paths** (`/user/42` → `/user/{id}`) → automatic **BOLA/IDOR**
  candidates; GET paths become **data-exposure** targets.
- **Headless-browser SPA mode** (optional): renders JavaScript, follows
  client-side routes, and captures the **XHR/fetch API endpoints** a SPA only creates
  at runtime — the surface a static crawler can't see. Enabled with `--spa` (or
  `asset.metadata.spa_crawl = true`); falls back to the static crawl if the headless
  browser isn't installed (a missing component never breaks a run).
- Runs in the `web` module's discovery phase and feeds the check engine
  automatically; also available standalone: `pentestiq crawl https://app.example.com --token <jwt> --spa`.

## 📡 Out-of-band detection (OAST)

For **blind** vulnerabilities — where the only signal is the target's own server
reaching back to infrastructure you control — PentestIQ ships a native,
self-hostable **OAST collaborator** (the Burp-Collaborator / AcuMonitor model):

- **`pentestiq oast-server --port 9099 [--dns-port 53 --domain oast.example.com]`**
  stands up a collaborator. HTTP mode records interactions by token from a Host
  sub-domain (`<token>.oast.example.com`, needs wildcard DNS) or a path
  (`http://<ip>:<port>/<token>`, needs only a public IP). The optional **DNS catcher**
  (`--dns-port`) answers `A` records for `<token>.<domain>` and logs the lookup — so
  it confirms blind interactions that only do a **DNS resolution** even when outbound
  HTTP is filtered (delegate the domain's NS to the collaborator's IP).
- OAST-enabled checks inject a unique collaborator URL/host and confirm the bug
  **only** if the callback lands — a hit is high-confidence proof, not a guess:
  - **Blind SSRF** — injected into discovered/likely URL params and SSRF-prone
    headers (`A10` / API7).
  - **Stored / blind XSS** — script payloads planted in forms; confirmed if a
    browser later renders them and loads the collaborator (deferred capture).
- Point the checks at a collaborator via `asset.metadata.oast = {"url": "http://collab:9099"}`
  (or `{"domain": "oast.example.com"}`); OAST checks are gated behind `allow_active`.

Verified end-to-end in `bench/`: the benchmark stands up a collaborator and
**confirms blind SSRF out-of-band** as the 14th planted vulnerability.

## 🧪 Native OWASP active checks (VAPT depth)

Generic scanners find *technical* web bugs; a real VAPT of a modern multi-tenant
SaaS is ~70% **authorization, JWT, and business-logic** testing that needs
authenticated, multi-identity, active probing. PentestIQ ships a native,
dependency-free checks engine (`pentestiq.checks`) that provides exactly that —
run in the `web` and `api` `assess()` phase, feeding the same dedup / risk-scoring
/ reporting pipeline.

| Check | Finds | OWASP |
|---|---|---|
| **JWT security** | `alg:none`, offline HMAC weak-secret crack, embedded secondary tokens / all-perms claims, long TTL, live none-alg accept probe | API2 / A02 |
| **BOLA / IDOR** | cross-identity object reads (two-identity diff) | API1 |
| **Tenant confusion** | query param overrides token tenant scope | API1 |
| **Excessive data exposure** | password hashes / secrets / tokens in responses | API3 |
| **Account enumeration** | valid-vs-invalid user response diff | A07 |
| **Login rate-limit** *(gated)* | missing lockout / 429 on failed logins | A07 |
| **Security headers / clickjacking / cookies** | HSTS, CSP, `frame-ancestors:*`, XFO, cookie flags | A05 |
| **CORS** | origin reflection with credentials | API8 |
| **HTTP methods / error handling** | dangerous methods; Java/Python/.NET/SQL stack-trace leakage | A05 |

**Safe by default** — every probe is read-only (GET/OPTIONS); anything that
generates auth traffic (login brute-force) is gated behind `allow_active`.

### Native injection-fuzzing engine

A from-scratch active fuzzer (`pentestiq.fuzzing`) drives payloads into every
injection point the crawler finds (query params, form fields, headers) and
confirms bugs by response signal — no external scanner needed:

| Class | Detection | OWASP / CWE |
|---|---|---|
| **SQL injection** | error-signature, boolean-blind (TRUE≈baseline / FALSE differs), **time-blind** (injected sleep) | A03 / CWE-89 |
| **Reflected XSS** | unique marker reflected unescaped in HTML context | A03 / CWE-79 |
| **OS command injection** | **blind out-of-band** (via the OAST collaborator) and time-blind | A03 / CWE-78 |
| **Path traversal / LFI** | reads `/etc/passwd` / `win.ini` via traversal | A01 / CWE-22 |
| **SSTI** | template evaluates a distinctive arithmetic product | A03 / CWE-1336 |

Payloads are non-destructive proofs (a syntax error, a benign reflection, a timed
sleep, a read-only file, an arithmetic evaluation) — never `DROP`/`DELETE`/`rm`.
Gated behind `allow_active`; blind command injection reuses the OAST collaborator.

**Authenticated testing** is configured per-asset via `asset.metadata`
(identities + object IDs, endpoints, login, JWT). Example:

```jsonc
{
  "base_url": "https://api.example.com",
  "identities": [
    {"name": "orgA", "headers": {"Authorization": "Bearer <jwtA>"}, "object_ids": ["uuid-a"]},
    {"name": "orgB", "token": "<jwtB>", "object_ids": ["uuid-b"]}
  ],
  "idor_endpoints": ["/api/user/{id}", "/api/org/{id}"],
  "data_endpoints": ["/api/user/me"],
  "login": {"url": "/auth/forgot", "field": "email", "valid_user": "a@x.com", "invalid_user": "no@x.com"}
}
```

**OWASP Top 10 coverage checklist.** Every finding is mapped to a canonical id
(A01–A10 2021 + API1–API10 2023); `GET /engagements/{id}/compliance` now returns
an `owasp_coverage` matrix showing which categories an engagement exercised — and
which remain gaps. See [`docs/GAP_ANALYSIS.md`](docs/GAP_ANALYSIS.md) for the full
benchmark against a real SaaS engagement.

---

## ⚙️ How It Works

```
  scope  ──►  ORCHESTRATION ENGINE  ──►  normalized findings  ──►  report
              │  scope enforcement          (deduped, scored,        (HTML/MD/
              │  safe-mode governor          correlated, validated)   PDF/DOCX)
              │  audit trail
              ▼
     ┌────────┴─────────────────────────────────────┐
     │  asset modules  ──►  scan engines             │
     │  (infra, web, … )    (native + bundled)       │
     │           │                                   │
     │           ▼                                   │
     │  safe validators  ──►  detected → validated   │
     │  (XSS / SQLi)          or  false-positive     │
     └───────────────────────────────────────────────┘
```

Pipeline: **scope → scan → normalize → validate → prioritize & correlate → report.** Full design in [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md).

---

## 🖼️ Screens & Samples

- **Web console** — a live dashboard (create engagements, upload apps/configs, run scans, view findings + severity chart + attack chains, open reports). Preview: [`examples/console-preview.html`](examples/console-preview.html).
- **Client report** — a branded, multi-format report with compliance mapping. Sample: [`examples/sample-report/`](examples/sample-report/) (HTML, Markdown, **PDF**, DOCX).

---

## 📦 Installation

PentestIQ runs on **Linux, macOS, and Windows**. Pick the path that fits — all
three give you the same CLI (`pentestiq`) and the web console (`pentestiq serve`).
See **[INSTALL.md](INSTALL.md)** for copy-paste quick-start blocks per OS.

### Requirements
- **Python 3.10+** (for the pip/pipx and source paths), **or** Docker (for the
  container path), **or** just download a prebuilt binary (no Python needed).
- PentestIQ's core (crawler, OWASP checks, out-of-band detection, injection fuzzer,
  reporting) needs **no external components**. The Docker image additionally bundles
  the deep-scan backend and the mobile-analysis service.

### Option A — prebuilt binary (no Python, no Docker)
Download the single-file executable for your OS from the
[**Releases**](https://github.com/sajid-infosec/PentestIQ/releases) page:

| OS | Asset |
|---|---|
| Linux (x64) | `pentestiq-linux-x64` |
| macOS (Apple Silicon) | `pentestiq-macos-arm64` |
| Windows (x64) | `pentestiq-windows-x64.exe` |

```bash
# Linux / macOS
chmod +x pentestiq-linux-x64 && ./pentestiq-linux-x64 serve
# Windows (PowerShell)
.\pentestiq-windows-x64.exe serve
```

### Option B — pipx / pip (cross-platform, recommended for CLI users)
```bash
# isolated global CLI (Linux/macOS/Windows)
pipx install "git+https://github.com/sajid-infosec/PentestIQ.git#egg=pentestiq[all]"
pentestiq --help
```
Or into a virtualenv:
```bash
git clone https://github.com/sajid-infosec/PentestIQ.git && cd PentestIQ
python3 -m venv .venv && source .venv/bin/activate      # Windows: .venv\Scripts\Activate.ps1
pip install ".[api,reports,desktop]"                    # or ".[all]" for everything incl. SPA rendering
pentestiq serve                                          # open http://localhost:8080
```

### Option C — one-command installer scripts
```bash
# Linux (Docker SaaS stack — full backend bundled)
sudo ./install.sh

# macOS (installs Docker via Homebrew, then deploys — no Docker Desktop GUI needed)
./install.sh

# Windows (PowerShell) — Python path (venv + serve); add -Docker for the container stack
powershell -ExecutionPolicy Bypass -File .\install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Docker
```

### Option D — Docker (any OS with Docker/Docker Desktop)
```bash
cd deploy
docker compose up -d --build          # PentestIQ console on :8080 (full backend bundled)
```

### Extras
| Extra | Adds | Enables |
|---|---|---|
| *(none)* | pydantic, PyYAML, typer, rich | Engine + CLI + crawler + OAST + fuzzer |
| `api` | fastapi, uvicorn, python-multipart | REST API, web console, uploads |
| `reports` | reportlab, python-docx | PDF & DOCX report export |
| `desktop` | binary-analysis backend | Desktop binary hardening analysis |
| `spa` | headless-browser engine | SPA crawling (one-time browser setup after install) |
| `all` | all of the above | Everything |
| `dev` | pytest, httpx (+ above) | Running the test suite |

### Deep-scan backend
The native crawler, OWASP checks, out-of-band detection, and injection fuzzer run
with **no external components**. The **Docker deployment bundles the full deep-scan
backend and the mobile-analysis service** — nothing else to install. (Advanced
operators running from `pip` can add optional backends; see `docs/`.)

---

## 🚀 Quick Start

### A. Command line (first 5 minutes)

```bash
# 1. verify install & see the modules
pentestiq version
pentestiq modules            # infra, web, wordpress, api, mobile, desktop, network-device, firewall, hardening

# 2. (optional) stand up the local vulnerable lab — needs Docker
cd lab && docker compose up -d && cd ..     # intentionally-vulnerable demo targets

# 3. write a scope file  (myscope.yaml)
cat > myscope.yaml <<'YAML'
engagement:
  name: "My First Engagement"
  authorized_by: "self (isolated lab)"
scope:
  in_scope:
    - web=http://localhost:3000
    - infra=127.0.0.1
  allowed_actions: [discover, assess, validate_safe]
safe_mode: true
enforcement: warn            # 'block' to hard-enforce scope
YAML

# 4. run the engagement and generate a client-ready report
pentestiq run -s myscope.yaml -o out/
#  -> out/report.html   (open in a browser)
#  -> out/report.md
#  -> out/engagement.json
```

### B. Server (API + web console)

```bash
pip install -e ".[api,reports,desktop]"
export PENTESTIQ_SECRET_KEY=$(openssl rand -hex 32)   # so logins survive restarts
pentestiq serve                                        # http://127.0.0.1:8000
```

Then open **http://127.0.0.1:8000** for the console, or **/docs** for interactive API docs.
On first run a default workspace is created — sign in with **`pentestiq`** / **`p3nt3st!q`**
(change the password after first login). To bootstrap another tenant + owner from the CLI:

```bash
pentestiq init-tenant --tenant "PentestIQ" --username sajid --password "s3cr3tpass"
#  -> prints an API key you can use with  -H "X-API-Key: <key>"
```

---

## 🐳 Deployment

### One command — installs everything, deploys the full SaaS

The installer **detects your Linux distribution**, installs **all prerequisites**
(Docker Engine, Docker Compose, git/curl/openssl), generates secrets, and brings up
the **entire stack** (PentestIQ API + web console + mobile-analysis service). No manual setup.

```bash
git clone https://github.com/sajid-infosec/PentestIQ.git
cd PentestIQ
sudo ./install.sh
```

That's it — open **http://localhost:8080** and sign in with **`pentestiq`** / **`p3nt3st!q`** (change it after first login), then start scanning.

> Works on Debian / Ubuntu / Kali / Parrot / Mint, RHEL / CentOS / Fedora / Rocky /
> AlmaLinux, Arch / Manjaro, and openSUSE / SLES. Idempotent — safe to re-run.

**Installer options:**

```bash
# macOS / Linux
sudo ./install.sh --port 9090   # custom console port
sudo ./install.sh --update      # rebuild & redeploy after a `git pull`
sudo ./install.sh --down        # stop the stack
./install.sh --help

# Windows (Docker stack) — identical actions
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Docker -Port 9090
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Docker -Update   # rebuild & redeploy
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Docker -Down     # stop the stack
```

| Service | Port | Purpose |
|---|---|---|
| `pentestiq` | 8080 | REST API + web console |
| `mobile-analysis` | 8000 | Mobile static-analysis service (managed by PentestIQ) |

### Manual (if you already run Docker)

```bash
export MOBSF_API_KEY=$(openssl rand -hex 32)
export PENTESTIQ_SECRET_KEY=$(openssl rand -hex 32)
docker compose -f deploy/docker-compose.yml up -d --build
```

Full deployment guide, environment variables, and production notes (Postgres, scale): **[docs/DEPLOYMENT.md](docs/DEPLOYMENT.md)**.

---

## 📚 User Manual

### Using the web console (step by step)

The console is the fastest way to run a full assessment — no CLI needed.

**1 · Sign in.** Open `http://localhost:8080`. A default workspace is provisioned on
first run: **`pentestiq`** / **`p3nt3st!q`** (change the password after first login).
Use **Create workspace** to set up a separate, isolated tenant.

**2 · Scan live targets (web / API / infra).** Go to **New scan → Scan targets**:
name the engagement, record who authorised it, enter targets one per line (optionally
prefixed — `web=`, `api=`, `wordpress=`, `infra=`), pick scope enforcement, then
**Create & open → Run scan**.

**3 · Test an API.** **New scan → Upload & scan**, asset type **API**: choose the
OpenAPI/Swagger file, set the **Base URL**, paste an access token. Add a **second
token + object IDs** to unlock cross-tenant access-control (BOLA) testing, tick
**Enable active testing** for injection & brute-force (authorised targets only), and
**Upload & scan**. Endpoints, identities and injection points are derived automatically.

**4 · Assess a mobile / desktop app or device config.** Pick the matching asset type
and upload the file (Android/iOS package, desktop binary, or a network-device /
firewall / hardening configuration). Analysis starts automatically. For live mobile
instrumentation, use the **Dynamic kit**.

**5 · Read the results (Dashboard).** Severity tiles and bars give the risk breakdown;
the **OWASP coverage** grid shows which Web/API Top-10 categories were exercised (red =
a critical finding); the **findings table** lists risk score, severity, title, location
and OWASP mapping. **Open report** produces a client-ready report (executive summary,
evidence, remediation, compliance mapping).

**6 · Good practice.** Only scan assets you're authorised to test; keep active testing
off for production unless you have a window; re-run engagements to track remediation.

> The same in-app guide is always available under **User manual** in the console sidebar.


### 1. Scope files

Every engagement is defined by a **scope file** (YAML). It declares what to test, what to exclude, and how strictly to enforce it.

```yaml
engagement:
  name: "PentestIQ External Assessment"
  authorized_by: "Sajid"                # who authorized this test
  window:                               # optional testing window
    start: "2026-01-01T00:00:00Z"
    end:   "2026-01-07T00:00:00Z"
scope:
  in_scope:
    - web=https://app.example.com       # explicit asset type (see below)
    - wordpress=https://blog.example.com
    - api=https://api.example.com/openapi.json
    - infra=10.0.0.0/24
    - network_device=./configs/router.cfg
    - firewall=./configs/iptables.rules
    - hardening=./configs/sshd_config
  exclusions:
    - admin.example.com                 # never touch these
  allowed_actions: [discover, assess, validate_safe]
safe_mode: true                         # non-destructive validation only
enforcement: warn                       # off | warn | block
```

**Explicit asset typing** — prefix a target with `type=` to force the module:
`infra`, `web`, `wordpress`, `api`, `mobile`, `desktop`, `network_device`, `firewall`, `hardening`.
Without a prefix, the type is inferred (URLs/hosts → web, IPs/CIDRs → infra, `.apk`/`.ipa` → mobile, `.exe`/`.dmg`/… → desktop).

**Enforcement modes:**

| Mode | Behavior |
|---|---|
| `off` | No scope checking |
| `warn` *(default)* | Logs out-of-scope targets but proceeds — permissive |
| `block` | Hard-blocks anything outside scope |

**Safe mode:** with `safe_mode: true`, only non-destructive actions run. Intrusive/exploit actions require `safe_mode: false` **and** the action listed in `allowed_actions` (explicit opt-in). A ready-to-copy template lives at [`config/scope.example.yaml`](config/scope.example.yaml).

### 2. CLI reference

| Command | Description |
|---|---|
| `pentestiq version` | Print the version |
| `pentestiq modules` | List registered asset modules |
| `pentestiq run -s <scope> [-c <config>] [-o <dir>]` | Run an engagement; `-o` writes report.html/.md + engagement.json |
| `pentestiq serve [--host H] [--port P]` | Start the REST API + web console |
| `pentestiq init-tenant --tenant N --username U --password P` | Bootstrap a tenant + owner, print an API key |

```bash
pentestiq run --scope engagement.yaml --config pentestiq.yaml --out reports/
pentestiq serve --host 0.0.0.0 --port 8080
```

### 3. Scanning each asset type

The **same command** runs any asset type — the module is chosen automatically from each target's type. Examples (put the targets in a scope file, then `pentestiq run -s scope.yaml -o out/`):

| Asset | Scope entry | Engine |
|---|---|---|
| **Infrastructure** | `infra=10.0.0.0/24` | Network discovery + vuln scanning |
| **Web app** | `web=https://app.example.com` | Crawl + OWASP active testing (native) |
| **WordPress** | `wordpress=https://blog.example.com` | CMS CVE + enumeration |
| **API** | `api=https://api.example.com/openapi.json` | Endpoint + access-control testing (native) |
| **Mobile** | *(upload the .apk/.ipa — see §4)* | Mobile analysis service (bundled) |
| **Desktop** | *(upload the binary — see §4)* | Native binary analysis |
| **Network device** | `network_device=./router.cfg` | *(built-in)* |
| **Active Directory** | `ad=./secpol.inf` *(secedit export)* | Native AD posture review |
| **Firewall** | `firewall=./iptables.rules` | *(built-in)* |
| **Hardening** | `hardening=./sshd_config` | *(built-in)* |

Config-file and binary modules (desktop, network device, firewall, hardening) run **natively** — no external tools required.

### 4. Uploading apps & configs

Mobile apps, desktop binaries, and device/firewall/hardening configs are **uploaded**, not referenced by path — the server stores them and runs the analysis.

**Via the web console:** open the console → **New engagement** panel → **Upload & scan a file** → pick the file, choose the type (or leave "auto" for apps/binaries) → the engagement is created and scanned automatically.

**Via the API:**

```bash
# APK (mobile) — auto-typed
curl -XPOST http://localhost:8080/engagements/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@DemoBank.apk" -F "name=DemoBank"

# a router config — set the type explicitly
curl -XPOST http://localhost:8080/engagements/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@router.cfg" -F "asset_type=network_device" -F "name=edge-router"
```

Then run it: `POST /engagements/{id}/run`.

**API VAPT — upload an OpenAPI/Swagger spec + bearer token** (like uploading an APK).
Everything runs from the one portal; no separate tool UI:

```bash
# spec + live base URL + a token -> OpenAPI enumeration + native OWASP API checks
curl -XPOST http://localhost:8080/engagements/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@openapi.json" -F "asset_type=api" -F "name=Example API" \
  -F "base_url=https://api.example.com" \
  -F "bearer_token=<JWT>"

# add a second identity + object IDs to unlock BOLA / tenant-confusion testing
curl -XPOST http://localhost:8080/engagements/upload \
  -H "Authorization: Bearer $TOKEN" \
  -F "file=@openapi.json" -F "asset_type=api" -F "base_url=https://api.example.com" \
  -F "bearer_token=<JWT-A>" -F "bearer_token_b=<JWT-B>" \
  -F "object_ids_a=uuid-a1,uuid-a2" -F "object_ids_b=uuid-b1"
```

The spec's `{id}`-style paths become BOLA/IDOR candidates and its `GET` paths
become data-exposure targets; the bearer token is auto-analysed by the JWT check.
In the console this is the **API** asset type — the form reveals base-URL, token
and object-ID fields dynamically.

**Dynamic mobile analysis.** Static analysis runs automatically on upload; for
live instrumentation, download the **dynamic-analysis kit** from the console (or
`GET /kit/frida.zip`) — SSL-pinning bypass, root/jailbreak-detection bypass,
crypto and WebView hooks, with a runner guide. Capture the app's API traffic,
then feed those endpoints + a token back into the **API** upload above.

### 5. Reports

Generate from the CLI (`-o out/`) or fetch from the API in any format:

```bash
curl "http://localhost:8080/engagements/<id>/report?format=html"  -H "Authorization: Bearer $TOKEN"  # HTML
curl "http://localhost:8080/engagements/<id>/report?format=md"    -H "Authorization: Bearer $TOKEN"  # Markdown
curl "http://localhost:8080/engagements/<id>/report?format=pdf"   -H "Authorization: Bearer $TOKEN" -o report.pdf
curl "http://localhost:8080/engagements/<id>/report?format=docx"  -H "Authorization: Bearer $TOKEN" -o report.docx
```

Every report includes an **executive summary**, severity breakdown, prioritized findings with evidence + remediation, attack chains, and a **compliance mapping** (OWASP Top 10 / PCI-DSS / ISO 27001 / MITRE ATT&CK). See also `GET /engagements/{id}/compliance`.

**White-label branding** (per tenant) — set your firm's name, accent color, and footer; it flows into every report format:

```bash
curl -XPUT http://localhost:8080/settings -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" \
  -d '{"company_name":"PentestIQ","accent_color":"#1e3a8a","footer_note":"Confidential"}'
```

### 6. Continuous scanning & scheduling

Create a schedule and PentestIQ re-runs it automatically, **diffing** each run against the last (new / fixed / persisting) and notifying a Slack/webhook URL.

```bash
# nightly scan with Slack notification
curl -XPOST http://localhost:8080/schedules -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{
    "name":"Nightly PentestIQ",
    "interval_seconds": 86400,
    "webhook_url":"https://hooks.slack.com/services/XXX",
    "scope":{"in_scope":["web=https://app.example.com"]}
  }'

curl -XPOST http://localhost:8080/schedules/<id>/run-now -H "Authorization: Bearer $TOKEN"  # run immediately
curl http://localhost:8080/schedules/<id>/diff          -H "Authorization: Bearer $TOKEN"  # what changed
curl http://localhost:8080/schedules/<id>/runs          -H "Authorization: Bearer $TOKEN"  # run history
```

Notification payload is Slack-compatible: *"PentestIQ · Nightly PentestIQ: scan complete — 1 new, 1 fixed, 2 persisting."*

### 7. Authentication, tenants & RBAC

PentestIQ is multi-tenant. Authenticate with a **session token** (`Authorization: Bearer …`) or a **per-tenant API key** (`X-API-Key: …`).

```bash
# register a tenant + owner, get a token
TOKEN=$(curl -s -XPOST http://localhost:8080/auth/register -H "Content-Type: application/json" \
  -d '{"tenant_name":"PentestIQ","username":"sajid","password":"password123"}' | jq -r .token)

# who am I
curl http://localhost:8080/me -H "Authorization: Bearer $TOKEN"

# mint an API key (for automation/CI) with a role
curl -XPOST http://localhost:8080/apikeys -H "Authorization: Bearer $TOKEN" \
  -H "Content-Type: application/json" -d '{"name":"ci","role":"member"}'
```

**Roles** (each inherits the ones below it):

| Role | Can |
|---|---|
| `viewer` | Read engagements, findings, reports, schedules |
| `member` | + Create/run engagements, upload files, create schedules |
| `admin` | + Manage API keys, edit branding/settings |
| `owner` | Full control (created by `register`) |

Passwords are PBKDF2-hashed; API keys are stored only as a hash (shown once at creation). Every record is scoped to its tenant.

### 8. Configuration

**Environment variables:**

| Variable | Default | Purpose |
|---|---|---|
| `PENTESTIQ_SECRET_KEY` | *(random per run)* | Signs session tokens — **set in production** so logins survive restarts |
| `MOBSF_URL` | `http://localhost:8000` | Mobile-analysis service base URL |
| `MOBSF_API_KEY` | *(empty)* | Mobile-analysis service API key |

**Engine config file** (optional, pass with `-c`): [`config/pentestiq.example.yaml`](config/pentestiq.example.yaml)

```yaml
log_level: INFO             # DEBUG | INFO | WARNING | ERROR
data_dir: ./data            # engagements, uploads, audit logs (git-ignored)
max_concurrency: 4          # parallel jobs
default_enforcement: warn   # off | warn | block
rate_limit_per_host: 10     # requests/sec/host (0 = unlimited)
```

---

## 🔌 REST API Reference

Base URL: `http://<host>:<port>` · Auth: `Authorization: Bearer <token>` **or** `X-API-Key: <key>` · Interactive docs: **`/docs`**

**Auth & tenancy**

| Method | Endpoint | Role | Description |
|---|---|---|---|
| `POST` | `/auth/register` | — | Create a tenant + owner, return a session token |
| `POST` | `/auth/login` | — | Log in, return a session token |
| `GET` | `/me` | any | Current principal (tenant, role) |
| `POST` | `/apikeys` | admin+ | Mint a per-tenant API key (shown once) |
| `GET` | `/apikeys` | admin+ | List API keys |

**Engagements**

| Method | Endpoint | Role | Description |
|---|---|---|---|
| `POST` | `/engagements` | member+ | Create an engagement from a scope body |
| `POST` | `/engagements/upload` | member+ | Upload an app/binary/config and create an engagement |
| `GET` | `/engagements` | any | List engagements (tenant-scoped) |
| `GET` | `/engagements/{id}` | any | Engagement detail (assets + findings) |
| `POST` | `/engagements/{id}/run` | member+ | Run the scan (background; status updates) |
| `GET` | `/engagements/{id}/findings` | any | Findings, prioritized by risk |
| `GET` | `/engagements/{id}/report?format=html\|md\|pdf\|docx` | any | Download the report |
| `GET` | `/engagements/{id}/compliance` | any | OWASP/PCI/ISO/MITRE mapping |

**Schedules (continuous scanning)**

| Method | Endpoint | Role | Description |
|---|---|---|---|
| `POST` | `/schedules` | member+ | Create a recurring schedule |
| `GET` | `/schedules` · `/schedules/{id}` | any | List / get schedules |
| `POST` | `/schedules/{id}/run-now` | member+ | Run immediately |
| `POST` | `/schedules/{id}/enable?enabled=true\|false` | member+ | Enable/disable |
| `GET` | `/schedules/{id}/runs` · `/schedules/{id}/diff` | any | Run history / latest change set |
| `DELETE` | `/schedules/{id}` | member+ | Delete |

**Settings & system**

| Method | Endpoint | Role | Description |
|---|---|---|---|
| `GET` / `PUT` | `/settings` | any / admin+ | Get / set white-label branding |
| `GET` | `/health` | — | Health check |
| `GET` | `/` | — | Web console |

---

## 🔒 Safety, Authorization & Legal

PentestIQ is an **offensive security tool**. These controls are enforced in code, not left to policy:

- **Authorized use only** — test only what you own or are explicitly authorized to test.
- **Scope enforcement** — every engagement requires a validated scope; `enforcement: block` hard-blocks out-of-scope targets.
- **Safe-mode governor** — non-destructive by default; intrusive/exploit actions require explicit, logged opt-in.
- **Non-destructive validation** — exploit confirmation proves the issue without destroying data, dumping databases, or gaining persistence.
- **Audit trail** — every action and policy decision is recorded (JSONL).
- **No bundled targets or credentials** — lab targets are clearly synthetic and isolated.

Full policy: **[docs/LEGAL_AND_ETHICS.md](docs/LEGAL_AND_ETHICS.md)**. *This is not legal advice — have the license and any acceptable-use terms reviewed for your jurisdiction before public use.*

---

## 🧪 Development & Testing

```bash
pip install -e ".[dev,api,reports,desktop]"
pytest -q            # 118 tests
```

- **Architecture & extension guide:** [docs/ARCHITECTURE.md](docs/ARCHITECTURE.md) — how to write a new asset module or tool integration.
- **Layout:** `pentestiq/` (engine, models, core, modules, integrations, validators, reporting, scheduling, api, storage, auth), `tests/`, `docs/`, `lab/`, `deploy/`.
- **Design pattern:** each module implements `discover / assess / validate`; each tool integration is a thin, independently-tested adapter mapping raw output into the normalized findings model.

CI runs the suite on Python 3.10–3.12 (workflow provided at [`docs/github-actions-ci.yml`](docs/github-actions-ci.yml)).

---

## 🗺️ Roadmap

- **Phase 1 — open-source engine (v0.1.0):** ✅ complete — 9 asset modules, safe validation, reporting.
- **Phase 2 — SaaS platform:** ✅ API, web console, auth/RBAC, scheduling, reporting at scale · ⏳ billing & tiers.
- **Beyond:** PostgreSQL backend, distributed scanning workers, dynamic mobile (emulator), more firewall vendors, OpenSCAP/XCCDF, live CVE feeds.

Detail: [docs/ROADMAP.md](docs/ROADMAP.md) · [docs/PHASE2_ROADMAP.md](docs/PHASE2_ROADMAP.md) · [CHANGELOG.md](CHANGELOG.md).

---

## 🤝 Contributing

Contributions are welcome — new modules, tool integrations, report templates, and docs. Please:

1. Open an issue to discuss significant changes first.
2. Add tests (`pytest -q` must pass) for parsers and logic.
3. Ensure new exploit/validation logic **respects safe-mode and authorization gating**.
4. Never commit real engagement data.

See [CONTRIBUTING.md](CONTRIBUTING.md), [SECURITY.md](SECURITY.md), and [CODE_OF_CONDUCT.md](CODE_OF_CONDUCT.md).

---

## 📄 License

**Apache-2.0** — see [LICENSE](LICENSE). Future hosted SaaS / enterprise features may ship under a separate commercial license (open-core), as described in the [business plan](docs/BUSINESS_PLAN.md).

---

<div align="center">

**Built by [Sajid](https://github.com/sajid-infosec)** — Senior Cybersecurity Engineer · EC-Council LPT (Master)

*If PentestIQ is useful to you, consider starring the repo. ⭐*

</div>

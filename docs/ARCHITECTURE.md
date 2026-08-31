# PentestIQ — Technical Architecture

*Version 0.1 · Draft · August 2026*

This document describes the system design for PentestIQ. Guiding principle:
**orchestrate best-in-class tools; build custom logic only where it
differentiates** (correlation, safe exploit-validation, risk scoring, AI
reporting, authorization/safety).

---

## 1. Design Principles

1. **Orchestrate, don't reinvent.** Wrap proven tools (Nmap, Nuclei, OpenVAS,
   ZAP, WPScan, MobSF, etc.) behind a uniform module interface.
2. **One normalized findings model.** Every tool's output maps to a shared
   schema so we dedupe, correlate, and score once.
3. **Assessment and validation are distinct phases.** VA discovers; PT validates.
   Validation is opt-in per finding and safe-by-default.
4. **Safety & authorization are core, not optional.** No scan runs without a
   valid scope; destructive actions require explicit, logged consent.
5. **Modular & pluggable.** New asset modules and tool integrations are drop-in.
6. **API-first.** The engine exposes an API; CLI and (later) SaaS UI are clients.
7. **Reproducible & auditable.** Every action is logged; engagements are
   re-runnable.

---

## 2. High-Level Architecture

```
                         ┌──────────────────────────────┐
   Clients               │  CLI   │  Web Console (SaaS)  │
                         └───────────────┬──────────────┘
                                         │  REST/gRPC API
                         ┌───────────────▼──────────────┐
                         │        API / Gateway          │
                         │  authn/z · scope enforcement  │
                         └───────────────┬──────────────┘
                                         │
              ┌──────────────────────────▼───────────────────────────┐
              │                 ORCHESTRATION ENGINE                  │
              │  scope mgr · scheduler · job queue · workflow runner  │
              │  safe-mode governor · audit logger                    │
              └───┬───────────────┬───────────────┬───────────────┬──┘
                  │               │               │               │
          ┌───────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐ ┌──────▼──────┐
          │ Asset Modules│ │ Integrations│ │ Correlation │ │  Reporting  │
          │ (per type)   │ │ (tool wrap) │ │  & Scoring  │ │   Engine    │
          └───────┬──────┘ └──────┬──────┘ └──────┬──────┘ └──────┬──────┘
                  │               │               │               │
          ┌───────▼───────────────▼───────────────▼───────────────▼──────┐
          │           Normalized Findings Model  +  Data Store            │
          │        engagements · assets · findings · evidence · logs      │
          └───────────────────────────────────────────────────────────────┘
```

---

## 3. Core Components

### 3.1 Orchestration Engine
The heart of PentestIQ. Responsibilities:
- **Scope Manager** — loads/validates the engagement scope (targets, exclusions,
  time windows, allowed actions). Nothing runs outside scope.
- **Workflow Runner** — executes per-asset workflows (recon → assess → validate →
  report) as a DAG of jobs.
- **Scheduler & Job Queue** — async, parallel job execution with rate limiting
  (be a good network citizen; avoid DoS).
- **Safe-Mode Governor** — enforces non-destructive defaults; gates any
  destructive/intrusive action behind explicit, scoped, logged consent.
- **Audit Logger** — immutable record of every action, target, and operator.

### 3.2 Asset Modules (`modules/`)
Each implements a standard interface: `discover()`, `assess()`, `validate()`,
`normalize()`. One module per asset type (see §5).

### 3.3 Integration Layer (`integrations/`)
Adapters that wrap external tools: build the command/API call, run it, capture
raw output, and map it into the normalized findings model. Each integration is
version-pinned and independently testable.

### 3.4 Correlation & Scoring
- **Deduplication** — merge the same finding reported by multiple tools.
- **Correlation** — link related findings (e.g., exposed service + known CVE +
  default creds → one attack chain).
- **Risk scoring** — CVSS ingestion + exploitability signal + business context →
  a single prioritized score. Confidence rating per finding.

### 3.5 Reporting Engine (`reporting/`)
- Templated technical + executive reports (Markdown/HTML/PDF/DOCX).
- **AI-assisted narrative** — turn structured findings into summary, impact, and
  remediation prose.
- Evidence bundling (request/response, screenshots, PoC logs).
- Compliance mappings (OWASP, MITRE ATT&CK, CIS, PCI/ISO references).

### 3.6 Data Store
- Relational core (engagements, assets, findings, users, audit) — PostgreSQL.
- Object storage for evidence artifacts.
- Optional queue/cache (Redis) for jobs.

---

## 4. Normalized Findings Model (sketch)

```yaml
finding:
  id: uuid
  engagement_id: uuid
  asset: { type: web|infra|api|mobile|..., identifier: <host/url/pkg> }
  title: string
  category: string           # e.g., OWASP A03, CWE-89
  severity: info|low|medium|high|critical
  cvss: { vector, base_score }
  confidence: low|medium|high # boosted when validated
  status: detected|validated|exploited|false_positive|remediated
  source_tools: [nuclei, zap, ...]   # provenance for dedupe
  evidence: [ {type, ref} ]          # req/resp, screenshot, PoC log
  validation:
    attempted: bool
    method: safe|intrusive
    result: confirmed|not_exploitable|inconclusive
  remediation: string
  references: [urls, CVE ids]
  first_seen / last_seen: timestamp
```

This shared schema is the product's core moat: every tool feeds it, everything
downstream (dedupe, scoring, reporting) reads it.

---

## 5. Asset Modules & Tool Mapping

> Tools listed are candidate open-source integrations. Final selection and
> version pinning happen per module during the build. All are industry-standard,
> publicly available tools.

| Module | Assessment (VA) | Validation/Exploitation (PT, safe-mode) | Candidate tools |
|---|---|---|---|
| **Infrastructure / network** | Host/port/service discovery, network vuln scan | Auth checks, service-exploit validation | Nmap, masscan, OpenVAS/Greenbone, Nuclei |
| **Web application** | Crawl, active/passive scan, OWASP Top 10 | Injection/auth/access-control validation w/ evidence | OWASP ZAP, Nuclei, Nikto, sqlmap (gated), ffuf |
| **WordPress** | Core/plugin/theme CVE + user enum + config audit | Known-vuln + weak-cred validation | WPScan, Nuclei WP templates |
| **API (REST/GraphQL/SOAP)** | Spec-driven discovery, OWASP API Top 10 | BOLA/BFLA/auth/injection validation | ZAP API scan, schemathesis, Nuclei, custom |
| **Mobile (APK & IPA)** | Static analysis, secrets, permissions, MASVS map | Dynamic checks where device/emulator available | MobSF, apktool, jadx, semgrep (mobile rules) |
| **Desktop (Win/macOS/Linux)** | Binary/dependency analysis, config/secret exposure | Local privesc & misconfig validation | custom analyzers, dependency scanners, YARA |
| **Network devices** | Config ingestion, firmware/CVE checks | Default-cred / exposure validation | custom parsers, Nuclei, CVE feeds |
| **Firewall / config audit** *(nipper-class)* | Policy analysis vs. benchmarks | Shadow/permissive-rule detection & scoring | custom rule engine, config parsers |
| **Patching & hardening** | CIS/DISA-STIG gap analysis, missing-patch detection | Remediation verification re-scan | OpenSCAP, Lynis, CIS benchmarks |

### 5.1 Lab Automation (`lab/`)
Docker/Vagrant/Terraform blueprints that stand up intentionally-vulnerable
targets (e.g., DVWA, Juice Shop, Metasploitable-class, a vulnerable WP, a vuln
API) for testing PentestIQ itself, demos, and training. **Isolated networks
only.**

---

## 6. Safety, Authorization & Exploitation Design

This is a first-class subsystem, not a footnote.

- **Scope file required.** Every engagement starts from a signed/validated scope
  (targets, exclusions, windows, permitted action classes). Out-of-scope targets
  are hard-blocked.
- **Safe-mode default.** Validation uses non-destructive techniques (e.g., prove
  SQLi via boolean/time inference, not data exfiltration or DROP). No DoS
  payloads, no destructive writes, no persistence.
- **Explicit intrusive opt-in.** Any action beyond safe-mode requires a per-
  engagement, per-action-class, logged authorization flag.
- **Rate limiting & blast-radius controls** to avoid outages on client systems.
- **Full audit trail.** Who ran what, against what, when, with what result.
- **No bundled real-world targets or credentials.** Lab targets are clearly
  synthetic and isolated.

See [LEGAL_AND_ETHICS.md](LEGAL_AND_ETHICS.md).

---

## 7. Technology Stack (proposed)

| Layer | Choice | Rationale |
|---|---|---|
| Engine / API | **Python** (FastAPI) | Dominant in security tooling; huge library ecosystem; fast to build |
| Job orchestration | Celery/RQ + Redis (or Temporal later) | Async, parallel, rate-limited scanning |
| Data | PostgreSQL + object storage | Relational findings model + evidence blobs |
| CLI | Python (Typer/Click) | First client; matches practitioner workflow |
| Tool execution | Containerized runners (Docker) | Isolate/pin each tool; reproducible |
| SaaS frontend (phase 2) | React/Next.js + Tailwind | Modern console; fast iteration |
| AI reporting | Pluggable LLM (hosted API or self-host) | Narrative generation; keep provider swappable |
| Packaging/deploy | Docker Compose (self-host); Helm/K8s (SaaS) | Easy self-host now, scale later |
| CI/CD | GitHub Actions | Native to the OSS home |

*Language note:* Python for the engine and orchestration; Go is a reasonable
option for high-performance scanner components later if needed. Keep the core in
one language to start.

---

## 8. Repository Layout

```
PentestIQ/
├── core/              # orchestration engine, scope mgr, scheduler, safe-mode governor
├── modules/           # per-asset-type modules (infra, web, wordpress, api, mobile, ...)
├── integrations/      # adapters wrapping external tools into the findings model
├── reporting/         # report templates + AI narrative + evidence bundling
├── lab/               # docker/vagrant/terraform vulnerable-range blueprints
├── config/            # engine config, tool version pins, scoring rules
├── tests/             # parsers, correlation, safety-gate tests
└── docs/              # architecture, roadmap, business plan, legal & ethics
```

---

## 9. Key Design Decisions (open)

1. **Monolith-first vs. microservices** — start as a modular monolith (one
   deployable), split later. *Recommended: monolith-first.*
2. **Sync vs. async engine** — async job queue from day one (scans are long).
3. **Self-host packaging** — Docker Compose as the v1 distribution.
4. **AI provider** — hosted API for speed now; design for self-hostable later
   (privacy-sensitive clients will demand it).
5. **License of the core** — see Business Plan §10.

---

## 10. Non-Goals (v1)

- Not a full commercial-grade multi-tenant SaaS at launch (that's phase 2).
- Not building custom scanners where a mature tool already exists.
- Not a fully autonomous "hack anything" agent — human-in-the-loop and scoped by
  design.

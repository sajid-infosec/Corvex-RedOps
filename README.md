<div align="center">

# PentestIQ

**An open-source, orchestration-driven Vulnerability Assessment & Penetration Testing platform.**

*One engine. Every asset. Assessment through validated exploitation — safely and with authorization built in.*

[Overview](#overview) · [What It Covers](#what-it-covers) · [Architecture](docs/ARCHITECTURE.md) · [Roadmap](docs/ROADMAP.md) · [Business Plan](docs/BUSINESS_PLAN.md) · [Legal & Ethics](docs/LEGAL_AND_ETHICS.md)

![CI](https://github.com/sajid-infosec/PentestIQ/actions/workflows/ci.yml/badge.svg) ![License](https://img.shields.io/badge/license-Apache--2.0-blue.svg) ![Python](https://img.shields.io/badge/python-3.10%2B-blue.svg) ![Tests](https://img.shields.io/badge/tests-66%20passing-brightgreen.svg)

</div>

---

## Overview

PentestIQ unifies the fragmented VAPT toolchain into a single, workflow-driven platform. Instead of stitching together Nmap, Nuclei, OpenVAS, ZAP, MobSF, WPScan, and a dozen others by hand for every engagement, PentestIQ orchestrates best-in-class open-source tools behind one engine, correlates their output into a single normalized findings model, safely validates exploitability, and produces client-ready reports.

It is built to do **both halves** of the job:

- **Vulnerability Assessment (VA)** — discover, enumerate, and prioritize weaknesses across the full asset surface.
- **Penetration Testing (PT)** — safely validate and, where authorized, demonstrate real exploitability of the findings, cutting false positives and proving business impact.

**Model:** open-core. The engine, modules, and CLI are open source (GitHub). A hosted multi-tenant SaaS console with team features, scheduling, and managed reporting follows as a commercial layer.

> ⚠️ **Authorized use only.** PentestIQ performs active security testing, including exploitation. It is designed for security professionals testing systems they own or are explicitly authorized to test. Authorization gating, scope enforcement, and a non-destructive safe mode are **core features**, not add-ons. See [Legal & Ethics](docs/LEGAL_AND_ETHICS.md).

---

## What It Covers

| Asset type | Assessment | Validation / Exploitation |
|---|---|---|
| **Infrastructure / network** | Host & service discovery, port/service enumeration, network vuln scanning | Auth-testing, service exploit validation (safe-mode default) |
| **Web applications** | Crawl, active/passive scan, OWASP Top 10 coverage | Injection, auth, access-control validation with evidence capture |
| **WordPress sites** | Core/plugin/theme version & CVE checks, user enum, config audit | Known-vuln validation, weak-credential checks |
| **APIs (REST/GraphQL/SOAP)** | Spec-driven discovery, OWASP API Top 10 | BOLA/BFLA, auth, injection validation |
| **Mobile apps (APK & IPA)** | Static analysis (MobSF-class), secrets, permissions, MASVS mapping | Dynamic/instrumented checks where a device/emulator is available |
| **Desktop apps (Win/macOS/Linux)** | Binary/dependency analysis, config & secret exposure, update-channel review | Local privilege & misconfiguration validation |
| **Network devices** | Config ingestion, firmware/CVE checks | Default-credential and exposure validation |
| **Firewall / device config audit** | Policy analysis against benchmarks (a nipper-class capability) | Rule-base risk scoring, shadow/overly-permissive rule detection |
| **Security patching & hardening** | CIS/DISA-STIG gap analysis, missing-patch detection | Remediation guidance & verification re-scan |

Plus: **lab setup automation** (Docker/Vagrant/Terraform-based intentionally-vulnerable ranges for testing and demos).

---

## Why PentestIQ

- **One normalized findings model** across every tool and asset type — dedupe, correlate, and score once.
- **Assessment *and* validated exploitation** — fewer false positives, provable impact.
- **Authorization & safety as first-class features** — scope files, safe mode, full audit trail.
- **AI-assisted reporting** — turn raw findings into an executive summary, technical detail, and remediation plan.
- **Open-core** — inspectable, self-hostable, community-extensible; SaaS for teams who want it managed.

---

## Project Status

🚀 **v0.1.0 — first release.** The full loop works end-to-end: scope → scan → normalize → validate → prioritize → report, across nine asset modules (infra, web, WordPress, API, mobile, desktop, network devices, firewall, hardening). See the [Quickstart](docs/QUICKSTART.md), [Demo](docs/DEMO.md), and [CHANGELOG](CHANGELOG.md). Earlier context: Working now: the
orchestration engine boots, loads an engagement scope, runs the
discover→assess→validate workflow across in-scope assets, and reports via a CLI.
The normalized findings model (with cross-tool dedup) and scope/safe-mode
scaffolding are in place. Week 2 added the safety/ops core: a **ScopeManager** and **SafeModeGovernor** (permissive `warn` default, strict `block` ready), an append-only **audit trail** (JSONL), and a dependency-free **concurrent job queue** with per-host **rate limiting**. Week 3 shipped the first real scanning: a tool-integration contract with **Nmap** (service discovery) and **Nuclei** (templated vuln scanning) adapters and an **infra module** that orchestrates them into normalized, deduplicated findings. Week 4 added the **web module** (OWASP ZAP + Nuclei) and the analysis brain: a **risk scorer** (severity+CVSS+confidence+validation → 0–100) and a **correlator** that links findings sharing a host+service into attack chains — so a scan yields one prioritized, correlated list. Week 5 added the **safe exploit-validation layer** (the core differentiator): non-destructive validators that *confirm* whether a finding is really exploitable — a benign reflected-marker check for XSS, boolean-based inference for SQLi — flipping findings from `detected` to `validated` (with evidence) or dismissing false positives, all gated by the safe-mode governor. Week 6 added the **reporting engine**: one command turns an engagement into a client-ready **HTML + Markdown report** (executive summary, severity breakdown, prioritized findings with evidence/remediation/CWE references, attack chains) plus an **engagement JSON**, with a pluggable AI-narrative hook that degrades gracefully to a strong data-driven summary when no LLM is configured. A rendered sample lives in [`examples/sample-report/`](examples/sample-report/). WordPress + API modules, hardening, and public launch come next.
See the [Roadmap](docs/ROADMAP.md) and [Architecture](docs/ARCHITECTURE.md).

## Quickstart (dev)

```bash
# 1. install (Python 3.10+)
python3 -m venv .venv && source .venv/bin/activate
pip install -e ".[dev]"

# 2. run the tests
pytest -q

# 3. (optional) spin up the local vulnerable lab — requires Docker
cd lab && docker compose up -d && cd ..

# 4. run an engagement against the lab scope
pentestiq run -s config/scope.lab.yaml
pentestiq modules      # list registered modules
pentestiq version
```

> The engine currently runs an *empty* workflow (no modules registered yet), so it
> visits and logs assets and produces zero findings — that’s the Week 1 skeleton.
> Real scanning arrives with the web + infra modules.

## REST API (Phase 2 · in progress)

PentestIQ is growing a hosted SaaS layer on top of the open-source engine. A
**web console** and the **REST API** backbone are in the repo — `pentestiq serve`
opens a dashboard (create engagements, run scans, view findings + charts + chains,
open reports) backed by the API:

```bash
pip install -e ".[api]"
pentestiq serve                 # web console at http://127.0.0.1:8000  (API docs at /docs)
```

```bash
# register a tenant + owner, then use the returned token (Authorization: Bearer)
TOK=$(curl -s -XPOST localhost:8000/auth/register -H "Content-Type: application/json" \
  -d '{"tenant_name":"Acme","username":"alice","password":"password123"}' | jq -r .token)

curl -XPOST localhost:8000/engagements -H "Authorization: Bearer $TOK" -H "Content-Type: application/json" \
  -d '{"engagement":{"name":"Acme"},"scope":{"in_scope":["web=http://localhost:3000"]}}'
curl -XPOST localhost:8000/engagements/<id>/run -H "Authorization: Bearer $TOK"
curl localhost:8000/engagements/<id>/report -H "Authorization: Bearer $TOK"   # HTML report
```

**Reports at scale:** every report is available as **HTML, Markdown, PDF, or DOCX**
(`?format=pdf`), includes a **compliance mapping** (OWASP/PCI/ISO/MITRE), and is
**white-labelled** per tenant via `PUT /settings` (company name, accent color, footer).
A branded sample lives in [`examples/sample-report/`](examples/sample-report/).

**Mobile testing:** upload an APK/IPA through the console's **Upload & scan** button (or `POST /engagements/upload`); the co-located **MobSF** analyzes it and results flow into the same findings pipeline. One-command self-host (PentestIQ + MobSF) in [docs/DEPLOYMENT.md](docs/DEPLOYMENT.md).

**Continuous scanning:** create a schedule (`POST /schedules` with an `interval_seconds`)
and PentestIQ re-runs it automatically, **diffing new vs fixed vs persisting** findings
between runs and posting a summary to a Slack/webhook URL. `GET /schedules/{id}/diff`
shows the latest change set.

**Auth & multi-tenancy:** register/login for session tokens, or mint per-tenant
**API keys** (`POST /apikeys`) for automation. Roles (viewer/member/admin/owner)
are enforced per endpoint; every record is tenant-scoped. Bootstrap without HTTP:
`pentestiq init-tenant --tenant Acme --username alice --password ...`. Persistence
is SQLite (Postgres-swappable). Web console, scheduling, and billing follow — see
[docs/PHASE2_ROADMAP.md](docs/PHASE2_ROADMAP.md).

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** — system design, engine, modules, data model, tech stack.
- **[Roadmap](docs/ROADMAP.md)** — 2-month, week-by-week build plan and MVP scope.
- **[Business Plan](docs/BUSINESS_PLAN.md)** — market, model, pricing, GTM, projections.
- **[Legal & Ethics](docs/LEGAL_AND_ETHICS.md)** — authorized-use, safety, and compliance design.

## License

Core engine & modules: **Apache-2.0** (see [LICENSE](LICENSE)). Future hosted SaaS / enterprise features will ship under a separate commercial license — the open-core split described in the [business plan](docs/BUSINESS_PLAN.md).

## Author

Built by **Sajid** — Senior Cybersecurity Engineer, LPT (Master). Contributions welcome once the contribution guide lands.

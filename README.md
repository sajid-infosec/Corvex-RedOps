<div align="center">

# PentestIQ

**An open-source, orchestration-driven Vulnerability Assessment & Penetration Testing platform.**

*One engine. Every asset. Assessment through validated exploitation — safely and with authorization built in.*

[Overview](#overview) · [What It Covers](#what-it-covers) · [Architecture](docs/ARCHITECTURE.md) · [Roadmap](docs/ROADMAP.md) · [Business Plan](docs/BUSINESS_PLAN.md) · [Legal & Ethics](docs/LEGAL_AND_ETHICS.md)

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

🚧 **Early development.** This repository currently contains the foundational planning and design docs. See the [Roadmap](docs/ROADMAP.md) for the 2-month build plan and [Architecture](docs/ARCHITECTURE.md) for the system design.

## Documentation

- **[Architecture](docs/ARCHITECTURE.md)** — system design, engine, modules, data model, tech stack.
- **[Roadmap](docs/ROADMAP.md)** — 2-month, week-by-week build plan and MVP scope.
- **[Business Plan](docs/BUSINESS_PLAN.md)** — market, model, pricing, GTM, projections.
- **[Legal & Ethics](docs/LEGAL_AND_ETHICS.md)** — authorized-use, safety, and compliance design.

## License

Planned: open-core. Core engine & modules under a permissive/OSS license; hosted SaaS features under a commercial license. See [LICENSE](LICENSE).

## Author

Built by **Sajid** — Senior Cybersecurity Engineer, LPT (Master). Contributions welcome once the contribution guide lands.

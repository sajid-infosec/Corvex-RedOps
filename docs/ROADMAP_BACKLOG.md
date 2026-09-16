# PentestIQ — Competitive Gap Backlog

> Analysis of ~45 enterprise security platforms grouped into the six product
> categories they actually occupy, mapped against PentestIQ's current state, and
> turned into a **sequenced, one-task-at-a-time backlog** you can work through.
>
> Every task is scoped for **$0 licensing** — it orchestrates open-source
> building blocks (nuclei, trivy, semgrep, subfinder/amass, prowler, OSV, …) the
> same way PentestIQ already wraps nmap / ZAP / MobSF / WPScan.
>
> Legend: **S** ≤1 session · **M** 1–2 sessions · **L** 3+ sessions.
> Do them top-to-bottom; each epic is ordered so earlier tasks unblock later ones.

---

## 1. The 45 tools, by the category they compete in

| # | Category | What it means | Tools in your list |
|---|---|---|---|
| **C1** | **Exposure / Attack-Surface Management (ASM/CTEM)** | Discover *all* assets (esp. internet-facing), map exposure, prioritize by real risk | Tenable One, CrowdStrike Falcon Exposure, Bishop Fox Cosmos, Outpost24, XM Cyber, Balbix, Brinqa, Wiz, Orca |
| **C2** | **Vulnerability Management (VM/VMDR)** | Continuous, authenticated, fleet-wide vuln detection + remediation + compliance | Qualys VMDR, Tenable VM / Security Center, Rapid7 InsightVM / Nexpose, MS Defender VM, Greenbone, MaxPatrol VM |
| **C3** | **Automated Security Validation / BAS** | *Prove* exploitability & test defensive controls against MITRE ATT&CK, continuously | Pentera, Horizon3 NodeZero, Cymulate, SafeBreach, Picus, AttackIQ, Mandiant Security Validation |
| **C4** | **PTaaS (Pentest-as-a-Service)** | Platform to run/track pentests: automated + human, retest, client portal, SLAs | BreachLock, Cobalt, Synack, NetSPI, Edgescan, Rapid7 PT, Secureworks, IBM X-Force Red, NCC Group |
| **C5** | **Application Security (AST)** | DAST + SAST + IAST + SCA + API security, with proof-of-exploit | Invicti, Burp DAST/EE, Acunetix, HCL AppScan, Fortify, Checkmarx One, Veracode |
| **C6** | **Cloud-native security (CNAPP)** | Cloud config (CSPM), container/image, IaC, cloud attack-paths | Wiz, Orca, CrowdStrike, (Qualys/Tenable cloud add-ons) |

---

## 2. Where PentestIQ stands vs each category

| Category | PentestIQ today | Gap to close |
|---|---|---|
| C1 ASM | ❌ no asset inventory, no external discovery | **Biggest strategic gap.** Asset register + EASM + exposure scoring |
| C2 VM | 🟡 active scanning across 10 asset types; nuclei/nmap; **no** authenticated/agent scanning, thin CVE breadth | Authenticated scans, CVE/NVD enrichment, continuous discovery |
| C3 Validation/BAS | 🟡 safe exploit validation + attack-chain correlation; **no** ATT&CK mapping, no attack-path graph, no control testing | ATT&CK mapping, attack-path graph, BAS-lite |
| C4 PTaaS | 🟡 engagements, RBAC, scheduling, reports; **no** retest workflow, client portal, ticketing | Retest/diff workflow, read-only client portal, integrations |
| C5 AST | 🟡 DAST (web active) + API + partial SCA (JS libs only); **no** SAST, no full SCA/SBOM | SCA (OSV/Trivy), SBOM, SAST (Semgrep), IAST-lite |
| C6 Cloud | ❌ none | Container/image (Trivy), IaC, CSPM (Prowler), K8s (kube-bench) |

**Strengths to keep leaning on:** VA+PT in one loop, transparent EPSS+KEV
prioritization, local private AI, self-hostable, $0. The backlog below turns the
❌/🟡 above into ✅ without breaking any of that.

---

## 3. The backlog (do these in order)

### EPIC A — Asset Inventory & Attack-Surface Management  *(closes C1; unblocks everything)*
> Enterprises start from "what do I even own?" PentestIQ has no asset register.
> This is the foundation the rest of the roadmap plugs into.

- **A1 · Asset inventory data model + store** — `S`
  A first-class `Asset` registry (not per-engagement): host/domain/IP/URL/cloud-id,
  type, tags, **business criticality**, owner, first/last seen, source. New
  `pentestiq/inventory/` + SQLite table + `GET/POST /assets`, `/assets/{id}`.
  *Accept:* create/list/tag assets; every finding links to an inventory asset; unit tests.
- **A2 · Auto-populate inventory from engagements** — `S`
  Every scan upserts its targets/discovered hosts into the registry (dedupe by
  identifier). *Accept:* run a scan → assets appear with source=engagement.
- **A3 · External discovery (EASM) module** — `M`
  Orchestrate **subfinder/amass** (subdomains), **httpx** (live hosts + tech),
  **tls/cert-transparency** (crt.sh) to expand a root domain into its external
  surface. New asset_type `attack_surface`; feed results into the registry.
  *Accept:* give `example.com` → get subdomains, live URLs, open ports, tech stack.
- **A4 · Exposure score + inventory UI** — `M`
  Per-asset exposure score (internet-facing × criticality × open findings × KEV),
  and a console **Inventory** view (filter/sort/tag, drill to findings).
  *Accept:* Inventory tab lists assets ranked by exposure; matches Tenable/Bishop-Fox framing.

### EPIC B — Unified Findings Ingestion & Risk Aggregation  *(closes part of C1/C2; Brinqa/Balbix-class)*
> Turn PentestIQ into the single pane that *aggregates* other scanners — a huge
> differentiator and easy given the normalized findings model already exists.

- **B1 · Normalized importer framework** — `S`
  A pluggable `pentestiq/ingest/` that maps 3rd-party output → the PentestIQ
  `Finding` model, dedupes, and applies PRP. *Accept:* base importer + tests.
- **B2 · Importers: Nessus (.nessus), Nuclei (jsonl), Trivy (json), ZAP, Semgrep (SARIF)** — `M`
  *Accept:* import a sample of each → normalized, de-duplicated findings with OWASP/CWE/CVE mapped.
- **B3 · SARIF in/out** — `S`
  Accept generic **SARIF** import and **export** PentestIQ findings as SARIF (GitHub code-scanning / CI native). *Accept:* round-trip SARIF.

### EPIC C — Application Security depth (SCA + SBOM + SAST)  *(closes C5; Checkmarx/Veracode/Snyk-class)*
- **C1t · SCA + SBOM** — `M`
  Dependency vulnerability scanning via **OSV.dev** + **Trivy** on an uploaded
  repo/lockfile/image; generate a **CycloneDX SBOM**. New asset_type `codebase`.
  *Accept:* upload a `package-lock.json`/`requirements.txt` → CVE findings + SBOM export.
- **C2t · SAST via Semgrep** — `M`
  Wrap **Semgrep** (open-source rulesets) for source-code findings; map to CWE/OWASP; feed PRP.
  *Accept:* scan a repo → SAST findings in the same model + report.
- **C3t · Secret scanning** — `S`
  **Gitleaks/trufflehog**-class secret detection over uploaded code. *Accept:* planted secret is found.

### EPIC D — MITRE ATT&CK + Attack-Path Graph  *(closes C3; XM Cyber / Pentera-class)*
- **D1 · ATT&CK mapping** — `S`
  Tag findings/chains with ATT&CK tactics/techniques (map from category/CWE);
  add an ATT&CK coverage matrix + `GET /coverage/attack`. *Accept:* findings show technique IDs; matrix renders.
- **D2 · Attack-path graph** — `M`
  Build a graph from correlated findings + assets (entry → pivot → impact);
  render it (inline SVG/mermaid) and score the shortest path to crown-jewel assets.
  *Accept:* a multi-finding engagement produces a visual attack path.
- **D3 · BAS-lite / control validation** — `L`
  Safe, opt-in **atomic checks** (Atomic Red Team-style) that test whether a
  control/detection fires; report ATT&CK coverage of *defenses*. *Accept:* run a benign technique check → pass/fail.

### EPIC E — Cloud & Container security  *(closes C6; Wiz/Orca entry-level)*
- **E1 · Container & IaC scanning (Trivy)** — `M`
  Scan an image / Dockerfile / Terraform / K8s manifest via **Trivy**; new
  asset_types `container`, `iac`. *Accept:* scan an image → CVE + misconfig findings.
- **E2 · CSPM (Prowler)** — `L`
  Read-only cloud posture checks via **Prowler** (AWS/Azure/GCP) against CIS
  benchmarks; ingest results. *Accept:* run against a test account → posture findings + compliance mapping.
- **E3 · K8s benchmark (kube-bench)** — `S`
  CIS Kubernetes checks. *Accept:* run kube-bench → normalized findings.

### EPIC F — Workflow, Integrations & PTaaS polish  *(closes C4)*
- **F1 · Retest / diff workflow** — `S`
  Per-finding **retest** action → new/fixed/persisting across scans, with MTTR.
  (Schedules already diff; surface it per finding + on demand.) *Accept:* re-run → statuses update.
- **F2 · Ticketing integrations (Jira / ServiceNow / Slack)** — `M`
  Push a finding to a ticket; two-way status sync via webhook. *Accept:* create a Jira issue from a finding (configurable endpoint).
- **F3 · Read-only client portal** — `M`
  A shareable, tokenized, read-only report/dashboard link for clients (PTaaS
  staple). *Accept:* generate a link → client sees findings/reports, no login, no write.
- **F4 · Remediation projects** — `S`
  Group findings into assignable projects with owners + due dates (SLA already exists). *Accept:* create a project, assign, track completion.

### EPIC G — VM depth (authenticated + CVE breadth)  *(closes C2; Qualys/Nessus depth)*
- **G1 · Authenticated scanning** — `M` ✅
  Credentialed local checks (sudo NOPASSWD, world-writable sensitive files,
  GTFOBins SUID, outdated services→CVE) over an injectable SSH runner; encrypted
  **credential vault** (scrypt + Fernet, secrets never returned by the API).
  `pentestiq/vault/`, `pentestiq/authscan/`; `/vault/credentials` CRUD,
  `POST /engagements/{eid}/authscan` (authorization-gated); Settings vault card + Auth-scan action.
  *Accept:* injected credentialed run surfaces sudo-NOPASSWD local privesc. ✔
- **G2 · CVE/NVD + KEV/EPSS enrichment on service findings** — `S` ✅
  Match discovered product+version → CVEs (curated seed + version ranges) and
  auto-enrich with the existing intel layer (PRP/KEV/EPSS). `pentestiq/intel/service_cve.py`;
  `POST /intel/service`, `POST /engagements/{eid}/enrich/services`; console "Match CVEs".
  *Accept:* "nginx 1.18.0" → CVE-2021-23017 ranked by PRP. ✔
- **G3 · nuclei template auto-update + tags** — `S` ✅
  Keep nuclei templates fresh; expose installed packs / severities / tags + version,
  and scope scans by tag/severity. `pentestiq/integrations/nuclei_templates.py`
  (NucleiTemplateManager, template_coverage); `POST /tools/nuclei/update`,
  `GET /tools/nuclei/coverage`; config `nuclei_tags`/`nuclei_severity`; Settings card.
  *Accept:* update command refreshes store; coverage returns total + per-pack count. ✔

### EPIC H — Continuous Exposure & Analytics  *(cross-cutting; CTEM)*
- **H1 · Posture trend analytics** — `M` ✅
  Posture snapshots (open/fixed/new, MTTR, exposure, KEV) captured after each scan;
  self-contained SVG trend chart on the Overview. `pentestiq/analytics/posture.py`,
  `store.py`; `POST /analytics/snapshot`, `GET /analytics/trends`. *Accept:* trend chart on Overview. ✔
- **H2 · Continuous exposure scoring + alerts** — `M` ✅
  Org exposure score tracked over time; webhook alert when a new KEV/critical lands
  on an internet-facing asset (delta vs. last snapshot). `pentestiq/analytics/alerts.py`;
  `/settings/alerts` + test; evaluated automatically on each snapshot. *Accept:* new KEV on exposed asset → alert fires. ✔

### Cross-cutting — Report embedding ✅
- The depth built across Epics C–H now surfaces into the client deliverables (HTML / PDF / DOCX / Markdown):
  **MITRE ATT&CK coverage** matrix, **attack-path analysis** (self-contained SVG in HTML; tables in PDF/DOCX),
  **cloud/container/IaC/CSPM findings**, and **compliance framework mapping** (OWASP/PCI/ISO/ATT&CK).
  `pentestiq/reporting/report.py` (`_intel_sections`, `_md_intel_sections`, `_cloud_findings`),
  `pdf_report.py`, `docx_report.py`. Sections auto-numbered before the conclusion; each self-guards on empty input.

---

## 4. Recommended order (fastest path to "beats the field")

1. **A1 → A2** (asset inventory) — the missing foundation, quick wins.
2. **B1 → B2** (ingestion) — instantly makes PentestIQ an aggregator; high wow, low effort.
3. **C1t** (SCA+SBOM) — the most-requested AppSec gap, open-source-easy.
4. **D1** (ATT&CK mapping) — cheap, very marketable.
5. **A3 → A4** (EASM + exposure UI) — the headline C1 capability.
6. **E1** (container/IaC) — opens the cloud story.
7. **F1 → F2** (retest + ticketing) — enterprise workflow.
8. Then **D2, C2t, G1, H1** as the platform matures.

Each item above is independently shippable, testable, and pushable the same day.

---

*Full tool-by-tool comparison of the core competitors: [COMPETITIVE.md](COMPETITIVE.md).*

# PentestIQ — 2-Month Build Roadmap

*Version 0.1 · Draft · Target window: ~8 weeks*

**Goal of this window:** ship a credible open-source v0.1 that demonstrates the
core promise end-to-end — *scope → orchestrated scan → normalized findings →
safe validation → client-ready report* — for a first set of asset types, and
launch it publicly on GitHub.

**Guiding rule:** orchestrate first, custom only where it differentiates. Depth
over breadth: a few asset modules that work *well* beat nine that half-work.

---

## Success Criteria (end of Week 8)

- [ ] `pentestiq run --scope scope.yaml` executes a full workflow against a lab
      target and produces a report.
- [ ] Findings from ≥3 tools are normalized, deduped, and risk-scored into one
      model.
- [ ] Safe-mode validation confirms/dismisses at least one class of finding with
      evidence.
- [ ] Scope enforcement + audit log demonstrably block out-of-scope actions.
- [ ] Public GitHub repo with README, docs, quickstart, and a demo GIF/video.
- [ ] At least the **web** and **infrastructure** modules are genuinely usable;
      **WordPress** and **API** in beta.

---

## MVP Scope (in) vs. Deferred (out)

**In (v0.1):** engine + scope/safety + async jobs; normalized findings model;
integrations for Nmap, Nuclei, OpenVAS or ZAP, WPScan; web + infra modules
(WordPress + API in beta); safe-mode validation for a couple of finding classes;
Markdown/HTML report + basic AI narrative; CLI; lab (Juice Shop + DVWA + a vuln
WP); docs.

**Deferred (post-v0.1):** mobile (APK/IPA), desktop apps, network-device &
firewall config audit, full hardening/OpenSCAP, SaaS web console, multi-tenant,
advanced AI reporting, PDF/DOCX polish. (These are sequenced in "Beyond Week 8".)

---

## Week-by-Week

### Week 1 — Foundations & Skeleton
- Finalize stack, repo conventions, license decision (Business Plan §10).
- Scaffold engine: config loader, logging, plugin/module interface.
- Define the **normalized findings model** (schema + storage, PostgreSQL).
- Stand up the `lab/` with one target (OWASP Juice Shop) via Docker.
- **Milestone:** engine boots; empty workflow runs against a lab target and logs.

### Week 2 — Scope, Safety & Job Engine
- Implement **Scope Manager** (scope file format, validation, hard-blocking).
- Implement **Safe-Mode Governor** + **Audit Logger**.
- Async job queue + scheduler (Celery/RQ + Redis); rate limiting.
- **Milestone:** out-of-scope action is blocked and logged; jobs run in parallel.

### Week 3 — First Integrations (Infra)
- Integration layer contract; adapter pattern.
- Wrap **Nmap** (discovery/enum) and **Nuclei** (templated scanning).
- Normalize their output → findings model; dedupe across the two.
- **Milestone:** infra module produces normalized, deduped findings from a lab
  network.

### Week 4 — Web Module + Correlation/Scoring
- Wrap **OWASP ZAP** (or Nikto) for web scanning.
- Build **correlation + risk scoring** (CVSS ingest + confidence + dedupe).
- Web module workflow: crawl → scan → normalize.
- **Milestone:** web app scan yields a single prioritized, correlated findings
  list.

### Week 5 — Safe Validation (the differentiator)
- Implement safe-mode **validation** for 1–2 classes (e.g., reflected XSS proof,
  inference-based SQLi confirmation) with **evidence capture**.
- Wire validation into the workflow (detected → validated → confidence boost).
- **Milestone:** a detected web finding is safely validated with captured
  evidence; false positive correctly dismissed.

### Week 6 — Reporting Engine
- Report templates (Markdown + HTML), evidence bundling, framework mappings
  (OWASP/CVSS/MITRE).
- **AI-assisted narrative** (pluggable LLM): exec summary + remediation prose.
- **Milestone:** one command turns an engagement into a readable, client-style
  report.

### Week 7 — WordPress + API (beta) & Hardening Pass
- Wrap **WPScan** → WordPress module (versions, CVEs, user enum, weak creds).
- API module beta (spec-driven discovery + OWASP API checks via ZAP/Nuclei).
- Harden the engine: error handling, timeouts, tool-failure resilience, tests
  for parsers/safety gates.
- **Milestone:** WordPress module usable end-to-end; API in beta; test suite green.

### Week 8 — Polish, Docs & Public Launch
- Quickstart ("first 15 minutes"), install docs, demo GIF/video.
- README polish, CONTRIBUTING, security policy, issue templates.
- Tag **v0.1.0**, publish repo, soft-launch (LinkedIn, r/netsec, relevant
  communities).
- **Milestone:** PentestIQ is public, installable, and demoable.

---

## Beyond Week 8 (backlog, prioritized)

1. **Mobile module** — MobSF integration (APK/IPA static), then dynamic.
2. **Firewall / config audit** (nipper-class) + **network devices**.
3. **Hardening/compliance** — OpenSCAP, Lynis, CIS benchmark reporting.
4. **Desktop app** analysis module.
5. **SaaS console (phase 2)** — hosted multi-project UI, scheduling, dashboards.
6. **Multi-tenant + MSSP/white-label** reporting.
7. **PDF/DOCX** report polish; richer AI reporting; continuous/scheduled scans.

---

## Cadence & Ways of Working

- **Weekly milestone** = a demoable increment (build-in-public friendly).
- Ruthless scope control: if a week slips, cut breadth (defer a module), never
  cut safety/scope enforcement.
- Write tests for parsers, correlation, and safety gates as you go.
- Keep a running CHANGELOG and short weekly dev-log posts to seed the launch
  audience.

---

## Risk Watch (build phase)

| Risk | Early mitigation |
|---|---|
| Scope creep across 9 asset types | Lock MVP to web+infra (+WP/API beta); defer the rest |
| Tool-integration brittleness | Version-pin tools; containerize runners; test parsers |
| Validation logic is hard/slow | Start with 1–2 safe finding classes; expand later |
| Solo-founder bandwidth | Weekly demoable milestones; automate CI; reuse OSS tools |
| Report quality underwhelms | Templates first, AI second; evidence-backed findings |

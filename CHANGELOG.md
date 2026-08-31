# Changelog

All notable changes to PentestIQ are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased] — Phase 2 (SaaS)

### Added
- **Reporting at scale** — **PDF and DOCX** report export (reportlab / python-docx),
  a **compliance mapping** view (OWASP Top 10 / PCI-DSS / ISO 27001 / MITRE ATT&CK)
  in every report and via `GET /engagements/{id}/compliance`, and **per-tenant
  white-label branding** (company name, accent color, footer) via `GET/PUT /settings`.
  `GET /engagements/{id}/report?format=html|md|pdf|docx`.
- **Scheduling & continuous scanning** — recurring engagements on an interval, with
  finding **diffing between runs** (new / fixed / persisting) and **notifications**
  (Slack-compatible / generic webhooks). In-process scheduler (no external broker);
  `POST /schedules`, `/schedules/{id}/run-now`, `/schedules/{id}/diff`, `/schedules/{id}/runs`.
- **Auth, multi-tenancy & RBAC** — user register/login (PBKDF2-hashed passwords),
  HMAC-signed session tokens, per-tenant **API keys** (hashed, shown once), and
  roles (viewer/member/admin/owner) enforced on every endpoint. `pentestiq init-tenant`
  bootstraps a tenant + owner. Auth via `Authorization: Bearer` or `X-API-Key`.
- **Web console** — a self-contained dashboard served at `/` by `pentestiq serve`:
  create engagements, run scans (live status polling), view findings with a severity
  chart and attack chains, and open reports. Vanilla JS, no build step.
- **REST API** (FastAPI) over the engine — `pentestiq serve`, or
  `uvicorn pentestiq.api.app:app`. Endpoints: create/list/get engagement, run
  (background with status), findings, report (HTML/Markdown), health. Auto docs at `/docs`.
- **Persistence layer** — `EngagementStore` with a SQLite backend (Postgres-swappable);
  engagements survive restarts.
- **Tenancy scaffolding** — every record scoped to a tenant via the `X-API-Key` header.
- Engine: programmatic entry points (`build_from_dict`, `run_from_dict`, `execute`).
- See [docs/PHASE2_ROADMAP.md](docs/PHASE2_ROADMAP.md) for the SaaS plan.

## [0.1.0] — 2026-08-31

First open-source release. End-to-end VAPT pipeline: **scope → scan → normalize
→ validate → prioritize → report**, across four asset types.

### Added
- **Engine**: config loader, structured logging, module interface + registry,
  concurrent workflow runner, Typer CLI (`run`, `modules`, `version`).
- **Normalized findings model** with cross-tool deduplication and provenance.
- **Safety & ops core**: ScopeManager, SafeModeGovernor (safe-mode default;
  intrusive/exploit require explicit opt-in), append-only JSONL audit trail,
  bounded concurrent job queue, per-host rate limiting.
- **Tool integrations**: Nmap, Nuclei, OWASP ZAP, WPScan, OpenAPI/Swagger.
- **Asset modules**: infrastructure, web, WordPress, API (beta).
- **Correlation & risk scoring**: 0–100 risk score (severity + CVSS + confidence
  + validation), host:port attack-chain correlation.
- **Safe exploit validation**: non-destructive reflected-XSS and boolean-based
  SQLi validators; `detected → validated` with evidence, false-positive dismissal.
- **Reporting engine**: client-ready HTML + Markdown reports + engagement JSON,
  with a pluggable AI-narrative hook that degrades to a data-driven summary.
- **Explicit asset typing** in scope files (`wordpress=`, `api=`, …).
- Lab (`docker compose`: Juice Shop + DVWA), example scopes, 66 tests.
- CI workflow provided at `docs/github-actions-ci.yml` — copy to `.github/workflows/ci.yml` to enable GitHub Actions (runs pytest on 3.10–3.12).

### Notes
- Orchestrated tools are optional and detected at runtime; missing tools are
  skipped, never fatal.
- Safe-mode and scope enforcement are enabled by scaffolding but default to a
  permissive `warn` mode; set `enforcement: block` to hard-enforce.

[0.1.0]: https://github.com/sajid-infosec/PentestIQ/releases/tag/v0.1.0

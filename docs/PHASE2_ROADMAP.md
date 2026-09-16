# Corvex — Phase 2 Roadmap (SaaS)

*Draft · the commercial layer on top of the open-source v0.1.0 engine.*

Phase 1 delivered the open-source engine (CLI, modules, validation, reporting).
Phase 2 turns it into a **hosted, multi-tenant SaaS console** — the "expand" half
of the open-core model in [BUSINESS_PLAN.md](BUSINESS_PLAN.md). The open-source
engine stays the core; SaaS adds convenience, collaboration, scale, and compliance.

## Guiding principles
- **API-first.** The engine gets a clean HTTP API; the web console and any
  integrations are just clients.
- **The OSS engine stays unchanged and reusable.** SaaS wraps it, never forks it.
- **Postgres-ready but lean to start.** SQLite for dev/self-host; Postgres for hosted.
- **Multi-tenant from the schema up.** Every record carries a tenant.

## Increments

### Increment 1 — API backbone + persistence  ✅
- REST API (FastAPI) over the engine: create engagement, run, list, findings, report.
- Persistence layer (EngagementStore) with a SQLite backend (Postgres-swappable).
- Tenancy scaffolding: `X-API-Key` → tenant; every record scoped to a tenant.
- Background scan execution with status (created → running → completed/failed).

### Increment 2 — Web console (MVP)  ✅
- React/Next.js app consuming the API: projects list, new-scan form, engagement
  dashboard (findings table, risk chart, chains), report viewer/download.
- Auth (session/JWT); minimal RBAC (owner/member).

### Increment 3 — Multi-tenancy, auth & RBAC  ✅
- Real tenant/user/membership model; API keys per tenant; SSO/SAML (enterprise).
- Client workspaces for MSSP/white-label; per-tenant data isolation & encryption.

### Increment 4 — Scheduling & continuous scanning  ✅
- Scheduled/recurring engagements; diffing between runs (new/fixed findings);
  notifications (email/Slack/webhook). Distributed job backend (Redis/Celery)
  swapped in behind the existing JobQueue interface.

### Increment 5 — Reporting at scale & compliance  ✅
- Managed report storage/history; white-label/branded reports; PDF/DOCX export;
  compliance views (OWASP/PCI/ISO/SOC 2 mappings); trends over time.

### Increment 6 — Billing & tiers  ← current
- Plan enforcement (Community/Pro/Team/Enterprise), usage metering, billing
  integration. Gate the first paid feature (TBD — see business plan open questions).

## Non-goals (early Phase 2)
- Not a full enterprise IAM on day one (start with API keys + simple RBAC).
- Not distributed scanning infra until single-node hosted is proven.
- No premature Kubernetes; Docker Compose for hosted MVP, scale later.

## Tech (proposed)
- API: FastAPI (done). DB: SQLite (dev) → PostgreSQL (hosted). Jobs: in-process now
  → Redis/Celery later. Frontend: React/Next.js + Tailwind. Deploy: Docker Compose → Helm.

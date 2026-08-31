# PentestIQ — Deployment

## Quick self-host (PentestIQ + MobSF, one command)

The mobile module needs **MobSF** running alongside PentestIQ. The provided
compose brings up both — the PentestIQ server orchestrates MobSF, and users
upload apps through the console (no file paths, no direct MobSF access).

```bash
export MOBSF_API_KEY=$(openssl rand -hex 32)
export PENTESTIQ_SECRET_KEY=$(openssl rand -hex 32)
docker compose -f deploy/docker-compose.yml up -d --build

# open http://localhost:8080  -> register -> "Upload & scan" an .apk/.ipa
```

## How mobile scanning works

1. A user uploads an APK/IPA through the console (`POST /engagements/upload`).
2. PentestIQ saves the file server-side and creates a `mobile` engagement.
3. On run, the mobile module hands the file to **MobSF** (co-located, reached via
   `MOBSF_URL`) which performs the static analysis.
4. MobSF's report is normalized into PentestIQ findings (with CWE / OWASP-Mobile /
   MASVS references), scored, and included in the report — same pipeline as every
   other asset type.

## Configuration (environment)

| Variable | Purpose |
|---|---|
| `PENTESTIQ_SECRET_KEY` | Signs session tokens — **set in production** so logins survive restarts |
| `MOBSF_URL` | MobSF base URL (default `http://localhost:8000`; compose sets `http://mobsf:8000`) |
| `MOBSF_API_KEY` | MobSF REST API key (same value on both services) |

## Other scanners

`nmap` is bundled in the PentestIQ image. `nuclei`, `zaproxy`, and `wpscan` (for
web / WordPress modules) can be added to the image or run on a dedicated scanning
host. Missing tools are skipped gracefully — the engine still runs.

## Data & scale

- Persistence is SQLite under `/app/data` (a Docker volume). For production/scale,
  swap in PostgreSQL behind the `EngagementStore` interface.
- The scheduler runs in-process; for horizontal scale, move to a distributed
  worker behind the existing `JobQueue` / `ScheduleService` interfaces.

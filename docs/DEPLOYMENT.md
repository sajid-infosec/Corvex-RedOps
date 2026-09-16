# Corvex — Deployment

## One-command install (recommended)

`install.sh` detects your Linux distribution, installs **all prerequisites**
(Docker Engine, Docker Compose, git/curl/openssl), generates secrets, and deploys
the full stack (Corvex API + web console + MobSF).

```bash
git clone https://github.com/sajid-infosec/PentestIQ.git
cd Corvex
sudo ./install.sh
```

Then open **http://localhost:8080**, click **Register**, and start scanning.

**Supported distributions** (auto-detected):

| Family | Distros |
|---|---|
| `apt` | Debian, Ubuntu, Kali, Parrot, Linux Mint, Pop!_OS |
| `dnf` | Fedora, RHEL, CentOS, Rocky Linux, AlmaLinux |
| `pacman` | Arch, Manjaro, EndeavourOS |
| `zypper` | openSUSE, SLES |

**What it does:** installs base tools → installs & starts Docker (via the official
convenience script, falling back to distribution packages) → ensures Docker Compose
v2 (installs the plugin if missing) → writes `deploy/.env` with generated
`MOBSF_API_KEY` and `PENTESTIQ_SECRET_KEY` → `docker compose up -d --build` → waits
for the API health check. It is **idempotent** — safe to re-run.

**Options:**

```bash
sudo ./install.sh --port 9090   # custom console port
sudo ./install.sh --update      # rebuild & redeploy (after a git pull)
sudo ./install.sh --down        # stop the stack
./install.sh --help
```

> Secrets live in `deploy/.env` (git-ignored, mode 600). Back them up — losing
> `PENTESTIQ_SECRET_KEY` invalidates existing login sessions.

## Manual deploy (if Docker is already installed)

```bash
export MOBSF_API_KEY=$(openssl rand -hex 32)
export PENTESTIQ_SECRET_KEY=$(openssl rand -hex 32)
docker compose -f deploy/docker-compose.yml up -d --build

# open http://localhost:8080  -> register -> "Upload & scan" an .apk/.ipa
```

## How mobile scanning works

1. A user uploads an APK/IPA through the console (`POST /engagements/upload`).
2. Corvex saves the file server-side and creates a `mobile` engagement.
3. On run, the mobile module hands the file to **MobSF** (co-located, reached via
   `MOBSF_URL`) which performs the static analysis.
4. MobSF's report is normalized into Corvex findings (with CWE / OWASP-Mobile /
   MASVS references), scored, and included in the report — same pipeline as every
   other asset type.

## Configuration (environment)

| Variable | Purpose |
|---|---|
| `PENTESTIQ_SECRET_KEY` | Signs session tokens — **set in production** so logins survive restarts |
| `MOBSF_URL` | MobSF base URL (default `http://localhost:8000`; compose sets `http://mobsf:8000`) |
| `MOBSF_API_KEY` | MobSF REST API key (same value on both services) |

## Other scanners

`nmap` is bundled in the Corvex image. `nuclei`, `zaproxy`, and `wpscan` (for
web / WordPress modules) can be added to the image or run on a dedicated scanning
host. Missing tools are skipped gracefully — the engine still runs.

## Data & scale

- Persistence is SQLite under `/app/data` (a Docker volume). For production/scale,
  swap in PostgreSQL behind the `EngagementStore` interface.
- The scheduler runs in-process; for horizontal scale, move to a distributed
  worker behind the existing `JobQueue` / `ScheduleService` interfaces.

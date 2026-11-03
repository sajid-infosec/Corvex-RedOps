# Installing Corvex-RedOps

Runs on **Linux, macOS, and Windows**. Every path gives you the same CLI
(`pentestiq`) and web console (`pentestiq serve` → http://localhost:8080).
Pick one.

| Path | Needs | Best for |
|---|---|---|
| [A. Prebuilt binary](#a-prebuilt-binary) | nothing | quickest — no Python/Docker |
| [B. pipx / pip](#b-pipx--pip) | Python 3.10+ | CLI users, dev |
| [C. Installer script](#c-installer-script) | Python **or** Docker | guided setup |
| [D. Docker](#d-docker) | Docker | full SaaS stack (+ mobile-analysis engine) |

---

## A. Prebuilt binary
No Python, no Docker. Download your OS's single-file executable from the
[Releases page](https://github.com/sajid-infosec/Corvex-RedOps/releases).

**Linux / macOS**
```bash
chmod +x pentestiq-linux-x64        # or pentestiq-macos-arm64
./pentestiq-linux-x64 serve          # console at http://localhost:8080
```

**Windows (PowerShell)**
```powershell
.\pentestiq-windows-x64.exe serve
```

---

## B. pipx / pip
Requires **Python 3.10+**.

**Global CLI (isolated, all OSes)**
```bash
pipx install "git+https://github.com/sajid-infosec/Corvex-RedOps.git#egg=pentestiq[all]"
pentestiq --help
```

**Virtualenv from source**
```bash
git clone https://github.com/sajid-infosec/Corvex-RedOps.git
cd Corvex-RedOps
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
pip install ".[api,reports,desktop]" # or ".[all]" for everything (incl. SPA)
pentestiq serve
```

Extras: `api` (REST + console), `reports` (PDF/DOCX), `desktop` (binary hardening),
`spa` (headless-browser SPA crawl — then `playwright install chromium`), `all`.

---

## C. Installer script

**One command. It installs everything, resolves its own dependencies, and brings
up the console.** It prefers a Docker deployment and **automatically falls back to
a native install** (Python venv + pip — needs only PyPI) if Docker is missing, not
running, or can't reach the image registry. It even tries to repair Docker's DNS
first. No prompts, no second command, nothing for you to fix.

**Linux** — `sudo ./install.sh` (Docker stack + mobile-analysis engine, or native fallback):
```bash
sudo ./install.sh
```

**macOS** — installs Colima + Docker via Homebrew (no Docker Desktop GUI), then deploys:
```bash
./install.sh
```

**Windows (PowerShell)** — one command, same auto-fallback (Docker Desktop → native):
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
```

Flags — same actions on every OS:
- Force an engine: `--native` / `--docker` (sh), `-Native` / `-Docker` (ps1)
- `--port 9090`, `--update`, `--down` (sh); `-Port 9090`, `-Update`, `-Down` (ps1)

The install is **non-interactive** — no questions. The optional local AI model
(~5 GB; needs 8+ cores / 16 GB+ RAM and Docker) is **off by default**; add
`--ai` (sh) / `-Ai` (ps1) to deploy it. The lightweight self-learning model is
installed either way.

## Troubleshooting

**macOS: `failed to connect to the docker API ... docker.sock`** — the Colima
Docker VM isn't running (it stops on reboot). Start it and re-run:
```bash
colima start
./install.sh --update
```
The installer now auto-starts Colima in `--update` mode, so this is handled for you.

**macOS: `git push` / HTTPS hangs while Colima is running** — start Colima with
**plain `colima start`**, never `colima start --network-address`. The
`--network-address` flag adds a vmnet interface that can black-hole outbound
routes to some hosts (e.g. `github.com:443` times out while other sites work).
Corvex-RedOps is reached via `localhost:8080` port-forwarding either way, so you
never need `--network-address`. If you already started it that way:
`colima stop && colima start`.

**macOS: don't use `sudo`** — Colima is per-user; the installer auto-re-execs as
your user if you run it with `sudo`, but `./install.sh` (no sudo) is cleanest.

---

## D. Docker
Any OS with Docker or Docker Desktop:
```bash
cd deploy
docker compose up -d --build         # console :8080, mobile-analysis :8000
```

---

## First run
1. Open **http://localhost:8080**.
2. Sign in as **`admin`**. No password ships — a strong one is generated on first run
   and printed **once** to the API log (`docker logs pentestiq-api 2>&1 | grep -A3 'first-run admin'`,
   or your console output for a non-Docker run). Change it after first login, or pin your
   own with the `CORVEX_ADMIN_USER` / `CORVEX_ADMIN_PASSWORD` env vars. Use **Create workspace**
   for a separate tenant.
   Locked out? `docker exec -it pentestiq-api corvex reset-password admin` prints a new one.
3. Add a target (New scan) or upload an app / OpenAPI spec, then **Run scan**.

## Deep-scan backend
Corvex-RedOps's native crawler, OWASP checks, out-of-band detection, and injection
fuzzer need **no external components**. The **Docker deployment (option D) bundles
the full deep-scan backend and mobile-analysis service** — nothing else to install.

## Verify
```bash
pentestiq version
pentestiq modules                    # lists the 9 asset modules
curl http://localhost:8080/health    # {"status":"ok",...} once serving
```

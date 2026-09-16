# Installing Corvex

Runs on **Linux, macOS, and Windows**. Every path gives you the same CLI
(`pentestiq`) and web console (`pentestiq serve` → http://localhost:8080).
Pick one.

| Path | Needs | Best for |
|---|---|---|
| [A. Prebuilt binary](#a-prebuilt-binary) | nothing | quickest — no Python/Docker |
| [B. pipx / pip](#b-pipx--pip) | Python 3.10+ | CLI users, dev |
| [C. Installer script](#c-installer-script) | Python **or** Docker | guided setup |
| [D. Docker](#d-docker) | Docker | full SaaS stack (+ MobSF) |

---

## A. Prebuilt binary
No Python, no Docker. Download your OS's single-file executable from the
[Releases page](https://github.com/sajid-infosec/PentestIQ/releases).

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
pipx install "git+https://github.com/sajid-infosec/PentestIQ.git#egg=pentestiq[all]"
pentestiq --help
```

**Virtualenv from source**
```bash
git clone https://github.com/sajid-infosec/PentestIQ.git
cd Corvex
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
pip install ".[api,reports,desktop]" # or ".[all]" for everything (incl. SPA)
pentestiq serve
```

Extras: `api` (REST + console), `reports` (PDF/DOCX), `desktop` (binary hardening),
`spa` (headless-browser SPA crawl — then `playwright install chromium`), `all`.

---

## C. Installer script

**Linux** — deploys the Docker SaaS stack (Corvex + MobSF):
```bash
sudo ./install.sh
```

**macOS** — installs Colima + Docker via Homebrew (no Docker Desktop GUI), then deploys:
```bash
./install.sh
```

**Windows (PowerShell)** — Python path (venv + serve); add `-Docker` for the stack:
```powershell
powershell -ExecutionPolicy Bypass -File .\install.ps1
powershell -ExecutionPolicy Bypass -File .\install.ps1 -Docker
```

Flags — same actions on every OS:
- macOS/Linux: `sudo ./install.sh --port 9090`, `sudo ./install.sh --update`, `sudo ./install.sh --down`
- Windows: `... install.ps1 -Docker -Port 9090`, `... install.ps1 -Docker -Update`, `... install.ps1 -Docker -Down`

During install/update you'll be asked **"Do you want to install / integrate AI? [y/N]"** — **y** adds the local self-hosted AI layer (Ollama, ~5 GB model; needs 8+ cores / 16 GB+ RAM), **n** installs lean. Skip the prompt with `--ai`/`--no-ai` (sh) or `-Ai`/`-NoAi` (ps1).

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
Corvex is reached via `localhost:8080` port-forwarding either way, so you
never need `--network-address`. If you already started it that way:
`colima stop && colima start`.

**macOS: don't use `sudo`** — Colima is per-user; the installer auto-re-execs as
your user if you run it with `sudo`, but `./install.sh` (no sudo) is cleanest.

---

## D. Docker
Any OS with Docker or Docker Desktop:
```bash
cd deploy
docker compose up -d --build         # console :8080, MobSF :8000
```

---

## First run
1. Open **http://localhost:8080**.
2. Sign in with the default workspace — **`pentestiq`** / **`p3nt3st!q`** (change the
   password after first login), or **Create workspace** for a separate tenant.
3. Add a target (New scan) or upload an app / OpenAPI spec, then **Run scan**.

## Deep-scan backend
Corvex's native crawler, OWASP checks, out-of-band detection, and injection
fuzzer need **no external components**. The **Docker deployment (option D) bundles
the full deep-scan backend and mobile-analysis service** — nothing else to install.

## Verify
```bash
pentestiq version
pentestiq modules                    # lists the 9 asset modules
curl http://localhost:8080/health    # {"status":"ok",...} once serving
```

# Installing PentestIQ

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
cd PentestIQ
python3 -m venv .venv
source .venv/bin/activate            # Windows: .venv\Scripts\Activate.ps1
pip install ".[api,reports,desktop]" # or ".[all]" for everything (incl. SPA)
pentestiq serve
```

Extras: `api` (REST + console), `reports` (PDF/DOCX), `desktop` (binary hardening),
`spa` (headless-browser SPA crawl — then `playwright install chromium`), `all`.

---

## C. Installer script

**Linux** — deploys the Docker SaaS stack (PentestIQ + MobSF):
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

Flags: `--port 9090` (sh) / `-Port 9090` (ps1), `sudo ./install.sh --update`,
`sudo ./install.sh --down`.

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
2. Click **Register** to create your first tenant + owner.
3. Add a target (New engagement) or upload an APK / OpenAPI spec, then **Run scan**.

## Optional external scanners
The native crawler, OWASP checks, OAST, and injection fuzzer need **no external
tools**. For the orchestrated modules, put these on PATH (each is skipped
gracefully if absent):
```bash
sudo apt install -y nmap wpscan      # Debian/Kali
brew install nmap                    # macOS
# nuclei: https://github.com/projectdiscovery/nuclei
# OWASP ZAP: https://www.zaproxy.org/download/
# MobSF: bundled in the Docker stack (option D)
```

## Verify
```bash
pentestiq version
pentestiq modules                    # lists the 9 asset modules
curl http://localhost:8080/health    # {"status":"ok",...} once serving
```

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
- `--port 9090`, `--listen 127.0.0.1`, `--trusted-proxy <ip|cidr>`, `--update`, `--down` (sh); `-Port 9090`, `-Listen 127.0.0.1`, `-TrustedProxy <ip|cidr>`, `-Update`, `-Down` (ps1)

**Network exposure.** The console serves plain HTTP on every interface by default (`--listen 0.0.0.0`). Put TLS in front of it (a reverse proxy with a certificate), or bind it to this host only with `--listen 127.0.0.1`; the installer's summary warns when it is reachable from the network. The mobile-analysis service and the local AI runtime are published on 127.0.0.1 only.

**Behind a reverse proxy.** Sign-in throttling uses the client's address. By default only a
proxy on the same host (127.0.0.1 / ::1) may supply it through `X-Forwarded-For`; any other
peer's forwarded header is ignored and the peer address is used. To put a TLS proxy in front:

- **Proxy on the host, console in Docker:** the proxy reaches the container through the
  compose network's gateway. Find it with
  `docker network inspect deploy_default --format '{{(index .IPAM.Config 0).Gateway}}'`
  (e.g. `172.18.0.1`), then `sudo ./install.sh --listen 127.0.0.1 --trusted-proxy 172.18.0.1`.
  **Trust the gateway only together with `--listen 127.0.0.1`:** with the console published on
  the network, other clients can arrive through that same gateway address and set their own
  `X-Forwarded-For`. The installer warns when a trusted proxy is set and the console isn't on
  loopback. On Windows: `.\install.ps1 -Listen 127.0.0.1 -TrustedProxy 172.18.0.1`.
- **Every client looks the same?** On Docker Desktop, rootless Docker or Docker's userland
  proxy, all connections can arrive from the container's default gateway. The console logs a
  one-time warning when that happens, because sign-in limits are then shared by all users. The
  fix is the setup above: a TLS proxy in front, trusted, with the console on `--listen 127.0.0.1`.
- **Proxy in another container or on another machine:** trust its IP, or its network as a
  CIDR (`--trusted-proxy 10.0.0.0/24`). The option can be repeated.
- **Never `*`.** Trusting every peer lets any client choose the address it is rate-limited
  under, which turns sign-in throttling off. The console refuses to start with `*` in
  `CORVEX_TRUSTED_PROXIES`.

The installer writes `CORVEX_TRUSTED_PROXIES` (loopback plus your entries) to `deploy/.env`.

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
2. Sign in. No password ships with Corvex-RedOps. `install.sh` signs you in as **`corvex`** with a
   random **one-time** password it prints once at the end of the install. Without the installer,
   the app generates one for **`admin`** and prints it **once** to the API log
   (`docker logs pentestiq-api 2>&1 | grep -A3 'first-run admin'`, or your console output for a
   non-Docker run). Either way the console makes you choose your own password at the first
   sign-in. For a separate tenant run `corvex init-tenant` on the server (self-service
   **Create workspace** is off unless `CORVEX_ALLOW_REGISTRATION=1`).
   Locked out? `docker exec -it pentestiq-api corvex reset-password <user>` prints a new one-time
   password (changed again at the next sign-in).
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

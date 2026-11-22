# Installing Corvex-RedOps

Runs on **Linux, macOS, and Windows**. Every path gives you the same CLI
(`pentestiq`) and web console (`pentestiq serve` → http://127.0.0.1:8000).
Pick one.

| Path | Needs | Best for |
|---|---|---|
| [A. Prebuilt binary](#a-prebuilt-binary) | nothing | quickest — no Python/Docker |
| [B. pipx / pip](#b-pipx--pip) | Python 3.10+ | CLI users, dev |
| [C. Installer script](#c-installer-script) | Python **or** Docker | guided setup |
| [D. Docker](#d-docker) | Docker | full SaaS stack (+ mobile-analysis engine) |

---

## A. Prebuilt binary
No Python, no Docker. Download your OS's single-file executable **and `SHA256SUMS`** from the
[Releases page](https://github.com/sajid-infosec/Corvex-RedOps/releases).

| OS | File |
|---|---|
| Linux (x64) | `corvex-redops-linux-x64` |
| macOS (Apple Silicon) | `corvex-redops-macos-arm64` |
| Windows (x64) | `corvex-redops-windows-x64.exe` |

**1. Check the download against `SHA256SUMS`** (both files in the same folder). Each command
prints `OK` only if the file is exactly the one the release published:
```bash
grep ' corvex-redops-linux-x64$' SHA256SUMS | sha256sum -c -           # Linux
grep ' corvex-redops-macos-arm64$' SHA256SUMS | shasum -a 256 -c -     # macOS
```
```powershell
# Windows (PowerShell)
$want = ((Select-String -Path SHA256SUMS -Pattern ' corvex-redops-windows-x64.exe$').Line -split '\s+')[0]
$got  = (Get-FileHash .\corvex-redops-windows-x64.exe -Algorithm SHA256).Hash.ToLower()
if ($got -eq $want) { "OK" } else { "MISMATCH - don't run it" }
```

**2. Run it**
```bash
chmod +x corvex-redops-linux-x64        # or corvex-redops-macos-arm64
./corvex-redops-linux-x64 serve          # console at http://127.0.0.1:8000
```
```powershell
.\corvex-redops-windows-x64.exe serve
```

**The binaries aren't code-signed yet** (no developer certificate, no notarization), so the
operating system warns the first time:

- **macOS:** Gatekeeper blocks the first open ("cannot be opened because Apple cannot check it
  for malicious software"). Once the checksum matches, allow it either by removing the download
  flag, `xattr -d com.apple.quarantine corvex-redops-macos-arm64`, or after the first blocked
  attempt in **System Settings → Privacy & Security → Open Anyway**.
- **Windows:** SmartScreen warns "Windows protected your PC". Once the checksum matches, choose
  **More info → Run anyway**.

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

**One command that never fails halfway.** It installs everything and brings up the console.
It prefers a Docker deployment and **falls back to a native install** if Docker is missing,
not running, or can't reach the image registry.

- **Preflight first, read-only:** platform, free memory and disk, Docker's state and every
  host port the deployment will use are checked before anything changes. A port that's taken
  is named with the program holding it. If it's the default port, the installer moves to the
  next free one; if you chose it with `--port`, it stops and tells you.
- **Never half-started:** if the stack doesn't come up healthy (or you press Ctrl-C), it's
  taken down again before the installer exits. Data is kept.
- **Docker DNS:** on networks whose DNS replies Docker's built-in resolver rejects (pulls fail
  with `lookup … on …:53: no such host` while the host resolves fine), the installer adds one
  file, `/etc/systemd/system/docker.service.d/corvex-dns.conf`
  (`Environment=GODEBUG=netdns=cgo`), restarts Docker and says so. Nothing else on the system
  is changed.
- **Native install:** its own venv (`/opt/corvex-redops/venv`) and data
  (`/var/lib/corvex-redops`), outside the checkout, run as the unprivileged user
  `corvex-redops` by the systemd unit `corvex-redops.service` — never as root. Without root it
  installs under `~/.local/share/corvex-redops` for your user instead.

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
- `--port 9090`, `--listen 0.0.0.0`, `--trusted-proxy <ip|cidr>`, `--publish-mobile [port]`, `--update`, `--down` (sh); `-Port 9090`, `-Listen 0.0.0.0`, `-TrustedProxy <ip|cidr>`, `-PublishMobile [-MobilePort n]`, `-Update`, `-Down` (ps1)

**Network exposure.** The console listens on **127.0.0.1** (this host only) by default. To reach it from other machines, opt in with `--listen 0.0.0.0` (or a specific address); it's plain HTTP, so the installer prints a one-line warning — put TLS in front of it (a reverse proxy with a certificate). An install from an older version that listened on 0.0.0.0 moves to 127.0.0.1 on `--update`, and the summary says so. The mobile-analysis engine and the local AI runtime have **no host port**: the console reaches them on the compose network. `--publish-mobile [port]` publishes the mobile engine on 127.0.0.1 (default port 8000) if you want to reach it from the host.

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

**Data directory and backups.** Accounts, engagements and settings live in one SQLite
database, `pentestiq.db`, in the data directory: the `pentestiq-data` Docker volume
(`/app/data` in the container), `/var/lib/corvex-redops/data` for a native install (or
`CORVEX_DATA_DIR`), or `data_dir` in the config file. Uploads and the audit log sit beside it as plain files.

- **Keep the data directory on a local disk, not NFS or SMB/CIFS.** The database runs in
  WAL mode: it keeps `pentestiq.db-wal` and `pentestiq.db-shm` next to `pentestiq.db` and
  relies on shared memory that network filesystems don't provide safely.
- **Back up with SQLite's backup API**, which is safe while the console runs. Native:
  `sqlite3 data/pentestiq.db ".backup 'pentestiq-backup.db'"`. Docker:
  `docker exec pentestiq-api python -c "import sqlite3; d = sqlite3.connect('/app/data/pentestiq-backup.db'); sqlite3.connect('/app/data/pentestiq.db').backup(d); d.close()"`,
  then `docker cp pentestiq-api:/app/data/pentestiq-backup.db .`
  Or stop the console and copy all three files together. **Never copy `pentestiq.db` alone
  while the console runs:** recent changes may still be in `pentestiq.db-wal`.
- **Restore** with the console stopped: put the backup in place as `pentestiq.db`, delete any
  `pentestiq.db-wal` and `pentestiq.db-shm` left beside it (an old WAL file would be replayed
  onto the restored database), then start the console.

**The local AI model is on request.** In a terminal, with neither `--ai` nor `--no-ai`, the
installer asks one question: *Install the local AI model? About 5 GB download, needs 8 GB
free memory. [y/N]* — **y** installs it, Enter or anything else skips it. Without a terminal
(CI, `curl … | sudo bash`) there's no question and no AI unless you pass `--ai` (`-Ai` in
install.ps1). On yes it checks free memory and disk first (and explains if they're short),
starts the AI runtime, downloads the model with visible progress (skipped when it's already
there), switches AI on, restarts the console and verifies it end to end — `/ai/status`
available and a real test narrative from the model — before printing **AI: ready**. If any
step fails it says which, switches AI off again, and reports work as before. The local model
needs Docker; a native install says how to add it later (`--docker --ai`). The lightweight
self-learning model is installed either way. `corvex ai-check` re-runs the end-to-end check.

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
docker compose up -d --build         # console on 127.0.0.1:8080 (mobile-analysis: compose network only)
```

---

## First run
1. Open **http://localhost:8080**.
2. Sign in. No password ships with Corvex-RedOps. `install.sh` signs you in as **`corvex`** with a
   random **one-time** password it prints once at the end of the install. Without the installer,
   the app generates one for **`admin`** and prints it **once** to the API log
   (`docker logs pentestiq-api 2>&1 | grep -A3 'first-run admin'`, or your console output for a
   non-Docker run). Either way the console makes you choose your own password at the first
   sign-in. Community includes one workspace, this one; with Premium, add separate workspaces with
   `corvex init-tenant` on the server (self-service **Create workspace** is off unless
   `CORVEX_ALLOW_REGISTRATION=1`).
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
curl http://127.0.0.1:8000/health    # {"status":"ok",...} once `serve` runs
curl http://localhost:8080/health    # the same, for a Docker / installer deployment
```

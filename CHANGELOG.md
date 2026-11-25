# Changelog

All notable changes to Corvex-RedOps are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Security
- The installer's console listens on 127.0.0.1 by default; `--listen 0.0.0.0` is opt-in, with a one-line warning. The mobile-analysis engine and the local AI runtime no longer publish host ports (`--publish-mobile` publishes the mobile engine on 127.0.0.1).
- The native install runs the console as the unprivileged `corvex-redops` user under a systemd unit, with its own venv and its data in `/var/lib/corvex-redops` — never as root and never from the checkout.
- The Docker image runs the console as a non-root user, pins its template engine and subdomain finder by version and SHA-256 (amd64 and arm64), and no longer copies `deploy/.env`, `data/` or a local venv into the image.

### Added
- First-visit registration. A fresh install shows **Create your Corvex-RedOps account**: full name, email, username and password (twice). The account is created at once, becomes the administrator, and is signed in. Email verification is off for now (`CORVEX_REGISTRY=off` is the default; the console never contacts corvex-redops.com); `CORVEX_REGISTRY=on` turns on 6-digit codes emailed through the account registry for sign-up, **Forgot password?**, email verification and Premium team invites. When the console listens beyond 127.0.0.1 the installer sets `CORVEX_SETUP_CODE_REQUIRED=1`, so the form also asks for the one-time setup code. `/me`, the header and Premium's team list show the full name; Premium's **Add user** takes one too.
- `corvex reset-setup` removes every console account so the registration form appears again (for an install whose sign-in is lost). Workspaces, engagements, findings, reports and API keys stay; the next account owns them all.
- The Docker install passes `CORVEX_INTEL_OFFLINE` and `CORVEX_INTEL_REFRESH_DAYS` to the console (they were ignored before).
- The local AI model is installed on request: in a terminal the installer asks "Install the local AI model? About 5 GB download, needs 8 GB free memory. [y/N]" (no terminal: no AI unless `--ai`). It checks memory and disk first, skips the download when the model is already there, and prints "AI: ready" only after `/ai/status` reports the model available and the model wrote a real test narrative; otherwise it says what failed and leaves AI off. `corvex ai-check` runs the same check.

### Changed
- No admin is created at install time and no password is printed or generated: the first visit's registration form creates the account. Until then every API route except setup and health refuses. `CORVEX_ADMIN_PASSWORD` still creates the admin directly for headless installs; installs that already have an admin never see the form. An older install whose only account is the built-in one on the old shipped password gets the form instead of a forced password change; registering takes that account over with its workspace and data.
- The sign-in hint for Docker installs is `sudo docker exec -it <console container> corvex reset-password <user>`.
- The installer runs a read-only preflight (platform, free memory and disk, Docker, every host port) before changing anything. A busy port is named with the program holding it; the next free port is used when you didn't choose one. A stack that doesn't come up healthy, or an interrupted install, is taken down again.
- Docker DNS repair is a single `docker.service` drop-in, added only when image pulls fail because Docker's built-in resolver rejects the network's DNS replies. The installer no longer changes systemd-resolved, `/etc/resolv.conf` or Docker's `daemon.json`.

- Everything you see carries the Corvex-RedOps / `corvex` name: the containers (`corvex-redops-console`, `corvex-redops-mobile`, `corvex-redops-ai`), the image `corvex-redops`, the compose project, network and volumes (`corvex-redops-data`, `corvex-redops-ai-models`), the database file (`corvex-redops.db`), the Python distribution and wheel (`corvex-redops`), and every setting (`CORVEX_*`). SARIF exports use a `corvex/` namespace (older exports still import), schedule webhooks carry their details under `corvex`, and tickets are labelled `corvex-redops`.

### Upgrading
- An update keeps the engine your deployment runs on: with too little disk for Docker it stops before changing anything rather than moving to the native install. Moving on purpose (`--native` / `-Native`) stops the old containers (they're kept) and copies their data across.
- `install.sh --update` (and `install.ps1 -Update`) keeps your data and settings: it rewrites `deploy/.env` to the new setting names, replaces the old containers, and copies the old data and model volumes into the new ones — the old volumes are kept, and the summary says how to remove them once you've checked. The console renames the database file (with its `-wal` / `-shm`) on its first start, only if the new one doesn't exist yet. Settings under their old names are still read.
- pip users: run `pip uninstall pentestiq` before installing `corvex-redops` (both install the same package).
- The old command name still works for now; it says it was renamed and runs `corvex`.

### Fixes
- A Docker install from a checkout with private files (mode 600, directories 700) no longer stops with `PermissionError` when the console starts: the image makes its code readable for the console's unprivileged user.
- The native install no longer reports "Dependency install failed" after its dependencies installed: the staged copy of the code that pip built in (as root) is removed as root, and a cleanup problem never fails the install.
- Copied data volumes are created with Compose's labels, so `docker compose up` no longer warns that `corvex-redops-ai-models` "already exists but was not created by Docker Compose".
- When the Docker install doesn't come up, the installer says so ("The Docker install didn't come up") instead of "Docker isn't usable here" before trying the native install.
- Windows: `install.ps1` finds an installed Python 3.10–3.12 again (it missed every one and installed another). After installing Python with winget it carries on in the same window; when it really can't, it stops with an error instead of reporting success.
- The AI memory check follows the chosen model: 8 GB for the default 7B model, less for a smaller `CORVEX_AI_MODEL`; `CORVEX_AI_MIN_MEM_MB` overrides it, now on Windows too.
- The headless crawl works in the arm64 image.
- The AI status no longer counts a different size of the same model as the configured one.

## [0.2.1] — 2026-11-19

### Fixes
- The per-username sign-in slowdown no longer resets at the top of each hour.
- Docs: the single-file binary's console is at http://127.0.0.1:8000, not 8080.
- Docs: generic names for bundled engines and practice targets; Premium's Deep Scan payload-fuzzing tab is now labelled "Fuzzer".

## [0.2.0] — 2026-11-18

Corvex-RedOps grows from a command-line scanner into a self-hosted security-testing platform
with a web console and REST API, and this release hardens sign-in, deployment and
portability. Community includes 10 scan types and one workspace; Premium adds the rest (see
the editions table in the README).

### Added
- **Web console and REST API.** Run and follow scans live (pause, resume, stop), triage
  findings, export reports. Interactive API docs at `/docs`.
- **Ten Community scan types:** web, REST/API, infrastructure, WordPress, mobile apps
  (APK/IPA), dependencies (with a CycloneDX SBOM), source code, secrets, proxy-history
  import, and imported scan results (SARIF and common scanner formats; SARIF export).
- **Built-in active checks and injection fuzzing** for the OWASP Top 10 and API Top 10:
  broken object- and function-level authorization, token weaknesses, mass assignment,
  unrestricted file upload, undocumented API endpoints, insecure-deserialization signals,
  and more. An attack-surface crawler, and out-of-band detection with a self-hostable
  callback server.
- **Prioritization:** EPSS and CISA KEV, exploit-availability intelligence (metadata only,
  never exploit code), and a validation planner that shows which findings were confirmed
  automatically and which need manual validation. SLA tracking and service-banner to CVE
  matching.
- **Asset inventory and external attack-surface discovery**, with exposure scoring and
  posture trends.
- **MITRE ATT&CK mapping, an attack-path graph and safe control validation.**
- **Reports** in HTML, Markdown, PDF and DOCX, with an executive summary, compliance mapping
  (OWASP, PCI-DSS, ISO 27001, MITRE ATT&CK) and exploitability and validation coverage.
- **Deep Scan core:** capture and HAR import for passive analysis.
- **An optional local AI layer** (self-hosted) and a self-learning false-positive model.
- **Editions.** Community and Premium, set with `CORVEX_EDITION` or an `EDITION` file;
  Premium-only routes answer HTTP 402 in Community. **Community includes one workspace:** a
  second one is refused (HTTP 403 `workspace_limit`; `corvex init-tenant` exits 1).
  Installs that already have more keep working.
- **Installers** for Linux, macOS and Windows (`install.sh`, `install.ps1`): Docker with a
  native fallback, `--update` / `--down`, and updates from the console.
- **Accounts:** session sign-in, per-workspace API keys, four built-in roles, self-service
  password change, and `corvex reset-password` for recovery.

### Security
- **No default credentials.** The first-run admin gets a random one-time password (the
  installer shows it once and never leaves it on disk) that must be changed at the first
  sign-in. A pinned `CORVEX_ADMIN_PASSWORD` shorter than 12 characters stops the console at
  first boot.
- **Every new password is at least 12 characters.** Existing shorter passwords still sign
  in.
- Passwords are hashed with PBKDF2-HMAC-SHA256 at 600,000 iterations and upgraded at the
  next sign-in.
- Sessions end when a password is changed or reset; roles are read from the database on
  every request.
- Self-service registration is closed by default (`CORVEX_ALLOW_REGISTRATION=1` opens it).
- **Sign-in throttling with no account lockout:** limits per username and address and per
  address (IPv6 by /64), counted before the password check so a burst of parallel requests
  can't get past them, and a per-username slowdown above 50 wrong passwords an hour that
  doesn't hold up other requests.
- **Reverse proxies:** only trusted proxies (`--trusted-proxy`, `CORVEX_TRUSTED_PROXIES`,
  never `*`) may set the client address. Warnings when a trusted proxy is set while the
  console isn't on loopback, and when every client appears to share one address.
- Helper services listen on 127.0.0.1 only; `--listen` / `-Listen` choose the console's
  address, with a warning when it is reachable over plain HTTP.
- **Uploaded archives:** path traversal and symlink escapes are rejected, and an archive
  whose files are all rejected is reported as an error instead of scanning as empty.

### Fixes
- The account database runs SQLite in WAL mode, and the checks made on every signed-in
  request no longer wait behind sign-in writes.
- Scans stop at exactly their time budget, measured on a monotonic clock. The default
  budget is 4 hours (it was 15 minutes, which stopped scans early).
- Archive uploads on macOS and Windows no longer scan as empty.
- On Windows, a session issued just before a password change now ends with it.
- Text files and tool output are read as UTF-8 on every platform.
- Console: severity bars, the posture-trend chart, light-theme readability and discovery
  status messages.
- Installers: the macOS summary, Python detection on Windows, starting Docker on update, a
  port clash on re-run, and quieter output.

### Platforms
- Linux, macOS and Windows; CI tests Python 3.10, 3.11 and 3.12 on all three.
- SQLite 3.24 or newer, including Enterprise Linux 9's 3.34 (tested in CI). The console
  refuses to start on an older SQLite and names the version it found.
- Single-file binaries for Linux x64, macOS arm64 and Windows x64, published with
  SHA256SUMS. They aren't code-signed yet; INSTALL.md explains what that means.

### Docs
- INSTALL.md with steps per OS, network exposure, reverse proxies, the data directory and
  backups (keep the data on a local disk; back up with SQLite's backup API).
- README: the editions table, and the CI status badge in place of a fixed test count.
- A manual QA guide and an architecture guide.

## [0.1.0] — 2026-08-31

First open-source release. End-to-end VAPT pipeline: **scope → scan → normalize
→ validate → prioritize → report**, across four asset types.

### Added
- **Engine**: config loader, structured logging, module interface + registry,
  concurrent workflow runner, CLI (`run`, `modules`, `version`).
- **Normalized findings model** with cross-tool deduplication and provenance.
- **Safety & ops core**: ScopeManager, SafeModeGovernor (safe-mode default;
  intrusive/exploit require explicit opt-in), append-only JSONL audit trail,
  bounded concurrent job queue, per-host rate limiting.
- **Scanning-engine integrations**: port & service discovery, template-based scanning, DAST web scanning, WordPress scanning, OpenAPI/Swagger.
- **Asset modules**: infrastructure, web, WordPress, API (beta).
- **Correlation & risk scoring**: 0–100 risk score (severity + CVSS + confidence
  + validation), host:port attack-chain correlation.
- **Safe exploit validation**: non-destructive reflected-XSS and boolean-based
  SQLi validators; `detected → validated` with evidence, false-positive dismissal.
- **Reporting engine**: client-ready HTML + Markdown reports + engagement JSON,
  with a pluggable AI-narrative hook that degrades to a data-driven summary.
- **Explicit asset typing** in scope files (`wordpress=`, `api=`, …).
- Lab (`docker compose`: two deliberately vulnerable practice apps), example scopes, 66 tests.
- CI workflow provided at `docs/github-actions-ci.yml` — copy to `.github/workflows/ci.yml` to enable GitHub Actions (runs pytest on 3.10–3.12).

### Notes
- Orchestrated tools are optional and detected at runtime; missing tools are
  skipped, never fatal.
- Safe-mode and scope enforcement are enabled by scaffolding but default to a
  permissive `warn` mode; set `enforcement: block` to hard-enforce.

[Unreleased]: https://github.com/sajid-infosec/corvex-redops/compare/v0.2.1...HEAD
[0.2.1]: https://github.com/sajid-infosec/corvex-redops/releases/tag/v0.2.1
[0.2.0]: https://github.com/sajid-infosec/corvex-redops/releases/tag/v0.2.0
[0.1.0]: https://github.com/sajid-infosec/Corvex-RedOps/releases/tag/v0.1.0

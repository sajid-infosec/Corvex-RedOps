# Changelog

All notable changes to Corvex-RedOps are documented here. This project adheres to
[Semantic Versioning](https://semver.org/).

## [Unreleased]

### Fixes
- The per-username sign-in slowdown no longer resets at the top of each hour.
- Docs: the single-file binary's console is at http://127.0.0.1:8000, not 8080.
- Docs and console: generic names for bundled engines and practice targets; the Deep Scan payload-fuzzing tab is now labelled "Fuzzer".

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

[Unreleased]: https://github.com/sajid-infosec/corvex-redops/compare/v0.2.0...HEAD
[0.2.0]: https://github.com/sajid-infosec/corvex-redops/releases/tag/v0.2.0
[0.1.0]: https://github.com/sajid-infosec/Corvex-RedOps/releases/tag/v0.1.0

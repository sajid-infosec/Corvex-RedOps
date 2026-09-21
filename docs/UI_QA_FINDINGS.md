# Corvex-RedOps — Console UI QA Findings (2026-09-21)

Live black-box test of the running console at `http://localhost:8080/` via the
browser: all 10 views, the API layer, and three real operations (EASM discovery,
posture snapshot, navigation). Fixes applied to both editions; suite green
(premium 482 passed).

## Summary

| Views tested | Console errors | Page-load API | Ops verified |
|---|---|---|---|
| 10 / 10 render | 0 | all 200 | Snapshot ✅, Discovery (ran, see B1) |

## Findings & fixes

### B1 — [High] EASM discovery resolves 0 of N candidates (DNS broken in container)
`example.com` → **150 candidates · 0 resolved · 0 live · 0 filed**. Even the root
domain failed to resolve, though crt.sh returned 150 names — so the `pentestiq-api`
container has HTTPS egress but **no working raw DNS** (`socket.getaddrinfo`). The
feature returned HTTP 200 but silently filed nothing.
- **Code fix (shipped):** `discovery/discover.py` now sets `stats.dns_ok` — false when
  candidates>0 but 0 resolved (the seed/root always being a candidate makes this a
  reliable signal). The console surfaces a clear "DNS resolution is unavailable in
  this environment" warning instead of a bland "0 resolved".
- **Environment fix (owner action):** confirm + repair container DNS —
  `docker exec pentestiq-api getent hosts example.com`. Likely the Colima
  `--network-address` route black-hole; use a plain `colima start` and redeploy.

### B2 — [Medium] Discovery blocks ~35s with no busy state
The "Find surface" button stayed enabled for the whole call (double-submit risk,
looked hung).
- **Fix (shipped):** button disables + shows "Discovering…" during the call, restored
  in a `finally`. (`api/static/index.html`)

### B3 — [Medium] Brand leak: old "PentestIQ" name on a user-facing surface
Dynamic-kit "PURPOSE" column showed "PentestIQ — …", sourced from the Frida script
header comments.
- **Fix (shipped):** rewrote the brand in `kit/frida/{crypto-hooks,root-jailbreak-bypass,
  ssl-pinning-bypass,webview-inspect}.js` + `kit/frida/README.md`. `grep -rn PentestIQ`
  now clean across `kit/`, `api/`, `reporting/`.

### B4 — [Low] Report-branding accent default was the dark-bg colour
Settings → Report branding "Accent color" defaulted to `#0f172a` (background), not the
brand steel-sky blue.
- **Fix (shipped):** default set to `#0ea5e9` in `reporting/branding.py` and
  `storage/settings_store.py`.

### B5 — [Low/UX] Posture-trend chart with a single snapshot showed a lone dot
- **Fix (shipped):** a "one snapshot so far — capture another…" note renders when
  `points < 2`. (`api/static/index.html`)

## Deploy note
The running container serves the previously baked image. These changes take effect
after `sudo ./install.sh --update`.

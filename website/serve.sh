#!/usr/bin/env bash
# Corvex marketing website — standalone launcher.
#
# This is SEPARATE from the SaaS/tool deployment (../install.sh). It only serves
# the static marketing site from this directory, on its own port (9090 by
# default), so it never collides with the Corvex console.
#
# Usage:
#   ./serve.sh              # → http://localhost:9090
#   ./serve.sh 9091         # pick another port
#   PORT=9091 ./serve.sh
set -euo pipefail
cd "$(dirname "$0")"
PORT="${1:-${PORT:-9090}}"
echo "──────────────────────────────────────────────"
echo "  Corvex website → http://localhost:${PORT}"
echo "  (static marketing site; Ctrl+C to stop)"
echo "──────────────────────────────────────────────"
exec python3 -m http.server "${PORT}"

#!/usr/bin/env bash
#
# Corvex-RedOps — one-command installer & deployer
# ------------------------------------------------
# ONE command. Installs everything, resolves its own dependencies, and brings
# the console up — on Linux (apt/dnf/pacman/zypper) and macOS.
#
# It is self-healing: it prefers a Docker deployment, but if Docker is missing,
# the daemon can't be started, or it can't reach the image registry (common on
# locked-down / VM / corporate-DNS networks), it FIRST tries to repair Docker's
# DNS and, failing that, AUTOMATICALLY falls back to a native install
# (Python venv + pip, which only needs PyPI) — with no prompts and no second
# command. You should never have to intervene.
#
#   sudo ./install.sh              # install everything + deploy (auto engine)
#   sudo ./install.sh --port 9090  # custom console port
#   sudo ./install.sh --ai         # also run the local AI model (Docker only, heavy)
#   sudo ./install.sh --native     # force the native (no-Docker) install
#   sudo ./install.sh --docker     # force the Docker install (no fallback)
#   sudo ./install.sh --down       # stop whatever is running
#   sudo ./install.sh --update     # rebuild/reinstall & redeploy
#   ./install.sh --help
#
# Note: no `set -e`/abort-on-error here on purpose — the installer must survive a
# failed step in order to fall back. Critical steps are checked explicitly.
set -uo pipefail

# ----------------------------------------------------------------------------- ui
c_blue='\033[1;34m'; c_grn='\033[1;32m'; c_yel='\033[1;33m'; c_red='\033[1;31m'; c_dim='\033[2m'; c_off='\033[0m'
log()  { printf "${c_blue}[Corvex-RedOps]${c_off} %s\n" "$*"; }
ok()   { printf "${c_grn}[ ok ]${c_off} %s\n" "$*"; }
warn() { printf "${c_yel}[warn]${c_off} %s\n" "$*"; }
err()  { printf "${c_red}[fail]${c_off} %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$REPO_DIR/deploy/docker-compose.yml"
ENV_FILE="$REPO_DIR/deploy/.env"
VENV_DIR="$REPO_DIR/.venv"
NATIVE_LOG="$REPO_DIR/corvex.log"
NATIVE_PID="$REPO_DIR/.corvex.pid"
PORT="8080"
ACTION="up"
ENGINE="auto"           # auto | docker | native
AI_CHOICE=0             # 0=no AI LLM (default, zero-touch), 1=yes (Docker only)
AI_MODEL="${PENTESTIQ_AI_MODEL:-qwen2.5:7b-instruct}"

usage() {
  cat <<'HELP'
Corvex-RedOps — one-command installer & deployer

Installs everything and brings up the console with a single command. Prefers a
Docker deployment and automatically falls back to a native (Python venv) install
if Docker is unavailable or can't reach the image registry — no prompts.

Usage:
  sudo ./install.sh              install everything + deploy (auto engine)
  sudo ./install.sh --port 9090  deploy on a custom console port
  sudo ./install.sh --ai         also run the local AI model (Docker only, heavy)
  sudo ./install.sh --native     force the native (no-Docker) install
  sudo ./install.sh --docker     force Docker (no native fallback)
  sudo ./install.sh --update     rebuild/reinstall & redeploy
  sudo ./install.sh --down       stop whatever is running
  ./install.sh --help            show this help
HELP
  exit 0
}
while [ $# -gt 0 ]; do
  case "$1" in
    --port) PORT="${2:?}"; shift 2;;
    --down) ACTION="down"; shift;;
    --ai) AI_CHOICE=1; shift;;
    --no-ai) AI_CHOICE=0; shift;;
    --native) ENGINE="native"; shift;;
    --docker) ENGINE="docker"; shift;;
    --update) ACTION="update"; shift;;
    -h|--help) usage;;
    *) die "unknown option: $1 (try --help)";;
  esac
done

# ----------------------------------------------------------------------------- sudo
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else SUDO=""; fi
fi

# ----------------------------------------------------------------------------- distro
detect_distro() {
  if [ "$(uname -s)" = "Darwin" ]; then
    OSKIND="macos"; FAMILY="brew"; SUDO=""
    DISTRO_NAME="macOS $(sw_vers -productVersion 2>/dev/null || echo '')"
    log "Detected: ${DISTRO_NAME}  (package manager: Homebrew)"
    return 0
  fi
  OSKIND="linux"
  if [ -r /etc/os-release ]; then
    # shellcheck disable=SC1091
    . /etc/os-release
    DISTRO_ID="${ID:-unknown}"; DISTRO_LIKE="${ID_LIKE:-}"; DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"
  else
    DISTRO_ID="unknown"; DISTRO_LIKE=""; DISTRO_NAME="unknown Linux"
  fi
  case " $DISTRO_ID $DISTRO_LIKE " in
    *debian*|*ubuntu*|*kali*|*parrot*|*mint*|*pop*) FAMILY="apt";;
    *rhel*|*fedora*|*centos*|*rocky*|*almalinux*)   FAMILY="dnf";;
    *arch*|*manjaro*|*endeavouros*)                 FAMILY="pacman";;
    *suse*|*sles*|*opensuse*)                       FAMILY="zypper";;
    *) case "$DISTRO_ID" in
         debian|ubuntu|kali|parrot|linuxmint|pop) FAMILY="apt";;
         fedora|rhel|centos|rocky|almalinux)      FAMILY="dnf";;
         arch|manjaro|endeavouros)                FAMILY="pacman";;
         opensuse*|sles)                          FAMILY="zypper";;
         *) FAMILY="unknown";; esac;;
  esac
  log "Detected: ${DISTRO_NAME}  (package family: ${FAMILY})"
}

pkg_install() { # best-effort install of packages for the detected family
  case "$FAMILY" in
    brew)   for p in "$@"; do brew list "$p" >/dev/null 2>&1 || brew install "$p" >/dev/null 2>&1 || true; done;;
    apt)    $SUDO apt-get update -y -qq >/dev/null 2>&1 || true
            $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1 || true;;
    dnf)    $SUDO dnf install -y -q "$@" >/dev/null 2>&1 || true;;
    pacman) $SUDO pacman -Sy --noconfirm --needed "$@" >/dev/null 2>&1 || true;;
    zypper) $SUDO zypper --non-interactive --quiet install "$@" >/dev/null 2>&1 || true;;
  esac
}

# ----------------------------------------------------------------------------- prerequisites
install_base() {
  log "Installing base prerequisites (curl, git, openssl, python)…"
  case "$FAMILY" in
    brew)   command -v brew >/dev/null 2>&1 || { warn "Homebrew not found — install from https://brew.sh (native install still works with system python3)."; }
            pkg_install git openssl python@3.12;;
    apt)    apt_fix_docker_repo
            pkg_install ca-certificates curl git openssl gnupg lsb-release python3 python3-venv python3-pip;;
    dnf)    pkg_install ca-certificates curl git openssl python3 python3-pip;;
    pacman) pkg_install curl git openssl ca-certificates python python-pip;;
    zypper) pkg_install curl git openssl ca-certificates python3 python3-pip;;
  esac
  ok "Base prerequisites installed."
}

apt_fix_docker_repo() {
  local f=/etc/apt/sources.list.d/docker.list
  if [ -f "$f" ] && grep -qi "download.docker.com" "$f" 2>/dev/null; then
    warn "removing an unusable Docker apt source ($f)"
    $SUDO rm -f "$f" 2>/dev/null || true
    $SUDO apt-get update -y -qq 2>/dev/null || true
  fi
}

docker_convenience_script() {
  log "Falling back to Docker's official install script…"
  curl -fsSL https://get.docker.com -o /tmp/ptiq-get-docker.sh 2>/dev/null \
    && $SUDO sh /tmp/ptiq-get-docker.sh >/dev/null 2>&1 || true
}

install_docker() { # returns 0 if docker CLI is present afterwards
  if [ "${OSKIND:-linux}" = "macos" ]; then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
      ok "Docker already available ($(docker --version 2>/dev/null | cut -d, -f1))."; return 0
    fi
    command -v brew >/dev/null 2>&1 || { warn "no Homebrew — cannot auto-install Docker on macOS."; return 1; }
    pkg_install colima docker docker-compose
    command -v docker >/dev/null 2>&1 && { ok "Docker (Colima) installed."; return 0; } || return 1
  fi
  if command -v docker >/dev/null 2>&1; then ok "Docker already installed ($(docker --version 2>/dev/null | cut -d, -f1))."; return 0; fi
  log "Installing Docker Engine…"
  case "$FAMILY" in
    apt)    apt_fix_docker_repo
            $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2 2>/dev/null \
              || $SUDO DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io 2>/dev/null \
              || docker_convenience_script;;
    dnf)    $SUDO dnf install -y -q docker docker-compose-plugin 2>/dev/null \
              || $SUDO dnf install -y -q docker 2>/dev/null \
              || $SUDO dnf install -y -q moby-engine 2>/dev/null \
              || docker_convenience_script;;
    pacman) $SUDO pacman -Sy --noconfirm --needed docker docker-compose 2>/dev/null || docker_convenience_script;;
    zypper) $SUDO zypper --non-interactive install docker docker-compose 2>/dev/null || docker_convenience_script;;
    *)      docker_convenience_script;;
  esac
  if command -v docker >/dev/null 2>&1; then
    ok "Docker installed ($(docker --version 2>/dev/null | cut -d, -f1))."
    if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
      $SUDO groupadd -f docker >/dev/null 2>&1 || true
      $SUDO usermod -aG docker "${SUDO_USER}" >/dev/null 2>&1 || true
    fi
    return 0
  fi
  warn "Docker could not be installed."; return 1
}

start_docker() { # returns 0 if the daemon is reachable
  if [ "${OSKIND:-linux}" = "macos" ]; then
    docker info >/dev/null 2>&1 && { ok "Docker daemon is running."; return 0; }
    log "Starting Colima (Docker runtime)…"
    colima status >/dev/null 2>&1 || colima start >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do docker info >/dev/null 2>&1 && { ok "Docker daemon is running."; return 0; }; sleep 2; done
    warn "Docker daemon did not start (Colima)."; return 1
  fi
  if command -v systemctl >/dev/null 2>&1; then
    $SUDO systemctl enable --now docker >/dev/null 2>&1 || $SUDO systemctl start docker >/dev/null 2>&1 || true
  else
    $SUDO service docker start >/dev/null 2>&1 || true
  fi
  for _ in $(seq 1 15); do $SUDO docker info >/dev/null 2>&1 && { ok "Docker daemon is running."; return 0; }; sleep 2; done
  warn "Docker daemon did not start."; return 1
}

ensure_compose() { # returns 0 and sets DC/DC_BIN if a compose implementation exists
  if $SUDO docker compose version >/dev/null 2>&1; then DC="$SUDO docker compose"; DC_BIN="docker compose"; ok "Docker Compose v2 available."; return 0; fi
  if command -v docker-compose >/dev/null 2>&1; then DC="$SUDO docker-compose"; DC_BIN="docker-compose"; ok "docker-compose (v1) available."; return 0; fi
  log "Installing the Docker Compose plugin…"
  local ver="v2.29.7" arch dest
  case "$(uname -m)" in x86_64) arch=x86_64;; aarch64|arm64) arch=aarch64;; armv7l) arch=armv7;; *) arch="$(uname -m)";; esac
  dest="/usr/local/lib/docker/cli-plugins"; $SUDO mkdir -p "$dest"
  $SUDO curl -fsSL "https://github.com/docker/compose/releases/download/${ver}/docker-compose-linux-${arch}" -o "$dest/docker-compose" 2>/dev/null \
    && $SUDO chmod +x "$dest/docker-compose"
  if $SUDO docker compose version >/dev/null 2>&1; then DC="$SUDO docker compose"; DC_BIN="docker compose"; ok "Docker Compose plugin installed."; return 0; fi
  warn "Docker Compose is unavailable."; return 1
}

# ----------------------------------------------------------------------------- secrets
gen_secret() { openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }

write_env() {
  mkdir -p "$(dirname "$ENV_FILE")"
  if [ -f "$ENV_FILE" ]; then ok "Reusing existing secrets ($ENV_FILE)."; return 0; fi
  log "Generating secrets → $ENV_FILE"
  cat > "$ENV_FILE" <<ENV
# Corvex-RedOps deployment secrets — generated by install.sh. Keep private; do not commit.
MOBSF_API_KEY=$(gen_secret)
PENTESTIQ_SECRET_KEY=$(gen_secret)
PENTESTIQ_PORT=${PORT}
PENTESTIQ_AI=${AI_CHOICE:-0}
OLLAMA_URL=http://ollama:11434
PENTESTIQ_AI_MODEL=${AI_MODEL}
ENV
  chmod 600 "$ENV_FILE" 2>/dev/null || true
  ok "Secrets generated."
}

set_ai_env() {
  [ -f "$ENV_FILE" ] || return 0
  if grep -q '^PENTESTIQ_AI=' "$ENV_FILE"; then
    sed -i.bak "s/^PENTESTIQ_AI=.*/PENTESTIQ_AI=${AI_CHOICE:-0}/" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
  else
    printf "PENTESTIQ_AI=%s\nOLLAMA_URL=http://ollama:11434\nPENTESTIQ_AI_MODEL=%s\n" "${AI_CHOICE:-0}" "$AI_MODEL" >> "$ENV_FILE"
  fi
}

# ----------------------------------------------------------------------------- docker engine
registry_reachable() { # can the daemon actually pull? also warms the base image cache.
  log "Checking image-registry reachability…"
  if timeout 90 $SUDO docker pull python:3.11-slim >/dev/null 2>&1; then ok "Registry reachable (base image ready)."; return 0; fi
  warn "Docker cannot reach the image registry."; return 1
}

dns_selfheal() { # best-effort: make the Docker daemon resolve the registry (Linux only)
  [ "${OSKIND:-linux}" = "linux" ] || return 1
  log "Attempting to repair Docker DNS (public resolvers)…"
  # 1) container-side DNS
  $SUDO mkdir -p /etc/docker 2>/dev/null || true
  if [ ! -f /etc/docker/daemon.json ]; then
    printf '{ "dns": ["8.8.8.8", "1.1.1.1"] }\n' | $SUDO tee /etc/docker/daemon.json >/dev/null 2>&1 || true
  fi
  # 2) systemd-resolved upstream (if present)
  if command -v systemctl >/dev/null 2>&1 && [ -d /etc/systemd ]; then
    $SUDO mkdir -p /etc/systemd/resolved.conf.d 2>/dev/null || true
    printf '[Resolve]\nDNS=8.8.8.8 1.1.1.1\nFallbackDNS=1.0.0.1 8.8.4.4\n' | $SUDO tee /etc/systemd/resolved.conf.d/corvex-dns.conf >/dev/null 2>&1 || true
    $SUDO systemctl restart systemd-resolved >/dev/null 2>&1 || true
  fi
  # 3) daemon-side resolver: append a public nameserver to resolv.conf when it's a
  #    plain file that lacks one (daemon reads this for registry pulls).
  if [ -f /etc/resolv.conf ] && [ ! -L /etc/resolv.conf ] \
     && ! grep -qE '127\.0\.0\.53' /etc/resolv.conf \
     && ! grep -qE 'nameserver[[:space:]]+(8\.8\.8\.8|1\.1\.1\.1)' /etc/resolv.conf; then
    $SUDO cp /etc/resolv.conf /etc/resolv.conf.corvex.bak 2>/dev/null || true
    printf 'nameserver 1.1.1.1\nnameserver 8.8.8.8\n' | $SUDO tee -a /etc/resolv.conf >/dev/null 2>&1 || true
  fi
  # restart docker so it re-reads resolvers
  if command -v systemctl >/dev/null 2>&1; then $SUDO systemctl restart docker >/dev/null 2>&1 || true
  else $SUDO service docker restart >/dev/null 2>&1 || true; fi
  for _ in $(seq 1 10); do $SUDO docker info >/dev/null 2>&1 && break; sleep 2; done
}

deploy_docker() { # returns 0 on a started stack
  [ -f "$COMPOSE_FILE" ] || { warn "compose file not found: $COMPOSE_FILE"; return 1; }
  log "Building and starting the Docker stack (first run can take a few minutes)…"
  local profile=""; [ "${AI_CHOICE:-0}" = "1" ] && profile="--profile ai" && log "AI layer enabled — the local AI runtime will start too."
  $SUDO env DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 ${DC_BIN:-docker compose} \
    --env-file "$ENV_FILE" -f "$COMPOSE_FILE" $profile up -d --build || { warn "docker compose failed."; return 1; }
  ok "Containers started."
}

try_docker() { # orchestrates the whole Docker path; 0 = success, 1 = fall back
  install_docker  || return 1
  start_docker    || return 1
  ensure_compose  || return 1
  write_env
  set_ai_env
  if ! registry_reachable; then
    dns_selfheal
    registry_reachable || { warn "Registry still unreachable after DNS repair."; return 1; }
  fi
  deploy_docker   || return 1
  return 0
}

# ----------------------------------------------------------------------------- native engine (no Docker)
py_bin() { command -v python3 2>/dev/null || command -v python 2>/dev/null || true; }

ensure_python() { # ensure a python3 >=3.10 with venv support; returns 0/1
  local py; py="$(py_bin)"
  if [ -z "$py" ]; then
    log "Installing Python…"
    case "$FAMILY" in
      apt) pkg_install python3 python3-venv python3-pip;;
      dnf) pkg_install python3 python3-pip;;
      pacman) pkg_install python python-pip;;
      zypper) pkg_install python3 python3-pip;;
      brew) pkg_install python@3.12;;
    esac
    py="$(py_bin)"
  fi
  [ -n "$py" ] || { warn "Python 3 is required for the native install but could not be installed."; return 1; }
  if ! "$py" -c 'import sys; raise SystemExit(0 if sys.version_info[:2] >= (3,10) else 1)' 2>/dev/null; then
    warn "Python >= 3.10 is required (found $("$py" -V 2>&1)). Install a newer Python and re-run."; return 1
  fi
  # ensure venv works (Debian/Kali split it into python3-venv)
  if ! "$py" -m venv --help >/dev/null 2>&1; then
    [ "$FAMILY" = "apt" ] && pkg_install python3-venv python3-full
  fi
  PY="$py"; return 0
}

deploy_native() { # returns 0 on a running server
  log "Using the native install (Python venv + pip) — no Docker required."
  ensure_python || return 1
  # a few optional system tools improve coverage; never fatal if missing
  case "$FAMILY" in
    apt)    pkg_install nmap;;
    dnf)    pkg_install nmap;;
    pacman) pkg_install nmap;;
    zypper) pkg_install nmap;;
    brew)   pkg_install nmap;;
  esac
  if [ ! -x "$VENV_DIR/bin/python" ]; then
    log "Creating virtual environment → $VENV_DIR"
    "$PY" -m venv "$VENV_DIR" || { warn "could not create venv"; return 1; }
  fi
  local vpip="$VENV_DIR/bin/pip" vpy="$VENV_DIR/bin/python"
  log "Resolving & installing Python dependencies (from PyPI)…"
  "$vpy" -m pip install -q --upgrade pip setuptools wheel >/dev/null 2>&1 || true
  # core set (present in every edition). AI confidence model + SPA browser are
  # added best-effort below so this never fails on an edition that lacks them.
  if ! ( cd "$REPO_DIR" && "$vpip" install -q -e ".[api,reports]" ); then
    warn "pip install failed — is PyPI reachable from this host?"; return 1
  fi
  "$vpip" install -q scikit-learn >/dev/null 2>&1 || true                                   # self-learning model
  "$vpip" install -q playwright >/dev/null 2>&1 && "$VENV_DIR/bin/playwright" install chromium >/dev/null 2>&1 || true  # SPA crawl
  ok "Dependencies installed."

  write_env
  # the app keeps its DB under ./data relative to its working dir — launch from
  # REPO_DIR so that is deterministic (REPO_DIR/data, which is gitignored).
  local secret; secret="$(grep -E '^PENTESTIQ_SECRET_KEY=' "$ENV_FILE" 2>/dev/null | cut -d= -f2-)"

  # stop a previous native instance, if any
  if [ -f "$NATIVE_PID" ] && kill -0 "$(cat "$NATIVE_PID" 2>/dev/null)" 2>/dev/null; then
    kill "$(cat "$NATIVE_PID")" 2>/dev/null || true; sleep 1
  fi
  log "Starting the console on port ${PORT}…"
  ( cd "$REPO_DIR" && PENTESTIQ_SECRET_KEY="$secret" PENTESTIQ_AI="${AI_CHOICE:-0}" \
      nohup "$VENV_DIR/bin/corvex" serve --host 0.0.0.0 --port "$PORT" >"$NATIVE_LOG" 2>&1 &
    echo $! > "$NATIVE_PID" )
  ENGINE_USED="native"
  return 0
}

# ----------------------------------------------------------------------------- health + summary
wait_healthy() { # polls /health; returns 0 if up, 1 on timeout (non-fatal)
  log "Waiting for the Corvex-RedOps API to become healthy…"
  for _ in $(seq 1 40); do
    if curl -fsS "http://localhost:${PORT}/health" >/dev/null 2>&1; then ok "Corvex-RedOps is up."; return 0; fi
    sleep 3
  done
  return 1
}

admin_password_hint() {
  # both engines log a one-time admin password on first boot
  if [ "${ENGINE_USED:-docker}" = "native" ]; then
    local p; p="$(grep -aoiE 'password:[[:space:]]*[^[:space:]]+' "$NATIVE_LOG" 2>/dev/null | tail -1)"
    [ -n "$p" ] && printf "  Admin login : ${c_dim}user 'admin' — %s${c_off}\n" "$p" \
                || printf "  Admin login : ${c_dim}user 'admin' — one-time password printed in %s (grep 'first-run admin')${c_off}\n" "$NATIVE_LOG"
  else
    printf "    read it:  ${c_dim}%s --env-file %s -f %s logs %s 2>&1 | grep -A3 'first-run admin'${c_off}\n" "$DC" "$ENV_FILE" "$COMPOSE_FILE" "pentestiq"
  fi
}

summary() {
  local ip="localhost"
  if [ "${OSKIND:-linux}" = "macos" ]; then
    ip="$(ipconfig getifaddr en0 2>/dev/null || ipconfig getifaddr en1 2>/dev/null || true)"
  else
    ip="$( { hostname -I 2>/dev/null || true; } | awk '{print $1}')"
  fi
  [ -n "$ip" ] || ip="localhost"
  printf "\n${c_grn}════════════════════════════════════════════════════════════${c_off}\n"
  printf "  ${c_grn}✔ Corvex-RedOps is deployed.${c_off}  ${c_dim}(engine: %s)${c_off}\n" "${ENGINE_USED:-docker}"
  printf "${c_grn}════════════════════════════════════════════════════════════${c_off}\n"
  printf "  Web console : ${c_blue}http://localhost:%s${c_off}   (or http://%s:%s)\n" "$PORT" "$ip" "$PORT"
  printf "  API docs    : ${c_blue}http://localhost:%s/docs${c_off}\n" "$PORT"
  if [ "${ENGINE_USED:-docker}" = "docker" ]; then
    if [ "${AI_CHOICE:-0}" = "1" ]; then
      printf "  AI layer    : ${c_grn}enabled${c_off} — model ${c_blue}%s${c_off} (http://localhost:11434)\n" "$AI_MODEL"
    else
      printf "  AI layer    : ${c_dim}disabled (re-run with --ai to enable)${c_off}\n"
    fi
  else
    printf "  AI layer    : ${c_dim}native mode — the self-learning model is installed; the local LLM needs Docker (--ai)${c_off}\n"
  fi
  printf "\n  Sign in as ${c_blue}admin${c_off}:\n"
  admin_password_hint
  printf "\n  Manage:\n"
  if [ "${ENGINE_USED:-docker}" = "docker" ]; then
    printf "    logs : ${c_dim}%s --env-file %s -f %s logs -f${c_off}\n" "$DC" "$ENV_FILE" "$COMPOSE_FILE"
  else
    printf "    logs : ${c_dim}tail -f %s${c_off}\n" "$NATIVE_LOG"
  fi
  printf "    stop : ${c_dim}sudo ./install.sh --down${c_off}\n"
  printf "${c_grn}════════════════════════════════════════════════════════════${c_off}\n\n"
}

stop_all() {
  # native
  if [ -f "$NATIVE_PID" ] && kill -0 "$(cat "$NATIVE_PID" 2>/dev/null)" 2>/dev/null; then
    log "Stopping native server…"; kill "$(cat "$NATIVE_PID")" 2>/dev/null || true; rm -f "$NATIVE_PID"; ok "Native server stopped."
  fi
  # docker
  if command -v docker >/dev/null 2>&1 && [ -f "$COMPOSE_FILE" ]; then
    ensure_compose >/dev/null 2>&1 || DC="$SUDO docker compose"
    [ -f "$ENV_FILE" ] || printf "MOBSF_API_KEY=x\nPENTESTIQ_SECRET_KEY=x\n" > "$ENV_FILE"
    log "Stopping Docker stack…"; $DC --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down >/dev/null 2>&1 && ok "Docker stack stopped." || true
  fi
}

# ----------------------------------------------------------------------------- main
main() {
  # macOS + Colima is per-user: if run with sudo, re-exec as the invoking user.
  if [ "$(uname -s)" = "Darwin" ] && [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    printf "[Corvex-RedOps] macOS uses Colima (per-user Docker) — re-running as %s…\n" "${SUDO_USER}"
    exec sudo -u "${SUDO_USER}" -H "$0" "$@"
  fi
  printf "${c_blue}"; cat <<'BANNER'
 ____ ___  ______     _________  __
 / ___/ _ \|  _ \ \   / / ____\ \/ /
| |  | | | | |_) \ \ / /|  _|  \  /
| |__| |_| |  _ < \ V / | |___ /  \
 \____\___/|_| \_\ \_/  |_____/_/\_\   RedOps · one-command deploy
BANNER
  printf "${c_off}\n"
  detect_distro

  if [ "$ACTION" = "down" ]; then stop_all; exit 0; fi

  install_base

  case "$ENGINE" in
    docker)
      if try_docker; then ENGINE_USED="docker"; wait_healthy || warn "health check timed out — the stack may still be warming up."; summary; exit 0; fi
      die "Docker install failed and --docker was forced (no fallback). Re-run without --docker to use the native fallback."
      ;;
    native)
      deploy_native || die "native install failed. Check that Python 3.10+ and PyPI are reachable."
      wait_healthy || warn "health check timed out — check: tail -f $NATIVE_LOG"
      summary; exit 0
      ;;
    auto|*)
      if try_docker; then
        ENGINE_USED="docker"
        wait_healthy || warn "health check timed out — the stack may still be warming up."
        summary; exit 0
      fi
      warn "Docker path unavailable — automatically falling back to the native install (no Docker needed)."
      if deploy_native; then
        wait_healthy || warn "health check timed out — check: tail -f $NATIVE_LOG"
        summary; exit 0
      fi
      die "Both the Docker and native installs failed. Ensure either Docker, or Python 3.10+ with PyPI access, is available."
      ;;
  esac
}
main "$@"

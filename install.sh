#!/usr/bin/env bash
#
# PentestIQ — one-command installer & deployer
# ---------------------------------------------
# Detects your OS (Linux distro or macOS), installs all prerequisites (Docker,
# Docker Compose, git/curl/openssl), generates secrets, and deploys the full
# SaaS stack (PentestIQ API + web console + MobSF) with a single command.
#
#   sudo ./install.sh              # install prerequisites + deploy
#   sudo ./install.sh --port 9090  # use a custom console port
#   sudo ./install.sh --down       # stop the stack
#   sudo ./install.sh --update      # rebuild & redeploy (git pull first, yourself)
#   ./install.sh --help
#
set -Eeuo pipefail

# ----------------------------------------------------------------------------- ui
c_blue='\033[1;34m'; c_grn='\033[1;32m'; c_yel='\033[1;33m'; c_red='\033[1;31m'; c_dim='\033[2m'; c_off='\033[0m'
log()  { printf "${c_blue}[PentestIQ]${c_off} %s\n" "$*"; }
ok()   { printf "${c_grn}[ ok ]${c_off} %s\n" "$*"; }
warn() { printf "${c_yel}[warn]${c_off} %s\n" "$*"; }
err()  { printf "${c_red}[fail]${c_off} %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }
trap 'code=$?; err "install aborted at line ${LINENO} (exit ${code})."; exit ${code}' ERR

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$REPO_DIR/deploy/docker-compose.yml"
ENV_FILE="$REPO_DIR/deploy/.env"
PORT="8080"
ACTION="up"
AI_CHOICE=""            # ""=ask, 1=yes, 0=no
AI_MODEL="${PENTESTIQ_AI_MODEL:-qwen2.5:7b-instruct}"

usage() {
  cat <<'HELP'
PentestIQ - one-command installer & deployer

Detects your OS (Linux distro or macOS), installs prerequisites (Docker via
the distro / Colima, git/openssl), generates secrets, and deploys the full
SaaS stack (PentestIQ API + web console + MobSF).

Usage:
  sudo ./install.sh              install prerequisites + deploy
  sudo ./install.sh --port 9090  deploy on a custom console port
  sudo ./install.sh --ai         deploy WITH the local AI layer (Ollama)
  sudo ./install.sh --no-ai      deploy without AI (skip the prompt)
  sudo ./install.sh --update     rebuild & redeploy (after a git pull)
  sudo ./install.sh --down       stop the stack
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
    --update) ACTION="update"; shift;;
    -h|--help) usage;;
    *) die "unknown option: $1 (try --help)";;
  esac
done

# ----------------------------------------------------------------------------- sudo
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else
    die "run as root, or install sudo first"; fi
fi

# ----------------------------------------------------------------------------- distro
detect_distro() {
  if [ "$(uname -s)" = "Darwin" ]; then
    OSKIND="macos"; FAMILY="brew"; SUDO=""
    DISTRO_NAME="macOS $(sw_vers -productVersion 2>/dev/null || echo '')"
    log "Detected: ${DISTRO_NAME}  (package manager: Homebrew)"
    command -v brew >/dev/null 2>&1 || die "Homebrew is required on macOS — install it from https://brew.sh then re-run."
    return 0
  fi
  OSKIND="linux"
  [ -r /etc/os-release ] || die "cannot detect distro (/etc/os-release missing)"
  # shellcheck disable=SC1091
  . /etc/os-release
  DISTRO_ID="${ID:-unknown}"; DISTRO_LIKE="${ID_LIKE:-}"; DISTRO_NAME="${PRETTY_NAME:-$DISTRO_ID}"
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
  if [ "$FAMILY" = "unknown" ]; then
    die "unsupported distro '${DISTRO_ID}'. Install Docker + Compose manually, then run: $SUDO docker compose -f deploy/docker-compose.yml up -d --build"
  fi
}

# ----------------------------------------------------------------------------- prerequisites
install_base() {
  log "Installing base prerequisites (curl, git, openssl)…"
  case "$FAMILY" in
    brew)   brew list git >/dev/null 2>&1 || brew install git;
            brew list openssl >/dev/null 2>&1 || brew install openssl;;
    apt)    apt_fix_docker_repo
            $SUDO apt-get update -y -qq || { apt_fix_docker_repo; $SUDO apt-get update -y -qq || true; }
            $SUDO apt-get install -y -qq ca-certificates curl git openssl gnupg lsb-release;;
    dnf)    $SUDO dnf install -y -q ca-certificates curl git openssl;;
    pacman) $SUDO pacman -Sy --noconfirm --needed curl git openssl ca-certificates;;
    zypper) $SUDO zypper --non-interactive --quiet install curl git openssl ca-certificates;;
  esac
  ok "Base prerequisites installed."
}

apt_fix_docker_repo() {
  # A prior failed get.docker.com run can leave a Docker apt source pinned to a
  # release Docker does not publish (e.g. Kali's kali-rolling), which then breaks
  # every apt-get update. We install distro docker.io, so drop that source.
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

install_docker() {
  if [ "${OSKIND:-linux}" = "macos" ]; then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then
      ok "Docker already available ($(docker --version 2>/dev/null | cut -d, -f1))."; return
    fi
    # scriptable Docker on macOS without the Desktop GUI, via Colima
    brew list colima >/dev/null 2>&1 || brew install colima
    brew list docker  >/dev/null 2>&1 || brew install docker
    brew list docker-compose >/dev/null 2>&1 || brew install docker-compose
    ok "Docker (Colima) installed."
    return
  fi
  if command -v docker >/dev/null 2>&1; then ok "Docker already installed ($(docker --version 2>/dev/null | cut -d, -f1))."; return; fi
  log "Installing Docker Engine…"
  # Prefer the distribution's own Docker package — reliable on Debian/Ubuntu/Kali/
  # Parrot/Mint/Fedora and free of third-party-repo breakage. Fall back to Docker's
  # convenience script only if the distro package isn't available.
  case "$FAMILY" in
    apt)    apt_fix_docker_repo
            $SUDO apt-get install -y -qq docker.io docker-compose-v2 2>/dev/null \
              || $SUDO apt-get install -y -qq docker.io 2>/dev/null \
              || docker_convenience_script;;
    dnf)    $SUDO dnf install -y -q docker docker-compose-plugin 2>/dev/null \
              || $SUDO dnf install -y -q docker 2>/dev/null \
              || $SUDO dnf install -y -q moby-engine 2>/dev/null \
              || docker_convenience_script;;
    pacman) $SUDO pacman -Sy --noconfirm --needed docker docker-compose 2>/dev/null || docker_convenience_script;;
    zypper) $SUDO zypper --non-interactive install docker docker-compose 2>/dev/null || docker_convenience_script;;
    *)      docker_convenience_script;;
  esac
  command -v docker >/dev/null 2>&1 || die "Docker installation failed. Install Docker manually and re-run."
  ok "Docker installed ($(docker --version 2>/dev/null | cut -d, -f1))."
  # let the invoking (non-root) user run docker without sudo after re-login
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    $SUDO groupadd -f docker >/dev/null 2>&1 || true
    $SUDO usermod -aG docker "${SUDO_USER}" >/dev/null 2>&1 \
      && log "Added ${SUDO_USER} to the 'docker' group (effective after next login)."
  fi
}

start_docker() {
  if [ "${OSKIND:-linux}" = "macos" ]; then
    if docker info >/dev/null 2>&1; then ok "Docker daemon is running."; return; fi
    log "Starting Colima (Docker runtime)…"
    colima status >/dev/null 2>&1 || colima start >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do docker info >/dev/null 2>&1 && { ok "Docker daemon is running."; return; }; sleep 2; done
    die "Docker daemon did not start. Try: colima start   (or open Docker Desktop)."
  fi
  if command -v systemctl >/dev/null 2>&1; then
    $SUDO systemctl enable --now docker >/dev/null 2>&1 || $SUDO systemctl start docker >/dev/null 2>&1 || true
  else
    $SUDO service docker start >/dev/null 2>&1 || true
  fi
  # wait for the daemon
  for _ in $(seq 1 15); do $SUDO docker info >/dev/null 2>&1 && { ok "Docker daemon is running."; return; }; sleep 2; done
  die "Docker daemon did not start. Check: $SUDO systemctl status docker"
}

ensure_compose() {
  if $SUDO docker compose version >/dev/null 2>&1; then DC="$SUDO docker compose"; DC_BIN="docker compose"; ok "Docker Compose v2 available."; return; fi
  if command -v docker-compose >/dev/null 2>&1; then DC="$SUDO docker-compose"; DC_BIN="docker-compose"; ok "docker-compose (v1) available."; return; fi
  log "Installing the Docker Compose plugin…"
  local ver="v2.29.7" arch dest
  case "$(uname -m)" in x86_64) arch=x86_64;; aarch64|arm64) arch=aarch64;; armv7l) arch=armv7;; *) arch="$(uname -m)";; esac
  dest="/usr/local/lib/docker/cli-plugins"
  $SUDO mkdir -p "$dest"
  $SUDO curl -fsSL "https://github.com/docker/compose/releases/download/${ver}/docker-compose-linux-${arch}" -o "$dest/docker-compose"
  $SUDO chmod +x "$dest/docker-compose"
  $SUDO docker compose version >/dev/null 2>&1 && { DC="$SUDO docker compose"; DC_BIN="docker compose"; } || die "Docker Compose install failed."
  ok "Docker Compose plugin installed."
}

# ----------------------------------------------------------------------------- secrets
gen_secret() { openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
ask_ai() {
  # honor flags / existing choice / non-interactive
  if [ -n "$AI_CHOICE" ]; then return; fi
  if [ -f "$ENV_FILE" ] && grep -q '^PENTESTIQ_AI=1' "$ENV_FILE" 2>/dev/null; then AI_CHOICE=1; return; fi
  if [ ! -t 0 ]; then AI_CHOICE=0; log "Non-interactive shell — installing without AI (use --ai to enable)."; return; fi
  printf "\n${c_blue}[PentestIQ]${c_off} Optional AI layer (local, self-hosted Ollama model).\n"
  printf "${c_dim}  It adds AI-written findings, attack-chain correlation, a false-positive\n"
  printf "  verifier, an in-console copilot, and a self-learning confidence model.\n"
  printf "  ${c_yel}Requires a high-spec workstation/lab: 8+ CPU cores, 16 GB+ RAM (GPU\n"
  printf "  optional), plus a ~5 GB one-time model download.${c_off}${c_dim} Everything runs locally;\n"
  printf "  no data leaves the host. You can enable it later with --ai.${c_off}\n"
  printf "${c_blue}Do you want to install / integrate AI? [y/N]:${c_off} "
  read -r _ans || _ans=""
  case "$_ans" in [Yy]*) AI_CHOICE=1;; *) AI_CHOICE=0;; esac
}

wait_ollama() {
  log "Waiting for the local AI service (Ollama) to become ready…"
  for _ in $(seq 1 40); do
    if curl -fsS "http://localhost:11434/api/tags" >/dev/null 2>&1; then ok "Ollama is up."; return 0; fi
    sleep 3
  done
  warn "Ollama did not become ready in time — you can pull the model later with:"
  warn "  $SUDO docker exec -it pentestiq-ollama ollama pull $AI_MODEL"
  return 1
}

pull_model() {
  log "Pulling the AI model '$AI_MODEL' (~5 GB, one-time)… this can take a while."
  if $SUDO docker exec pentestiq-ollama ollama pull "$AI_MODEL"; then
    ok "AI model ready: $AI_MODEL"
  else
    warn "Model pull failed — retry later with: $SUDO docker exec -it pentestiq-ollama ollama pull $AI_MODEL"
  fi
}

write_env() {
  mkdir -p "$(dirname "$ENV_FILE")"
  if [ -f "$ENV_FILE" ]; then ok "Reusing existing secrets ($ENV_FILE)."; return; fi
  log "Generating secrets → $ENV_FILE"
  cat > "$ENV_FILE" <<ENV
# PentestIQ deployment secrets — generated by install.sh. Keep private; do not commit.
MOBSF_API_KEY=$(gen_secret)
PENTESTIQ_SECRET_KEY=$(gen_secret)
PENTESTIQ_PORT=${PORT}
PENTESTIQ_AI=${AI_CHOICE:-0}
OLLAMA_URL=http://ollama:11434
PENTESTIQ_AI_MODEL=${AI_MODEL}
ENV
  chmod 600 "$ENV_FILE"
  ok "Secrets generated."
}

set_ai_env() {
  # keep PENTESTIQ_AI in an existing .env in sync with the chosen option
  [ -f "$ENV_FILE" ] || return 0
  if grep -q '^PENTESTIQ_AI=' "$ENV_FILE"; then
    sed -i.bak "s/^PENTESTIQ_AI=.*/PENTESTIQ_AI=${AI_CHOICE:-0}/" "$ENV_FILE" && rm -f "$ENV_FILE.bak"
  else
    printf "PENTESTIQ_AI=%s\nOLLAMA_URL=http://ollama:11434\nPENTESTIQ_AI_MODEL=%s\n" "${AI_CHOICE:-0}" "$AI_MODEL" >> "$ENV_FILE"
  fi
}

# ----------------------------------------------------------------------------- deploy
deploy() {
  [ -f "$COMPOSE_FILE" ] || die "compose file not found: $COMPOSE_FILE (run this from the PentestIQ repo)"
  log "Building and starting the stack (this can take a few minutes on first run)…"
  # Pre-pull the base image via the daemon (reliable), then build with the LEGACY
  # builder. BuildKit uses a separate DNS resolver that some VM / corporate DNS
  # setups can't use to reach the registry (auth.docker.io), even when the daemon
  # itself resolves fine; the legacy builder shares the daemon's networking.
  $SUDO docker pull python:3.11-slim >/dev/null 2>&1 || true
  local profile=""; [ "${AI_CHOICE:-0}" = "1" ] && profile="--profile ai" && log "AI layer enabled — the Ollama service will start too."
  $SUDO env DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 ${DC_BIN:-docker compose} \
    --env-file "$ENV_FILE" -f "$COMPOSE_FILE" $profile up -d --build
  ok "Containers started."
}

wait_healthy() {
  log "Waiting for the PentestIQ API to become healthy…"
  for _ in $(seq 1 40); do
    if curl -fsS "http://localhost:${PORT}/health" >/dev/null 2>&1; then ok "PentestIQ is up."; return 0; fi
    sleep 3
  done
  warn "API health check timed out — it may still be starting. Check logs: $DC -f \"$COMPOSE_FILE\" logs -f pentestiq"
}

summary() {
  local ip="localhost"
  if [ "${OSKIND:-linux}" = "macos" ]; then
    ip="$(ipconfig getifaddr en0 2>/dev/null)" || ip="localhost"
  else
    ip="$(hostname -I 2>/dev/null | awk '{print $1}')" || ip="localhost"
  fi
  [ -n "$ip" ] || ip="localhost"
  printf "\n${c_grn}════════════════════════════════════════════════════════════${c_off}\n"
  printf "  ${c_grn}✔ PentestIQ is deployed.${c_off}\n"
  printf "${c_grn}════════════════════════════════════════════════════════════${c_off}\n"
  printf "  Web console : ${c_blue}http://localhost:%s${c_off}   (or http://%s:%s)\n" "$PORT" "$ip" "$PORT"
  printf "  API docs    : ${c_blue}http://localhost:%s/docs${c_off}\n" "$PORT"
  printf "  MobSF       : http://localhost:8000  ${c_dim}(mobile analysis engine)${c_off}\n"
  if [ "${AI_CHOICE:-0}" = "1" ]; then
    printf "  AI layer    : ${c_grn}enabled${c_off} — local model ${c_blue}%s${c_off} via Ollama (http://localhost:11434)\n" "$AI_MODEL"
  else
    printf "  AI layer    : ${c_dim}disabled (re-run with --ai to enable)${c_off}\n"
  fi
  printf "\n  Next steps:\n"
  printf "    1) Open the console and sign in with ${c_blue}pentestiq${c_off} / ${c_blue}p3nt3st!q${c_off} (change the password after first login).\n"
  printf "    2) Create a scan from ${c_blue}New scan${c_off}, or upload an app / API spec, then Run scan.\n"
  printf "\n  Manage:\n"
  printf "    logs   : ${c_dim}%s --env-file %s -f %s logs -f${c_off}\n" "$DC" "$ENV_FILE" "$COMPOSE_FILE"
  printf "    stop   : ${c_dim}sudo ./install.sh --down${c_off}\n"
  printf "    secrets: ${c_dim}%s${c_off}\n" "$ENV_FILE"
  printf "${c_grn}════════════════════════════════════════════════════════════${c_off}\n\n"
}

# ----------------------------------------------------------------------------- main
main() {
  printf "${c_blue}"; cat <<'BANNER'
  ____            _            _   ___ ___
 |  _ \ ___ _ __ | |_ ___  ___| |_|_ _/ _ \
 | |_) / _ \ '_ \| __/ _ \/ __| __|| | | | |
 |  __/  __/ | | | ||  __/\__ \ |_ | | |_| |
 |_|   \___|_| |_|\__\___||___/\__|___\__\_\   one-command deploy
BANNER
  printf "${c_off}\n"
  detect_distro

  if [ "$ACTION" = "down" ]; then
    ensure_compose 2>/dev/null || DC="$SUDO docker compose"
    [ -f "$ENV_FILE" ] || printf "MOBSF_API_KEY=x\nPENTESTIQ_SECRET_KEY=x\n" > "$ENV_FILE"
    log "Stopping the stack…"; $DC --env-file "$ENV_FILE" -f "$COMPOSE_FILE" down; ok "Stopped."; exit 0
  fi

  if [ "$ACTION" = "update" ]; then
    log "Update mode: rebuilding and redeploying (skipping prerequisite install)."
    ensure_compose
    ask_ai
    write_env
    set_ai_env
    deploy
    wait_healthy
    if [ "${AI_CHOICE:-0}" = "1" ]; then wait_ollama && pull_model; fi
    summary || true
    exit 0
  fi

  install_base
  install_docker
  start_docker
  ensure_compose
  ask_ai
  write_env
  set_ai_env
  deploy
  wait_healthy
  if [ "${AI_CHOICE:-0}" = "1" ]; then wait_ollama && pull_model; fi
  summary || true
}
main "$@"

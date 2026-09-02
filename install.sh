#!/usr/bin/env bash
#
# PentestIQ — one-command installer & deployer
# ---------------------------------------------
# Detects your Linux distribution, installs all prerequisites (Docker Engine,
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

usage() {
  cat <<'HELP'
PentestIQ - one-command installer & deployer

Detects your Linux distribution, installs prerequisites (Docker Engine,
Docker Compose, git/curl/openssl), generates secrets, and deploys the full
SaaS stack (PentestIQ API + web console + MobSF).

Usage:
  sudo ./install.sh              install prerequisites + deploy
  sudo ./install.sh --port 9090  deploy on a custom console port
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
    apt)    $SUDO apt-get update -y -qq
            $SUDO apt-get install -y -qq ca-certificates curl git openssl gnupg lsb-release;;
    dnf)    $SUDO dnf install -y -q ca-certificates curl git openssl;;
    pacman) $SUDO pacman -Sy --noconfirm --needed curl git openssl ca-certificates;;
    zypper) $SUDO zypper --non-interactive --quiet install curl git openssl ca-certificates;;
  esac
  ok "Base prerequisites installed."
}

install_docker() {
  if command -v docker >/dev/null 2>&1; then ok "Docker already installed ($(docker --version 2>/dev/null | cut -d, -f1))."; return; fi
  log "Installing Docker Engine…"
  # Docker's official convenience script covers Ubuntu/Debian/Fedora/CentOS/RHEL/etc.
  if curl -fsSL https://get.docker.com -o /tmp/ptiq-get-docker.sh 2>/dev/null && \
     $SUDO sh /tmp/ptiq-get-docker.sh >/dev/null 2>&1 && command -v docker >/dev/null 2>&1; then
    ok "Docker installed via get.docker.com."
  else
    warn "convenience script unavailable — using distribution packages."
    case "$FAMILY" in
      apt)    $SUDO apt-get update -y -qq
              # docker.io ships the engine; docker-compose-v2 (Kali/Debian/Ubuntu) ships the plugin
              $SUDO apt-get install -y -qq docker.io docker-compose-v2 2>/dev/null \
                || $SUDO apt-get install -y -qq docker.io;;
      dnf)    $SUDO dnf install -y -q docker docker-compose-plugin 2>/dev/null \
                || $SUDO dnf install -y -q docker \
                || $SUDO dnf install -y -q moby-engine;;
      pacman) $SUDO pacman -Sy --noconfirm --needed docker docker-compose;;
      zypper) $SUDO zypper --non-interactive install docker docker-compose;;
    esac
  fi
  command -v docker >/dev/null 2>&1 || die "Docker installation failed. Install it manually and re-run."
  ok "Docker installed ($(docker --version 2>/dev/null | cut -d, -f1))."
  # let the invoking (non-root) user run docker without sudo after re-login
  if [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    $SUDO groupadd -f docker >/dev/null 2>&1 || true
    $SUDO usermod -aG docker "${SUDO_USER}" >/dev/null 2>&1 \
      && log "Added ${SUDO_USER} to the 'docker' group (effective after next login)."
  fi
}

start_docker() {
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
  if $SUDO docker compose version >/dev/null 2>&1; then DC="$SUDO docker compose"; ok "Docker Compose v2 available."; return; fi
  if command -v docker-compose >/dev/null 2>&1; then DC="$SUDO docker-compose"; ok "docker-compose (v1) available."; return; fi
  log "Installing the Docker Compose plugin…"
  local ver="v2.29.7" arch dest
  case "$(uname -m)" in x86_64) arch=x86_64;; aarch64|arm64) arch=aarch64;; armv7l) arch=armv7;; *) arch="$(uname -m)";; esac
  dest="/usr/local/lib/docker/cli-plugins"
  $SUDO mkdir -p "$dest"
  $SUDO curl -fsSL "https://github.com/docker/compose/releases/download/${ver}/docker-compose-linux-${arch}" -o "$dest/docker-compose"
  $SUDO chmod +x "$dest/docker-compose"
  $SUDO docker compose version >/dev/null 2>&1 && DC="$SUDO docker compose" || die "Docker Compose install failed."
  ok "Docker Compose plugin installed."
}

# ----------------------------------------------------------------------------- secrets
gen_secret() { openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
write_env() {
  mkdir -p "$(dirname "$ENV_FILE")"
  if [ -f "$ENV_FILE" ]; then ok "Reusing existing secrets ($ENV_FILE)."; return; fi
  log "Generating secrets → $ENV_FILE"
  cat > "$ENV_FILE" <<ENV
# PentestIQ deployment secrets — generated by install.sh. Keep private; do not commit.
MOBSF_API_KEY=$(gen_secret)
PENTESTIQ_SECRET_KEY=$(gen_secret)
PENTESTIQ_PORT=${PORT}
ENV
  chmod 600 "$ENV_FILE"
  ok "Secrets generated."
}

# ----------------------------------------------------------------------------- deploy
deploy() {
  [ -f "$COMPOSE_FILE" ] || die "compose file not found: $COMPOSE_FILE (run this from the PentestIQ repo)"
  log "Building and starting the stack (this can take a few minutes on first run)…"
  $DC --env-file "$ENV_FILE" -f "$COMPOSE_FILE" up -d --build
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
  local ip; ip="$(hostname -I 2>/dev/null | awk '{print $1}')"; ip="${ip:-<server-ip>}"
  printf "\n${c_grn}════════════════════════════════════════════════════════════${c_off}\n"
  printf "  ${c_grn}✔ PentestIQ is deployed.${c_off}\n"
  printf "${c_grn}════════════════════════════════════════════════════════════${c_off}\n"
  printf "  Web console : ${c_blue}http://localhost:%s${c_off}   (or http://%s:%s)\n" "$PORT" "$ip" "$PORT"
  printf "  API docs    : ${c_blue}http://localhost:%s/docs${c_off}\n" "$PORT"
  printf "  MobSF       : http://localhost:8000  ${c_dim}(mobile analysis engine)${c_off}\n"
  printf "\n  Next steps:\n"
  printf "    1) Open the console and click ${c_blue}Register${c_off} to create your first tenant + owner.\n"
  printf "    2) Or from the CLI (inside the container):\n"
  printf "       ${c_dim}%s -f %s exec pentestiq pentestiq init-tenant --tenant Acme --username you --password 'ChangeMe123'${c_off}\n" "$DC" "$COMPOSE_FILE"
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
    write_env
    deploy
    wait_healthy
    summary
    exit 0
  fi

  install_base
  install_docker
  start_docker
  ensure_compose
  write_env
  deploy
  wait_healthy
  summary
}
main "$@"

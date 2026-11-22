#!/usr/bin/env bash
#
# Corvex-RedOps — one-command installer & deployer
# ------------------------------------------------
# ONE command installs everything and brings the console up — on Linux (apt/dnf/pacman/
# zypper) and macOS. It prefers a Docker deployment and falls back to a native install
# (its own Python venv, run as an unprivileged service) when Docker can't be used.
#
# It never fails halfway: a read-only preflight (platform, memory, disk, Docker, every host
# port) runs before anything is changed, and a stack that doesn't come up healthy is taken
# down again before the installer exits.
#
#   sudo ./install.sh                  # install + deploy (auto engine), console on 127.0.0.1:8080
#   sudo ./install.sh --port 9090      # custom console port
#   sudo ./install.sh --listen 0.0.0.0 # reachable from the network (plain HTTP — put TLS in front)
#   sudo ./install.sh --native         # force the native (no-Docker) install
#   sudo ./install.sh --docker         # force the Docker install (no fallback)
#   sudo ./install.sh --down           # stop whatever is running
#   sudo ./install.sh --update         # rebuild/reinstall & redeploy
#   ./install.sh --help
#
# No `set -e` on purpose: the installer must survive a failed step in order to fall back
# and to clean up. Critical steps are checked explicitly.
set -uo pipefail

# ----------------------------------------------------------------------------- ui
if [ -n "${NO_COLOR:-}" ] || [ ! -t 1 ]; then
  c_blue=''; c_grn=''; c_yel=''; c_red=''; c_dim=''; c_off=''
else
  c_blue='\033[1;34m'; c_grn='\033[1;32m'; c_yel='\033[1;33m'; c_red='\033[1;31m'; c_dim='\033[2m'; c_off='\033[0m'
fi
log()  { printf "${c_blue}[Corvex-RedOps]${c_off} %s\n" "$*"; }
ok()   { printf "${c_grn}[ ok ]${c_off} %s\n" "$*"; }
warn() { printf "${c_yel}[warn]${c_off} %s\n" "$*"; }
err()  { printf "${c_red}[fail]${c_off} %s\n" "$*" >&2; }
die()  { err "$*"; exit 1; }

REPO_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
COMPOSE_FILE="$REPO_DIR/deploy/docker-compose.yml"
COMPOSE_MOBILE_FILE="$REPO_DIR/deploy/docker-compose.publish-mobile.yml"
ENV_FILE="$REPO_DIR/deploy/.env"
# Native install (A5): its own venv and data, outside the checkout, run as an unprivileged
# user under systemd. Every path can be overridden (the test suite points them at a temp dir).
NATIVE_USER="${CORVEX_NATIVE_USER:-corvex-redops}"
NATIVE_HOME="${CORVEX_NATIVE_HOME:-/var/lib/corvex-redops}"
NATIVE_PREFIX="${CORVEX_NATIVE_PREFIX:-/opt/corvex-redops}"
NATIVE_ETC="${CORVEX_NATIVE_ETC:-/etc/corvex-redops}"
UNIT_DIR="${CORVEX_UNIT_DIR:-/etc/systemd/system}"
UNIT_NAME="corvex-redops.service"
DOCKER_DROPIN_DIR="${CORVEX_DOCKER_DROPIN_DIR:-/etc/systemd/system/docker.service.d}"
# What 0.2.x native installs used (stopped and migrated on --update, never deleted).
LEGACY_PID="$REPO_DIR/.corvex.pid"
LEGACY_DATA="$REPO_DIR/data"
# Containers this deployment owns (a host port they hold is "ours", not a conflict).
OUR_CONTAINERS="pentestiq-api pentestiq-mobsf pentestiq-ollama"

PORT="8080";  PORT_SET=0
LISTEN="127.0.0.1"; LISTEN_SET=0     # console bind address; 0.0.0.0 is opt-in (--listen)
TRUSTED_PROXY=""                     # extra reverse proxies (--trusted-proxy), added to loopback
PUBLISH_MOBILE=0; MOBILE_PORT="8000"; MOBILE_PORT_SET=0
ACTION="up"
ENGINE="auto"                        # auto | docker | native
AI_CHOICE=""                         # "" = ask (in a terminal), 1 = --ai, 0 = --no-ai
AI_MODEL="${CORVEX_AI_MODEL:-${PENTESTIQ_AI_MODEL:-qwen2.5:7b-instruct}}"   # env override, e.g. a tiny model in CI
# Preflight thresholds (MB). Below MIN the installer stops before changing anything.
MIN_MEM_MB=1024;  REC_MEM_MB=2048
MIN_DISK_DOCKER_MB=8192; MIN_DISK_NATIVE_MB=2048
HEALTH_TRIES="${CORVEX_HEALTH_TRIES:-60}"   # x 3 s
LISTEN_CHANGED_FROM=""; LEGACY_DATA_COPIED=0; ADMIN_PW_CONSUMED=0; STACK_STARTED=""; ENGINE_USED=""
NATIVE_MODE=""; DC_BIN=""; PY=""

usage() {
  cat <<'HELP'
Corvex-RedOps — one-command installer & deployer

Installs everything and brings up the console with a single command. Prefers a Docker
deployment and falls back to a native install (its own venv, run as an unprivileged
service) if Docker can't be used. A read-only preflight runs before anything changes.

Usage:
  sudo ./install.sh                  install everything + deploy (auto engine)
  sudo ./install.sh --port 9090      console port (default 8080; if 8080 is taken and you
                                     didn't choose a port, the next free one is used)
  sudo ./install.sh --listen 0.0.0.0 address the console listens on (default 127.0.0.1 = this
                                     host only; anything else is plain HTTP on the network)
  sudo ./install.sh --trusted-proxy 172.18.0.1
                                     a reverse proxy (IP or CIDR; repeatable) whose X-Forwarded-For
                                     the console trusts for the client address. Never "*".
  sudo ./install.sh --publish-mobile [PORT]
                                     also publish the mobile-analysis engine on 127.0.0.1:PORT
                                     (default 8000). Off by default: the console reaches it on
                                     the compose network.
  sudo ./install.sh --ai             install the local AI model (Docker only; ~5 GB, 8 GB free memory)
  sudo ./install.sh --no-ai          don't (without either flag, a terminal is asked; CI/pipes: no)
  sudo ./install.sh --native         force the native (no-Docker) install
  sudo ./install.sh --docker         force Docker (no native fallback)
  sudo ./install.sh --update         rebuild/reinstall & redeploy
  sudo ./install.sh --down           stop whatever is running
  ./install.sh --help                show this help
HELP
  exit 0
}

parse_args() {
  while [ $# -gt 0 ]; do
    case "$1" in
      --port) PORT="${2:?--port needs a number}"; PORT_SET=1; shift 2;;
      --listen) LISTEN="${2:?--listen needs an address}"; LISTEN_SET=1; shift 2;;
      --trusted-proxy) TRUSTED_PROXY="${TRUSTED_PROXY:+$TRUSTED_PROXY,}${2:?}"; shift 2;;
      --publish-mobile)
        PUBLISH_MOBILE=1
        case "${2:-}" in [0-9]*) MOBILE_PORT="$2"; MOBILE_PORT_SET=1; shift;; esac
        shift;;
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
  validate_args
}

validate_args() {
  case "$PORT" in *[!0-9]*|"") die "invalid --port: $PORT";; esac
  [ "$PORT" -ge 1 ] && [ "$PORT" -le 65535 ] || die "invalid --port: $PORT (1-65535)"
  case "$MOBILE_PORT" in *[!0-9]*|"") die "invalid --publish-mobile port: $MOBILE_PORT";; esac
  # --listen is an IP address (v4 or v6) or "localhost" — nothing else reaches the env file
  case "$LISTEN" in
    localhost) ;;
    *[!0-9A-Fa-f.:]*|"") die "invalid --listen address: $LISTEN (use an IP address, e.g. 127.0.0.1 or 0.0.0.0)";;
  esac
  # --trusted-proxy: IPs or CIDR ranges only — never "*" (any client could pick its own address)
  local _tp
  for _tp in $(printf '%s' "$TRUSTED_PROXY" | tr ',' ' '); do
    case "$_tp" in
      *[!0-9A-Fa-f.:/]*|/*|*/) die "invalid --trusted-proxy: $_tp (use an IP or CIDR, e.g. 172.18.0.1 or 10.0.0.0/24; never \"*\")";;
    esac
  done
}

# ----------------------------------------------------------------------------- sudo
if [ "$(id -u)" -eq 0 ]; then SUDO=""; else
  if command -v sudo >/dev/null 2>&1; then SUDO="sudo"; else SUDO=""; fi
fi
privileged() { [ "$(id -u)" -eq 0 ] || [ -n "$SUDO" ]; }

# ----------------------------------------------------------------------------- distro
detect_distro() {
  ARCH="$(uname -m)"
  if [ "$(uname -s)" = "Darwin" ]; then
    OSKIND="macos"; FAMILY="brew"; SUDO=""
    DISTRO_NAME="macOS $(sw_vers -productVersion 2>/dev/null || echo '')"
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
    *) FAMILY="unknown";;
  esac
}

pkg_install() { # best-effort install of packages for the detected family
  case "$FAMILY" in
    brew)   for p in "$@"; do brew list "$p" >/dev/null 2>&1 || brew install "$p" >/dev/null 2>&1 || true; done;;
    apt)    $SUDO apt-get update -y -qq >/dev/null 2>&1 || true
            $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq "$@" >/dev/null 2>&1 || true;;
    dnf)    $SUDO dnf install -y -q "$@" >/dev/null 2>&1 || true;;
    pacman) $SUDO pacman -Sy --noconfirm --needed "$@" >/dev/null 2>&1 || true;;
    zypper) $SUDO zypper --non-interactive --quiet install "$@" >/dev/null 2>&1 || true;;
  esac
}

# ----------------------------------------------------------------------------- env file helpers
env_get() { # env_get KEY [file] -> value (empty if absent)
  local f="${2:-$ENV_FILE}" rd=()
  [ -r "$f" ] || { [ -n "$SUDO" ] && $SUDO test -f "$f" 2>/dev/null && rd=($SUDO); } || [ -f "$f" ] || return 0
  ${rd[@]+"${rd[@]}"} grep -E "^$1=" "$f" 2>/dev/null | tail -n 1 | cut -d= -f2-
}
with_timeout() { # with_timeout SECONDS CMD… (macOS has no `timeout`)
  local s="$1"; shift
  if command -v timeout >/dev/null 2>&1; then timeout "$s" "$@"; else "$@"; fi
}
env_set() { # env_set KEY VALUE [file] — replace or append, keep the file's mode
  local f="${3:-$ENV_FILE}" tmp
  [ -f "$f" ] || return 0
  tmp="$(mktemp "${f}.XXXXXX")" || return 1
  grep -vE "^$1=" "$f" > "$tmp" 2>/dev/null || true
  printf '%s=%s\n' "$1" "$2" >> "$tmp"
  cat "$tmp" > "$f" && rm -f "$tmp"
}

# ----------------------------------------------------------------------------- preflight (read-only)
mem_available_mb() {
  [ -n "${CORVEX_TEST_MEM_MB:-}" ] && { printf '%s' "$CORVEX_TEST_MEM_MB"; return; }
  if [ -r /proc/meminfo ]; then
    awk '/^MemAvailable:/ {print int($2/1024); found=1} END {if (!found) print 0}' /proc/meminfo
  elif command -v vm_stat >/dev/null 2>&1; then
    local ps; ps="$(sysctl -n hw.pagesize 2>/dev/null || echo 4096)"
    vm_stat | awk -v ps="$ps" '/Pages (free|inactive|speculative)/ {gsub("\\.","",$NF); n+=$NF} END {print int(n*ps/1048576)}'
  else
    echo 0
  fi
}
disk_free_mb() { # disk_free_mb PATH (nearest existing parent)
  [ -n "${CORVEX_TEST_DISK_MB:-}" ] && { printf '%s' "$CORVEX_TEST_DISK_MB"; return; }
  local p="$1"
  while [ ! -e "$p" ] && [ "$p" != "/" ]; do p="$(dirname "$p")"; done
  df -Pk "$p" 2>/dev/null | awk 'NR==2 {print int($4/1024)}'
}
docker_state() { # missing | stopped | running
  command -v docker >/dev/null 2>&1 || { echo missing; return; }
  if $SUDO docker info >/dev/null 2>&1; then echo running; else echo stopped; fi
}
docker_root_dir() {
  local d=""
  [ "$(docker_state)" = running ] && d="$($SUDO docker info -f '{{.DockerRootDir}}' 2>/dev/null)"
  printf '%s' "${d:-/var/lib/docker}"
}

# The process (or container) listening on TCP port $1, as "description|pid|container"; empty if free.
port_holder() {
  local p="$1" line name="" pid="" user="" cname=""
  if command -v ss >/dev/null 2>&1; then
    line="$($SUDO ss -ltnp "sport = :$p" 2>/dev/null | tail -n +2 | head -n 1)"
    if [ -n "$line" ]; then
      name="$(printf '%s' "$line" | grep -oE 'users:\(\("[^"]+"' | head -n 1 | cut -d'"' -f2)"
      pid="$(printf '%s' "$line" | grep -oE 'pid=[0-9]+' | head -n 1 | cut -d= -f2)"
      [ -n "$line" ] && [ -z "$name" ] && name="?"
    fi
  elif command -v lsof >/dev/null 2>&1; then
    line="$($SUDO lsof -nP -iTCP:"$p" -sTCP:LISTEN 2>/dev/null | tail -n +2 | head -n 1)"
    if [ -n "$line" ]; then
      name="$(printf '%s' "$line" | awk '{print $1}')"; pid="$(printf '%s' "$line" | awk '{print $2}')"
    fi
  fi
  # a container publishing the port (also catches published ports with no userland proxy)
  if command -v docker >/dev/null 2>&1 && [ "$(docker_state)" = running ]; then
    cname="$($SUDO docker ps --format '{{.Names}}|{{.Ports}}' 2>/dev/null \
             | grep -E "[:]$p->" | head -n 1 | cut -d'|' -f1)"
  fi
  [ -n "$name" ] || [ -n "$cname" ] || return 0
  if [ -n "$cname" ]; then
    printf "Docker container '%s'|%s|%s" "$cname" "$pid" "$cname"; return
  fi
  if [ "$name" = "?" ]; then
    printf 'another program (run the installer with sudo to see which)|%s|' "$pid"; return
  fi
  [ -n "$pid" ] && user="$(ps -o user= -p "$pid" 2>/dev/null | tr -d ' ')"
  printf '%s (pid %s%s)|%s|' "$name" "${pid:-?}" "${user:+, user $user}" "$pid"
}
native_pid() { # pid of the console this installer runs natively, if any
  local pid=""
  if command -v systemctl >/dev/null 2>&1; then
    pid="$($SUDO systemctl show -p MainPID --value "$UNIT_NAME" 2>/dev/null)"
    [ "$pid" = 0 ] && pid=""
  fi
  [ -z "$pid" ] && [ -f "$NATIVE_HOME/console.pid" ] && pid="$(cat "$NATIVE_HOME/console.pid" 2>/dev/null)"
  printf '%s' "$pid"
}
is_ours() { # is_ours "description|pid|container" — held by this deployment (or its 0.2.x predecessor)?
  local pid cname c np
  pid="$(printf '%s' "$1" | cut -d'|' -f2)"; cname="$(printf '%s' "$1" | cut -d'|' -f3)"
  if [ -n "$cname" ]; then
    for c in $OUR_CONTAINERS; do [ "$cname" = "$c" ] && return 0; done
    return 1
  fi
  [ -n "$pid" ] || return 1
  np="$(native_pid)"; [ -n "$np" ] && [ "$pid" = "$np" ] && return 0
  [ -f "$LEGACY_PID" ] && [ "$pid" = "$(cat "$LEGACY_PID" 2>/dev/null)" ] && return 0
  # its command line runs our own console (the native venv or a 0.2.x checkout venv)
  grep -qaE "($NATIVE_PREFIX|$REPO_DIR)/(venv|\\.venv)/bin/(corvex|pentestiq)" "/proc/$pid/cmdline" 2>/dev/null
}
# Pick the port for one listener: free or ours -> keep; taken -> stop (port given by the user)
# or move to the next free port (default port). Prints the chosen port; dies with the holder.
resolve_port() { # resolve_port PORT WAS_SET FLAG_NAME
  local p="$1" set="$2" flag="$3" h q
  h="$(port_holder "$p")"
  if [ -z "$h" ] || is_ours "$h"; then printf '%s' "$p"; return 0; fi
  if [ "$set" = 1 ]; then
    die "port $p is in use by ${h%%|*}. Stop it, or choose another port with $flag N."
  fi
  for q in $(seq $((p + 1)) $((p + 50))); do
    if [ -z "$(port_holder "$q")" ]; then
      log "Port $p is in use by ${h%%|*} — using $q instead (choose one with $flag N)." >&2
      printf '%s' "$q"; return 0
    fi
  done
  die "port $p is in use by ${h%%|*}, and no free port was found up to $((p + 50)). Choose one with $flag N."
}

preflight() {
  log "Preflight — checking this machine before changing anything…"
  # platform
  case "$OSKIND/$ARCH" in
    linux/x86_64|linux/aarch64|linux/arm64|macos/x86_64|macos/arm64) ok "Platform: $DISTRO_NAME, $ARCH." ;;
    *) warn "Platform: $DISTRO_NAME, $ARCH — not a tested combination (x86_64/arm64); continuing." ;;
  esac
  # memory
  local mem; mem="$(mem_available_mb)"
  if [ "${mem:-0}" -gt 0 ] && [ "$mem" -lt "$MIN_MEM_MB" ]; then
    die "only ${mem} MB of memory is free; Corvex-RedOps needs at least ${MIN_MEM_MB} MB (${REC_MEM_MB} MB recommended). Free some memory and re-run."
  elif [ "${mem:-0}" -gt 0 ] && [ "$mem" -lt "$REC_MEM_MB" ]; then
    warn "Memory: ${mem} MB free (${REC_MEM_MB} MB recommended) — large scans may be slow."
  else
    ok "Memory: ${mem} MB free."
  fi
  # Docker
  DOCKER_STATE="$(docker_state)"
  case "$DOCKER_STATE" in
    running) ok "Docker: running ($(docker --version 2>/dev/null | cut -d, -f1))." ;;
    stopped) log "Docker: installed but not running — the installer will start it." ;;
    missing) log "Docker: not installed — the installer will install it$( [ "$ENGINE" = native ] && printf ' (skipped: --native)')." ;;
  esac
  # disk — decides the engine on auto: the Docker images need far more room than a venv
  local need_docker=0 dfree nfree
  [ "$ENGINE" != native ] && need_docker=1
  if [ "$need_docker" = 1 ]; then
    dfree="$(disk_free_mb "$(docker_root_dir)")"
    if [ "${dfree:-0}" -lt "$MIN_DISK_DOCKER_MB" ]; then
      if [ "$ENGINE" = docker ]; then
        die "only ${dfree} MB free for Docker ($(docker_root_dir)); the images need at least ${MIN_DISK_DOCKER_MB} MB. Free some space, or use --native."
      fi
      warn "Disk: ${dfree} MB free for Docker (needs ${MIN_DISK_DOCKER_MB} MB) — using the native install instead."
      ENGINE="native"
    else
      ok "Disk: ${dfree} MB free for Docker."
    fi
  fi
  if [ "$ENGINE" = native ]; then
    nfree="$(disk_free_mb "$NATIVE_PREFIX")"
    [ "${nfree:-0}" -ge "$MIN_DISK_NATIVE_MB" ] \
      || die "only ${nfree} MB free in $(dirname "$NATIVE_PREFIX"); the native install needs at least ${MIN_DISK_NATIVE_MB} MB."
    ok "Disk: ${nfree} MB free for the native install."
  fi
  # ports — every host port the deployment will publish
  PORT="$(resolve_port "$PORT" "$PORT_SET" --port)" || exit 1
  ok "Console port: $PORT."
  if [ "$PUBLISH_MOBILE" = 1 ] && [ "$ENGINE" != native ]; then
    MOBILE_PORT="$(resolve_port "$MOBILE_PORT" "$MOBILE_PORT_SET" --publish-mobile)" || exit 1
    ok "Mobile-analysis engine port: 127.0.0.1:$MOBILE_PORT."
  fi
  ok "Preflight passed."
}

# ----------------------------------------------------------------------------- prerequisites
install_base() {
  log "Installing base prerequisites (curl, openssl, python)…"
  case "$FAMILY" in
    brew)   command -v brew >/dev/null 2>&1 || warn "Homebrew not found — install it from https://brew.sh (the native install still works with the system python3)."
            pkg_install openssl python@3.12;;
    apt)    pkg_install ca-certificates curl openssl python3 python3-venv python3-pip;;
    dnf)    pkg_install ca-certificates curl openssl python3 python3-pip;;
    pacman) pkg_install curl openssl ca-certificates python python-pip;;
    zypper) pkg_install curl openssl ca-certificates python3 python3-pip;;
  esac
  ok "Base prerequisites installed."
}

docker_convenience_script() {
  log "Falling back to Docker's official install script…"
  local f; f="$(mktemp)"
  curl -fsSL https://get.docker.com -o "$f" 2>/dev/null && $SUDO sh "$f" >/dev/null 2>&1 || true
  rm -f "$f"
}

install_docker() { # returns 0 if the docker CLI is present afterwards
  if [ "${OSKIND:-linux}" = "macos" ]; then
    if command -v docker >/dev/null 2>&1 && docker info >/dev/null 2>&1; then return 0; fi
    command -v brew >/dev/null 2>&1 || { warn "no Homebrew — cannot install Docker on macOS."; return 1; }
    pkg_install colima docker docker-compose
    command -v docker >/dev/null 2>&1 && { ok "Docker (Colima) installed."; return 0; } || return 1
  fi
  command -v docker >/dev/null 2>&1 && return 0
  log "Installing Docker Engine…"
  case "$FAMILY" in
    apt)    $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io docker-compose-v2 >/dev/null 2>&1 \
              || $SUDO env DEBIAN_FRONTEND=noninteractive apt-get install -y -qq docker.io >/dev/null 2>&1 \
              || docker_convenience_script;;
    dnf)    $SUDO dnf install -y -q docker docker-compose-plugin >/dev/null 2>&1 \
              || $SUDO dnf install -y -q moby-engine >/dev/null 2>&1 || docker_convenience_script;;
    pacman) $SUDO pacman -Sy --noconfirm --needed docker docker-compose >/dev/null 2>&1 || docker_convenience_script;;
    zypper) $SUDO zypper --non-interactive install docker docker-compose >/dev/null 2>&1 || docker_convenience_script;;
    *)      docker_convenience_script;;
  esac
  command -v docker >/dev/null 2>&1 || { warn "Docker could not be installed."; return 1; }
  ok "Docker installed ($(docker --version 2>/dev/null | cut -d, -f1))."
}

start_docker() { # returns 0 if the daemon is reachable
  if [ "${OSKIND:-linux}" = "macos" ]; then
    docker info >/dev/null 2>&1 && return 0
    log "Starting Colima (Docker runtime)…"
    colima status >/dev/null 2>&1 || colima start >/dev/null 2>&1 || true
    for _ in $(seq 1 20); do docker info >/dev/null 2>&1 && return 0; sleep 2; done
    warn "Docker daemon did not start (Colima)."; return 1
  fi
  $SUDO docker info >/dev/null 2>&1 && return 0
  if command -v systemctl >/dev/null 2>&1; then
    $SUDO systemctl enable --now docker >/dev/null 2>&1 || $SUDO systemctl start docker >/dev/null 2>&1 || true
  else
    $SUDO service docker start >/dev/null 2>&1 || true
  fi
  for _ in $(seq 1 15); do $SUDO docker info >/dev/null 2>&1 && { ok "Docker daemon started."; return 0; }; sleep 2; done
  warn "Docker daemon did not start."; return 1
}

ensure_compose() { # returns 0 and sets DC_BIN if a compose implementation exists
  if $SUDO docker compose version >/dev/null 2>&1; then DC_BIN="docker compose"; return 0; fi
  if command -v docker-compose >/dev/null 2>&1; then DC_BIN="docker-compose"; return 0; fi
  log "Installing the Docker Compose plugin…"
  local ver="v2.29.7" arch dest
  case "$(uname -m)" in x86_64) arch=x86_64;; aarch64|arm64) arch=aarch64;; armv7l) arch=armv7;; *) arch="$(uname -m)";; esac
  dest="/usr/local/lib/docker/cli-plugins"; $SUDO mkdir -p "$dest"
  $SUDO curl -fsSL "https://github.com/docker/compose/releases/download/${ver}/docker-compose-linux-${arch}" -o "$dest/docker-compose" 2>/dev/null \
    && $SUDO chmod +x "$dest/docker-compose"
  if $SUDO docker compose version >/dev/null 2>&1; then DC_BIN="docker compose"; ok "Docker Compose plugin installed."; return 0; fi
  warn "Docker Compose is unavailable."; return 1
}

# ----------------------------------------------------------------------------- secrets
gen_secret() { openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | od -An -tx1 | tr -d ' \n'; }
# 20-character random one-time password (letters + digits, ~119 bits) for the first-run admin.
gen_password() {
  local p=""
  while [ "${#p}" -lt 20 ]; do
    p="$p$( { openssl rand -base64 48 2>/dev/null || head -c 48 /dev/urandom | base64; } | tr -dc 'A-Za-z0-9')"
  done
  printf '%s' "${p:0:20}"
}
FIRST_ADMIN_PW=""   # set only when THIS run created the env file; shown once in the summary

write_env() {
  mkdir -p "$(dirname "$ENV_FILE")"
  if [ -f "$ENV_FILE" ]; then ok "Reusing existing secrets ($ENV_FILE)."; return 0; fi
  log "Generating secrets → $ENV_FILE"
  FIRST_ADMIN_PW="$(gen_password)"
  ( umask 077
    cat > "$ENV_FILE" <<ENV
# Corvex-RedOps deployment secrets — generated by install.sh. Keep private; do not commit.
MOBSF_API_KEY=$(gen_secret)
PENTESTIQ_SECRET_KEY=$(gen_secret)
PENTESTIQ_PORT=${PORT}
PENTESTIQ_LISTEN=$(compose_listen)
CORVEX_TRUSTED_PROXIES=$(trusted_list)
PENTESTIQ_AI=0
OLLAMA_URL=http://ollama:11434
PENTESTIQ_AI_MODEL=${AI_MODEL}
# First-run admin. The password is a random ONE-TIME password generated by install.sh and
# shown once at the end of the install. Only the first boot reads it; install.sh blanks it
# here as soon as the console is up, and the console makes you choose a new password at the
# first sign-in.
CORVEX_ADMIN_USER=corvex
CORVEX_ADMIN_PASSWORD=${FIRST_ADMIN_PW}
ENV
  )
  chmod 600 "$ENV_FILE" 2>/dev/null || true
  ok "Secrets generated."
}

# Once the console is up the first-run admin exists, so the one-time password must not stay
# on disk: blank it in the env file (the summary still shows it, this one time).
consume_admin_password() {
  [ -n "${FIRST_ADMIN_PW:-}" ] && [ -f "$ENV_FILE" ] || return 0
  env_set CORVEX_ADMIN_PASSWORD "" && ADMIN_PW_CONSUMED=1
}

# Loopback (always) plus any --trusted-proxy entries.
trusted_list() { printf '127.0.0.1,::1%s' "${TRUSTED_PROXY:+,$TRUSTED_PROXY}"; }
is_loopback() { case "$1" in 127.*|::1|"[::1]"|localhost) return 0;; *) return 1;; esac; }
# compose port syntax needs IPv6 in brackets ([::1]:8080:8080); the native server takes it bare
compose_listen() { case "$LISTEN" in *:*) printf '[%s]' "$LISTEN";; *) printf '%s' "$LISTEN";; esac; }
health_host() { # where the installer itself reaches the console
  case "$LISTEN" in 0.0.0.0|localhost) printf '127.0.0.1';; ::|::0) printf '[::1]';; *:*) printf '[%s]' "$LISTEN";; *) printf '%s' "$LISTEN";; esac
}

# An existing install keeps its port and listen address unless this run sets them. 0.2.x
# installers defaulted to 0.0.0.0; that becomes 127.0.0.1 now, saying so.
load_existing_settings() {
  [ -f "$ENV_FILE" ] || return 0
  local p l
  p="$(env_get PENTESTIQ_PORT)"; l="$(env_get PENTESTIQ_LISTEN)"; l="${l#[}"; l="${l%]}"
  if [ "$PORT_SET" = 0 ] && [ -n "$p" ]; then PORT="$p"; fi
  if [ "$LISTEN_SET" = 0 ] && [ -n "$l" ] && [ "$l" != "$LISTEN" ]; then
    if [ "$l" = "0.0.0.0" ] || [ "$l" = "::" ]; then
      LISTEN_CHANGED_FROM="$l"            # reported once, in the summary
    else
      LISTEN="$l"
    fi
  fi
}
sync_env() { # the env file follows this run's port / listen / proxies / AI choice
  [ -f "$ENV_FILE" ] || return 0
  env_set PENTESTIQ_PORT "$PORT"
  env_set PENTESTIQ_LISTEN "$(compose_listen)"
  [ -n "$TRUSTED_PROXY" ] && env_set CORVEX_TRUSTED_PROXIES "$(trusted_list)"
  [ "${AI_CHOICE:-0}" = 1 ] || env_set PENTESTIQ_AI 0     # switched on only once the model is proven
  [ -n "$(env_get PENTESTIQ_AI)" ] || env_set PENTESTIQ_AI 0
  [ -n "$(env_get OLLAMA_URL)" ] || env_set OLLAMA_URL "http://ollama:11434"
  [ -n "$(env_get PENTESTIQ_AI_MODEL)" ] || env_set PENTESTIQ_AI_MODEL "$AI_MODEL"
  return 0
}

listen_warning() { # one line, only when the console is reachable from the network
  is_loopback "$LISTEN" && return 0
  printf "  ${c_yel}⚠ The console listens on %s over plain HTTP — anyone on your network can reach it; put TLS in front of it.${c_off}\n" "$LISTEN"
}
# Extra trusted proxies in effect: this run's --trusted-proxy, else what the env file holds.
trust_extras() {
  local t; t="$(env_get CORVEX_TRUSTED_PROXIES)"
  [ -n "$TRUSTED_PROXY" ] && t="$(trusted_list)"
  t="${t#127.0.0.1,::1}"; printf '%s' "${t#,}"
}
proxy_trust_warning() {
  is_loopback "$LISTEN" && return 0
  local x; x="$(trust_extras)"; [ -n "$x" ] || return 0
  printf "  ${c_yel}⚠ Trusted proxy %s is set while the console listens on %s: clients could choose their own X-Forwarded-For. Use --listen 127.0.0.1.${c_off}\n" "$x" "$LISTEN"
}

# ----------------------------------------------------------------------------- Docker engine
compose_files() { # the -f arguments for this deployment
  printf -- '-f\n%s\n' "$COMPOSE_FILE"
  [ "$PUBLISH_MOBILE" = 1 ] && printf -- '-f\n%s\n' "$COMPOSE_MOBILE_FILE"
  return 0
}
compose() { # compose ARGS… — the deployment's compose command (profiles from AI_CHOICE)
  local files=() f
  while IFS= read -r f; do files+=("$f"); done < <(compose_files)
  local profile=(); [ "${AI_CHOICE:-0}" = 1 ] && profile=(--profile ai)
  # shellcheck disable=SC2086
  $SUDO env DOCKER_BUILDKIT=0 COMPOSE_DOCKER_CLI_BUILD=0 CORVEX_MOBILE_PORT="$MOBILE_PORT" \
    ${DC_BIN:-docker compose} --env-file "$ENV_FILE" "${files[@]}" ${profile[@]+"${profile[@]}"} "$@"
}

# Docker's own (Go) DNS resolver rejects some networks' DNS replies that the system resolver
# accepts — the daemon then can't pull although the host resolves the registry fine.
go_resolver_symptom() { # $1 = output of a failed pull
  printf '%s' "$1" | grep -qE 'lookup [^ ]+ on [^ ]+: *(no such host|server misbehaving)' || return 1
  getent hosts registry-1.docker.io >/dev/null 2>&1
}
docker_dns_dropin() { # the only DNS change the installer makes: a docker.service drop-in
  command -v systemctl >/dev/null 2>&1 || return 1
  local f="$DOCKER_DROPIN_DIR/corvex-dns.conf"
  $SUDO mkdir -p "$DOCKER_DROPIN_DIR" || return 1
  printf '[Service]\nEnvironment=GODEBUG=netdns=cgo\n' | $SUDO tee "$f" >/dev/null || return 1
  $SUDO systemctl daemon-reload && $SUDO systemctl restart docker || return 1
  for _ in $(seq 1 15); do $SUDO docker info >/dev/null 2>&1 && break; sleep 2; done
  warn "Changed: added $f (Environment=GODEBUG=netdns=cgo) so Docker resolves names with the system resolver, and restarted Docker (containers with a restart policy came back up)."
  warn "To undo: sudo rm $f && sudo systemctl daemon-reload && sudo systemctl restart docker"
}
registry_reachable() { # can the daemon pull? fixes the Go-resolver case once, saying what it changed
  local out
  out="$(with_timeout 120 $SUDO docker pull python:3.11-slim 2>&1)" && return 0
  if go_resolver_symptom "$out"; then
    log "Docker can't resolve the image registry although this host can (Docker's built-in resolver rejects this network's DNS replies)."
    if docker_dns_dropin; then
      out="$(with_timeout 120 $SUDO docker pull python:3.11-slim 2>&1)" && { ok "Image registry reachable now."; return 0; }
    fi
  fi
  warn "Docker can't pull images: $(printf '%s' "$out" | tail -n 1)"
  return 1
}

fix_data_volume_owner() { # the console runs as an unprivileged user (uid 10001) since 0.3
  compose run --rm --no-deps --user 0 --entrypoint chown pentestiq -R 10001:10001 /app/data >/dev/null 2>&1 \
    || warn "could not hand the data volume to the console user (it may not be able to write)."
}
rollback_docker() {
  warn "Taking the stack down again — nothing is left half-started (data volumes are kept)."
  compose down --remove-orphans >/dev/null 2>&1 || true
  STACK_STARTED=""
}
show_docker_logs() {
  warn "Last console log lines:"
  compose logs --no-color --tail 30 pentestiq 2>/dev/null | sed 's/^/    /' >&2 || true
}

deploy_docker() { # returns 0 on a healthy stack
  [ -f "$COMPOSE_FILE" ] || { warn "compose file not found: $COMPOSE_FILE"; return 1; }
  log "Building the console image (the first run can take several minutes)…"
  if ! compose build; then warn "The image build failed (the running deployment, if any, is untouched)."; return 1; fi
  log "Pulling the other images…"
  compose pull --ignore-buildable >/dev/null 2>&1 || compose pull --ignore-pull-failures >/dev/null 2>&1 || true
  stop_native_instances
  fix_data_volume_owner
  log "Starting the stack…"
  STACK_STARTED="docker"
  if ! compose up -d --remove-orphans; then
    warn "The Docker stack didn't start."; rollback_docker; return 1
  fi
  if ! wait_healthy; then
    warn "The console didn't become healthy."; show_docker_logs; rollback_docker; return 1
  fi
  [ "${AI_CHOICE:-0}" = 1 ] || compose --profile ai stop ollama >/dev/null 2>&1 || true
  return 0
}

try_docker() { # orchestrates the whole Docker path; 0 = success, 1 = fall back
  install_docker  || return 1
  start_docker    || return 1
  ensure_compose  || return 1
  write_env
  sync_env
  registry_reachable || return 1
  deploy_docker   || return 1
  ENGINE_USED="docker"
  return 0
}

# ----------------------------------------------------------------------------- native engine
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
  if ! "$py" -m venv --help >/dev/null 2>&1 || ! "$py" -c 'import ensurepip' >/dev/null 2>&1; then
    [ "$FAMILY" = "apt" ] && pkg_install python3-venv python3-full
  fi
  PY="$py"; return 0
}

# Where the native console lives. With root (or sudo) it is a system service run as an
# unprivileged user; without, everything goes under the invoking user's home.
native_layout() {
  if privileged && [ "${OSKIND:-linux}" = linux ]; then
    NATIVE_MODE="system"
  else
    NATIVE_MODE="user"
    NATIVE_USER="$(id -un)"
    NATIVE_HOME="${CORVEX_NATIVE_HOME:-${XDG_DATA_HOME:-$HOME/.local/share}/corvex-redops}"
    NATIVE_PREFIX="${CORVEX_NATIVE_PREFIX:-$NATIVE_HOME}"
    NATIVE_ETC="${CORVEX_NATIVE_ETC:-$NATIVE_HOME}"
  fi
  NATIVE_DATA="$NATIVE_HOME/data"
  NATIVE_VENV="$NATIVE_PREFIX/venv"
  NATIVE_ENV="$NATIVE_ETC/corvex.env"
  NATIVE_LOG="$NATIVE_HOME/console.log"
}
have_systemd() { [ -d /run/systemd/system ] && command -v systemctl >/dev/null 2>&1; }

ensure_service_user() {
  id -u "$NATIVE_USER" >/dev/null 2>&1 && return 0
  log "Creating the unprivileged service user '$NATIVE_USER'…"
  local nologin; nologin="$(command -v nologin 2>/dev/null || echo /usr/sbin/nologin)"
  $SUDO useradd --system --user-group --home-dir "$NATIVE_HOME" --no-create-home --shell "$nologin" "$NATIVE_USER" 2>/dev/null \
    || $SUDO adduser -S -D -H -h "$NATIVE_HOME" -s "$nologin" "$NATIVE_USER" 2>/dev/null \
    || { warn "could not create the service user '$NATIVE_USER'."; return 1; }
}
as_root() { if [ "$NATIVE_MODE" = system ]; then $SUDO "$@"; else "$@"; fi; }

# The code is copied out of the checkout before pip builds it, so nothing in the checkout is
# written (or owned) by root, and the service never reads the checkout.
stage_source() { # a copy of the checkout without its venv, data, secrets or build leftovers
  local src e
  src="$(mktemp -d)" || return 1
  for e in "$REPO_DIR"/* "$REPO_DIR"/.[!.]*; do
    [ -e "$e" ] || continue
    case "$(basename "$e")" in .git|.venv|data|build|dist|*.egg-info|.pytest_cache) continue;; esac
    cp -a "$e" "$src/" || { rm -rf "$src"; return 1; }
  done
  rm -f "$src/deploy/.env" "$src/.corvex.pid" "$src/corvex.log"
  chmod -R a+rX "$src"
  printf '%s' "$src"
}
native_pip_install() {
  local src blog="$1"
  src="$(stage_source)" || return 1
  as_root "$NATIVE_VENV/bin/python" -m pip install -q --upgrade pip 'setuptools>=77' wheel >>"$blog" 2>&1 || true
  if ! as_root "$NATIVE_VENV/bin/python" -m pip install -q "$src[api,reports]" >>"$blog" 2>&1; then
    rm -rf "$src"; return 1
  fi
  as_root "$NATIVE_VENV/bin/python" -m pip install -q scikit-learn >>"$blog" 2>&1 || true   # self-learning model
  if as_root "$NATIVE_VENV/bin/python" -m pip install -q playwright >>"$blog" 2>&1; then  # SPA crawl, best-effort
    as_root env PLAYWRIGHT_BROWSERS_PATH="$NATIVE_PREFIX/pw-browsers" "$NATIVE_VENV/bin/playwright" install chromium >>"$blog" 2>&1 || true
  fi
  rm -rf "$src"
}

write_native_env() { # the service's settings: secrets reused from deploy/.env or the previous install
  local secret tp
  secret="$(env_get PENTESTIQ_SECRET_KEY "$NATIVE_ENV" 2>/dev/null)"
  [ -n "$secret" ] || secret="$(env_get PENTESTIQ_SECRET_KEY)"
  [ -n "$secret" ] || secret="$(gen_secret)"
  tp="$(env_get CORVEX_TRUSTED_PROXIES)"; [ -n "$TRUSTED_PROXY" ] && tp="$(trusted_list)"; tp="${tp:-$(trusted_list)}"
  local tmp; tmp="$(mktemp)" || return 1
  cat > "$tmp" <<ENV
# Corvex-RedOps native console settings — generated by install.sh. Keep private.
CORVEX_DATA_DIR=$NATIVE_DATA
CORVEX_LISTEN=$LISTEN
CORVEX_PORT=$PORT
PENTESTIQ_SECRET_KEY=$secret
CORVEX_TRUSTED_PROXIES=$tp
PENTESTIQ_AI=0
PLAYWRIGHT_BROWSERS_PATH=$NATIVE_PREFIX/pw-browsers
ENV
  local adu adp
  adu="$(env_get CORVEX_ADMIN_USER)"; adp="$(env_get CORVEX_ADMIN_PASSWORD)"
  [ -n "$adu" ] && printf 'CORVEX_ADMIN_USER=%s\n' "$adu" >> "$tmp"
  [ -n "$adp" ] && printf 'CORVEX_ADMIN_PASSWORD=%s\n' "$adp" >> "$tmp"
  as_root mkdir -p "$NATIVE_ETC"
  if [ "$NATIVE_MODE" = system ]; then
    $SUDO install -m 640 -o root -g "$NATIVE_USER" "$tmp" "$NATIVE_ENV"
  else
    install -m 600 "$tmp" "$NATIVE_ENV"
  fi
  rm -f "$tmp"
}

unit_file_text() {
  cat <<UNIT
[Unit]
Description=Corvex-RedOps console
After=network-online.target
Wants=network-online.target

[Service]
Type=simple
User=$NATIVE_USER
Group=$NATIVE_USER
EnvironmentFile=$NATIVE_ENV
WorkingDirectory=$NATIVE_HOME
ExecStart=$NATIVE_VENV/bin/corvex serve --host \${CORVEX_LISTEN} --port \${CORVEX_PORT}
Restart=on-failure
RestartSec=3
NoNewPrivileges=yes
PrivateTmp=yes
ProtectSystem=full
ReadWritePaths=$NATIVE_HOME

[Install]
WantedBy=multi-user.target
UNIT
}

# 0.2.x ran the native console from the checkout (data in ./data, a pid file there). Its data
# is copied into the new data directory once — only when that is still empty — and never deleted.
migrate_legacy_native_data() {
  [ -d "$LEGACY_DATA" ] || return 0
  [ -n "$(ls -A "$LEGACY_DATA" 2>/dev/null)" ] || return 0
  if [ -n "$(ls -A "$NATIVE_DATA" 2>/dev/null)" ]; then return 0; fi
  log "Copying the data of the previous native install ($LEGACY_DATA) to $NATIVE_DATA…"
  as_root cp -a "$LEGACY_DATA/." "$NATIVE_DATA/" || { warn "could not copy $LEGACY_DATA"; return 1; }
  [ "$NATIVE_MODE" = system ] && $SUDO chown -R "$NATIVE_USER:$NATIVE_USER" "$NATIVE_DATA"
  LEGACY_DATA_COPIED=1
}
stop_legacy_native() { # a 0.2.x console started from the checkout
  local pid; pid="$(cat "$LEGACY_PID" 2>/dev/null)"
  if [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && grep -qaE 'corvex|pentestiq' "/proc/$pid/cmdline" 2>/dev/null; then
    log "Stopping the previous console started from the checkout (pid $pid)…"
    $SUDO kill "$pid" 2>/dev/null || true
    for _ in $(seq 1 10); do kill -0 "$pid" 2>/dev/null || break; sleep 1; done
  fi
  rm -f "$LEGACY_PID" 2>/dev/null || $SUDO rm -f "$LEGACY_PID" 2>/dev/null || true
}
stop_native_instances() { # before the Docker stack takes the port
  stop_legacy_native
  if command -v systemctl >/dev/null 2>&1 && [ -f "$UNIT_DIR/$UNIT_NAME" ]; then
    $SUDO systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
  fi
  local pid; pid="$(cat "$NATIVE_HOME/console.pid" 2>/dev/null)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && { $SUDO kill "$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true; }
  return 0
}
stop_docker_stack() { # before the native console takes the port
  command -v docker >/dev/null 2>&1 && [ -f "$ENV_FILE" ] && [ "$(docker_state)" = running ] || return 0
  ensure_compose >/dev/null 2>&1 || return 0
  compose down --remove-orphans >/dev/null 2>&1 || true
}

start_native() {
  if [ "$NATIVE_MODE" = system ] && have_systemd; then
    unit_file_text | $SUDO tee "$UNIT_DIR/$UNIT_NAME" >/dev/null || return 1
    $SUDO systemctl daemon-reload && $SUDO systemctl enable "$UNIT_NAME" >/dev/null 2>&1 \
      && $SUDO systemctl restart "$UNIT_NAME" || return 1
    return 0
  fi
  # no systemd (or no root): run in the background as the service user / the invoking user
  local pidf="$NATIVE_HOME/console.pid" runner=()
  [ "$NATIVE_MODE" = system ] && runner=($SUDO runuser -u "$NATIVE_USER" --)
  [ "$(id -u)" -eq 0 ] && [ "$NATIVE_MODE" != system ] && { warn "refusing to run the console as root."; return 1; }
  ${runner[@]+"${runner[@]}"} bash -c 'set -a; . "$1"; set +a; cd "$2"; nohup "$3/bin/corvex" serve --host "$CORVEX_LISTEN" --port "$CORVEX_PORT" >>"$4" 2>&1 & echo $! > "$5"' \
    _ "$NATIVE_ENV" "$NATIVE_HOME" "$NATIVE_VENV" "$NATIVE_LOG" "$pidf"
}
stop_native() {
  if [ "$NATIVE_MODE" = system ] && have_systemd && [ -f "$UNIT_DIR/$UNIT_NAME" ]; then
    $SUDO systemctl disable --now "$UNIT_NAME" >/dev/null 2>&1 || true
  fi
  local pid; pid="$(cat "$NATIVE_HOME/console.pid" 2>/dev/null)"
  [ -n "$pid" ] && kill -0 "$pid" 2>/dev/null && { $SUDO kill "$pid" 2>/dev/null || kill "$pid" 2>/dev/null || true; }
  rm -f "$NATIVE_HOME/console.pid" 2>/dev/null || $SUDO rm -f "$NATIVE_HOME/console.pid" 2>/dev/null || true
}
rollback_native() {
  warn "Stopping the native console again — nothing is left half-started (data is kept)."
  stop_native; STACK_STARTED=""
}
show_native_logs() {
  warn "Last console log lines:"
  if [ "$NATIVE_MODE" = system ] && have_systemd; then
    $SUDO journalctl -u "$UNIT_NAME" -n 30 --no-pager 2>/dev/null | sed 's/^/    /' >&2 || true
  else
    tail -n 30 "$NATIVE_LOG" 2>/dev/null | sed 's/^/    /' >&2 || true
  fi
}

deploy_native() { # returns 0 on a healthy console
  native_layout
  log "Using the native install (own venv in $NATIVE_VENV, data in $NATIVE_DATA)."
  ensure_python || return 1
  pkg_install nmap                                  # better infra coverage; never fatal
  if [ "$NATIVE_MODE" = system ]; then
    ensure_service_user || return 1
    $SUDO install -d -m 755 -o root -g root "$NATIVE_PREFIX" || return 1
    $SUDO install -d -m 750 -o "$NATIVE_USER" -g "$NATIVE_USER" "$NATIVE_HOME" "$NATIVE_DATA" || return 1
  else
    mkdir -p "$NATIVE_PREFIX" "$NATIVE_DATA" && chmod 700 "$NATIVE_HOME" || return 1
  fi
  if [ ! -x "$NATIVE_VENV/bin/python" ]; then
    log "Creating the virtual environment → $NATIVE_VENV"
    as_root "$PY" -m venv "$NATIVE_VENV" || { warn "could not create the venv"; return 1; }
  fi
  log "Installing Corvex-RedOps and its dependencies (from PyPI)…"
  local blog; blog="$(mktemp)"
  if ! native_pip_install "$blog"; then
    warn "Dependency install failed — is PyPI reachable from this host? Last lines:"; tail -n 15 "$blog" >&2; rm -f "$blog"; return 1
  fi
  rm -f "$blog"; ok "Dependencies installed."
  write_native_env || { warn "could not write $NATIVE_ENV"; return 1; }
  migrate_legacy_native_data
  stop_legacy_native
  stop_docker_stack
  log "Starting the console on $(health_host):$PORT (as user $NATIVE_USER)…"
  STACK_STARTED="native"
  if ! start_native; then warn "The native console didn't start."; show_native_logs; rollback_native; return 1; fi
  if ! wait_healthy; then warn "The console didn't become healthy."; show_native_logs; rollback_native; return 1; fi
  ENGINE_USED="native"
  return 0
}

# ----------------------------------------------------------------------------- local AI model (B)
AI_PROMPT="Install the local AI model? About 5 GB download, needs 8 GB free memory. [y/N] "
AI_MIN_MEM_MB="${CORVEX_AI_MIN_MEM_MB:-8192}"
AI_MIN_DISK_MB=6144          # the model (~5 GB) plus room; +4 GB when the runtime image isn't pulled yet
AI_STATUS=""                 # the summary's AI line: ready | skipped: … | failed: …

is_terminal() { [ -t 0 ] && [ -t 1 ]; }
# Decide whether to install the local model, before anything changes. --ai / --no-ai win;
# an install that already runs it keeps it; otherwise ask — only in a terminal.
decide_ai() {
  if [ "$ENGINE" = native ]; then
    [ "$AI_CHOICE" = 1 ] && AI_STATUS="skipped: the local AI model needs Docker (this is a native install). Add it later with: sudo ./install.sh --docker --ai"
    AI_CHOICE=0; return 0
  fi
  [ -n "$AI_CHOICE" ] && return 0
  if [ "$(env_get PENTESTIQ_AI)" = 1 ]; then
    AI_CHOICE=1; log "Keeping the local AI model this install already runs (--no-ai turns it off)."; return 0
  fi
  if is_terminal; then
    local ans=""
    printf '%s' "$AI_PROMPT"
    read -r ans || ans=""
    case "$ans" in y|Y|yes|YES|Yes) AI_CHOICE=1;; *) AI_CHOICE=0;; esac
  else
    AI_CHOICE=0       # CI, pipes: no AI unless --ai
  fi
}

ai_resources_ok() { # explains and returns 1 when this machine can't run the model
  local mem dfree need
  mem="$(mem_available_mb)"
  if [ "${mem:-0}" -lt "$AI_MIN_MEM_MB" ]; then
    AI_STATUS="skipped: only ${mem} MB of memory is free; the local model needs ${AI_MIN_MEM_MB} MB"; return 1
  fi
  need="$AI_MIN_DISK_MB"
  $SUDO docker image inspect ollama/ollama:latest >/dev/null 2>&1 || need=$((need + 4096))
  dfree="$(disk_free_mb "$(docker_root_dir)")"
  if [ "${dfree:-0}" -lt "$need" ]; then
    AI_STATUS="skipped: only ${dfree} MB of disk is free for Docker; the local model needs ${need} MB"; return 1
  fi
  return 0
}

ai_model_present() { # is $AI_MODEL already in the runtime? (exact name, ":latest" implied)
  local want="$AI_MODEL"; case "$want" in *:*) ;; *) want="$want:latest";; esac
  compose exec -T ollama ollama list 2>/dev/null | awk 'NR>1 {print $1}' | grep -qxF "$want"
}

ai_turn_off() { # back to a working install without AI
  env_set PENTESTIQ_AI 0
  compose stop ollama >/dev/null 2>&1 || true
  AI_CHOICE=0
  compose up -d --no-deps pentestiq >/dev/null 2>&1 && wait_healthy >/dev/null 2>&1 || true
}

# Start the runtime, download the model (visible progress, skipped when present), switch AI on,
# restart the console and prove it: /ai/status available AND a real narrative from the model.
install_ai() {
  [ "$AI_CHOICE" = 1 ] || return 0
  [ "${ENGINE_USED:-}" = docker ] || { AI_STATUS="skipped: the local AI model needs Docker"; return 0; }
  ai_resources_ok || { warn "AI: ${AI_STATUS#skipped: } — skipping it. Reports still work without AI."; AI_CHOICE=0; env_set PENTESTIQ_AI 0; return 0; }
  log "Starting the local AI runtime…"
  if ! compose up -d ollama; then ai_fail "the AI runtime container didn't start"; return 0; fi
  local i; for i in $(seq 1 30); do compose exec -T ollama ollama list >/dev/null 2>&1 && break; sleep 2; done
  if ai_model_present; then
    ok "The model $AI_MODEL is already downloaded — skipping the download."
  else
    log "Downloading the model $AI_MODEL (about 5 GB for the default model)…"
    if ! compose exec -T ollama ollama pull "$AI_MODEL"; then ai_fail "the model $AI_MODEL could not be downloaded"; return 0; fi
  fi
  env_set PENTESTIQ_AI 1
  env_set PENTESTIQ_AI_MODEL "$AI_MODEL"
  log "Switching AI on and restarting the console…"
  if ! compose up -d --no-deps pentestiq || ! wait_healthy; then ai_fail "the console didn't come back after switching AI on"; return 0; fi
  log "Checking the AI end to end (status + a test narrative from the model)…"
  local out
  if out="$(compose exec -T pentestiq corvex ai-check 2>&1)"; then
    AI_STATUS="ready"; ok "AI: ready"
  else
    ai_fail "$(printf '%s' "$out" | grep -E '^AI check failed:' | head -n 1 | sed 's/^AI check failed: //')"
  fi
}
ai_fail() {
  local why="${1:-unknown error}"
  AI_STATUS="failed: $why"
  warn "AI: not enabled — $why. Reports still work without AI. Re-run with --ai to try again."
  ai_turn_off
}

# ----------------------------------------------------------------------------- health + summary
wait_healthy() { # polls /health; 0 if up, 1 on timeout
  log "Waiting for the console to become healthy…"
  local i
  for i in $(seq 1 "$HEALTH_TRIES"); do
    if curl -fsS -m 3 "http://$(health_host):${PORT}/health" >/dev/null 2>&1; then ok "Corvex-RedOps is up."; return 0; fi
    sleep 3
  done
  return 1
}

admin_password_hint() {
  local eu ep
  eu="$(env_get CORVEX_ADMIN_USER)"; eu="${eu:-corvex}"
  ep="$(env_get CORVEX_ADMIN_PASSWORD)"
  if [ -n "${FIRST_ADMIN_PW:-}" ]; then
    printf "  Admin login : ${c_grn}%s${c_off} / ${c_grn}%s${c_off}   ${c_dim}(one-time password)${c_off}\n" "$eu" "$FIRST_ADMIN_PW"
    printf "  ${c_yel}⚠ Save it now — it is shown only this once.${c_off} The console asks you for a new password at the first sign-in.\n"
    if [ "${ADMIN_PW_CONSUMED:-0}" = 1 ]; then
      printf "  ${c_dim}It has been removed from %s.${c_off}\n" "$ENV_FILE"
    else
      printf "  ${c_dim}It stays in %s until the console first starts; re-run the installer or blank CORVEX_ADMIN_PASSWORD after that.${c_off}\n" "$ENV_FILE"
    fi
    return
  fi
  if [ "$ep" = "corvex" ]; then
    printf "  ${c_yel}⚠ %s still contains the old default password.${c_off} The console now forces a change at the next sign-in;\n" "$ENV_FILE"
    printf "    after that, blank the CORVEX_ADMIN_PASSWORD line in that file.\n"
    return
  fi
  if [ -n "$ep" ]; then
    printf "  Admin login : ${c_grn}%s${c_off} / the CORVEX_ADMIN_PASSWORD you set in %s (change it at the first sign-in)\n" "$eu" "$ENV_FILE"
    return
  fi
  printf "  Admin login : ${c_grn}%s${c_off} / your existing password. Forgotten it? ${c_dim}corvex reset-password %s${c_off}\n" "$eu" "$eu"
}

summary() {
  local ip="" host
  if [ "${OSKIND:-linux}" = "macos" ]; then
    ip="$(ipconfig getifaddr en0 2>/dev/null || true)"
  else
    ip="$( { hostname -I 2>/dev/null || true; } | awk '{print $1}')"
  fi
  printf "\n${c_grn}════════════════════════════════════════════════════════════${c_off}\n"
  printf "  ${c_grn}✔ Corvex-RedOps is deployed.${c_off}  ${c_dim}(engine: %s)${c_off}\n" "${ENGINE_USED:-docker}"
  printf "${c_grn}════════════════════════════════════════════════════════════${c_off}\n"
  if is_loopback "$LISTEN"; then
    printf "  Web console : ${c_blue}http://%s:%s${c_off}   (this host only)\n" "$(health_host)" "$PORT"
  elif [ "$LISTEN" = 0.0.0.0 ] && [ -n "$ip" ]; then
    printf "  Web console : ${c_blue}http://%s:%s${c_off}   (or http://127.0.0.1:%s on this host)\n" "$ip" "$PORT" "$PORT"
  else
    printf "  Web console : ${c_blue}http://%s:%s${c_off}\n" "$(health_host)" "$PORT"
  fi
  [ "$PUBLISH_MOBILE" = 1 ] && [ "${ENGINE_USED:-docker}" = docker ] \
    && printf "  Mobile engine: ${c_blue}http://127.0.0.1:%s${c_off}   (--publish-mobile)\n" "$MOBILE_PORT"
  case "$AI_STATUS" in
    ready)     printf "  AI          : ${c_grn}ready${c_off} — local model %s\n" "$AI_MODEL";;
    skipped:*) printf "  AI          : ${c_dim}%s${c_off}\n" "${AI_STATUS#skipped: }";;
    failed:*)  printf "  AI          : ${c_yel}not enabled — %s.${c_off} Reports still work without AI.\n" "${AI_STATUS#failed: }";;
    *)         printf "  AI          : ${c_dim}off (sudo ./install.sh --ai adds the local model)${c_off}\n";;
  esac
  if [ "${ENGINE_USED:-docker}" = native ]; then
    printf "  Runs as     : user %s · data in %s · settings in %s\n" "$NATIVE_USER" "$NATIVE_DATA" "$NATIVE_ENV"
  fi
  if [ -n "${LISTEN_CHANGED_FROM:-}" ]; then
    printf "  ${c_yel}Note:${c_off} the console now listens on 127.0.0.1 only (it was on %s); re-run with --listen 0.0.0.0 to keep network access.\n" "$LISTEN_CHANGED_FROM"
  fi
  [ "${LEGACY_DATA_COPIED:-0}" = 1 ] && printf "  Previous native data copied from %s (left in place; remove it once you've checked).\n" "$LEGACY_DATA"
  printf "\n  Sign in:\n"
  admin_password_hint
  listen_warning
  proxy_trust_warning
  printf "\n  Manage:\n"
  if [ "${ENGINE_USED:-docker}" = docker ]; then
    printf "    logs : ${c_dim}sudo %s --env-file %s -f %s logs -f${c_off}\n" "${DC_BIN:-docker compose}" "$ENV_FILE" "$COMPOSE_FILE"
  elif [ "$NATIVE_MODE" = system ] && have_systemd; then
    printf "    logs : ${c_dim}sudo journalctl -u %s -f${c_off}\n" "$UNIT_NAME"
  else
    printf "    logs : ${c_dim}tail -f %s${c_off}\n" "$NATIVE_LOG"
  fi
  printf "    stop : ${c_dim}sudo ./install.sh --down${c_off}\n"
  printf "${c_grn}════════════════════════════════════════════════════════════${c_off}\n\n"
}

stop_all() {
  native_layout
  if command -v docker >/dev/null 2>&1 && [ -f "$COMPOSE_FILE" ] && [ -f "$ENV_FILE" ] && [ "$(docker_state)" = running ]; then
    ensure_compose >/dev/null 2>&1 && { log "Stopping the Docker stack…"; compose down --remove-orphans >/dev/null 2>&1 && ok "Docker stack stopped."; }
  fi
  if [ -f "$UNIT_DIR/$UNIT_NAME" ] || [ -f "$NATIVE_HOME/console.pid" ]; then
    log "Stopping the native console…"; stop_native; ok "Native console stopped."
  fi
  stop_legacy_native
  return 0
}

on_abort() { # Ctrl-C / kill during an install: never leave a half-started stack
  trap - INT TERM
  err "Interrupted."
  case "${STACK_STARTED:-}" in
    docker) rollback_docker;;
    native) rollback_native;;
  esac
  exit 130
}

# ----------------------------------------------------------------------------- main
main() {
  # macOS + Colima is per-user: if run with sudo, re-exec as the invoking user.
  if [ "$(uname -s)" = "Darwin" ] && [ "$(id -u)" = "0" ] && [ -n "${SUDO_USER:-}" ] && [ "${SUDO_USER}" != "root" ]; then
    printf "[Corvex-RedOps] macOS uses Colima (per-user Docker) — re-running as %s…\n" "${SUDO_USER}"
    exec sudo -u "${SUDO_USER}" -H "$0" "$@"
  fi
  parse_args "$@"
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

  native_layout
  load_existing_settings
  preflight
  is_loopback "$LISTEN" || warn "--listen $LISTEN: the console will be reachable from your network over plain HTTP — put TLS in front of it."
  decide_ai
  trap on_abort INT TERM

  install_base
  case "$ENGINE" in
    docker)
      try_docker || die "the Docker install failed and --docker was forced (no fallback). Nothing was left running."
      ;;
    native)
      deploy_native || die "the native install failed (nothing was left running). Check that Python 3.10+ and PyPI are reachable."
      ;;
    auto|*)
      if ! try_docker; then
        log "Docker isn't usable here — installing natively instead (own venv, unprivileged service)."
        deploy_native || die "both the Docker and the native install failed; nothing was left running. Make Docker, or Python 3.10+ with PyPI access, available and re-run."
      fi
      ;;
  esac
  trap - INT TERM
  install_ai
  consume_admin_password
  summary
}
# CORVEX_INSTALL_SOURCE_ONLY=1 lets the test suite load the functions without installing anything.
[ -n "${CORVEX_INSTALL_SOURCE_ONLY:-}" ] || main "$@"

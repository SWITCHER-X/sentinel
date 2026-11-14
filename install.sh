#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Project SENTINEL — Linux Installer
#
#   sudo ./install.sh                        hub + agent (fresh install)
#   sudo ./install.sh --hub-only             hub only (no eBPF agent)
#   sudo ./install.sh --reset-credentials    rotate the dashboard password
#
# Re-running an install keeps existing credentials and state. The script shows
# numbered progress steps and is idempotent: it reuses the virtualenv, only
# installs missing packages, and rebuilds the eBPF objects incrementally.
#
# Installs to /opt/sentinel, state in /var/lib/sentinel, config in /etc/sentinel.
# Creates systemd services: sentinel-hub (+ sentinel-agent unless --hub-only).
# ─────────────────────────────────────────────────────────────────────────────
set -Eeuo pipefail

trap 'echo "[-] install.sh failed at line $LINENO: $BASH_COMMAND" >&2' ERR

# ─── Progress helpers ───
STEP=0
TOTAL=8
INSTALL_START=$(date +%s)
STEP_T0=$INSTALL_START

step() {
  STEP=$((STEP + 1))
  STEP_T0=$(date +%s)
  local pct=$(( STEP * 100 / TOTAL ))
  local filled=$(( STEP * 20 / TOTAL ))
  local bar empty
  bar=$(printf '%*s' "$filled" '' | tr ' ' '#')
  empty=$(printf '%*s' "$(( 20 - filled ))" '')
  printf '\n[%s%s] %2d/%d (%3d%%) %s\n' "$bar" "$empty" "$STEP" "$TOTAL" "$pct" "$*"
}
note() { printf '       ..  %s\n' "$*"; }
step_ok() { printf '       ok  %s (%ss)\n' "${1:-done}" "$(( $(date +%s) - STEP_T0 ))"; }
die() { printf '       !!  %s\n' "$*" >&2; exit 1; }

# Live elapsed ticker for silent steps (build, venv creation).
SPIN_PID=""
SPIN_T0=0
spinner_start() {
  [[ ${PROGRESS:-0} -eq 1 ]] || return 0
  SPIN_T0=$(date +%s)
  ( while :; do
      printf '\r       ..  %s (%ss)' "${1:-working}" "$(( $(date +%s) - SPIN_T0 ))"
      sleep 1
    done ) &
  SPIN_PID=$!
}
spinner_stop() {
  if [[ -n "${SPIN_PID:-}" ]]; then
    kill "$SPIN_PID" 2>/dev/null || true
    wait "$SPIN_PID" 2>/dev/null || true
    SPIN_PID=""
    printf '\r\033[K'
  fi
}
trap 'spinner_stop' EXIT

usage() {
  sed -n '2,14p' "$0" | sed 's/^# \{0,1\}//'
  exit 0
}

# ─── Arguments ───
SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HUB_ONLY=0
RESET_CREDS=0
for arg in "$@"; do
  case "$arg" in
    --hub-only) HUB_ONLY=1 ;;
    --reset-credentials) RESET_CREDS=1 ;;
    -h|--help) usage ;;
    *) die "unknown option: $arg (valid: --hub-only, --reset-credentials, --help)" ;;
  esac
done

[[ $EUID -eq 0 ]] || die "run as root: sudo ./install.sh"

OPT=/opt/sentinel
VARLIB=/var/lib/sentinel
ETC=/etc/sentinel
PORT="${SENTINEL_PORT:-5000}"

printf '[*] Project SENTINEL installer\n'
printf '    source : %s\n' "$SRC_DIR"
printf '    target : %s  (state: %s, config: %s)\n' "$OPT" "$VARLIB" "$ETC"
[[ $HUB_ONLY -eq 1 ]] && printf '    mode   : hub only (no eBPF agent)\n'

# Live download progress (pacman/apt/pip/rsync bars + speeds) when we have a TTY.
# In CI/logs it stays quiet so the output remains readable.
PROGRESS=0
[[ -t 1 ]] && PROGRESS=1
[[ $PROGRESS -eq 1 ]] && printf '    progress: live download bars enabled\n'


# ─── Source preflight (fail before touching the system) ───
REQUIRED_SRC=(Makefile requirements.txt collector/sentinel_hub_lineage.py collector/sentinel_auth.py)
if [[ $HUB_ONLY -eq 0 ]]; then
  REQUIRED_SRC+=(agent/sentinel_lineage_agent.py ebpf/sentinel_lineage_core.bpf.c ebpf/vmlinux.h ebpf/sentinel_loader.c)
fi
for f in "${REQUIRED_SRC[@]}"; do
  [[ -e "$SRC_DIR/$f" ]] || die "source tree is incomplete: missing $f"
done

# ─── Distro detection ───
PKG=""
for pm in apt-get dnf yum pacman zypper; do
  if command -v "$pm" >/dev/null 2>&1; then PKG="$pm"; break; fi
done
[[ -n "$PKG" ]] || die "unknown package manager — install python3, python3-venv, pip, rsync, curl manually"

# Run a command with output suppressed unless the terminal is showing progress.
_run_pkg() {
  if [[ $PROGRESS -eq 1 ]]; then "$@"; else "$@" >/dev/null 2>&1; fi
}

apt_install() {
  export DEBIAN_FRONTEND=noninteractive
  _run_pkg apt-get install -y --no-install-recommends "$@"
}
pacman_install() {
  local pkgs=("$@") i
  _run_pkg pacman -S --needed --noconfirm "${pkgs[@]}" && return 0
  for i in 1 2 3; do
    note "pacman mirror timeout (attempt $i/3) — refreshing package db"
    pacman -Sy --noconfirm >/dev/null 2>&1 || true
    sleep 3
    _run_pkg pacman -S --needed --noconfirm "${pkgs[@]}" && return 0
  done
  return 1
}
dnf_install() { _run_pkg "$PKG" install -y "$@"; }
zypper_install() { _run_pkg zypper --non-interactive install --no-recommends "$@"; }

pkg_install() {
  case "$PKG" in
    apt-get) apt_install "$@" ;;
    pacman)  pacman_install "$@" ;;
    dnf|yum) dnf_install "$@" ;;
    zypper)  zypper_install "$@" ;;
  esac
}

# ─── [1/8] System dependencies ───
step "Installing system dependencies ($PKG)"
BASE_DEPS=()
case "$PKG" in
  apt-get)
    if [[ $PROGRESS -eq 1 ]]; then apt-get update -q; else apt-get update -qq; fi
    BASE_DEPS=(python3 python3-venv python3-pip rsync curl openssl) ;;
  pacman)  BASE_DEPS=(python python-pip rsync curl openssl) ;;
  dnf|yum) BASE_DEPS=(python3 python3-pip rsync curl openssl git) ;;
  zypper)  BASE_DEPS=(python3 python3-pip python3-venv rsync curl openssl) ;;
esac
pkg_install "${BASE_DEPS[@]}" || die "failed to install base dependencies"
step_ok "base packages installed"

if [[ $HUB_ONLY -eq 0 ]]; then
  TOOLCHAIN=()
  case "$PKG" in
    apt-get) TOOLCHAIN=(clang llvm libbpf-dev libelf-dev gcc make) ;;
    pacman)  TOOLCHAIN=(clang llvm libbpf gcc make) ;;
    dnf|yum) TOOLCHAIN=(clang llvm libbpf-devel libelf-devel gcc make) ;;
    zypper)  TOOLCHAIN=(clang llvm libbpf-devel libelf-devel gcc make) ;;
  esac
  note "installing eBPF toolchain: ${TOOLCHAIN[*]}"
  pkg_install "${TOOLCHAIN[@]}" || note "package install had errors — verifying toolchain below"

  MISSING=""
  for bin in clang gcc make; do
    command -v "$bin" >/dev/null 2>&1 || MISSING="$MISSING $bin"
  done
  BPF_HDR=""
  for d in /usr/include/bpf /usr/local/include/bpf /usr/include/"$(uname -m)"-linux-gnu/bpf; do
    [[ -f "$d/bpf_helpers.h" ]] && BPF_HDR="$d" && break
  done
  if [[ -n "$MISSING" || -z "$BPF_HDR" ]]; then
    echo "       missing:${MISSING:-}" >&2
    if [[ -z "$BPF_HDR" ]]; then echo "       libbpf headers not found (need <include>/bpf/bpf_helpers.h)" >&2; fi
    echo "       Debian/Ubuntu: sudo apt install clang llvm libbpf-dev libelf-dev gcc make" >&2
    echo "       Fedora/RHEL:   sudo dnf install clang llvm libbpf-devel libelf-devel gcc make" >&2
    echo "       Arch:          sudo pacman -S clang llvm libbpf gcc make" >&2
    echo "       Or install the hub only: sudo ./install.sh --hub-only" >&2
    exit 1
  fi
fi

# ─── [2/8] Service user + directories ───
step "Creating service user and directories"
if ! id sentinel >/dev/null 2>&1; then
  NOLOGIN_BIN=$(command -v nologin || echo /usr/sbin/nologin)
  useradd --system --home-dir "$VARLIB" --shell "$NOLOGIN_BIN" sentinel
  note "created system user sentinel"
else
  note "system user sentinel already exists"
fi
install -d -m 755 "$OPT"
install -d -m 750 -o sentinel -g sentinel "$VARLIB"
install -d -m 750 "$ETC"
step_ok "directories ready"

# ─── [3/8] Application files ───
step "Copying application to $OPT"
RSYNC_OPTS=(-a --delete
  --exclude '.venv' --exclude 'build' --exclude 'dist' --exclude '__pycache__'
  --exclude '*.pyc' --exclude 'lineage_db.json' --exclude '.git')
if [[ $PROGRESS -eq 1 ]]; then RSYNC_OPTS+=(--info=progress2 --human-readable); fi
rsync "${RSYNC_OPTS[@]}" "$SRC_DIR"/ "$OPT"/
chown -R sentinel:sentinel "$OPT"
chmod 750 "$OPT"
step_ok "source copied"

# ─── [4/8] Python environment ───
step "Preparing Python environment"
export PIP_DISABLE_PIP_VERSION_CHECK=1
if [[ -x "$OPT/.venv/bin/python" ]]; then
  note "reusing existing virtualenv"
else
  note "creating virtualenv"
  spinner_start "creating virtualenv"
  python3 -m venv "$OPT/.venv"
  spinner_stop
fi
[[ -x "$OPT/.venv/bin/pip" ]] || "$OPT/.venv/bin/python" -m ensurepip --upgrade >/dev/null 2>&1 || true
note "installing requirements (this is the slowest step; cached wheels make re-runs fast)"
PIP_FLAGS=(--no-input)
if [[ $PROGRESS -eq 1 ]]; then PIP_FLAGS+=(--progress-bar on); else PIP_FLAGS+=(--quiet); fi
if ! "$OPT/.venv/bin/pip" install "${PIP_FLAGS[@]}" -r "$OPT/requirements.txt"; then
  note "requirements.txt failed — falling back to explicit package list"
  "$OPT/.venv/bin/pip" install "${PIP_FLAGS[@]}" flask pyyaml requests psutil geoip2 gunicorn
fi
chown -R sentinel:sentinel "$OPT/.venv"
step_ok "Python deps installed"

# ─── [5/8] eBPF build ───
step "Building CO-RE eBPF object and libbpf loader"
if [[ $HUB_ONLY -eq 1 ]]; then
  note "skipped (hub only)"
  step_ok "skipped"
else
  MAKE=(make)
  if command -v ccache >/dev/null 2>&1; then MAKE=(make CLANG="ccache clang"); fi
  spinner_start "compiling eBPF (clang) and loader (gcc)"
  if ( cd "$OPT" && "${MAKE[@]}" build-core build-loader >/tmp/sentinel-build.log 2>&1 ); then
    spinner_stop
    for f in "$OPT/build/sentinel_lineage_core.o" "$OPT/build/sentinel-loader"; do
      [[ -s "$f" ]] || { cat /tmp/sentinel-build.log >&2; die "build did not produce $f"; }
    done
    chown -R sentinel:sentinel "$OPT/build"
    step_ok "built sentinel_lineage_core.o + sentinel-loader"
  else
    spinner_stop
    cat /tmp/sentinel-build.log >&2
    die "eBPF build failed — re-run with --hub-only to install just the dashboard"
  fi
fi

# ─── [6/8] Config + secrets ───
step "Writing configuration and secrets"
for f in rules.yaml geo_rules.json trusted_binaries.json; do
  if [[ -f "$OPT/config/$f" && ! -f "$ETC/$f" ]]; then cp "$OPT/config/$f" "$ETC/$f"; fi
done

GEN_CAT=$ETC/sentinel.env
EXISTING_INSTALL=0
[[ -f "$GEN_CAT" ]] && EXISTING_INSTALL=1

if [[ $EXISTING_INSTALL -eq 0 ]]; then
  sed -e "s#/opt/sentinel/config#$ETC#g" \
      -e "s#^SENTINEL_DB=.*#SENTINEL_DB=$VARLIB/lineage_db.json#" \
      -e "s#^SENTINEL_AGENT_DB=.*#SENTINEL_AGENT_DB=$VARLIB/agent_state.json#" \
      "$OPT/.env.example" > "$GEN_CAT"
else
  note "keeping existing $GEN_CAT"
fi

add_secret() {  # key value — only if absent
  grep -q "^$1=" "$GEN_CAT" || echo "$1=$2" >> "$GEN_CAT"
}

ADMIN_PW=""
if [[ $EXISTING_INSTALL -eq 1 && $RESET_CREDS -eq 0 ]]; then
  note "existing installation detected — credentials preserved"
else
  ADMIN_PW=$(openssl rand -base64 18 2>/dev/null || head -c 24 /dev/urandom | base64)
  add_secret "SENTINEL_ADMIN_USER" "admin"
  if [[ $RESET_CREDS -eq 1 && $EXISTING_INSTALL -eq 1 ]]; then
    sed -i "s#^SENTINEL_ADMIN_PASSWORD=.*#SENTINEL_ADMIN_PASSWORD=$ADMIN_PW#" "$GEN_CAT"
  else
    add_secret "SENTINEL_ADMIN_PASSWORD" "$ADMIN_PW"
  fi
fi

add_secret "SENTINEL_AGENT_KEY"      "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p -c 64)"
add_secret "SENTINEL_SESSION_SECRET" "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p -c 64)"
add_secret "SENTINEL_ALLOWLIST_KEY"  "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p -c 64)"
add_secret "SENTINEL_DB_PATH"        "$VARLIB/sentinel.db"
chmod 600 "$GEN_CAT"
chown root:sentinel "$GEN_CAT" 2>/dev/null || chown root:root "$GEN_CAT"
step_ok "config in $ETC"

# ─── [7/8] systemd services ───
step "Installing and starting services"
SYSTEMD=0
if command -v systemctl >/dev/null 2>&1; then
  SYSTEMD=1
  install -m 644 "$SRC_DIR/deploy/sentinel-hub.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now sentinel-hub
  note "sentinel-hub enabled"

  if [[ $HUB_ONLY -eq 0 ]]; then
    [[ -f /sys/kernel/btf/vmlinux ]] \
      || note "WARN: no /sys/kernel/btf/vmlinux — CO-RE needs CONFIG_DEBUG_INFO_BTF=y"
    grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
      || note "WARN: 'bpf' not in the LSM list — LSM hooks will not attach (boot with lsm=...,bpf)"

    install -m 644 "$SRC_DIR/deploy/sentinel-agent.service" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable sentinel-agent 2>/dev/null || true
    systemctl start sentinel-agent 2>/dev/null \
      && note "sentinel-agent started" \
      || note "WARN: sentinel-agent did not start (no BPF support?) — the hub still works"
  fi
  step_ok "services installed"
else
  note "systemd not available — services skipped"
  note "start manually: $OPT/.venv/bin/python $OPT/collector/sentinel_hub_lineage.py"
  step_ok "skipped"
fi

# ─── [8/8] Credentials sync + health check ───
step "Syncing dashboard credentials and checking the hub"
ADMIN_PW_SYNCED=$(grep "^SENTINEL_ADMIN_PASSWORD=" "$GEN_CAT" | head -1 | cut -d= -f2-)
ADMIN_USER_SYNCED=$(grep "^SENTINEL_ADMIN_USER=" "$GEN_CAT" | head -1 | cut -d= -f2-)
"$OPT/.venv/bin/python" - <<PYEOF
import sys
sys.path.insert(0, "$OPT/collector")
import os
os.environ.setdefault("SENTINEL_DB_PATH", "$VARLIB/sentinel.db")
import sentinel_auth as sa
sa.ensure_user("$ADMIN_USER_SYNCED", """$ADMIN_PW_SYNCED""", reset=True)
PYEOF

HUB_OK=0
for _ in $(seq 1 20); do
  if curl -sf --max-time 2 "http://127.0.0.1:$PORT/health" >/dev/null 2>&1; then HUB_OK=1; break; fi
  sleep 1
done

if [[ $HUB_OK -eq 1 ]]; then
  step_ok "hub responding on :$PORT"
else
  note "WARN: hub not responding on :$PORT after 20s — diagnosing"
  # 1. Is something else holding the port (stale hub from an earlier run)?
  if command -v ss >/dev/null 2>&1; then
    HOLDER=$(ss -ltnp 2>/dev/null | awk -v p=":$PORT" '$4 ~ p {print $0; exit}')
    if [[ -n "$HOLDER" ]]; then
      note "port $PORT is already held by: $HOLDER"
      note "if that is a stale hub, stop it: sudo pkill -f sentinel_hub_lineage && sudo systemctl restart sentinel-hub"
    fi
  fi
  # 2. Placeholder secrets make the hub refuse to boot by design.
  if grep -q 'CHANGE_ME' "$GEN_CAT" 2>/dev/null; then
    note "secrets still contain CHANGE_ME placeholders — run: sudo ./install.sh --reset-credentials"
  fi
  # 3. Show the unit state and the real error.
  if [[ $SYSTEMD -eq 1 ]]; then
    note "unit state: $(systemctl is-active sentinel-hub 2>/dev/null || true) / $(systemctl is-enabled sentinel-hub 2>/dev/null || true)"
    if command -v journalctl >/dev/null 2>&1; then
      printf '       -- last sentinel-hub log lines --\n'
      journalctl -u sentinel-hub -n 30 --no-pager 2>/dev/null | sed 's/^/       /'
    fi
  fi
  step_ok "hub not verified (see diagnostics above)"
fi

# ─── Summary ───
TOTAL_TIME=$(( $(date +%s) - INSTALL_START ))
printf '\n─────────────────────────────────────────────────────────────\n'
printf '  Project SENTINEL installed in %ss\n\n' "$TOTAL_TIME"
printf '  Dashboard : http://127.0.0.1:%s/\n' "$PORT"
printf '              (set SENTINEL_BIND=0.0.0.0 in %s to expose it; put TLS in front)\n' "$GEN_CAT"
printf '  Config    : %s\n' "$GEN_CAT"
printf '  State     : %s\n' "$VARLIB"
printf '  Logs      : journalctl -u sentinel-hub -f\n'
if [[ $HUB_ONLY -eq 0 ]]; then printf '  Agent log : journalctl -u sentinel-agent -f\n'; fi
printf '  Uninstall : sudo %s/uninstall.sh\n' "$OPT"

if [[ -n "$ADMIN_PW" ]]; then
  printf '\n┌──────────────────────────────────────────────────────┐\n'
  printf '│  DASHBOARD LOGIN (save this — shown once)            │\n'
  printf '│    user: %-45s│\n' "admin"
  printf '│    pass: %-45s│\n' "$ADMIN_PW"
  printf '└──────────────────────────────────────────────────────┘\n'
else
  printf '\n  Dashboard password: %s\n' "$GEN_CAT (SENTINEL_ADMIN_PASSWORD)"
fi
printf '─────────────────────────────────────────────────────────────\n'

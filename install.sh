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

# ─── Preflight: fail before changing anything ───
printf '\n[*] Preflight checks\n'
python3 -c 'import sys; sys.exit(0 if sys.version_info >= (3, 10) else 1)' \
  || die "Python 3.10+ is required (found: $(python3 -V 2>&1))"
printf '    ok   Python %s\n' "$(python3 -c 'import sys; print("%d.%d" % sys.version_info[:2])')"

free_kb() { df -Pk "$1" 2>/dev/null | awk 'NR==2 {print $4}'; }
for d in /opt /var/lib; do
  avail=$(free_kb "$d" || echo 0)
  [[ ${avail:-0} -ge 300000 ]] || die "not enough free space in $d ($(( ${avail:-0} / 1024 )) MB free, need ~300 MB)"
  printf '    ok   free space on %s: %s MB\n' "$d" "$(( avail / 1024 ))"
done

port_busy() {
  # Prefer the filter form; fall back to grepping plain ss where netlink filters
  # are restricted (containers) or ss is missing entirely.
  if command -v ss >/dev/null 2>&1; then
    if ss -ltn "sport = :$PORT" >/dev/null 2>&1; then
      ss -ltn "sport = :$PORT" 2>/dev/null | grep -q LISTEN && return 0
    else
      ss -ltn 2>/dev/null | grep -q ":$PORT " && return 0
    fi
    return 1
  fi
  return 1
}

port_pid() {
  if ss -ltnp "sport = :$PORT" >/dev/null 2>&1; then
    ss -ltnp "sport = :$PORT" 2>/dev/null | sed -nE 's/.*pid=([0-9]+).*/\1/p' | head -1
  else
    ss -ltnp 2>/dev/null | grep ":$PORT " | sed -nE 's/.*pid=([0-9]+).*/\1/p' | head -1
  fi
}

if port_busy; then
  # ss only prints the short process name ("python"); read /proc/<pid>/cmdline
  # to tell our hub apart from an unrelated service on the same port.
  PORT_PID=$(port_pid || true)
  PORT_CMD=""
  if [[ -n "$PORT_PID" ]]; then
    PORT_CMD=$(tr '\0' ' ' < "/proc/$PORT_PID/cmdline" 2>/dev/null || true)
  fi
  if [[ "$PORT_CMD" == *sentinel_hub_lineage* ]]; then
    note "the hub is already running on :$PORT (pid $PORT_PID) — stopping it for the upgrade"
    if command -v systemctl >/dev/null 2>&1; then
      systemctl stop sentinel-hub 2>/dev/null || kill "$PORT_PID" 2>/dev/null || true
    else
      kill "$PORT_PID" 2>/dev/null || true
    fi
    sleep 1
    if port_busy; then
      die "port $PORT is still held after stopping the hub — stop it manually or set SENTINEL_PORT"
    fi
  else
    die "port $PORT is in use by pid ${PORT_PID:-?} (${PORT_CMD:-unknown process}) — stop it or set SENTINEL_PORT"
  fi
fi
printf '    ok   port %s is free\n' "$PORT"

command -v systemctl >/dev/null 2>&1 || note "WARN: no systemd — services will be skipped"
if [[ $HUB_ONLY -eq 0 ]]; then
  [[ -f /sys/kernel/btf/vmlinux ]] || note "WARN: no /sys/kernel/btf/vmlinux — the agent will not load (the hub is fine)"
  grep -qw bpf /sys/kernel/security/lsm 2>/dev/null || note "WARN: 'bpf' is not in the LSM list — LSM hooks will not attach"
fi
printf '    ok   preflight complete\n'

# ─── [1/8] System dependencies ───
step "Installing system dependencies ($PKG)"
BASE_DEPS=()
case "$PKG" in
  apt-get)
    if [[ $PROGRESS -eq 1 ]]; then apt-get update -q; else apt-get update -qq; fi
    BASE_DEPS=(python3 python3-venv python3-pip rsync curl openssl git) ;;
  pacman)  BASE_DEPS=(python python-pip rsync curl openssl git) ;;
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
# Older installs (or a root-run credential sync) can leave state owned by root;
# the hub runs as 'sentinel' and SQLite needs write access to the file AND dir.
chown -R sentinel:sentinel "$VARLIB" 2>/dev/null || true
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
INSTALL_COMMIT=$(git -C "$SRC_DIR" rev-parse HEAD 2>/dev/null || echo unknown)
{
  echo "commit=$INSTALL_COMMIT"
  echo "installed_at=$(date -Is)"
} > "$OPT/.install-meta"
chmod 644 "$OPT/.install-meta"
chown sentinel:sentinel "$OPT/.install-meta"
step_ok "source copied (${INSTALL_COMMIT:0:12})"

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

set_secret() {  # key value — replace the line, whatever it currently holds
  local key=$1 val=$2 tmp
  tmp=$(mktemp)
  grep -v "^${key}=" "$GEN_CAT" > "$tmp" 2>/dev/null || true
  printf '%s=%s\n' "$key" "$val" >> "$tmp"
  cat "$tmp" > "$GEN_CAT"
  rm -f "$tmp"
}

add_secret() {  # key value — set when missing OR still a CHANGE_ME placeholder
  local key=$1 val=$2 cur=""
  cur=$(grep -m1 "^${key}=" "$GEN_CAT" 2>/dev/null | cut -d= -f2- || true)
  if [[ -z "$cur" || "$cur" == CHANGE_ME* ]]; then
    set_secret "$key" "$val"
  fi
}

ADMIN_PW=""
if [[ $EXISTING_INSTALL -eq 1 && $RESET_CREDS -eq 0 ]]; then
  CUR_PW=$(grep -m1 '^SENTINEL_ADMIN_PASSWORD=' "$GEN_CAT" 2>/dev/null | cut -d= -f2- || true)
  if [[ -z "$CUR_PW" || "$CUR_PW" == CHANGE_ME* ]]; then
    # Older installs copied the placeholder and never replaced it.
    ADMIN_PW=$(openssl rand -base64 18 2>/dev/null || head -c 24 /dev/urandom | base64)
    set_secret "SENTINEL_ADMIN_PASSWORD" "$ADMIN_PW"
    note "placeholder dashboard password replaced — printed below"
  else
    note "existing installation detected — credentials preserved"
  fi
  add_secret "SENTINEL_ADMIN_USER" "admin"
else
  ADMIN_PW=$(openssl rand -base64 18 2>/dev/null || head -c 24 /dev/urandom | base64)
  add_secret "SENTINEL_ADMIN_USER" "admin"
  if [[ $RESET_CREDS -eq 1 && $EXISTING_INSTALL -eq 1 ]]; then
    set_secret "SENTINEL_ADMIN_PASSWORD" "$ADMIN_PW"
  else
    add_secret "SENTINEL_ADMIN_PASSWORD" "$ADMIN_PW"
  fi
fi

add_secret "SENTINEL_AGENT_KEY"      "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p -c 64)"
add_secret "SENTINEL_SESSION_SECRET" "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p -c 64)"
add_secret "SENTINEL_ALLOWLIST_KEY"  "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p -c 64)"
add_secret "SENTINEL_DB_PATH"        "$VARLIB/sentinel.db"
UPDATE_BRANCH=$(git -C "$SRC_DIR" rev-parse --abbrev-ref HEAD 2>/dev/null || echo master)
[[ "$UPDATE_BRANCH" == "HEAD" ]] && UPDATE_BRANCH=master
add_secret "SENTINEL_UPDATE_REF"      "$UPDATE_BRANCH"

# Never leave a placeholder behind: the hub refuses to boot on one.
if grep -q '=CHANGE_ME' "$GEN_CAT"; then
  die "$GEN_CAT still contains CHANGE_ME placeholders — edit it and re-run"
fi
chmod 600 "$GEN_CAT"
chown root:sentinel "$GEN_CAT" 2>/dev/null || chown root:root "$GEN_CAT"
step_ok "config in $ETC"

# ─── [7/8] systemd services ───
step "Installing and starting services"
SYSTEMD=0
if command -v systemctl >/dev/null 2>&1; then
  SYSTEMD=1
  install -m 644 "$SRC_DIR/deploy/sentinel-hub.service" /etc/systemd/system/
  install -m 644 "$SRC_DIR/deploy/sentinel-update.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now sentinel-hub
  note "sentinel-hub enabled (gunicorn, reload = zero-downtime cutover)"

  # Let the unprivileged hub trigger exactly one root action: the updater.
  SUDOERS_FILE=/etc/sudoers.d/sentinel-update
  printf 'sentinel ALL=(root) NOPASSWD: /usr/bin/systemctl start --no-block sentinel-update.service\n' > "$SUDOERS_FILE"
  chmod 440 "$SUDOERS_FILE"
  if command -v visudo >/dev/null 2>&1 && ! visudo -cf "$SUDOERS_FILE" >/dev/null 2>&1; then
    rm -f "$SUDOERS_FILE"
    note "WARN: sudoers drop-in failed validation — dashboard updates disabled"
  else
    note "dashboard update trigger installed"
  fi

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
step "Syncing credentials and verifying the installation"
ADMIN_PW_SYNCED=$(grep "^SENTINEL_ADMIN_PASSWORD=" "$GEN_CAT" | head -1 | cut -d= -f2-)
ADMIN_USER_SYNCED=$(grep "^SENTINEL_ADMIN_USER=" "$GEN_CAT" | head -1 | cut -d= -f2-)
AGENT_KEY_SYNCED=$(grep "^SENTINEL_AGENT_KEY=" "$GEN_CAT" | head -1 | cut -d= -f2-)
"$OPT/.venv/bin/python" - <<PYEOF
import sys
sys.path.insert(0, "$OPT/collector")
import os
os.environ.setdefault("SENTINEL_DB_PATH", "$VARLIB/sentinel.db")
import sentinel_auth as sa
sa.ensure_user("$ADMIN_USER_SYNCED", """$ADMIN_PW_SYNCED""", reset=True)
PYEOF

# This heredoc ran as root: give the DB (and any -wal/-shm) back to the service user.
chown -R sentinel:sentinel "$VARLIB"
if [[ $SYSTEMD -eq 1 ]]; then
  systemctl restart sentinel-hub
fi

CHECKS_PASS=0; CHECKS_FAIL=0; CHECKS_WARN=0
pass_chk() { printf '       PASS  %s\n' "$1"; CHECKS_PASS=$((CHECKS_PASS + 1)); }
fail_chk() { printf '       FAIL  %s\n' "$1"; CHECKS_FAIL=$((CHECKS_FAIL + 1)); }
warn_chk() { printf '       WARN  %s\n' "$1"; CHECKS_WARN=$((CHECKS_WARN + 1)); }
run_chk()  { local label=$1; shift; if "$@" >/dev/null 2>&1; then pass_chk "$label"; else fail_chk "$label"; fi; }
run_warn() { local label=$1; shift; if "$@" >/dev/null 2>&1; then pass_chk "$label"; else warn_chk "$label"; fi; }

have_file()       { [[ -s "$1" ]]; }
have_exe()        { [[ -x "$1" ]]; }
no_placeholders() { ! grep -q '=CHANGE_ME' "$1"; }
env_perms()       { [[ "$(stat -c %a "$1" 2>/dev/null)" == "600" ]]; }
py_import()       { "$OPT/.venv/bin/python" -c "import $1"; }
health_ok()       { curl -sf --max-time 3 -H "X-Sentinel-Key: ${AGENT_KEY_SYNCED:-}" "http://127.0.0.1:$PORT/health" 2>/dev/null | grep -qE '"status":"(ok|healthy)"'; }
page_ok()         { curl -sf --max-time 3 -o /dev/null "http://127.0.0.1:$PORT/login"; }
agent_active()    { systemctl is-active --quiet sentinel-agent 2>/dev/null; }
update_ready()    { [[ -f /etc/sudoers.d/sentinel-update ]] && [[ -f /etc/systemd/system/sentinel-update.service ]]; }
state_owned()     { [[ "$(stat -c %U "$VARLIB" 2>/dev/null)" == "sentinel" ]] && \
                    { [[ ! -e "$VARLIB/sentinel.db" ]] || [[ "$(stat -c %U "$VARLIB/sentinel.db")" == "sentinel" ]]; }; }
rules_ok()        { "$OPT/.venv/bin/python" "$OPT/tools/validate_rules.py" "$ETC/rules.yaml" 2>&1 | grep -q "All rules passed"; }
login_ok() {
  PORT="$PORT" CHECK_PW="$ADMIN_PW_SYNCED" CHECK_USER="$ADMIN_USER_SYNCED" "$OPT/.venv/bin/python" - <<'PYLOGIN'
import json, os, urllib.request
req = urllib.request.Request(
    "http://127.0.0.1:%s/api/v1/login" % os.environ["PORT"],
    data=json.dumps({"username": os.environ.get("CHECK_USER", "admin"),
                     "password": os.environ["CHECK_PW"]}).encode(),
    headers={"Content-Type": "application/json"})
try:
    with urllib.request.urlopen(req, timeout=5) as r:
        ok = json.load(r).get("ok") is True
except Exception:
    ok = False
raise SystemExit(0 if ok else 1)
PYLOGIN
}

# Wait for the hub once (systemd path only); the checks below reuse the result.
if [[ $SYSTEMD -eq 1 ]]; then
  for _ in $(seq 1 20); do health_ok && break; sleep 1; done
fi

printf '       -- verification --\n'
run_chk  "secrets have no CHANGE_ME placeholders" no_placeholders "$GEN_CAT"
run_chk  "secret file permissions are 600" env_perms "$GEN_CAT"
run_chk  "state dir and auth DB owned by sentinel" state_owned
run_warn "dashboard self-update wired" update_ready
run_chk  "Python env imports flask" py_import flask
run_chk  "Python env imports yaml" py_import yaml
run_chk  "Python env imports gunicorn" py_import gunicorn
run_chk  "rules file validates" rules_ok
if [[ $SYSTEMD -eq 1 ]]; then
  run_chk  "hub /health is healthy" health_ok
  run_chk  "dashboard login page reachable" page_ok
  run_chk  "admin login with the env password" login_ok
else
  # No service manager: the operator starts the hub by hand, so don't fail the install.
  run_warn "hub /health is healthy (start it manually)" health_ok
  run_warn "dashboard login page reachable (start it manually)" page_ok
  run_warn "admin login with the env password (start it manually)" login_ok
fi
if [[ $HUB_ONLY -eq 0 ]]; then
  run_chk  "CO-RE object built" have_file "$OPT/build/sentinel_lineage_core.o"
  run_chk  "libbpf loader built" have_exe "$OPT/build/sentinel-loader"
  run_warn "sentinel-agent is active" agent_active
fi

if [[ $CHECKS_FAIL -eq 0 ]]; then
  step_ok "verification passed (${CHECKS_PASS} passed, ${CHECKS_WARN} warning(s))"
else
  note "WARN: ${CHECKS_FAIL} check(s) failed — collecting diagnostics"
  if command -v ss >/dev/null 2>&1; then
    HOLDER=$(ss -ltnp 2>/dev/null | awk -v p=":$PORT" '$4 ~ p {print $0; exit}')
    [[ -n "$HOLDER" ]] && note "port $PORT held by: $HOLDER"
  fi
  if [[ $SYSTEMD -eq 1 ]]; then
    note "unit state: $(systemctl is-active sentinel-hub 2>/dev/null || true) / $(systemctl is-enabled sentinel-hub 2>/dev/null || true)"
    if command -v journalctl >/dev/null 2>&1; then
      printf '       -- last sentinel-hub log lines --\n'
      journalctl -u sentinel-hub -n 30 --no-pager 2>/dev/null | sed 's/^/       /'
    fi
  fi
  step_ok "verification failed (${CHECKS_FAIL} failed, ${CHECKS_PASS} passed)"
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
printf '  Checks    : %s passed, %s failed, %s warning(s)\n' "$CHECKS_PASS" "$CHECKS_FAIL" "$CHECKS_WARN"
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

if [[ ${CHECKS_FAIL:-0} -gt 0 ]]; then
  printf '\n  !! %s verification check(s) failed — see the output above.\n' "$CHECKS_FAIL"
  exit 1
fi

#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Project SENTINEL — Linux Installer
#
#   sudo ./install.sh                        hub + agent (fresh install)
#   sudo ./install.sh --hub-only             hub only (no eBPF agent)
#   sudo ./install.sh --reset-credentials    rotate the dashboard password
# Re-running an install keeps existing credentials — nothing is re-printed.
#
# Installs to /opt/sentinel, state in /var/lib/sentinel, config in /etc/sentinel.
# Creates systemd services: sentinel-hub (+ sentinel-agent unless --hub-only).
# ─────────────────────────────────────────────────────────────────────────────
set -euo pipefail

# ─── Preconditions ───
if [[ $EUID -ne 0 ]]; then
  echo "[-] Run as root: sudo ./install.sh" >&2; exit 1
fi

SRC_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
HUB_ONLY=0
RESET_CREDS=0
for arg in "$@"; do
  case "$arg" in
    --hub-only) HUB_ONLY=1 ;;
    --reset-credentials) RESET_CREDS=1 ;;
    *) echo "[-] Unknown option: $arg (valid: --hub-only, --reset-credentials)" >&2; exit 1 ;;
  esac
done

OPT=/opt/sentinel
VARLIB=/var/lib/sentinel
ETC=/etc/sentinel

echo "[*] Project SENTINEL installer"
echo "    source : $SRC_DIR"
echo "    target : $OPT  (state: $VARLIB, config: $ETC)"
[[ $HUB_ONLY -eq 1 ]] && echo "    mode   : hub only (no eBPF agent)"

# ─── Distro detection ───
PKG=""
if command -v apt-get >/dev/null 2>&1; then PKG=apt
elif command -v dnf >/dev/null 2>&1; then PKG=dnf
elif command -v yum >/dev/null 2>&1; then PKG=yum
elif command -v pacman >/dev/null 2>&1; then PKG=pacman
else
  echo "[!] Unknown package manager — install python3, python3-venv, pip manually." >&2
fi

# ─── System deps ───
echo "[*] Installing system dependencies ($PKG)…"
case "$PKG" in
  apt)
    export DEBIAN_FRONTEND=noninteractive
    apt-get update -qq
    apt-get install -y -qq python3 python3-venv python3-pip rsync curl openssl >/dev/null
    if [[ $HUB_ONLY -eq 0 ]]; then
      apt-get install -y -qq clang llvm libbpf-dev libelf-dev gcc make >/dev/null 2>&1 \
        || echo "[!] eBPF build toolchain not installed — the agent will not build. Install: clang llvm libbpf-dev libelf-dev gcc make"
    fi
    ;;
  dnf|yum)
    $PKG install -y -q python3 python3-pip rsync curl git openssl >/dev/null
    [[ $HUB_ONLY -eq 0 ]] && $PKG install -y -q clang llvm libbpf-devel libelf-devel gcc make >/dev/null 2>&1 || true
    ;;
  pacman)
    for attempt in 1 2 3; do
      pacman -Sy --noconfirm --needed python python-pip rsync curl openssl >/dev/null && break
      echo "[!] pacman mirror timeout (attempt $attempt/3) — retrying in 5s…"
      sleep 5
    done
    if [[ $HUB_ONLY -eq 0 ]]; then
      pacman -Sy --noconfirm --needed clang llvm libbpf gcc make >/dev/null 2>&1 \
        || echo "[!] WARNING: eBPF toolchain failed to install. The hub will run, but the agent needs: sudo pacman -S clang llvm libbpf gcc make"
    fi
    ;;
esac

# ─── Verify the build toolchain (fail early with an actionable message) ───
if [[ $HUB_ONLY -eq 0 ]]; then
  MISSING=""
  for bin in clang gcc make; do
    command -v "$bin" >/dev/null 2>&1 || MISSING="$MISSING $bin"
  done
  BPF_HDR=""
  for d in /usr/include/bpf /usr/local/include/bpf /usr/include/"$(uname -m)"-linux-gnu/bpf; do
    [[ -f "$d/bpf_helpers.h" ]] && BPF_HDR="$d" && break
  done
  if [[ -n "$MISSING" || -z "$BPF_HDR" ]]; then
    echo "[-] Missing eBPF build prerequisites:${MISSING:-} ${BPF_HDR:+}"
    [[ -z "$BPF_HDR" ]] && echo "    libbpf headers not found (need <include>/bpf/bpf_helpers.h)"
    echo "    Debian/Ubuntu: sudo apt install clang llvm libbpf-dev libelf-dev gcc make"
    echo "    Fedora/RHEL:   sudo dnf install clang llvm libbpf-devel libelf-devel gcc make"
    echo "    Arch:          sudo pacman -S clang llvm libbpf gcc make"
    echo "    Or install the hub only: sudo ./install.sh --hub-only"
    exit 1
  fi
fi

# ─── Service user ───
if ! id sentinel >/dev/null 2>&1; then
  NOLOGIN_BIN=$(command -v nologin || echo /usr/sbin/nologin)
  useradd --system --home-dir "$VARLIB" --shell "$NOLOGIN_BIN" sentinel
  echo "[✓] Created system user: sentinel"
fi

# ─── Directories ───
mkdir -p "$OPT" "$VARLIB" "$ETC"
chown sentinel:sentinel "$VARLIB"
chmod 750 "$VARLIB"
echo "[✓] Directories ready"

# ─── Install application ───
echo "[*] Copying application to $OPT…"
rsync -a --delete \
  --exclude '.venv' --exclude 'build' --exclude '__pycache__' \
  --exclude '*.pyc' --exclude 'lineage_db.json' --exclude '.git' \
  "$SRC_DIR"/ "$OPT"/
chown -R sentinel:sentinel "$OPT"
chmod 750 "$OPT"

# ─── Python venv ───
echo "[*] Creating virtualenv and installing Python deps…"
python3 -m venv "$OPT/.venv"
"$OPT/.venv/bin/pip" install --quiet --upgrade pip
"$OPT/.venv/bin/pip" install --quiet -r "$OPT/requirements.txt" \
  || "$OPT/.venv/bin/pip" install --quiet flask pyyaml requests psutil geoip2 gunicorn
chown -R sentinel:sentinel "$OPT/.venv"
echo "[✓] Python environment ready"

# ─── eBPF: build the CO-RE object and the libbpf loader ───
if [[ $HUB_ONLY -eq 0 ]]; then
  echo "[*] Building CO-RE eBPF object and libbpf loader…"
  if ( cd "$OPT" && make build-core build-loader ); then
    chown -R sentinel:sentinel "$OPT/build"
    for f in "$OPT/build/sentinel_lineage_core.o" "$OPT/build/sentinel-loader"; do
      [[ -s "$f" ]] || { echo "[-] build did not produce $f" >&2; exit 1; }
    done
    echo "[✓] Built build/sentinel_lineage_core.o and build/sentinel-loader"
  else
    echo "[-] eBPF build failed (need clang, libbpf headers and gcc)." >&2
    echo "    The hub can still be installed with: sudo ./install.sh --hub-only" >&2
    exit 1
  fi
fi

# ─── Config ───
for f in rules.yaml geo_rules.json trusted_binaries.json; do
  [[ -f "$OPT/config/$f" && ! -f "$ETC/$f" ]] && cp "$OPT/config/$f" "$ETC/$f"
done
if [[ ! -f "$ETC/sentinel.env" ]]; then
  sed -e "s#/opt/sentinel/config#$ETC#g" \
      -e "s#^SENTINEL_DB=.*#SENTINEL_DB=$VARLIB/lineage_db.json#" \
      -e "s#^SENTINEL_AGENT_DB=.*#SENTINEL_AGENT_DB=$VARLIB/agent_state.json#" \
      "$OPT/.env.example" > "$ETC/sentinel.env"
  chmod 600 "$ETC/sentinel.env"
else
  echo "[=] Keeping existing $ETC/sentinel.env"
fi

# ─── Secrets (generated on fresh install; preserved on re-install) ───
GEN_CAT=$ETC/sentinel.env
EXISTING_INSTALL=0
[[ -f "$GEN_CAT" ]] && EXISTING_INSTALL=1

add_secret() {  # key value — only if absent
  grep -q "^$1=" "$GEN_CAT" || echo "$1=$2" >> "$GEN_CAT"
}

ADMIN_PW=""
if [[ $EXISTING_INSTALL -eq 1 && $RESET_CREDS -eq 0 ]]; then
  echo "[=] Existing installation detected — credentials preserved"
  echo "[=] (dashboard password: see SENTINEL_ADMIN_PASSWORD in $GEN_CAT;"
  echo "[=]  rotate it with: sudo ./install.sh --reset-credentials)"
else
  ADMIN_PW=$(openssl rand -base64 18 2>/dev/null || head -c 24 /dev/urandom | base64)
  add_secret "SENTINEL_ADMIN_USER"     "admin"
  if [[ $RESET_CREDS -eq 1 && $EXISTING_INSTALL -eq 1 ]]; then
    sed -i "s#^SENTINEL_ADMIN_PASSWORD=.*#SENTINEL_ADMIN_PASSWORD=$ADMIN_PW#" "$GEN_CAT"
  else
    add_secret "SENTINEL_ADMIN_PASSWORD" "$ADMIN_PW"
  fi
fi

# secrets every install must have (idempotent — only added if missing)
add_secret "SENTINEL_AGENT_KEY"      "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p -c 64)"
add_secret "SENTINEL_SESSION_SECRET" "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p -c 64)"
add_secret "SENTINEL_ALLOWLIST_KEY"  "$(openssl rand -hex 32 2>/dev/null || head -c 32 /dev/urandom | xxd -p -c 64)"
add_secret "SENTINEL_DB_PATH"        "$VARLIB/sentinel.db"
chmod 600 "$GEN_CAT"
chown root:sentinel "$GEN_CAT"
echo "[✓] Config + secrets at $GEN_CAT (chmod 600)"

if [[ -n "$ADMIN_PW" ]]; then
  echo ""
  echo "┌──────────────────────────────────────────────────────┐"
  echo "│  DASHBOARD LOGIN (save this — shown once)            │"
  echo "│    user: admin                                       │"
  echo "│    pass: $ADMIN_PW"
  echo "└──────────────────────────────────────────────────────┘"
fi
chown root:sentinel "$ETC"/*.env 2>/dev/null || true

# ─── systemd units ───
if ! command -v systemctl >/dev/null 2>&1; then
  echo "[!] systemd not available — skipping services. Start manually:"
  echo "    $OPT/.venv/bin/python $OPT/collector/sentinel_hub_lineage.py"
  [[ $HUB_ONLY -eq 0 ]] && echo "    sudo $OPT/.venv/bin/python $OPT/agent/sentinel_lineage_agent.py"
else
  echo "[*] Installing systemd services…"
  install -m 644 "$SRC_DIR/deploy/sentinel-hub.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable --now sentinel-hub

  if [[ $HUB_ONLY -eq 0 ]]; then
    # Kernel prerequisites: warn, don't fail — the hub is still useful.
    [[ -f /sys/kernel/btf/vmlinux ]] \
      || echo "[!] No /sys/kernel/btf/vmlinux — the CO-RE object cannot load (need CONFIG_DEBUG_INFO_BTF=y)."
    grep -qw bpf /sys/kernel/security/lsm 2>/dev/null \
      || echo "[!] 'bpf' is not in the LSM list — LSM hooks will not attach. Boot with lsm=...,bpf."

    install -m 644 "$SRC_DIR/deploy/sentinel-agent.service" /etc/systemd/system/
    systemctl daemon-reload
    systemctl enable sentinel-agent 2>/dev/null || true
    # Agent needs the hub up first; start it, but don't fail install on a headless/VM kernel
    systemctl start sentinel-agent 2>/dev/null \
      && echo "[✓] eBPF agent started" \
      || echo "[!] Agent did not start (no BPF support in this kernel?) — hub is still fully functional"
  fi
fi

# ─── Sync dashboard credentials: env file is the source of truth ───
# (re-installs must never leave the DB row desynced from the env password)
ADMIN_PW_SYNCED=$(grep "^SENTINEL_ADMIN_PASSWORD=" "$ETC/sentinel.env" | head -1 | cut -d= -f2-)
ADMIN_USER_SYNCED=$(grep "^SENTINEL_ADMIN_USER=" "$ETC/sentinel.env" | head -1 | cut -d= -f2-)
"$OPT/.venv/bin/python" - <<PYEOF
import sys
sys.path.insert(0, "$OPT/collector")
import os
os.environ.setdefault("SENTINEL_DB_PATH", "$VARLIB/sentinel.db")
import sentinel_auth as sa
sa.ensure_user("$ADMIN_USER_SYNCED", """$ADMIN_PW_SYNCED""", reset=True)
print("[✓] Dashboard credentials synced to database")
PYEOF

# ─── Verify (poll up to 10s — first start may lag) ───
HUB_OK=0
for i in 1 2 3 4 5 6 7 8 9 10; do
  sleep 1
  if curl -sf http://127.0.0.1:5000/api/v1/stats >/dev/null 2>&1; then HUB_OK=1; break; fi
done
if [[ $HUB_OK -eq 1 ]]; then
  echo "[✓] Hub healthy → http://127.0.0.1:5000/"
else
  echo "[!] Hub not responding after 10s — check: journalctl -u sentinel-hub -n 50"
fi

cat <<EOF

─────────────────────────────────────────────────────────────
  Project SENTINEL installed.

  Dashboard : http://127.0.0.1:5000/   (set SENTINEL_BIND=0.0.0.0 in $ETC/sentinel.env to expose it; put TLS in front)
  Config    : $ETC/sentinel.env
  State     : $VARLIB
  Logs      : journalctl -u sentinel-hub -f
EOF
[[ $HUB_ONLY -eq 0 ]] && echo "  Agent log : journalctl -u sentinel-agent -f"
echo "  Uninstall : sudo $OPT/uninstall.sh"
echo "─────────────────────────────────────────────────────────────"

#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Sentinel Lineage EDR — Linux Installer
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

echo "[*] Sentinel Lineage EDR installer"
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
    apt-get install -y -qq python3 python3-venv python3-pip rsync curl >/dev/null
    if [[ $HUB_ONLY -eq 0 ]]; then
      apt-get install -y -qq bpfcc-tools python3-bcc clang llvm libbpf-dev \
        linux-headers-"$(uname -r)" >/dev/null 2>&1 \
        || echo "[!] eBPF toolchain not packaged for this kernel — install manually if needed."
    fi
    ;;
  dnf|yum)
    $PKG install -y -q python3 python3-pip rsync curl git >/dev/null
    [[ $HUB_ONLY -eq 0 ]] && $PKG install -y -q bcc-tools python3-bcc clang llvm \
      kernel-headers kernel-devel >/dev/null 2>&1 || true
    ;;
  pacman)
    for attempt in 1 2 3; do
      pacman -Sy --noconfirm --needed python python-pip rsync curl >/dev/null && break
      echo "[!] pacman mirror timeout (attempt $attempt/3) — retrying in 5s…"
      sleep 5
    done
    if [[ $HUB_ONLY -eq 0 ]]; then
      pacman -Sy --noconfirm --needed bcc python-bcc clang llvm linux-headers >/dev/null 2>&1 \
        || echo "[!] WARNING: eBPF toolchain failed to install (mirror timeout?). The hub will run, but the agent needs: sudo pacman -Sy bcc python-bcc clang llvm linux-headers"
    fi
    ;;
esac

# ─── Service user ───
if ! id sentinel >/dev/null 2>&1; then
  useradd --system --home-dir "$VARLIB" --shell /usr/sbin/nologin sentinel
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
# --system-site-packages: the agent imports distro BCC bindings (python-bcc),
# which don't exist on PyPI and must come from the system package manager.
python3 -m venv --system-site-packages "$OPT/.venv"
"$OPT/.venv/bin/pip" install --quiet --upgrade pip
if [[ $HUB_ONLY -eq 1 ]]; then
  "$OPT/.venv/bin/pip" install --quiet flask flask-cors pyyaml requests psutil
else
  "$OPT/.venv/bin/pip" install --quiet -r "$OPT/requirements.txt" \
    || "$OPT/.venv/bin/pip" install --quiet flask flask-cors pyyaml requests psutil geoip2
fi
# bcc bindings come from the distro (python-bcc) — visible via --system-site-packages
if [[ $HUB_ONLY -eq 0 ]] && ! "$OPT/.venv/bin/python" -c "import bcc" 2>/dev/null; then
  echo "[!] WARNING: bcc bindings not importable — the eBPF agent will not start until 'python-bcc' (distro package) is installed"
fi
chown -R sentinel:sentinel "$OPT/.venv"
echo "[✓] Python environment ready"

# ─── Config ───
for f in rules.yaml geo_rules.json trusted_binaries.json; do
  [[ -f "$OPT/config/$f" && ! -f "$ETC/$f" ]] && cp "$OPT/config/$f" "$ETC/$f"
done
if [[ ! -f "$ETC/sentinel.env" ]]; then
  sed -e "s#/opt/sentinel/config#$ETC#g" \
      -e "s#^SENTINEL_DB=.*#SENTINEL_DB=$VARLIB/lineage_db.json#" \
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
echo "[*] Installing systemd services…"
install -m 644 "$SRC_DIR/deploy/sentinel-hub.service" /etc/systemd/system/
systemctl daemon-reload
systemctl enable --now sentinel-hub

if [[ $HUB_ONLY -eq 0 ]]; then
  install -m 644 "$SRC_DIR/deploy/sentinel-agent.service" /etc/systemd/system/
  systemctl daemon-reload
  systemctl enable sentinel-agent 2>/dev/null || true
  # Agent needs the hub up first; start it, but don't fail install on a headless/VM kernel
  systemctl start sentinel-agent 2>/dev/null \
    && echo "[✓] eBPF agent started" \
    || echo "[!] Agent did not start (no BPF support in this kernel?) — hub is still fully functional"
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
  Sentinel Lineage EDR installed.

  Dashboard : http://$(hostname -I 2>/dev/null | awk '{print $1}' || echo localhost):5000/
  Config    : $ETC/sentinel.env
  State     : $VARLIB
  Logs      : journalctl -u sentinel-hub -f
EOF
[[ $HUB_ONLY -eq 0 ]] && echo "  Agent log : journalctl -u sentinel-agent -f"
echo "  Uninstall : sudo $OPT/uninstall.sh"
echo "─────────────────────────────────────────────────────────────"

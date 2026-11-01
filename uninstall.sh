#!/usr/bin/env bash
# Sentinel Lineage EDR — Uninstaller
# Removes services, app dir, and (with --purge) config + state.
set -euo pipefail

PURGE=0
[[ "${1:-}" == "--purge" ]] && PURGE=1

echo "[*] Stopping services…"
systemctl disable --now sentinel-agent 2>/dev/null || true
systemctl disable --now sentinel-hub 2>/dev/null || true
rm -f /etc/systemd/system/sentinel-hub.service /etc/systemd/system/sentinel-agent.service
systemctl daemon-reload

echo "[*] Removing application…"
rm -rf /opt/sentinel

if [[ $PURGE -eq 1 ]]; then
  echo "[*] Purging config and state…"
  rm -rf /etc/sentinel /var/lib/sentinel
else
  echo "[=] Config and state kept: /etc/sentinel /var/lib/sentinel"
  echo "    Remove with: sudo rm -rf /etc/sentinel /var/lib/sentinel"
fi

if id sentinel >/dev/null 2>&1; then
  userdel sentinel 2>/dev/null || true
  echo "[✓] Removed system user: sentinel"
fi

echo "[✓] Sentinel Lineage EDR uninstalled."

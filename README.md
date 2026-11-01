# Sentinel Lineage EDR

Root-resistant endpoint detection built on eBPF process-lineage signatures. Every process gets an immutable 64-bit lineage ID inherited from its parent — threats are identified by **who launched them**, not just what they look like, and malicious trees are killed at `execve` before they run.

```
eBPF (kernel)  →  Agent (userspace)  →  Hub + SOC Dashboard (:5000)
```

- **Lineage tracking** — LRU maps pin `pid → lineage`, children inherit the root signature across forks and execves
- **Signature rules** — YAML rules with MITRE ATT&CK tags, severity, and per-rule actions (`SIGKILL`, block-tree, log)
- **Kill-switch** — blocked lineage IDs live in a kernel hash map; the eBPF hook sends `SIGKILL` before the binary executes
- **Exfiltration detection** — covert ICMP channels, DNS tunneling rates, bulk-read volume
- **Geo-blocking** — country allow/block lists on network events
- **SOC dashboard** — real-time SSE feed, lineage force-graph, keyboard-first triage (`j/k`, `Ctrl+K` palette), light/dark, fully offline (no CDN dependencies)

## Install (Linux)

```bash
git clone <repo> sentinel && cd sentinel        # or untar a release
sudo ./install.sh            # full sensor: hub + eBPF agent
sudo ./install.sh --hub-only # collector + dashboard only (VMs/containers)
```

What it does: creates the `sentinel` system user, installs to `/opt/sentinel`, state in `/var/lib/sentinel`, config in `/etc/sentinel/`, enables `sentinel-hub.service` (and `sentinel-agent.service` unless `--hub-only`) via systemd.

Open **`http://<host>:5000/`** — the hub serves the dashboard itself, same-origin API.

### Requirements

| Component | Needs |
|---|---|
| Hub | Python 3.10+, 256 MB RAM — runs anywhere |
| Agent | Linux 5.8+, root, BPF-capable kernel (`CONFIG_BPF_SYSCALL`), clang/llvm + kernel headers to rebuild |

## Configuration

Everything lives in `/etc/sentinel/sentinel.env` (created from `.env.example`):

- `SENTINEL_PORT` — hub port (default 5000)
- `SENTINEL_COLLECTOR_URL` — where the agent ships events
- `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` — optional kill alerts
- Rules: `/etc/sentinel/rules.yaml` · Geo: `/etc/sentinel/geo_rules.json` · Binary allowlist: `/etc/sentinel/trusted_binaries.json`

Restart after edits: `sudo systemctl restart sentinel-hub`

## Authentication

The hub is authenticated out of the box:

- **Dashboard** — sign-in at `/login`; credentials generated at install (printed once) or set via `SENTINEL_ADMIN_PASSWORD`. Sessions are signed cookies (12h) with CSRF protection on every state-changing action.
- **Agents** — POST with an enrollment key (`X-Sentinel-Key` header, value of `SENTINEL_AGENT_KEY` from `/etc/sentinel/sentinel.env`). Unauthenticated ingestion is rejected unless no key is configured (local dev mode, warned at boot).
- **Rate-limited login** — 5 failures locks the source IP for 60s; all logins and admin actions land in the audit log.

If you're locked out locally, reset with: set `SENTINEL_ADMIN_PASSWORD` in `/etc/sentinel/sentinel.env` and `sudo systemctl restart sentinel-hub`.

## Learn vs. Enforce

The header badge toggles the global enforcement mode:

- **Enforce** (default) — rules with `KILL`/`BLOCK` actions execute the kill-switch
- **Learn** — everything is logged and alerted, nothing is killed. Run this for the first 1–2 weeks on a production host to baseline what's normal, then flip to enforce.

The agent polls the hub for the mode every 30s, so one toggle governs the whole sensor.

## Storage

All state lives in one SQLite database (WAL mode): persisted events, lineage history, tiered allowlist (hash pins / distro-publisher / trusted lineages, HMAC-signed distribution), and the audit log. Zero-ops by design — no database server to run.

### Allowlist engine

The allowlist is managed on the hub and distributed to agents as an **HMAC-signed blob** — agents verify the signature before applying, so a compromised HTTP port can't inject trust. Hash-tier entries feed the kernel's `trusted_binaries` eBPF map (checked natively at exec, no userspace latency). Revocations propagate on the next 60s poll: an entry removed on the hub is deleted from the kernel map. Manage entries via `POST /api/v1/allowlist` (admin session + CSRF), or add hashes directly:

```bash
curl -X POST http://localhost:5000/api/v1/allowlist \
  -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -d '{"tier":"hash","value":"<sha256>","label":"our nginx build"}'
```

Binary identification anchors to **content, not paths**: the kernel reads the executing inode, so renamed or bind-mounted impostors don't match pins, and `memfd` (fileless) executables are unallowlisted by definition.

## Simulate attacks (demo/validation)

```bash
/opt/sentinel/tools/simulate_attacks.py 200   # ships synthetic threats to the hub
```

## Production deployment

For enterprise traffic, serve the hub under gunicorn instead of the built-in dev server:

```bash
/opt/sentinel/.venv/bin/pip install gunicorn
# edit /etc/systemd/system/sentinel-hub.service →
#   ExecStart=/opt/sentinel/.venv/bin/gunicorn -w 1 --threads 8 -b 0.0.0.0:5000 sentinel_hub_lineage:app
sudo systemctl daemon-reload && sudo systemctl restart sentinel-hub
```

**`-w 1` is mandatory** — hub state (lineage trees, telemetry ring) is in-process; extra workers would hold separate copies. Scale with threads, not workers. For higher throughput, put nginx in front as a reverse proxy and shard agents across multiple hubs.

## Verify

```bash
systemctl status sentinel-hub sentinel-agent
curl -s http://127.0.0.1:5000/health | jq
curl -s http://127.0.0.1:5000/metrics        # Prometheus-format
```

## Keyboard (dashboard)

`j/k` navigate · `Enter` lineage detail · `/` search · `1-8` severity filters · `9` all · `Ctrl+K` command palette · `Ctrl+T` theme · `b` block lineage · `t` trust · `e` export JSON · `r` refresh

## Uninstall

```bash
sudo /opt/sentinel/uninstall.sh          # keeps config + state
sudo /opt/sentinel/uninstall.sh --purge  # removes everything
```

## Packaging

```bash
make package   # → dist/sentinel-lineage-edr-<version>.tar.gz
```

Deep architecture, eBPF map layout, and rule grammar: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md)

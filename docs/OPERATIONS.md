# Operations guide

How to run SENTINEL day to day: read the console, decide on a lineage, keep the
sensor healthy. For installation see [README](../README.md); for secrets and
trust boundaries see [SECURITY.md](SECURITY.md).

## What the console is for

Three tasks, in order of frequency:

1. **Triage** — scan the feed and notice the event that matters (seconds).
2. **Investigate** — open that event's lineage and understand the chain.
3. **Respond** — block, trust, or export, and know what happened afterwards.

Everything is designed around the lineage id, which is stable and printed on
every event.

## Lineage model

A lineage is created when a process starts with no tracked parent (a login
shell, a service, a container entrypoint). Every descendant joins the same
lineage. The hub keeps the tree (`nodes`, `root_pid`, `first_seen`,
`last_seen`, `threat_count`, `host`, `blocked`, `trusted`).

| State | Shown as | What it means |
|---|---|---|
| monitoring | `monitoring` | seen, no threat, younger than 10 minutes |
| stable | `stable` | seen, no threat, alive longer than 10 minutes |
| threat | `N threats` | at least one rule matched in this tree |
| trusted | `trusted` | operator allowlisted it; alerts suppressed |
| blocked | `blocked` | killed and refused in the kernel; survives restarts |

States are derived, not stored: threat > blocked > trusted > stable/monitoring.
Stability exists so a healthy box does not look suspicious just because it has
lineages open.

## Operations

| Action | Where | Effect |
|---|---|---|
| Block | inspector, right-click, palette | intent to hub, command to agent, SIGKILL whole tree; persisted |
| Trust | same | suppress alerts for the lineage/binary; never kills |
| Inspect | click a row / `Enter` | process tree, events, MITRE, facts |
| Export | `E` or palette | JSON of the currently filtered events |
| Mode | header pill / palette | learn (log only) ⇄ enforce (kill) |
| Diagnostics | empty state, palette | why is the pipeline not delivering |
| Update | palette | staged build + health gate + zero-downtime swap |

Every admin action is written to the audit table with the operator and time.

## Playbooks

### Empty or frozen feed

The console diagnoses it: unit state, telemetry age, kernel BTF/tracefs/LSM,
agent key, DB writability. Follow the first failing check; copy the command.
Manually: `sudo journalctl -u sentinel-agent -n 80 --no-pager`.

### Agent restart loop

`Loader ready … programs=14` followed by `not all programs attached` means the
object loaded but tracepoints could not attach — almost always tracefs:

```bash
sudo mount -t tracefs tracefs /sys/kernel/tracing
sudo systemctl restart sentinel-agent
```

A restart counter climbing in `systemctl status` confirms it. The loader now
names the exact programs that failed.

### Sudden mass of alerts

1. Switch to **learn** (stops kills while you investigate).
2. Check the rule ids in the feed; one rule usually dominates.
3. If benign: trust the lineage (fast) or fix the rule pattern (better).
4. If real: block the root lineage, then export the evidence.

### Enforcement verification

```bash
sudo python3 tools/verify_enforcement.py
```

Runs the kill-switch test in both modes and restores your mode. Do it after
kernel upgrades, rule-pack changes, or updates.

### Updating and rollback

Updates stage into `/opt/sentinel.staging`, boot on `PORT+1`, must pass
`/health`, then swap and reload. The old release keeps serving until the new one
answers, so a failed update is a no-op. Rollback = reinstall the previous tag
with `git checkout <tag> && sudo ./install.sh`.

### Backup

Only two things matter:
- `/etc/sentinel/` (env file: keys + password)
- `/var/lib/sentinel/sentinel.db` (users, audit, lineages)

`sqlite3 /var/lib/sentinel/sentinel.db ".backup /backup/sentinel.db"` is safe
while the hub runs.

## Metrics to watch

| Signal | Healthy | Act when |
|---|---|---|
| agent `Stats: exec=` | climbs with host activity | flat for hours on a busy host |
| `killed_processes` | only rises on real detections | rises without alerts (rule too broad) |
| telemetry age | < 5 min | > 5 min → diagnostics |
| restart counter | stable | climbing → loader/attach problem |
| disk free on `/var/lib` | > 200 MB | below → prune/rotate DB |

## Scaling and retention

Single-node is the default (in-memory + SQLite). Set `SENTINEL_REDIS_URL` to
share state across multiple gunicorn workers or a second hub; telemetry is capped
in memory and rotated on disk. There is no built-in retention policy for the
SQLite store yet — monitor its size if you keep months of history.

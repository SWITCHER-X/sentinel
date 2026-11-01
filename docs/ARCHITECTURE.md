# Project SENTINEL — Signature-Based Process Lineage EDR

## Overview

Project SENTINEL extends the Project SENTINEL eBPF EDR with **signature-based process lineage tracking**. Every process execution gets a unique 64-bit `lineage_id` derived from its parent's lineage, binary path, UID, and timestamp. Children inherit their parent's lineage ID, creating an immutable process tree signature that persists across forks, execves, and container boundaries.

## Architecture

```
┌─────────────────────────────────────────────────────────────────┐
│                     SENTINEL LINEAGE STACK                      │
├─────────────────────────────────────────────────────────────────┤
│                                                                 │
│  ┌──────────────┐    ┌──────────────┐    ┌──────────────┐      │
│  │   eBPF       │    │   Agent      │    │   Collector  │      │
│  │   Kernel     │───▶│   Userspace  │───▶│   Hub (SOC)  │      │
│  │   Module     │    │   Engine     │    │   Dashboard  │      │
│  └──────────────┘    └──────────────┘    └──────────────┘      │
│        │                    │                    │               │
│        ▼                    ▼                    ▼               │
│  ┌──────────────────────────────────────────────────────┐       │
│  │              LINEAGE STATE (Shared)                  │       │
│  │  • LRU Hash: pid → LineageEntry                      │       │
│  │  • LRU Hash: lineage_id → LineageEntry (root)        │       │
│  │  • Hash Map: blocked_lineages (instant kill-switch)  │       │
│  │  • Hash Map: trusted_binaries (SHA256 allowlist)     │       │
│  │  • Ring Buffers: exec, conn, file, alert events      │       │
│  └──────────────────────────────────────────────────────┘       │
│                                                                 │
└─────────────────────────────────────────────────────────────────┘
```

## Lineage ID Generation

```
lineage_id = Hash(parent_lineage_id || binary_path || uid || timestamp_ns)

Hash: SplitMix64-inspired (fast, good distribution)
Seed: 0x9e3779b97f4a7c15 (golden ratio)
```

Properties:
- **Deterministic**: Same inputs → same ID
- **Unique**: Timestamp + path + UID ensures collision resistance
- **Inheritable**: Child's parent_lineage_id = Parent's lineage_id
- **Tamper-evident**: Any binary/UID change creates new lineage

## eBPF Module (`ebpf/sentinel_lineage.bpf.c`)

### Tracepoints
| Tracepoint | Purpose |
|------------|---------|
| `sys_enter_execve` | Create lineage entry, emit exec event |
| `sys_enter_connect` | Network connection with lineage context |
| `sys_enter_openat` | File access with lineage context |
| `sys_exit_execve` | Cleanup on exec failure |
| `sched_process_exit` | Mark lineage as exited |

### LSM Hooks (Root-Resistant)
| Hook | Protection |
|------|------------|
| `task_kill` | Blocks `SIGKILL` to trusted Sentinel processes |
| `file_open` | Monitors sensitive file access (/etc/shadow, SSH keys) |

### Maps
| Map | Type | Purpose |
|-----|------|---------|
| `lineage_map` | LRU_HASH | pid → LineageEntry (65K entries) |
| `lineage_by_id` | LRU_HASH | lineage_id → root LineageEntry |
| `rule_map` | HASH | Rule ID → RuleEntry (1K rules) |
| `trusted_binaries` | HASH | SHA256(binary) → trusted |
| `blocked_lineages` | HASH | lineage_id → blocked (instant kill) |
| `exec_events` | RINGBUF | Process execution events |
| `conn_events` | RINGBUF | Network connections |
| `file_events` | RINGBUF | File accesses |
| `alert_events` | RINGBUF | Kernel-generated alerts |

## Agent (`agent/sentinel_lineage_agent.py`)

### Core Features
- **Lineage Tree Construction**: Builds in-memory process trees with parent/child links
- **Rule Engine**: Regex + binary + lineage + UID matching
- **Instant Kill-Switch**: `SIGKILL` entire lineage tree on match
- **Lineage Blocking**: Blocks all future execves in compromised lineage
- **Persistence**: JSON DB survives restarts
- **Telemetry**: Streams to collector hub via HTTP

### Actions
| Action | Behavior |
|--------|----------|
| `LOG` | Record only |
| `ALERT` | Record + notify (Telegram/Discord) |
| `KILL` | SIGKILL process + all children in lineage |
| `BLOCK` | Add lineage to blocked map (kernel enforces) |
| `QUARANTINE` | Block + restrict network/files (cgroups) |

## Collector Hub (`collector/sentinel_hub_lineage.py`)

### API Endpoints
| Endpoint | Method | Purpose |
|----------|--------|---------|
| `/api/v1/telemetry` | GET/POST | Telemetry ingestion + query |
| `/api/v1/stats` | GET | Aggregated stats + lineage metrics |
| `/api/v1/lineage` | GET | All lineage trees |
| `/api/v1/lineage/<id>` | GET | Specific lineage tree |
| `/api/v1/lineage/<id>/block` | POST | Block entire lineage |
| `/api/v1/lineage/<id>/trust` | POST | Mark lineage trusted |
| `/api/v1/rules` | GET/POST | Rule management |
| `/api/v1/geo` | GET/POST | GeoIP rules |
| `/api/v1/stream` | GET | SSE live feed |

### Dashboard Features
- Real-time telemetry table with filtering (ALL/KILL/GEO/FILE/NET)
- Lineage forest visualization with block/trust actions
- Stats cards: nodes, events, kills, lineages, blocked lineages, criticals
- Cyberpunk Tailwind theme with live SSE updates
- Export JSON, clear feed

## Configuration

### Rules (`config/rules.yaml`)
```yaml
version: "2.0"
rules:
  - id: 1001
    name: "Reverse Shell - nc -e"
    pattern: "nc\\s+-e"
    action: "KILL"
    severity: "CRITICAL"
    flags: 1  # REGEX | CMDLINE

  - id: 5001
    name: "Blocked Lineage Execution"
    action: "KILL"
    severity: "CRITICAL"
    flags: 8  # LINEAGE
    lineage_id: 0  # Set dynamically

  - id: 6001
    name: "Outbound to Blocked Country"
    action: "BLOCK"
    severity: "HIGH"
    flags: 32  # NETWORK
```

### Geo Rules (`config/geo_rules.json`)
```json
{
  "ALLOW": ["US", "CA", "GB", "DE", "FR", "JP"],
  "BLOCK": ["CN", "RU", "KP", "IR", "SY"],
  "MONITOR": ["BR", "IN", "VN", "TR"]
}
```

### Trusted Binaries (`config/trusted_binaries.json`)
```json
{
  "hashes": ["sha256_of_bash", "sha256_of_python3"],
  "paths": ["/usr/bin/bash", "/usr/bin/python3"]
}
```

## Deployment

### Requirements
- Linux kernel 5.10+ with BTF (`CONFIG_DEBUG_INFO_BTF=y`)
- `bcc` Python package (0.37+)
- Root for eBPF attach
- Kernel headers (`linux-headers`)

### Quick Start
```bash
# 1. Install dependencies (Arch)
sudo pacman -S linux-headers bcc python-bcc python-psutil python-yaml python-requests python-geoip2 geoip2-database clang llvm

# 2. Load kernel modules
sudo modprobe bpf
sudo mount -t debugfs none /sys/kernel/debug
sudo mount -t tracefs none /sys/kernel/tracing

# 3. Start collector hub (user)
python3 collector/sentinel_hub_lineage.py
# → http://localhost:5000

# 4. Start agent (root, separate terminal)
sudo python3 agent/sentinel_lineage_agent.py
```

### Remote Deployment (Arch Test PC)
```bash
# Configure target
export ARCH_HOST="arch-test.local"
export ARCH_USER="void"

# Run full deployment
./deploy/deploy_test.sh all

# Or step by step
./deploy/deploy_test.sh ssh      # Setup SSH
./deploy/deploy_test.sh prep     # Install deps
./deploy/deploy_test.sh sync     # Transfer files
./deploy/deploy_test.sh build    # Verify eBPF compile
./deploy/deploy_test.sh test     # Run unit tests
./deploy/deploy_test.sh start    # Start hub
./deploy/deploy_test.sh live     # Run attack sim
./deploy/deploy_test.sh results  # View results
```

## Testing

### Unit Tests (`tests/test_lineage.py`)
```bash
python3 tests/test_lineage.py
```
Tests:
- Lineage ID generation (determinism, variance)
- Parent-child inheritance
- Rule matching (reverse shell, pipe exec, shadow access)
- Lineage blocking propagation
- Trusted binary verification
- Persistence (save/load)
- E2E attack chain simulation

### Live Attack Simulation
The `live` target runs:
1. Benign `ls` (no alert)
2. `curl | bash` pipe execute → **KILL + BLOCK LINEAGE**
3. `bash -i >& /dev/tcp/...` reverse shell → **KILL**
4. `sudo cat /etc/shadow` → **KILL**

All processes in the attack lineage get blocked at kernel level.

## Performance

| Metric | Target |
|--------|--------|
| eBPF overhead | < 1% CPU |
| Ring buffer latency | < 1ms |
| Lineage lookup (LRU) | O(1) |
| Rule matching | ~50 rules in < 100μs |
| Memory (65K entries) | ~50 MB |
| Kill-switch latency | < 10ms (kernel enforce) |

## Root Resistance

The LSM `task_kill` hook prevents threat actors with root/sudo from killing Sentinel processes:
- Only processes in the **same trusted lineage** can kill each other
- `blocked_lineages` map enforced in kernel — even root cannot exec in blocked lineage
- Lineage IDs cannot be forged (kernel-generated at execve)

## Files

```
Sentinel/
├── ebpf/
│   └── sentinel_lineage.bpf.c   # Lineage eBPF
├── agent/
│   └── sentinel_lineage_agent.py # Lineage agent
├── collector/
│   └── sentinel_hub_lineage.py   # Lineage hub
├── config/
│   ├── rules.yaml               # 30+ detection rules
│   ├── geo_rules.json           # GeoIP allow/block/monitor
│   └── trusted_binaries.json    # SHA256 allowlist
├── tests/
│   └── test_lineage.py          # Unit test suite
├── deploy/
│   └── deploy_test.sh           # Remote deployment script
└── README_LINEAGE.md            # This file
```

## License

All rights reserved. © 2026 Ayuba Charles Medugu. The source is published for
review and evaluation only — see [LICENSE](../LICENSE).

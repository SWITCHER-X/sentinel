#!/bin/bash
# Oracle Cloud Free Tier ARM - Project SENTINEL bootstrap
# Run as: sudo bash sentinel-oracle-bootstrap.sh
# Or paste into "Cloud-init" / "User data" when creating instance

set -euo pipefail

echo "[*] Updating apt..."
apt-get update -y

echo "[*] Installing kernel headers (exact match)..."
apt-get install -y linux-headers-$(uname -r)

echo "[*] Installing eBPF toolchain..."
apt-get install -y \
  clang llvm libbpf-dev bpftool \
  python3 python3-venv python3-pip \
  linux-tools-common linux-tools-$(uname -r) \
  linux-tools-generic \
  bpfcc-tools python3-bcc \
  git curl wget

echo "[*] Mounting debugfs & tracefs (persistent)..."
mkdir -p /sys/kernel/debug /sys/kernel/tracing
mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
mount -t tracefs none /sys/kernel/tracing 2>/dev/null || true

# Make mounts persistent
grep -q "debugfs" /etc/fstab || echo "debugfs /sys/kernel/debug debugfs defaults 0 0" >> /etc/fstab
grep -q "tracefs" /etc/fstab || echo "tracefs /sys/kernel/tracing tracefs defaults 0 0" >> /etc/fstab

echo "[*] Verifying BTF support..."
if [ -f /sys/kernel/btf/vmlinux ]; then
  echo "  ✓ BTF vmlinux found: /sys/kernel/btf/vmlinux"
else
  echo "  ⚠ BTF not found — CO-RE may not work. Check kernel config."
fi

echo "[*] Cloning Sentinel..."
cd /opt
git clone https://github.com/SWITCHER-X/sentinel-lineage-edr.git
cd sentinel-lineage-edr

echo "[*] Building eBPF program..."
make build

echo "[*] Installing Python deps..."
pip3 install -r requirements.txt

echo "[*] Running unit tests..."
python3 tests/test_lineage.py

echo ""
echo "=========================================="
echo "  ✓ Bootstrap complete"
echo "=========================================="
echo ""
echo "To run the agent (requires root):"
echo "  cd /opt/sentinel-lineage-edr"
echo "  sudo python3 agent/sentinel_lineage_agent.py"
echo ""
echo "To run the collector hub:"
echo "  python3 collector/sentinel_hub_lineage.py"
echo ""
echo "To simulate attacks:"
echo "  python3 tools/simulate_attacks.py 200"
echo ""
echo "Dashboard: http://<instance-ip>:5000"
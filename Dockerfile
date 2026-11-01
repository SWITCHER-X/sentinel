# Project SENTINEL - Dockerfile
# Multi-stage build for eBPF compilation and runtime

# ─── Build Stage ───
FROM alpine:3.20 AS builder

# Install build dependencies
RUN apk add --no-cache \
    clang \
    llvm \
    linux-headers \
    bpftool \
    make \
    git

WORKDIR /build

# Copy eBPF source
COPY ebpf/sentinel_lineage_core.bpf.c ebpf/vmlinux.h ./

# Compile eBPF program
RUN mkdir -p /build/out && \
    clang -target bpf -D__TARGET_ARCH_x86 -I. -I/usr/include/bpf \
    -Wall -O2 -g -c sentinel_lineage_core.bpf.c -o /build/out/sentinel_lineage_core.o

# ─── Runtime Stage ───
FROM python:3.12-slim-bookworm

# Install runtime dependencies
RUN apt-get update && apt-get install -y --no-install-recommends \
    linux-headers-$(uname -r) \
    bcc \
    python3-bcc \
    python3-psutil \
    python3-yaml \
    python3-requests \
    python3-geoip2 \
    geoip-database \
    libbpf-dev \
    iproute2 \
    iptables \
    curl \
    && rm -rf /var/lib/apt/lists/*

# Install Python packages
RUN pip install --no-cache-dir \
    flask \
    flask-cors \
    geoip2 \
    pyyaml \
    requests \
    psutil

# Create sentinel user
RUN useradd -m -s /bin/bash sentinel

# Set working directory
WORKDIR /opt/sentinel

# Copy project files
COPY --from=builder /build/out/sentinel_lineage_core.o ./ebpf/
COPY agent/ ./agent/
COPY collector/ ./collector/
COPY config/ ./config/
COPY tests/ ./tests/
COPY deploy/ ./deploy/
COPY Makefile ./

# Create necessary directories
RUN mkdir -p /var/lib/sentinel /var/log/sentinel && \
    chown -R sentinel:sentinel /opt/sentinel /var/lib/sentinel /var/log/sentinel

# Copy eBPF source for runtime compilation (BCC compiles at runtime)
COPY ebpf/sentinel_lineage_core.bpf.c ebpf/vmlinux.h .//ebpf/

# Environment variables
ENV SENTINEL_CONFIG=/opt/sentinel/config/rules.yaml \
    SENTINEL_GEO_RULES=/opt/sentinel/config/geo_rules.json \
    SENTINEL_DB=/var/lib/sentinel/lineage_db.json \
    SENTINEL_TRUSTED=/opt/sentinel/config/trusted_binaries.json \
    SENTINEL_EBPF=/opt/sentinel/ebpf/sentinel_lineage.bpf.c \
    SENTINEL_COLLECTOR_URL=http://0.0.0.0:5000/api/v1/telemetry

# Expose collector hub port
EXPOSE 5000

# Health check
HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://localhost:5000/api/v1/stats || exit 1

# Default command runs collector hub
USER sentinel
CMD ["python3", "collector/sentinel_hub_lineage.py"]

# ─── Agent Stage (requires privileged) ───
# To run agent: docker run --privileged --pid=host --cgroupns=host -v /sys/kernel:/sys/kernel:ro sentinel-lineage python3 agent/sentinel_lineage_agent.py
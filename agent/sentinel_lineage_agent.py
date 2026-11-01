#!/usr/bin/env python3
"""
Project SENTINEL Agent - Signature-based process lineage tracking
Integrates with eBPF lineage module for enterprise-grade process tree monitoring
"""

import os
import sys
import signal
import json
import time
import re
import yaml
import hashlib
import hmac
import threading
import urllib.request
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple
from bcc import BPF
from bcc.utils import printb

# ─── Configuration ───
import os

_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_SCRIPT_DIR)

CONFIG_PATH = os.getenv("SENTINEL_CONFIG", os.path.join(_PROJECT_DIR, "config", "rules.yaml"))
GEO_RULES_FILE = os.getenv("SENTINEL_GEO_RULES", os.path.join(_PROJECT_DIR, "config", "geo_rules.json"))
LINEAGE_DB_PATH = os.getenv("SENTINEL_DB", os.path.join(_SCRIPT_DIR, "lineage_db.json"))
TRUSTED_BINARIES_FILE = os.getenv("SENTINEL_TRUSTED", os.path.join(_PROJECT_DIR, "config", "trusted_binaries.json"))
EBPF_SOURCE_CORE = os.getenv("SENTINEL_EBPF_CORE", os.path.join(_PROJECT_DIR, "ebpf", "sentinel_lineage_core.bpf.c"))
EBPF_SOURCE_LEGACY = os.getenv("SENTINEL_EBPF", os.path.join(_PROJECT_DIR, "ebpf", "sentinel_lineage.bpf.c"))

# Default to CO-RE (works everywhere with BTF)
EBPF_SOURCE = EBPF_SOURCE_CORE
COLLECTOR_URL = os.getenv("SENTINEL_COLLECTOR_URL", "http://127.0.0.1:5000/api/v1/telemetry")

# ─── Enforcement mode (learn = observe-only; hub is the source of truth) ───
ENFORCEMENT_MODE = "enforce"

def _mode_poller():
    """Refresh enforcement mode from the hub every 30s. Learn mode downgrades
    every KILL/BLOCK/QUARANTINE to LOG — observe, never enforce."""
    global ENFORCEMENT_MODE
    base = COLLECTOR_URL.rsplit("/api/", 1)[0]
    while True:
        try:
            req = urllib.request.Request(f"{base}/api/v1/mode", method="GET")
            with urllib.request.urlopen(req, timeout=5) as r:
                mode = json.loads(r.read()).get("mode")
                if mode in ("learn", "enforce") and mode != ENFORCEMENT_MODE:
                    ENFORCEMENT_MODE = mode
                    print(f"[*] enforcement mode → {mode}", flush=True)
        except Exception:
            pass  # hub down → keep last known mode
        time.sleep(30)

threading.Thread(target=_mode_poller, daemon=True).start()

# ─── Signed allowlist engine ───
# The hub owns the tiered allowlist (hash pins / publisher / lineage contexts)
# and distributes it as an HMAC-signed blob. The agent verifies the signature
# BEFORE applying — an attacker who can reach the hub's HTTP port cannot inject
# trust. Hash-tier entries feed the kernel's trusted_binaries map (fast path).
ALLOWLIST_KEY_FILE = os.getenv("SENTINEL_ALLOWLIST_KEY_FILE",
                               os.path.join(_PROJECT_DIR, "config", "allowlist.key"))
_trusted_bpf_map = None          # set in main() once eBPF is loaded
_applied_allow_hashes: set = set()

def _allowlist_key() -> bytes:
    key = os.getenv("SENTINEL_ALLOWLIST_KEY", "")
    if key:
        return key.encode()
    try:
        with open(ALLOWLIST_KEY_FILE) as f:
            k = f.read().strip()
        if k:
            return k.encode()
    except OSError:
        pass
    return b""

def verify_allowlist_blob(blob: dict, signature: str) -> bool:
    body = json.dumps(blob, sort_keys=True, separators=(",", ":")).encode()
    return hmac.compare_digest(
        hmac.new(_allowlist_key(), body, hashlib.sha256).hexdigest(), signature or "")

def _apply_hash_allowlist(hashes: set):
    """Diff new hash pins into the kernel trusted map (adds + revocations)."""
    global trusted_hashes, _applied_allow_hashes, _trusted_bpf_map
    trusted_hashes |= hashes
    if _trusted_bpf_map is None:
        return
    for h in hashes - _applied_allow_hashes:
        try:
            _trusted_bpf_map[int(h[:16], 16).to_bytes(8, "little")] = b"\x01"
            _applied_allow_hashes.add(h)
        except Exception:
            pass
    # revocations: entries applied earlier but no longer in the signed list
    for h in _applied_allow_hashes - hashes:
        try:
            del _trusted_bpf_map[int(h[:16], 16).to_bytes(8, "little")]
            _applied_allow_hashes.discard(h)
        except (KeyError, Exception):
            pass

def _allowlist_poller():
    """Fetch + verify the signed allowlist from the hub every 60s."""
    base = COLLECTOR_URL.rsplit("/api/", 1)[0]
    while True:
        try:
            with urllib.request.urlopen(f"{base}/api/v1/allowlist", timeout=5) as r:
                payload = json.loads(r.read())
            blob = {"entries": payload.get("entries", []),
                    "generated_at": payload.get("generated_at", 0)}
            sig = payload.get("signature", "")
            if sig and verify_allowlist_blob(blob, sig):
                hashes = {e["value"] for e in blob["entries"] if e.get("tier") == "hash"
                          and len(e.get("value", "")) == 64}
                _apply_hash_allowlist(hashes)
            else:
                print("[-] allowlist signature INVALID — keeping previous allowlist", flush=True)
        except Exception:
            pass  # hub down → keep last known allowlist
        time.sleep(60)

threading.Thread(target=_allowlist_poller, daemon=True).start()
BLOCKED_COUNTRIES = ["CN", "RU", "KP", "IR"]

# ─── Data Structures ───
@dataclass
class LineageEntry:
    lineage_id: int
    parent_lineage_id: int
    pid: int
    ppid: int
    uid: int
    gid: int
    ns_pid: int
    comm: str
    binary_path: str
    cmdline: str
    exec_timestamp: float
    flags: int
    rule_matched: int = 0
    children: List[int] = field(default_factory=list)
    exited: bool = False
    alerts: List[dict] = field(default_factory=list)

@dataclass
class Rule:
    id: int
    name: str
    pattern: str
    binary_pattern: str = ""
    action: str = "KILL"
    severity: str = "HIGH"
    lineage_id: int = 0
    flags: int = 0
    uid_min: int = 0
    uid_max: int = 0
    compiled_pattern: Optional[re.Pattern] = None
    compiled_binary: Optional[re.Pattern] = None

# ─── Global State ───
lineage_tree: Dict[int, LineageEntry] = {}  # pid -> entry
lineage_by_id: Dict[int, LineageEntry] = {}  # lineage_id -> root entry
rules: List[Rule] = []
trusted_hashes: Set[str] = set()
blocked_lineages: Set[int] = set()
geo_rules: Dict = {"ALLOW": [], "BLOCK": []}
telemetry_buffer: deque = deque(maxlen=10000)
stats = {
    "exec_events": 0,
    "conn_events": 0,
    "file_events": 0,
    "alerts": 0,
    "killed": 0,
    "blocked_lineages": 0,
    "start_time": time.time()
}
stats_lock = threading.Lock()
bpf: Optional[BPF] = None
running = True

# ─── Lineage Flag Constants ───
LF_ROOT = 1 << 0
LF_SUID = 1 << 1
LF_CONTAINER = 1 << 2
LF_SUSPICIOUS = 1 << 3
LF_KILLED = 1 << 4
LF_TRUSTED = 1 << 5
LF_ANONYMOUS = 1 << 6

# ─── Rule Flag Constants ───
RF_REGEX = 1 << 0
RF_CMDLINE = 1 << 1
RF_BINARY = 1 << 2
RF_LINEAGE = 1 << 3
RF_UID_RANGE = 1 << 4
RF_NETWORK = 1 << 5
RF_FILE_WRITE = 1 << 6

ACTION_MAP = {"LOG": 0, "ALERT": 1, "KILL": 2, "BLOCK": 3, "QUARANTINE": 4}
SEVERITY_MAP = {"INFO": 0, "LOW": 1, "MEDIUM": 2, "HIGH": 3, "CRITICAL": 4}


# ─── Utility Functions ───
def hash_binary(path: str) -> str:
    """Generate SHA256 hash of binary for trust verification"""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""

def load_trusted_binaries():
    """Load trusted binary hashes from config"""
    global trusted_hashes
    trusted_file = TRUSTED_BINARIES_FILE
    if os.path.exists(trusted_file):
        try:
            with open(trusted_file, "r") as f:
                data = json.load(f)
                trusted_hashes = set(data.get("hashes", []))
            print(f"[*] Loaded {len(trusted_hashes)} trusted binary hashes")
        except Exception as e:
            print(f"[-] Failed to load trusted binaries: {e}")

def save_lineage_db():
    """Persist lineage tree to disk"""
    try:
        data = {
            "lineages": {str(k): asdict(v) for k, v in lineage_tree.items()},
            "lineage_by_id": {str(k): asdict(v) for k, v in lineage_by_id.items()},
            "blocked_lineages": list(blocked_lineages),
            "saved_at": time.time()
        }
        with open(LINEAGE_DB_PATH, "w") as f:
            json.dump(data, f, indent=2)
    except Exception as e:
        print(f"[-] Failed to save lineage DB: {e}")

def load_lineage_db():
    """Load lineage tree from disk"""
    global lineage_tree, lineage_by_id, blocked_lineages
    if not os.path.exists(LINEAGE_DB_PATH):
        return
    try:
        with open(LINEAGE_DB_PATH, "r") as f:
            data = json.load(f)
        for k, v in data.get("lineages", {}).items():
            lineage_tree[int(k)] = LineageEntry(**v)
        for k, v in data.get("lineage_by_id", {}).items():
            lineage_by_id[int(k)] = LineageEntry(**v)
        blocked_lineages = set(data.get("blocked_lineages", []))
        print(f"[*] Loaded lineage DB: {len(lineage_tree)} processes, {len(lineage_by_id)} trees, {len(blocked_lineages)} blocked")
    except Exception as e:
        print(f"[-] Failed to load lineage DB: {e}")

def load_rules():
    global rules
    if not os.path.exists(CONFIG_PATH):
        return []
    try:
        with open(CONFIG_PATH, "r") as f:
            data = yaml.safe_load(f)
        raw_rules = data.get("rules", [])
        rules = []
        for r in raw_rules:
            rule = Rule(
                id=r.get("id", 0),
                name=r.get("name", ""),
                pattern=r.get("pattern", ""),
                binary_pattern=r.get("binary_pattern", ""),
                action=r.get("action", "KILL"),
                severity=r.get("severity", "HIGH"),
                lineage_id=r.get("lineage_id", 0),
                flags=r.get("flags", 0),
                uid_min=r.get("uid_min", 0),
                uid_max=r.get("uid_max", 0),
            )
            if rule.pattern and (rule.flags & RF_REGEX):
                try:
                    rule.compiled_pattern = re.compile(rule.pattern, re.IGNORECASE)
                except Exception:
                    rule.compiled_pattern = None
            if rule.binary_pattern and (rule.flags & RF_REGEX):
                try:
                    rule.compiled_binary = re.compile(rule.binary_pattern, re.IGNORECASE)
                except Exception:
                    rule.compiled_binary = None
            rules.append(rule)
        print(f"[*] Loaded {len(rules)} detection rules")
    except Exception as e:
        print(f"[-] Failed loading rules: {e}")

def load_geo_rules():
    global geo_rules
    if os.path.exists(GEO_RULES_FILE):
        try:
            with open(GEO_RULES_FILE, "r") as f:
                geo_rules = json.load(f)
        except Exception:
            geo_rules = {"ALLOW": [], "BLOCK": []}

def dispatch_telemetry(payload: dict):
    """Send telemetry to collector hub"""
    try:
        data = json.dumps(payload).encode("utf-8")
        req = urllib.request.Request(
            COLLECTOR_URL,
            data=data,
            headers={"Content-Type": "application/json", "User-Agent": "Sentinel-Lineage-Agent"}
        )
        with urllib.request.urlopen(req, timeout=2):
            pass
    except Exception as e:
        print(f"[-] Telemetry dispatch error: {e}")

def match_rule(entry: LineageEntry, rule: Rule) -> bool:
    """Check if lineage entry matches rule"""
    # Lineage ID match
    if rule.flags & RF_LINEAGE:
        if rule.lineage_id != 0:
            if entry.lineage_id != rule.lineage_id and entry.parent_lineage_id != rule.lineage_id:
                return False
        else:
            # Dynamic lineage rule - lineage_id will be set at runtime
            # Don't match anything until populated via API
            return False

    # UID range match
    if rule.flags & RF_UID_RANGE:
        if rule.uid_min and entry.uid < rule.uid_min:
            return False
        if rule.uid_max and entry.uid > rule.uid_max:
            return False

    # Binary pattern match
    if rule.flags & RF_BINARY:
        if not rule.binary_pattern:
            return False  # Flag set but no pattern = no match
        target = entry.binary_path
        if rule.compiled_binary:
            if not rule.compiled_binary.search(target):
                return False
        elif rule.binary_pattern.lower() not in target.lower():
            return False

    # Cmdline pattern match
    if rule.flags & RF_CMDLINE:
        if not rule.pattern:
            return False  # Flag set but no pattern = no match
        target = entry.cmdline
        if rule.compiled_pattern:
            if not rule.compiled_pattern.search(target):
                return False
        elif rule.pattern.lower() not in target.lower():
            return False

    # If rule has no matching criteria at all, it should not match
    # (e.g., placeholder rules with flags=0)
    if rule.flags == 0:
        return False

    return True

def handle_exec_event(cpu, data, size):
    """Handle process execution event from eBPF"""
    global stats
    event = bpf["exec_events"].event(data)

    pid = event.pid
    ppid = event.ppid
    uid = event.uid
    ns_pid = event.ns_pid
    lineage_id = event.lineage_id
    parent_lineage_id = event.parent_lineage_id
    comm = event.comm.decode('utf-8', 'replace').strip()
    binary_path = event.filename.decode('utf-8', 'replace').strip()
    cmdline = event.cmdline.decode('utf-8', 'replace').strip() if hasattr(event, 'cmdline') else f"{comm} {binary_path}"

    with stats_lock:
        stats["exec_events"] += 1

    # Create lineage entry
    entry = LineageEntry(
        lineage_id=lineage_id,
        parent_lineage_id=parent_lineage_id,
        pid=pid,
        ppid=ppid,
        uid=uid,
        gid=0,  # Would need from event
        ns_pid=ns_pid,
        comm=comm,
        binary_path=binary_path,
        cmdline=cmdline,
        exec_timestamp=time.time(),
        flags=0  # Would come from event
    )
    
    # Check trusted binary
    if hash_binary(binary_path) in trusted_hashes:
        entry.flags |= LF_TRUSTED
    
    if uid == 0:
        entry.flags |= LF_ROOT
    
    # Build lineage tree
    lineage_tree[pid] = entry
    lineage_by_id[lineage_id] = entry
    
    # Link to parent
    if ppid in lineage_tree:
        lineage_tree[ppid].children.append(pid)
    
    # Rule matching
    for rule in rules:
        if match_rule(entry, rule):
            entry.rule_matched = rule.id
            entry.flags |= LF_SUSPICIOUS
            
            alert = {
                "type": "EXEC_THREAT",
                "rule_id": rule.id,
                "rule_name": rule.name,
                "severity": rule.severity,
                "pid": pid,
                "ppid": ppid,
                "ns_pid": ns_pid,
                "lineage_id": lineage_id,
                "parent_lineage_id": parent_lineage_id,
                "comm": comm,
                "binary_path": binary_path,
                "cmdline": entry.cmdline,
                "killed": False,
                "action": rule.action,
                "timestamp": time.time()
            }
            
            entry.alerts.append(alert)
            telemetry_buffer.append(alert)
            dispatch_telemetry(alert)
            
            with stats_lock:
                stats["alerts"] += 1
            
            # Execute action (learn mode downgrades enforcement to logging)
            if ENFORCEMENT_MODE == "learn":
                alert["action"] = "LOG"
                alert["tags"] = list(set((alert.get("tags") or []) + ["learn-mode"]))
                entry.alerts[-1]["action"] = "LOG"
                print(f"[-] LEARN MODE (no enforcement): {rule.name} -> PID {pid}")
            elif rule.action == "KILL":
                kill_process(pid, entry, rule)
            elif rule.action == "BLOCK":
                block_lineage(lineage_id, rule)
            elif rule.action == "QUARANTINE":
                quarantine_lineage(lineage_id, entry, rule)
            
            print(f"[!] RULE MATCH: {rule.name} (ID:{rule.id}) -> PID {pid} ({comm}) Lineage:{lineage_id:#x}")
            break
    else:
        # No rule matched - log normal execution
        log_entry = {
            "type": "EXEC_LOG",
            "rule_id": "INFO",
            "rule_name": "Process Execution",
            "severity": "INFO",
            "pid": pid,
            "ppid": ppid,
            "ns_pid": ns_pid,
            "lineage_id": lineage_id,
            "parent_lineage_id": parent_lineage_id,
            "comm": comm,
            "binary_path": binary_path,
            "cmdline": entry.cmdline,
            "killed": False,
            "action": "LOG",
            "timestamp": time.time()
        }
        telemetry_buffer.append(log_entry)
        dispatch_telemetry(log_entry)

def handle_conn_event(cpu, data, size):
    """Handle network connection event"""
    global stats
    event = bpf["conn_events"].event(data)
    
    pid = event.pid
    ns_pid = event.ns_pid
    lineage_id = event.lineage_id
    comm = event.comm.decode('utf-8', 'replace').strip()
    daddr = event.daddr
    dport = event.dport

    with stats_lock:
        stats["conn_events"] += 1

    # Track DNS queries (port 53) for tunneling detection
    if dport == 53 or dport == 5353:  # DNS and mDNS
        try:
            dns_map = bpf["dns_queries"]
            key = pid.to_bytes(4, 'little')
            current = dns_map[key].value if key in dns_map else 0
            dns_map[key] = (current + 1).to_bytes(8, 'little')
        except Exception:
            pass

    # Check geo-blocking
    # Would need geoip lookup here
    
    # Check rules for network
    entry = lineage_tree.get(pid)
    if entry:
        for rule in rules:
            if rule.flags & RF_NETWORK and match_rule(entry, rule):
                alert = {
                    "type": "NETWORK_THREAT",
                    "rule_id": rule.id,
                    "rule_name": rule.name,
                    "severity": rule.severity,
                    "pid": pid,
                    "ns_pid": ns_pid,
                    "lineage_id": lineage_id,
                    "comm": comm,
                    "daddr": daddr,
                    "dport": dport,
                    "killed": False,
                    "action": rule.action,
                    "timestamp": time.time()
                }
                telemetry_buffer.append(alert)
                dispatch_telemetry(alert)
                with stats_lock:
                    stats["alerts"] += 1
                break

def handle_file_event(cpu, data, size):
    """Handle file access event"""
    global stats
    event = bpf["file_events"].event(data)
    
    pid = event.pid
    ns_pid = event.ns_pid
    lineage_id = event.lineage_id
    comm = event.comm.decode('utf-8', 'replace').strip()
    path = event.path.decode('utf-8', 'replace').strip()
    flags = event.flags
    
    with stats_lock:
        stats["file_events"] += 1
    
    # Check for sensitive file access
    sensitive_paths = ["/etc/shadow", "/etc/passwd", "/etc/sudoers", "/root/.ssh", "/home/*/.ssh"]
    for sp in sensitive_paths:
        if sp.replace("*", "") in path:
            alert = {
                "type": "FILE_THREAT",
                "rule_id": "SENSITIVE_FILE",
                "rule_name": f"Sensitive File Access: {path}",
                "severity": "HIGH",
                "pid": pid,
                "ns_pid": ns_pid,
                "lineage_id": lineage_id,
                "comm": comm,
                "path": path,
                "flags": flags,
                "killed": False,
                "action": "ALERT",
                "timestamp": time.time()
            }
            telemetry_buffer.append(alert)
            dispatch_telemetry(alert)
            with stats_lock:
                stats["alerts"] += 1
            break

def handle_alert_event(cpu, data, size):
    """Handle alert from eBPF (blocked lineage, etc.)"""
    event = bpf["alert_events"].event(data)
    # Process alert from kernel
    pass

def handle_icmp_event(cpu, data, size):
    """Handle ICMP event from eBPF (covert channel detection)"""
    global stats
    event = bpf["icmp_events"].event(data)

    pid = event.pid
    ns_pid = event.ns_pid
    lineage_id = event.lineage_id
    comm = event.comm.decode('utf-8', 'replace').strip()
    icmp_type = event.type
    icmp_code = event.code
    daddr = event.daddr
    icmp_id = event.id
    icmp_seq = event.seq
    data_len = event.data_len

    with stats_lock:
        stats["alerts"] += 1

    # ICMP echo request (type 8) with large payload = potential covert channel
    if icmp_type == 8 and data_len > 64:
        alert = {
            "type": "ICMP_COVERT_CHANNEL",
            "rule_id": "ICMP_EXFIL",
            "rule_name": f"ICMP Exfiltration Attempt (payload={data_len}B)",
            "severity": "HIGH",
            "pid": pid,
            "ns_pid": ns_pid,
            "lineage_id": lineage_id,
            "comm": comm,
            "daddr": daddr,
            "icmp_type": icmp_type,
            "icmp_code": icmp_code,
            "icmp_id": icmp_id,
            "icmp_seq": icmp_seq,
            "data_len": data_len,
            "killed": False,
            "action": "ALERT",
            "timestamp": time.time()
        }
        telemetry_buffer.append(alert)
        dispatch_telemetry(alert)
        print(f"[!] ICMP COVERT CHANNEL: PID {pid} ({comm}) -> {daddr} payload={data_len}B")

def kill_process(pid: int, entry: LineageEntry, rule: Rule):
    """Kill process and all children in lineage"""
    try:
        # Kill the process
        os.kill(pid, signal.SIGKILL)
        entry.flags |= LF_KILLED
        entry.exited = True
        
        # Kill all children in lineage tree
        killed_pids = [pid]
        for child_pid in entry.children:
            try:
                os.kill(child_pid, signal.SIGKILL)
                if child_pid in lineage_tree:
                    lineage_tree[child_pid].flags |= LF_KILLED
                    lineage_tree[child_pid].exited = True
                killed_pids.append(child_pid)
            except ProcessLookupError:
                pass
        
        # Block entire lineage
        block_lineage(entry.lineage_id, rule)
        
        with stats_lock:
            stats["killed"] += 1 + len(killed_pids) - 1
        
        print(f"[!] KILLED lineage {entry.lineage_id:#x}: PID {pid} + {len(killed_pids)-1} children")
        
    except ProcessLookupError:
        pass
    except Exception as e:
        print(f"[-] Kill failed: {e}")

def block_lineage(lineage_id: int, rule: Rule):
    """Block entire lineage tree"""
    global blocked_lineages
    blocked_lineages.add(lineage_id)
    
    # Update BPF map
    try:
        key = lineage_id.to_bytes(8, 'little')
        bpf["blocked_lineages"][key] = b'\x01'
    except Exception as e:
        print(f"[-] Failed to update blocked_lineages map: {e}")
    
    # Kill all processes in this lineage
    for pid, entry in list(lineage_tree.items()):
        if entry.lineage_id == lineage_id or entry.parent_lineage_id == lineage_id:
            try:
                os.kill(pid, signal.SIGKILL)
                entry.flags |= LF_KILLED
                entry.exited = True
            except ProcessLookupError:
                pass
    
    with stats_lock:
        stats["blocked_lineages"] += 1
    
    print(f"[!] BLOCKED lineage {lineage_id:#x} (Rule: {rule.name})")

def quarantine_lineage(lineage_id: int, entry: LineageEntry, rule: Rule):
    """Quarantine lineage - restrict network, file access"""
    # Implementation: could use cgroups, network namespace isolation, etc.
    block_lineage(lineage_id, rule)
    print(f"[!] QUARANTINED lineage {lineage_id:#x}")

def periodic_save():
    """Periodically save lineage DB"""
    while running:
        time.sleep(30)
        save_lineage_db()

def print_stats():
    """Print periodic statistics"""
    while running:
        time.sleep(10)
        with stats_lock:
            uptime = int(time.time() - stats["start_time"])
            print(f"[*] Stats: exec={stats['exec_events']} conn={stats['conn_events']} "
                  f"file={stats['file_events']} alerts={stats['alerts']} "
                  f"killed={stats['killed']} blocked_lineages={stats['blocked_lineages']} "
                  f"uptime={uptime}s lineages={len(lineage_by_id)}")

def check_anomalies():
    """Periodic anomaly detection: DNS entropy, data volume, ICMP"""
    import math
    from collections import Counter

    DNS_ENTROPY_THRESHOLD = 3.5  # bits per char
    DNS_LENGTH_THRESHOLD = 50    # subdomain length
    DNS_RATE_THRESHOLD = 100     # queries per minute
    DATA_VOLUME_THRESHOLD = 100 * 1024 * 1024  # 100 MB

    while running:
        time.sleep(60)  # Check every minute

        # Check data volume per PID
        try:
            vol_map = bpf["data_volume"]
            for k, v in vol_map.items():
                pid = int.from_bytes(k, 'little')
                bytes_sent = v.value
                if bytes_sent > DATA_VOLUME_THRESHOLD:
                    entry = lineage_tree.get(pid)
                    if entry:
                        alert = {
                            "type": "DATA_EXFILTRATION_VOLUME",
                            "rule_id": "DATA_VOLUME_HIGH",
                            "rule_name": f"High Data Volume: {bytes_sent / (1024*1024):.1f} MB",
                            "severity": "HIGH",
                            "pid": pid,
                            "ns_pid": entry.ns_pid,
                            "lineage_id": entry.lineage_id,
                            "comm": entry.comm,
                            "binary_path": entry.binary_path,
                            "bytes_sent": bytes_sent,
                            "killed": False,
                            "action": "ALERT",
                            "timestamp": time.time()
                        }
                        telemetry_buffer.append(alert)
                        dispatch_telemetry(alert)
                        print(f"[!] HIGH DATA VOLUME: PID {pid} ({entry.comm}) sent {bytes_sent / (1024*1024):.1f} MB")
        except Exception as e:
            pass

        # Check DNS queries for entropy/length anomalies
        # This would require hooking getaddrinfo or monitoring port 53
        # For now, we track via conn_events to port 53
        try:
            dns_map = bpf["dns_queries"]
            for k, v in dns_map.items():
                pid = int.from_bytes(k, 'little')
                query_count = v.value
                if query_count > DNS_RATE_THRESHOLD:
                    entry = lineage_tree.get(pid)
                    if entry:
                        alert = {
                            "type": "DNS_TUNNELING_RATE",
                            "rule_id": "DNS_RATE_HIGH",
                            "rule_name": f"High DNS Query Rate: {query_count}/min",
                            "severity": "HIGH",
                            "pid": pid,
                            "ns_pid": entry.ns_pid,
                            "lineage_id": entry.lineage_id,
                            "comm": entry.comm,
                            "query_count": query_count,
                            "killed": False,
                            "action": "ALERT",
                            "timestamp": time.time()
                        }
                        telemetry_buffer.append(alert)
                        dispatch_telemetry(alert)
                        print(f"[!] HIGH DNS RATE: PID {pid} ({entry.comm}) {query_count} queries/min")
        except Exception as e:
            pass

def signal_handler(sig, frame):
    global running
    print("\n[*] Shutting down...")
    running = False
    save_lineage_db()
    if bpf:
        bpf.cleanup()
    sys.exit(0)

def main():
    global bpf, running
    
    print("[*] Project SENTINEL Agent starting...")
    print("[*] Loading eBPF program...")
    
    # Load configuration
    load_rules()
    load_geo_rules()
    load_trusted_binaries()
    load_lineage_db()
    
    # Load eBPF program
    bpf_src = open(EBPF_SOURCE).read()
    bpf = BPF(text=bpf_src)
    
    # Open ring buffers
    bpf["exec_events"].open_ring_buffer(handle_exec_event)
    bpf["conn_events"].open_ring_buffer(handle_conn_event)
    bpf["file_events"].open_ring_buffer(handle_file_event)
    bpf["alert_events"].open_ring_buffer(handle_alert_event)
    bpf["icmp_events"].open_ring_buffer(handle_icmp_event)
    
    # Load rules into BPF map
    rule_map = bpf["rule_map"]
    for rule in rules:
        # Pack rule into BPF format matching rule_entry_t struct
        rule_data = bpf["rule_map"].TableEntry()
        rule_data.id = rule.id
        rule_data.action = ACTION_MAP.get(rule.action, 2)
        rule_data.severity = SEVERITY_MAP.get(rule.severity, 3)
        rule_data.pattern = rule.pattern.encode('utf-8')[:127]
        rule_data.binary_pattern = rule.binary_pattern.encode('utf-8')[:255]
        rule_data.lineage_id = rule.lineage_id
        rule_data.flags = rule.flags
        rule_data.uid_min = rule.uid_min
        rule_data.uid_max = rule.uid_max
        rule_map[rule_data.id] = rule_data
    print(f"[*] Loaded {len(rules)} rules into BPF map")
    
    # Load trusted binaries into BPF map
    trusted_map = bpf["trusted_binaries"]
    global _trusted_bpf_map
    _trusted_bpf_map = trusted_map
    for h in trusted_hashes:
        key = int(h[:16], 16).to_bytes(8, 'little')
        trusted_map[key] = b'\x01'
    
    # Load blocked lineages into BPF map
    blocked_map = bpf["blocked_lineages"]
    for lid in blocked_lineages:
        key = lid.to_bytes(8, 'little')
        blocked_map[key] = b'\x01'
    
    # Start background threads
    threading.Thread(target=periodic_save, daemon=True).start()
    threading.Thread(target=print_stats, daemon=True).start()
    threading.Thread(target=check_anomalies, daemon=True).start()
    
    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)
    
    print(f"[*] Project SENTINEL Engine active (Loaded {len(rules)} rules, {len(trusted_hashes)} trusted binaries)")
    print("[*] Monitoring: execve, connect, openat with lineage tracking")
    print("[*] LSM hooks: task_kill (anti-tamper), file_open (sensitive files)")
    
    # Main loop
    while running:
        try:
            bpf.ring_buffer_poll(timeout=100)
        except KeyboardInterrupt:
            break
        except Exception as e:
            print(f"[-] Poll error: {e}")
            time.sleep(1)
    
    signal_handler(signal.SIGTERM, None)

if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
Project SENTINEL Agent - Signature-based process lineage tracking
Integrates with eBPF lineage module via libbpf loader for enterprise-grade process tree monitoring
"""

import os
import sys
import select
import signal
import json
import time
import re
import yaml
import hashlib
import hmac
import threading
import urllib.request
import subprocess
import queue
import socket
import struct
import functools
from collections import defaultdict, deque
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set, Tuple, Any
from types import SimpleNamespace

# ─── Configuration ───
_SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
_PROJECT_DIR = os.path.dirname(_SCRIPT_DIR)

CONFIG_PATH = os.getenv("SENTINEL_CONFIG", os.path.join(_PROJECT_DIR, "config", "rules.yaml"))
GEO_RULES_FILE = os.getenv("SENTINEL_GEO_RULES", os.path.join(_PROJECT_DIR, "config", "geo_rules.json"))

def _default_agent_db() -> str:
    """Agent-owned state. Deliberately NOT the hub's SENTINEL_DB: the two write
    different schemas and used to clobber each other."""
    env = os.getenv("SENTINEL_AGENT_DB")
    if env:
        return env
    varlib = "/var/lib/sentinel/agent_state.json"
    d = os.path.dirname(varlib)
    if os.path.isdir(d) and os.access(d, os.W_OK):
        return varlib
    return os.path.join(_SCRIPT_DIR, "agent_state.json")

LINEAGE_DB_PATH = _default_agent_db()
TRUSTED_BINARIES_FILE = os.getenv("SENTINEL_TRUSTED", os.path.join(_PROJECT_DIR, "config", "trusted_binaries.json"))
EBPF_SOURCE_CORE = os.getenv("SENTINEL_EBPF_CORE", os.path.join(_PROJECT_DIR, "ebpf", "sentinel_lineage_core.bpf.c"))
EBPF_SOURCE_LEGACY = os.getenv("SENTINEL_EBPF", os.path.join(_PROJECT_DIR, "ebpf", "sentinel_lineage.bpf.c"))
LOADER_BINARY = os.getenv("SENTINEL_LOADER", os.path.join(_PROJECT_DIR, "build", "sentinel-loader"))

# Default to CO-RE (works everywhere with BTF)
EBPF_SOURCE = EBPF_SOURCE_CORE
COLLECTOR_URL = os.getenv("SENTINEL_COLLECTOR_URL", "http://127.0.0.1:5000/api/v1/telemetry")
AGENT_KEY = os.getenv("SENTINEL_AGENT_KEY", "")

# ─── Enforcement mode (learn = observe-only; hub is the source of truth) ───
ENFORCEMENT_MODE = "enforce"

# ─── Signed allowlist engine ───
ALLOWLIST_KEY_FILE = os.getenv("SENTINEL_ALLOWLIST_KEY_FILE",
                               os.path.join(_PROJECT_DIR, "config", "allowlist.key"))

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

# ─── Trusted-binary sync ───
# The kernel's is_trusted_binary() keys the trusted_binaries map on a hash of the
# PATH STRING (it never sees file contents). The old code inserted the first 8
# bytes of the file's SHA-256, so the two keys could never match and the kernel
# never marked anything trusted. We now mirror the kernel's path hash exactly and
# only pin a path once its content matches a pinned SHA-256 (trust-by-content at
# sync time; a small TOCTOU window remains between the check and the insert).
_KEY_MASK = (1 << 64) - 1
LINEAGE_ID_SEED = 0x9e3779b97f4a7c15
_PATH_HASH_CACHE_MAX = 8192

# Load the fast C implementation of path_key (falls back to pure Python if unavailable)
try:
    import ctypes
    _PATH_KEY_LIB = ctypes.CDLL(os.path.join(os.path.dirname(__file__), "path_key.so"))
    _PATH_KEY_LIB.path_key.argtypes = [ctypes.c_char_p]
    _PATH_KEY_LIB.path_key.restype = ctypes.c_uint64
    def path_key(path: str) -> bytes:
        return _PATH_KEY_LIB.path_key(path.encode("utf-8")).to_bytes(8, "little")
except Exception:
    # Pure Python fallback (matches kernel's signed-char arithmetic exactly)
    _KEY_MASK = (1 << 64) - 1
    def path_key(path: str) -> bytes:
        key = 0
        for b in path.encode("utf-8")[:256]:
            c = b - 256 if b > 127 else b
            term = (c + 0x9e3779b9 + (key << 6) + (key >> 2)) & ((1 << 64) - 1)
            key = (key ^ term) & ((1 << 64) - 1)
        return key.to_bytes(8, "little")


def lineage_hash(parent_id: int, path: str, uid: int, ts: int) -> int:
    """Mirror of the kernel's lineage_hash() (u64 wraparound, signed chars)."""
    h = (parent_id ^ LINEAGE_ID_SEED) & _KEY_MASK
    h ^= (uid + 0x9e3779b9 + (h << 6) + (h >> 2)) & _KEY_MASK
    h ^= (ts + 0x9e3779b9 + (h << 6) + (h >> 2)) & _KEY_MASK
    for b in path.encode("utf-8")[:256]:
        c = b - 256 if b > 127 else b
        h ^= (c + 0x9e3779b9 + (h << 6) + (h >> 2)) & _KEY_MASK
    return h


_path_hashes: Dict[str, tuple] = {}      # path -> (sha256, mtime_ns, size)
_applied_trusted_paths: Set[str] = set()  # paths currently in the kernel map
_config_hashes: Set[str] = set()          # pins from config/trusted_binaries.json
_allowlist_hashes: Set[str] = set()       # pins from the hub's signed allowlist


def _recompute_trusted():
    global trusted_hashes
    trusted_hashes = _config_hashes | _allowlist_hashes


def _insert_trusted_path(path: str) -> bool:
    if path in _applied_trusted_paths:
        return False
    try:
        loader.trust(path_key(path))
        _applied_trusted_paths.add(path)
        return True
    except Exception as e:
        print(f"[-] trusted-map insert failed for {path}: {e}")
        return False


def _remove_trusted_path(path: str) -> bool:
    _applied_trusted_paths.discard(path)
    try:
        loader.untrust(path_key(path))
        return True
    except Exception:
        return False


def _record_path_hash(path: str) -> str:
    """SHA-256 of a binary, cached on (mtime_ns, size) so we do not re-read the
    whole file on every exec (the old code did, inside the ring-buffer callback)."""
    try:
        st = os.stat(path)
    except OSError:
        return ""
    cached = _path_hashes.get(path)
    if cached and cached[1] == st.st_mtime_ns and cached[2] == st.st_size:
        return cached[0]
    h = hash_binary(path)
    if len(_path_hashes) >= _PATH_HASH_CACHE_MAX:
        _path_hashes.clear()                    # cheap bound; refilled on demand
    _path_hashes[path] = (h, st.st_mtime_ns, st.st_size)
    return h


def _sync_trusted_paths():
    """Reconcile the kernel trusted map with the current pinned-hash set."""
    for path, (h, _m, _z) in list(_path_hashes.items()):
        if not h:
            continue
        if h in trusted_hashes:
            _insert_trusted_path(path)
        else:
            _remove_trusted_path(path)


def _seed_self_trusted():
    """Pin the agent's own binary and mark its running process trusted in-kernel,
    so the task_kill LSM hook refuses to let anything kill the agent."""
    me = os.path.realpath(__file__)
    _path_hashes.setdefault(me, (hash_binary(me), 0, 0))
    if _insert_trusted_path(me):
        print(f"[*] kernel trust: pinned agent binary {me}")
    # Note: we can't directly write to lineage_map from userspace anymore.
    # The kernel will see our exec and mark us trusted via the trusted_binaries map.
    # For the running process, we rely on the parent's lineage or the kernel's LSM.
    print(f"[*] kernel trust: agent pid {os.getpid()} will be shielded by task_kill LSM")


def _apply_hash_allowlist(hashes: set):
    """Adopt the hub's signed hash pins (adds + revocations) and resync paths."""
    global _allowlist_hashes
    _allowlist_hashes = set(hashes)
    _recompute_trusted()
    _sync_trusted_paths()


SYNC_INTERVAL = int(os.getenv("SENTINEL_SYNC_INTERVAL", "30"))
_last_sync_time = 0.0


def apply_directive(payload: dict) -> bool:
    """Verify and apply one signed hub directive (GET /api/v1/agent/commands).

    Order matters: signature first, then schema, then replay check, and only then
    anything that changes agent state. Returns True when the directive was applied.
    """
    global ENFORCEMENT_MODE, _last_sync_time
    sig = payload.get("signature", "")
    body = {k: v for k, v in payload.items() if k != "signature"}
    if not _allowlist_key() or not sig or not verify_allowlist_blob(body, sig):
        print("[-] hub directive signature INVALID — ignoring", flush=True)
        return False
    if body.get("schema") != 1:
        print(f"[-] hub directive schema {body.get('schema')!r} unsupported — ignoring", flush=True)
        return False
    try:
        server_time = float(body.get("server_time", 0))
    except (TypeError, ValueError):
        return False
    if server_time <= _last_sync_time:
        print("[-] hub directive is older than the last applied one (replay?) — ignoring", flush=True)
        return False
    _last_sync_time = server_time

    mode = body.get("mode")
    if mode in ("learn", "enforce") and mode != ENFORCEMENT_MODE:
        ENFORCEMENT_MODE = mode
        print(f"[*] enforcement mode → {mode}", flush=True)

    _apply_hash_allowlist({e["value"] for e in body.get("allowlist", [])
                           if e.get("tier") == "hash" and len(e.get("value", "")) == 64})

    if ENFORCEMENT_MODE == "enforce":
        for cmd in body.get("commands", []):
            if cmd.get("type") != "block_lineage" or cmd.get("action") != "kill":
                continue                       # unknown / unsupported command types are skipped
            try:
                lid = int(cmd["lineage_id"], 16)
            except (KeyError, ValueError, TypeError):
                continue
            if lid not in blocked_lineages:
                block_lineage(lid, Rule(id=0, name="Operator block (hub)", pattern=""))
    return True


def _sync_poller():
    """Poll the hub's signed directive every SYNC_INTERVAL seconds."""
    base = COLLECTOR_URL.rsplit("/api/", 1)[0]
    while True:
        try:
            req = urllib.request.Request(f"{base}/api/v1/agent/commands", method="GET")
            if AGENT_KEY:
                req.add_header("X-Sentinel-Key", AGENT_KEY)
            with urllib.request.urlopen(req, timeout=5) as r:
                apply_directive(json.loads(r.read()))
        except Exception as e:
            print(f"[-] hub sync failed: {e}")
        time.sleep(SYNC_INTERVAL)


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
loader = None
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


# ─── KernelLoader Class ───
class KernelLoader:
    """Manages the sentinel-loader subprocess and dispatches events."""

    def __init__(self, object_path: str):
        self.object_path = object_path
        self.proc: Optional[subprocess.Popen] = None
        self.reader_thread: Optional[threading.Thread] = None
        self.command_queue: queue.Queue = queue.Queue()
        self._running = False

    def start(self) -> bool:
        """Start the loader process, wait for its first line, then start the reader thread."""
        if not os.path.exists(self.object_path):
            print(f"[-] eBPF object not found: {self.object_path}")
            return False
        if not os.path.exists(LOADER_BINARY):
            print(f"[-] Loader binary not found: {LOADER_BINARY}")
            return False

        try:
            self.proc = subprocess.Popen(
                [LOADER_BINARY, self.object_path],
                stdin=subprocess.PIPE,
                stdout=subprocess.PIPE,
                stderr=None,          # inherit: libbpf warnings reach the journal; an unread PIPE would fill and stall the loader
                text=True,
                bufsize=1,
            )
        except Exception as e:
            print(f"[-] Failed to start loader: {e}")
            return False

        # The first line (info or error) must be read here, before the reader thread exists.
        # Two threads reading one pipe race for it, and losing the race blocks start() forever.
        try:
            ready, _, _ = select.select([self.proc.stdout], [], [], 10)
            line = self.proc.stdout.readline() if ready else ""
        except Exception as e:
            print(f"[-] Failed to read loader info: {e}")
            line = ""
        if not line or not self._handle_info_line(line.strip()):
            print("[-] Loader did not report ready")
            self.stop()
            return False

        self._running = True
        self.reader_thread = threading.Thread(target=self._reader_loop, daemon=True)
        self.reader_thread.start()
        return True

    def alive(self) -> bool:
        return bool(self._running and self.proc and self.proc.poll() is None)

    def _handle_info_line(self, line: str) -> bool:
        """Parse the first loader line. True only for a well-formed info line."""
        try:
            data = json.loads(line)
        except json.JSONDecodeError:
            return False
        if data.get("t") == "info":
            print(f"[*] Loader ready: LSM={'enabled' if data.get('lsm') else 'disabled'}, programs={data.get('programs', 0)}")
            return True
        if data.get("t") == "error":
            print(f"[-] Loader error: {data.get('msg', 'unknown')}")
        return False

    def _reader_loop(self):
        """Read JSON lines from loader stdout and dispatch to handlers."""
        while self._running and self.proc and self.proc.poll() is None:
            try:
                line = self.proc.stdout.readline()
                if not line:
                    break
                line = line.strip()
                if not line:
                    continue
                self._dispatch_event(line)
            except Exception as e:
                if self._running:
                    print(f"[-] Loader reader error: {e}")
        if self._running:
            print("[-] Loader process exited unexpectedly")
            self._running = False

    def _dispatch_event(self, line: str):
        """Parse a JSON event line and call the appropriate handler."""
        try:
            event = json.loads(line)
        except json.JSONDecodeError:
            return

        event_type = event.get("t")
        if event_type == "exec":
            handle_exec_event(event)
        elif event_type == "conn":
            handle_conn_event(event)
        elif event_type == "file":
            handle_file_event(event)
        elif event_type == "alert":
            handle_alert_event(event)
        elif event_type == "error":
            print(f"[-] Loader error: {event.get('msg', 'unknown')}")
        elif event_type == "ack":
            # Acknowledgment for a command - currently ignored
            pass

    def send_command(self, cmd: str):
        """Send a command to the loader via stdin."""
        if self.proc and self.proc.stdin:
            try:
                self.proc.stdin.write(cmd + "\n")
                self.proc.stdin.flush()
            except Exception as e:
                print(f"[-] Failed to send command to loader: {e}")

    def block(self, lineage_id: int):
        self.send_command(f"block 0x{lineage_id:016X}")

    def unblock(self, lineage_id: int):
        self.send_command(f"unblock 0x{lineage_id:016X}")

    def trust(self, key: bytes):
        # key is the 8-byte little-endian map key; the loader parses a u64 with strtoull(),
        # so send the numeric value, not the byte string (that would byte-swap the key).
        self.send_command(f"trust {int.from_bytes(key, 'little'):016x}")

    def untrust(self, key: bytes):
        self.send_command(f"untrust {int.from_bytes(key, 'little'):016x}")

    def stop(self):
        """Stop the loader process."""
        self._running = False
        if self.proc:
            try:
                self.proc.stdin.write("quit\n")
                self.proc.stdin.flush()
                self.proc.stdin.close()          # EOF also makes the loader exit
            except Exception:
                pass
            try:
                self.proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                self.proc.terminate()
                try:
                    self.proc.wait(timeout=2)
                except subprocess.TimeoutExpired:
                    self.proc.kill()


# ─── Utility Functions ───
@functools.lru_cache(maxsize=4096)
def hash_binary(path: str) -> str:
    """Generate SHA256 hash of binary for trust verification"""
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""

def load_trusted_binaries():
    """Load trusted binary hashes from config into the config-pin set."""
    global _config_hashes
    trusted_file = TRUSTED_BINARIES_FILE
    if os.path.exists(trusted_file):
        try:
            with open(trusted_file, "r") as f:
                data = json.load(f)
                _config_hashes = set(data.get("hashes", []))
            _recompute_trusted()
            print(f"[*] Loaded {len(_config_hashes)} trusted binary hashes")
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
            # A rule that defines a pattern or binary_pattern must actually test it.
            # Network / file-integrity rules are scoped to their own event types.
            if not (rule.flags & (RF_NETWORK | RF_FILE_WRITE)):
                if rule.binary_pattern:
                    rule.flags |= RF_BINARY
                if rule.pattern:
                    rule.flags |= RF_CMDLINE
                if rule.flags & (RF_BINARY | RF_CMDLINE):
                    rule.flags |= RF_REGEX
            if rule.pattern and (rule.flags & RF_REGEX):
                try:
                    rule.compiled_pattern = re.compile(rule.pattern, re.IGNORECASE)
                except re.error:
                    rule.compiled_pattern = None
            if rule.binary_pattern and (rule.flags & RF_BINARY):
                try:
                    # match at the start of the executable NAME, not anywhere in the path
                    rule.compiled_binary = re.compile(
                        r"(?:" + rule.binary_pattern + r")(?![A-Za-z0-9])", re.IGNORECASE)
                except re.error:
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
    """Send telemetry to collector hub — non-blocking, queues for worker thread."""
    try:
        telemetry_queue.put_nowait(payload)
    except queue.Full:
        # Count drops once per minute
        global _telemetry_drops
        _telemetry_drops += 1
        if _telemetry_drops % 1000 == 1:  # log every 1000th drop to avoid spam
            print(f"[-] Telemetry queue full, dropped {_telemetry_drops} messages")

# Telemetry worker thread
telemetry_queue = queue.Queue(maxsize=10000)
_telemetry_drops = 0
_telemetry_worker_started = False

def _telemetry_worker():
    """Background thread that sends telemetry from the queue."""
    global _telemetry_drops
    while running:
        try:
            payload = telemetry_queue.get(timeout=1)
            data = json.dumps(payload).encode("utf-8")
            headers = {"Content-Type": "application/json", "User-Agent": "Sentinel-Lineage-Agent"}
            if AGENT_KEY:
                headers["X-Sentinel-Key"] = AGENT_KEY
            req = urllib.request.Request(
                COLLECTOR_URL,
                data=data,
                headers=headers
            )
            with urllib.request.urlopen(req, timeout=2):
                pass
        except queue.Empty:
            continue
        except Exception as e:
            print(f"[-] Telemetry dispatch error: {e}")

def _start_telemetry_worker():
    """Start the telemetry worker thread if not already started."""
    global _telemetry_worker_started
    if not _telemetry_worker_started:
        t = threading.Thread(target=_telemetry_worker, daemon=True)
        t.start()
        _telemetry_worker_started = True

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
        target = os.path.basename(entry.binary_path)
        if rule.compiled_binary:
            if not rule.compiled_binary.match(target):
                return False
        elif rule.binary_pattern.lower() != target.lower():
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

    # If rule has NETWORK or FILE_WRITE flags but no cmdline/binary/lineage/uid criteria,
    # it should not match here (those are handled separately in agent)
    if rule.flags & (RF_NETWORK | RF_FILE_WRITE):
        if not (rule.flags & (RF_CMDLINE | RF_BINARY | RF_LINEAGE | RF_UID_RANGE)):
            return False

    # If rule has no matching criteria at all, it should not match
    # (e.g., placeholder rules with flags=0)
    if rule.flags == 0:
        return False

    return True

def _make_ns_for_event(event: dict) -> SimpleNamespace:
    """Convert loader JSON event dict to SimpleNamespace with bytes fields
    so existing handler code (decode()) works unchanged."""
    ns = SimpleNamespace()
    for k, v in event.items():
        if k == "t":
            continue
        if isinstance(v, str) and k in ("comm", "filename", "cmdline", "path", "binary_path", "matched_pattern"):
            # These are strings in JSON; encode to bytes so .decode() works
            setattr(ns, k, v.encode("utf-8"))
        elif k == "lineage_id" or k == "parent_lineage_id":
            # These are hex strings like "0x00000000000000AB"
            if isinstance(v, str) and v.startswith("0x"):
                setattr(ns, k, int(v, 16))
            else:
                setattr(ns, k, v)
        elif k in ("daddr", "dport", "family", "pid", "ppid", "uid", "ns_pid", "rule_id", "action", "flags", "timestamp"):
            setattr(ns, k, v)
        else:
            setattr(ns, k, v)
    return ns

def handle_exec_event(event_dict: dict):
    """Handle process execution event from loader"""
    global stats
    event = _make_ns_for_event(event_dict)

    pid = event.pid
    ppid = event.ppid
    uid = event.uid
    ns_pid = event.ns_pid
    lineage_id = event.lineage_id
    parent_lineage_id = event.parent_lineage_id
    comm = event.comm.decode('utf-8', 'replace').strip()
    binary_path = event.filename.decode('utf-8', 'replace').strip()
    if binary_path:
        comm = os.path.basename(binary_path)[:15]   # kernel comm is still the pre-exec image here
    cmdline = event.cmdline.decode('utf-8', 'replace').strip() if hasattr(event, 'cmdline') else f"{comm} {binary_path}"

    # Task 2: Backfill empty filename/cmdline from /proc (first exec after fork
    # can arrive with empty fields because user memory not resident yet)
    if not binary_path:
        try:
            binary_path = os.readlink(f"/proc/{pid}/exe")
        except OSError:
            pass
    if not cmdline or cmdline == f"{comm} {binary_path}":
        try:
            with open(f"/proc/{pid}/cmdline", "rb") as f:
                cmdline = f.read().replace(b"\0", b" ").decode("utf-8", "replace").strip()
        except OSError:
            pass

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
    _h = _record_path_hash(binary_path) if binary_path else ""
    if _h and _h in trusted_hashes:
        entry.flags |= LF_TRUSTED
        _insert_trusted_path(binary_path)   # pin the PATH key the kernel checks

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
            elif (entry.flags & LF_TRUSTED) and not (rule.flags & RF_CMDLINE):
                # Trusted binary: exempt from identity (binary-name) rules only.
                # Command-line behaviour rules still enforce, because attackers
                # abuse trusted tools (bash, python, curl).
                alert["action"] = "LOG"
                alert["tags"] = list(set((alert.get("tags") or []) + ["trusted-binary"]))
                entry.alerts[-1]["action"] = "LOG"
                print(f"[-] TRUSTED BINARY (no enforcement): {rule.name} -> PID {pid} ({binary_path})")
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

def handle_conn_event(event_dict: dict):
    """Handle network connection event from loader"""
    global stats
    event = _make_ns_for_event(event_dict)

    pid = event.pid
    ns_pid = event.ns_pid
    lineage_id = event.lineage_id
    comm = event.comm.decode('utf-8', 'replace').strip()
    daddr = event.daddr
    dport = event.dport

    # Task 5: Convert network byte order to host byte order
    # Kernel stores dport in network byte order (big-endian)
    dport = socket.ntohs(dport)
    # Convert daddr from network byte order (uint32) to dotted IP string
    try:
        daddr_str = socket.inet_ntoa(struct.pack("!I", daddr))
    except Exception:
        daddr_str = str(daddr)

    with stats_lock:
        stats["conn_events"] += 1

    # Track DNS queries (port 53) for tunneling detection
    # DNS rate limiting is now handled in check_anomalies() by reading dns_queries map
    # The loader doesn't expose dns_queries map yet, so we skip for now

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
                    "daddr_str": daddr_str,
                    "killed": False,
                    "action": rule.action,
                    "timestamp": time.time()
                }
                telemetry_buffer.append(alert)
                dispatch_telemetry(alert)
                with stats_lock:
                    stats["alerts"] += 1
                break

def handle_file_event(event_dict: dict):
    """Handle file access event from loader"""
    global stats
    event = _make_ns_for_event(event_dict)

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

def handle_alert_event(event_dict: dict):
    """Handle alert from eBPF (blocked lineage, etc.)"""
    global stats
    event = _make_ns_for_event(event_dict)

    killed = (event.action == 2)

    alert = {
        "type": "KERNEL_ALERT",
        "lineage_id": f"0x{event.lineage_id:016X}",
        "pid": event.pid,
        "rule_id": event.rule_id,
        "severity": "HIGH",
        "action": "KILL" if killed else "ALERT",
        "killed": killed,
        "tag": event.matched_pattern.decode("utf-8", "replace"),
        "binary_path": event.binary_path.decode("utf-8", "replace"),
        "comm": event.comm.decode("utf-8", "replace"),
    }
    telemetry_buffer.append(alert)
    dispatch_telemetry(alert)

    with stats_lock:
        stats["alerts"] += 1

    print(f"[!] KERNEL ALERT: {alert['tag']} lineage={alert['lineage_id']} pid={event.pid} comm={event.comm.decode('utf-8','replace')} killed={killed}")

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

def _lineage_subtree(root_id: int) -> Set[int]:
    """Every lineage ID that descends from root_id (including root_id)."""
    ids = {root_id}
    changed = True
    while changed:
        changed = False
        for e in list(lineage_tree.values()):
            if e.parent_lineage_id in ids and e.lineage_id not in ids:
                ids.add(e.lineage_id)
                changed = True
    return ids

def block_lineage(lineage_id: int, rule: Rule):
    """Block a lineage and all of its descendants (kernel map + live processes)."""
    global blocked_lineages
    ids = _lineage_subtree(lineage_id)
    for lid in ids:
        blocked_lineages.add(lid)
        try:
            loader.block(lid)
        except Exception as e:
            print(f"[-] Failed to update blocked_lineages map: {e}")

    for pid, entry in list(lineage_tree.items()):
        if entry.lineage_id in ids:
            try:
                os.kill(pid, signal.SIGKILL)
                entry.flags |= LF_KILLED
                entry.exited = True
            except ProcessLookupError:
                pass

    with stats_lock:
        stats["blocked_lineages"] += 1

    print(f"[!] BLOCKED lineage {lineage_id:#x} (+{len(ids) - 1} descendants) (Rule: {rule.name})")

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
    """Periodic anomaly detection: DNS entropy, data volume, ICMP

    Note: The following checks are disabled until the loader exposes the
    corresponding BPF maps (dns_queries, data_volume). Once available,
    implement per-PID DNS query counting with 60s window reset, data volume
    tracking (bytes not calls), and ICMP covert channel detection.
    """
    import math
    from collections import Counter

    DNS_ENTROPY_THRESHOLD = 3.5  # bits per char
    DNS_LENGTH_THRESHOLD = 50    # subdomain length
    DNS_RATE_THRESHOLD = 100     # queries per minute
    DATA_VOLUME_THRESHOLD = 100 * 1024 * 1024  # 100 MB

    while running:
        time.sleep(60)  # Check every minute

        # TODO: Implement when loader exposes dns_queries and data_volume maps
        # For now, these checks are skipped

def signal_handler(sig, frame):
    global running
    print("\n[*] Shutting down...")
    running = False
    save_lineage_db()
    if loader:
        loader.stop()
    sys.exit(0)

def main():
    global loader, running

    print("[*] Project SENTINEL Agent starting...")
    print("[*] Loading eBPF program via libbpf loader...")

    # Load configuration
    load_rules()
    load_geo_rules()
    load_trusted_binaries()
    load_lineage_db()

    # Start telemetry worker thread
    _start_telemetry_worker()

    # Start kernel loader
    loader = KernelLoader(os.path.join(_PROJECT_DIR, "build", "sentinel_lineage_core.o"))
    if not loader.start():
        print("[-] Failed to start kernel loader")
        sys.exit(1)

    # Re-apply blocked lineages to the new kernel map
    for lid in blocked_lineages:
        loader.block(lid)

    # Trusted binaries: the map is keyed on the PATH hash, so a path can only be
    # pinned once its content matches a pinned SHA-256. Seed the agent's own
    # binary (and its running process) so task_kill protects this process.
    _seed_self_trusted()
    _sync_trusted_paths()
    print(f"[*] kernel trusted map seeded "
          f"({len(_applied_trusted_paths)} paths, {len(trusted_hashes)} pinned hashes)")

    # Start background threads
    threading.Thread(target=_sync_poller, daemon=True).start()
    threading.Thread(target=periodic_save, daemon=True).start()
    threading.Thread(target=print_stats, daemon=True).start()
    threading.Thread(target=check_anomalies, daemon=True).start()

    # Setup signal handlers
    signal.signal(signal.SIGINT, signal_handler)
    signal.signal(signal.SIGTERM, signal_handler)

    print(f"[*] Project SENTINEL Engine active (Loaded {len(rules)} rules, {len(trusted_hashes)} trusted binaries)")
    print("[*] Monitoring: execve, connect, openat with lineage tracking")
    print("[*] LSM hooks: task_kill (anti-tamper), file_open (sensitive files)")

    # Main loop with a watchdog: if the loader dies the kernel programs detach and the agent
    # goes blind, so restart it a few times and then exit non-zero (systemd restarts the unit).
    restarts = 0
    while running:
        time.sleep(1)
        if loader and not loader.alive() and running:
            if restarts >= 3:
                print("[-] loader keeps dying; exiting so the service manager can restart the agent")
                sys.exit(1)
            restarts += 1
            print(f"[-] loader exited unexpectedly; restarting ({restarts}/3)")
            time.sleep(2 ** restarts)
            loader.stop()
            if loader.start():
                for lid in list(blocked_lineages):
                    loader.block(lid)
                _applied_trusted_paths.clear()      # the new kernel map is empty
                _seed_self_trusted()
                _sync_trusted_paths()

    signal_handler(signal.SIGTERM, None)

if __name__ == "__main__":
    main()
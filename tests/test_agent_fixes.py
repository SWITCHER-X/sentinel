#!/usr/bin/env python3
"""
Regression tests for agent correctness fixes: PID reuse, hash cache, tree eviction
"""

import os
import sys
import types
import tempfile
import time

# Stub bcc so agent imports
_bcc = types.ModuleType("bcc"); _bcc.BPF = object
_bcc_utils = types.ModuleType("bcc.utils"); _bcc_utils.printb = lambda *a, **k: None
sys.modules.setdefault("bcc", _bcc)
sys.modules.setdefault("bcc.utils", _bcc_utils)

# Stub ctypes so path_key.so loading doesn't fail
_ctypes = types.ModuleType("ctypes")
_ctypes.CDLL = lambda *a, **k: None
sys.modules.setdefault("ctypes", _ctypes)

# Point to our config
REPO = os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
os.environ["SENTINEL_CONFIG"] = os.path.join(REPO, "config", "rules.yaml")

# Import the real agent
sys.path.insert(0, os.path.join(REPO, "agent"))
import sentinel_lineage_agent as A

import signal


def _reset():
    A.lineage_tree.clear()
    A.lineage_by_id.clear()
    A.blocked_lineages.clear()


def _mk(pid, lid, plid=0, ppid=1, start=5):
    e = A.LineageEntry(
        lineage_id=lid, parent_lineage_id=plid, pid=pid, ppid=ppid, uid=1000, gid=1000,
        ns_pid=pid, comm="x", binary_path="/tmp/x", cmdline="x",
        exec_timestamp=time.time(), flags=0, start_time=start)
    A.lineage_tree[pid] = e
    A.lineage_by_id[lid] = e
    return e


class _Patch:
    """Swap module attributes for a test and restore them afterwards."""
    def __init__(self, **kw):
        self.kw, self.old = kw, {}
    def __enter__(self):
        for k, v in self.kw.items():
            self.old[k] = getattr(A, k)
            setattr(A, k, v)
    def __exit__(self, *a):
        for k, v in self.old.items():
            setattr(A, k, v)


def test_kill_skips_recycled_pid():
    _reset()
    e = _mk(4242, 0x10, start=111)
    sent = []
    with _Patch(_start_time=lambda pid: 222, **{"os": types.SimpleNamespace(kill=lambda p, s: sent.append(p), environ=os.environ, path=os.path, getpid=os.getpid)}):
        assert A._kill_if_same_process(4242, e) is False
    assert sent == [], "a recycled PID must never be signalled"
    assert not e.flags & A.LF_KILLED


def test_kill_hits_the_real_process():
    _reset()
    e = _mk(4242, 0x10, start=111)
    sent = []
    fake_os = types.SimpleNamespace(kill=lambda p, s: sent.append((p, s)), environ=os.environ, path=os.path, getpid=os.getpid)
    with _Patch(_start_time=lambda pid: 111, os=fake_os):
        assert A._kill_if_same_process(4242, e) is True
    assert sent == [(4242, signal.SIGKILL)]
    assert e.exited and e.flags & A.LF_KILLED and e.exit_time > 0


def test_kill_skips_entry_without_start_time():
    _reset()
    e = _mk(4242, 0x10, start=0)
    sent = []
    fake_os = types.SimpleNamespace(kill=lambda p, s: sent.append(p), environ=os.environ, path=os.path, getpid=os.getpid)
    with _Patch(_start_time=lambda pid: 999, os=fake_os):
        assert A._kill_if_same_process(4242, e) is False
    assert sent == []


def test_protected_process_is_never_killed():
    _reset()
    e = _mk(1, 0x10, start=111)
    sent = []
    fake_os = types.SimpleNamespace(kill=lambda p, s: sent.append(p), environ=os.environ, path=os.path, getpid=os.getpid)
    with _Patch(_start_time=lambda pid: 111, os=fake_os):
        assert A._kill_if_same_process(1, e) is False
    assert sent == [], "PID 1 must never be signalled"
    e.comm = "sshd"
    assert A.is_protected(31337, e) is True


def test_dry_run_never_kills_or_blocks():
    _reset()
    _mk(4242, 0x10, start=111)
    sent = []
    fake_os = types.SimpleNamespace(kill=lambda p, s: sent.append(p), environ=os.environ, path=os.path, getpid=os.getpid)
    with _Patch(_start_time=lambda pid: 111, os=fake_os, DRY_RUN=True, loader=None):
        assert A._kill_if_same_process(4242, A.lineage_tree[4242]) is False
        A.block_lineage(0x10, A.Rule(id=0, name="t", pattern=""))
    assert sent == [], "dry-run must not signal anything"
    assert 0x10 in A.blocked_lineages


def test_block_subtree_does_not_kill_recycled_descendant():
    _reset()
    _mk(100, 0x1, 0, start=5)
    _mk(101, 0x2, 0x1, 100, start=5)
    _mk(102, 0x3, 0x2, 101, start=5)      # this PID was recycled below
    sent = []
    fake_os = types.SimpleNamespace(kill=lambda p, s: sent.append(p), environ=os.environ, path=os.path, getpid=os.getpid)
    start = {100: 5, 101: 5, 102: 99}
    with _Patch(_start_time=lambda pid: start.get(pid, 0), os=fake_os, loader=None):
        A.block_lineage(0x1, A.Rule(id=0, name="t", pattern=""))
    assert {0x1, 0x2, 0x3} <= A.blocked_lineages, "the whole subtree is still blocked in the kernel map"
    assert sorted(sent) == [100, 101], "only live, matching processes are killed"


def test_hash_binary_sees_a_replaced_file():
    with tempfile.NamedTemporaryFile(delete=False) as f:
        f.write(b"first")
        path = f.name
    try:
        h1 = A.hash_binary(path)
        with open(path, "wb") as f:
            f.write(b"other")     # same size, different content
        # Ensure mtime changes for cache invalidation (lazytime mount option may delay mtime updates)
        os.utime(path, ns=(os.stat(path).st_atime_ns, time.time_ns()))
        assert A.hash_binary(path) != h1
    finally:
        os.unlink(path)


def test_sweep_marks_exits_then_evicts_and_prunes_children():
    _reset()
    parent = _mk(10, 0x1, 0, 1, start=5)
    child = _mk(11, 0x2, 0x1, 10, start=5)
    parent.children = [11]
    with _Patch(_start_time=lambda pid: 5 if pid == 10 else 0):
        A.sweep_lineage_tree()
        assert child.exited and 11 in A.lineage_tree, "kept for the grace period"
        child.exit_time = time.time() - A.LINEAGE_EXIT_GRACE - 1
        A.sweep_lineage_tree()
    assert 11 not in A.lineage_tree
    assert parent.children == [], "parent must not keep dead child PIDs"
    assert 10 in A.lineage_tree


def test_sweep_enforces_size_cap_and_spares_blocked_ids():
    _reset()
    for i in range(50):
        _mk(1000 + i, 0x100 + i, 0, 1, start=5)
    A.blocked_lineages.add(0x100)
    with _Patch(_start_time=lambda pid: 5, LINEAGE_TREE_MAX=20, LINEAGE_BY_ID_MAX=30):
        A.sweep_lineage_tree()
    assert len(A.lineage_tree) <= 20
    assert len(A.lineage_by_id) <= 30
    assert 0x100 in A.lineage_by_id, "blocked lineages are never evicted"


def test_old_lineage_db_without_new_fields_still_loads():
    old = {"lineage_id": 1, "parent_lineage_id": 0, "pid": 1, "ppid": 0, "uid": 0, "gid": 0,
           "ns_pid": 1, "comm": "init", "binary_path": "/sbin/init", "cmdline": "init",
           "exec_timestamp": 0.0, "flags": 0}
    e = A.LineageEntry(**old)
    assert e.start_time == 0 and e.exit_time == 0.0


if __name__ == "__main__":
    test_kill_skips_recycled_pid()
    test_kill_hits_the_real_process()
    test_kill_skips_entry_without_start_time()
    test_block_subtree_does_not_kill_recycled_descendant()
    test_hash_binary_sees_a_replaced_file()
    test_sweep_marks_exits_then_evicts_and_prunes_children()
    test_sweep_enforces_size_cap_and_spares_blocked_ids()
    test_old_lineage_db_without_new_fields_still_loads()
    print("All tests passed!")
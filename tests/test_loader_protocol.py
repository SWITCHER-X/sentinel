#!/usr/bin/env python3
"""Agent <-> sentinel-loader protocol tests (no root, no kernel needed).

The loader's JSON lines are fed to the real agent dispatcher; commands the agent writes to
the loader's stdin are captured and checked, including the trust-map key encoding.
Run: python3 tests/test_loader_protocol.py
"""
import io
import json
import os
import stat
import sys
import tempfile
import time
import types
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
os.environ.setdefault("SENTINEL_ALLOWLIST_KEY", "test-allowlist-key")
for _n in ("bcc", "bcc.utils"):
    sys.modules.setdefault(_n, types.ModuleType(_n))
sys.path.insert(0, str(REPO / "agent"))
import sentinel_lineage_agent as A  # noqa: E402

MASK = (1 << 64) - 1


def kernel_path_key(path: str) -> int:
    """Independent copy of the eBPF is_trusted_binary() hash (signed char arithmetic)."""
    key = 0
    for b in path.encode()[:256]:
        c = b - 256 if b > 127 else b
        key ^= (c + 0x9e3779b9 + (key << 6) + (key >> 2)) & MASK
    return key


class FakeProc:
    def __init__(self):
        self.stdin = io.StringIO()
    def poll(self):
        return None


def make_loader():
    ld = A.KernelLoader("unused.o")
    ld.proc = FakeProc()
    return ld, ld.proc.stdin


class Commands(unittest.TestCase):
    def test_block_format(self):
        ld, out = make_loader(); ld.block(0xAB)
        self.assertEqual(out.getvalue(), "block 0x00000000000000AB\n")

    def test_trust_sends_the_numeric_key_the_kernel_computes(self):
        for path in ("/bin/true", "/usr/bin/bash", "/opt/app/bin/server"):
            ld, out = make_loader(); ld.trust(A.path_key(path))
            sent = int(out.getvalue().split()[1], 16)     # what the loader's strtoull() stores
            self.assertEqual(sent, kernel_path_key(path), path)

    def test_untrust_uses_the_same_encoding(self):
        ld, out = make_loader(); ld.untrust(A.path_key("/bin/true"))
        self.assertEqual(out.getvalue(), f"untrust {kernel_path_key('/bin/true'):016x}\n")


class Dispatch(unittest.TestCase):
    def setUp(self):
        self.seen = []
        self._orig = {n: getattr(A, n) for n in ("handle_exec_event", "handle_conn_event", "handle_file_event", "handle_alert_event")}
        for n in self._orig:
            setattr(A, n, lambda ev, _n=n: self.seen.append((_n, ev)))
        self.ld, _ = make_loader()

    def tearDown(self):
        for n, f in self._orig.items():
            setattr(A, n, f)

    def test_each_event_type_reaches_its_handler(self):
        for t, h in (("exec", "handle_exec_event"), ("conn", "handle_conn_event"),
                     ("file", "handle_file_event"), ("alert", "handle_alert_event")):
            self.ld._dispatch_event(json.dumps({"t": t, "pid": 7}))
            self.assertEqual(self.seen[-1][0], h)

    def test_malformed_and_unknown_lines_are_ignored(self):
        for line in ("not json", "{}", '{"t":"mystery"}', '{"t":"ack","cmd":"block","ok":true}', ""):
            self.ld._dispatch_event(line)
        self.assertEqual(self.seen, [])


class BlockSubtree(unittest.TestCase):
    def test_block_lineage_blocks_every_descendant_in_the_kernel_map(self):
        sent = []
        class L:
            def block(self, lid): sent.append(lid)
        old = getattr(A, "loader", None)
        A.loader = L()
        A.lineage_tree.clear(); A.blocked_lineages.clear()
        killed = []; real_kill = A.os.kill; A.os.kill = lambda pid, sig: killed.append(pid)
        try:
            for pid, lid, parent in ((10, 0xA, 0), (11, 0xB, 0xA), (12, 0xC, 0xB), (13, 0xD, 0xC), (99, 0xE, 0)):
                A.lineage_tree[pid] = A.LineageEntry(lineage_id=lid, parent_lineage_id=parent, pid=pid, ppid=1,
                    uid=0, gid=0, ns_pid=pid, comm="x", binary_path="/x", cmdline="x", exec_timestamp=0.0, flags=0)
            A.block_lineage(0xA, A.Rule(id=0, name="t", pattern=""))
        finally:
            A.os.kill = real_kill; A.loader = old
        self.assertEqual(set(sent), {0xA, 0xB, 0xC, 0xD})
        self.assertEqual(set(killed), {10, 11, 12, 13})
        self.assertNotIn(0xE, A.blocked_lineages)         # unrelated tree untouched


def _fake_loader(body: str) -> str:
    path = os.path.join(tempfile.mkdtemp(prefix="fake-loader-"), "loader")
    with open(path, "w") as f:
        f.write("#!/usr/bin/env python3\nimport sys, json, time\n" + body)
    os.chmod(path, os.stat(path).st_mode | stat.S_IXUSR)
    return path


class Startup(unittest.TestCase):
    """KernelLoader.start() must never lose the first line or hang (two threads used to race for it)."""

    def setUp(self):
        self._bin = A.LOADER_BINARY
        self._h = A.handle_exec_event
        self.seen = []
        A.handle_exec_event = lambda ev: self.seen.append(ev)

    def tearDown(self):
        A.LOADER_BINARY = self._bin
        A.handle_exec_event = self._h

    def test_start_is_reliable_when_events_follow_the_info_line_immediately(self):
        A.LOADER_BINARY = _fake_loader(
            'print(json.dumps({"t":"info","lsm":False,"programs":7}), flush=True)\n'
            'for i in range(5): print(json.dumps({"t":"exec","pid":i}), flush=True)\n'
            'sys.stdin.read()\n')
        for _ in range(25):
            self.seen.clear()
            ld = A.KernelLoader(__file__)
            self.assertTrue(ld.start())
            deadline = time.time() + 3
            while len(self.seen) < 5 and time.time() < deadline:
                time.sleep(0.01)
            self.assertEqual([e["pid"] for e in self.seen], [0, 1, 2, 3, 4])   # none lost, none stolen
            self.assertTrue(ld.alive())
            ld.stop()

    def test_error_line_fails_start(self):
        A.LOADER_BINARY = _fake_loader('print(json.dumps({"t":"error","msg":"nope"}), flush=True)\nsys.exit(1)\n')
        self.assertFalse(A.KernelLoader(__file__).start())

    def test_silent_loader_exit_fails_start(self):
        A.LOADER_BINARY = _fake_loader("sys.exit(1)\n")
        self.assertFalse(A.KernelLoader(__file__).start())

    def test_alive_turns_false_when_loader_dies(self):
        A.LOADER_BINARY = _fake_loader(
            'print(json.dumps({"t":"info","lsm":False,"programs":1}), flush=True)\ntime.sleep(0.3)\n')
        ld = A.KernelLoader(__file__)
        self.assertTrue(ld.start())
        time.sleep(1.0)
        self.assertFalse(ld.alive())


if __name__ == "__main__":
    unittest.main(verbosity=2)

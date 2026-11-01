#!/usr/bin/env python3
"""TASK-001 — StateBackend contract tests.

The SAME contract suite runs against every backend so they cannot drift:

  * InMemoryState                    — always runs.
  * RedisState (in-process stand-in) — always runs. Exercises the real
    RedisState code paths (key formats, hex encoding, list/set handling)
    against a minimal redis-py stand-in, so it works with no server.
  * RedisState (real server)         — runs when SENTINEL_TEST_REDIS_URL is
    set and redis-py + a reachable server exist; skipped otherwise.

Run: python3 tests/test_state_backend.py
     SENTINEL_TEST_REDIS_URL=redis://127.0.0.1:6379/0 python3 tests/test_state_backend.py
"""
import json
import os
import sys
import time
import types
import unittest
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collector"))

import state as state_mod  # noqa: E402


# ─────────────────────────────────────────────────────────────────────────────
# Minimal in-process stand-in for redis-py.
# Implements ONLY the commands collector/state.py::RedisState actually uses, so
# the backend's own logic is what gets tested (not redis-py).
# ─────────────────────────────────────────────────────────────────────────────
class _MiniPubSub:
    def subscribe(self, *a, **k):
        return None

    def close(self):
        return None


class _MiniPipeline:
    def __init__(self, redis):
        self._r = redis
        self._ops = []

    def lpush(self, k, v):
        self._ops.append(("lpush", (k, v)))
        return self

    def ltrim(self, k, a, b):
        self._ops.append(("ltrim", (k, a, b)))
        return self

    def execute(self):
        for name, args in self._ops:
            getattr(self._r, name)(*args)
        self._ops = []
        return []


class _MiniRedis:
    """Decode-responses stand-in backed by plain dicts/lists/sets."""

    def __init__(self):
        self._kv = {}
        self._list = {}
        self._set = {}
        self._expiry = {}

    def get(self, k):
        return self._kv.get(k)

    def set(self, k, v):
        self._kv[k] = v
        return True

    def setex(self, k, ttl, v):
        self._kv[k] = v
        self._expiry[k] = ttl
        return True

    def delete(self, *keys):
        n = 0
        for k in keys:
            for store in (self._kv, self._list, self._set):
                if k in store:
                    del store[k]
                    n += 1
        return n

    def incr(self, k):
        v = int(self._kv.get(k, 0)) + 1
        self._kv[k] = str(v)
        return v

    def lpush(self, k, v):
        self._list.setdefault(k, []).insert(0, v)
        return len(self._list[k])

    def ltrim(self, k, a, b):
        lst = self._list.get(k)
        if lst is not None:
            self._list[k] = lst[a:] if b < 0 else lst[a:b + 1]
        return True

    def lrange(self, k, a, b):
        lst = self._list.get(k, [])
        return lst[a:] if b < 0 else lst[a:b + 1]

    def sadd(self, k, v):
        s = self._set.setdefault(k, set())
        before = len(s)
        s.add(v)
        return 1 if len(s) != before else 0

    def srem(self, k, v):
        s = self._set.get(k, set())
        if v in s:
            s.discard(v)
            return 1
        return 0

    def smembers(self, k):
        return set(self._set.get(k, set()))

    def keys(self, pattern):
        prefix = pattern.replace("*", "")
        out = []
        for store in (self._kv, self._list, self._set):
            out.extend(x for x in store if x.startswith(prefix))
        return out

    def ping(self):
        return True

    def pubsub(self):
        return _MiniPubSub()

    def pipeline(self):
        return _MiniPipeline(self)


def _stub_redis_module():
    """A module-like object exposing redis-py's from_url()."""
    mod = types.ModuleType("redis_stub")

    def from_url(url, decode_responses=True):
        return _MiniRedis()

    mod.from_url = from_url
    return mod


# ─────────────────────────────────────────────────────────────────────────────
# Contract
# ─────────────────────────────────────────────────────────────────────────────
class StateBackendContract:
    """Every assertion here must hold for any StateBackend implementation."""

    def make_backend(self):  # pragma: no cover - overridden
        raise NotImplementedError

    def setUp(self):
        self.backend = self.make_backend()
        if hasattr(self.backend, "_redis"):
            for k in self.backend._redis.keys("sentinel:*"):
                self.backend._redis.delete(k)

    # ── mode ──
    def test_mode_default_and_set(self):
        self.assertEqual(self.backend.get_mode(), "enforce")
        self.backend.set_mode("learn")
        self.assertEqual(self.backend.get_mode(), "learn")
        self.backend.set_mode("enforce")
        self.assertEqual(self.backend.get_mode(), "enforce")

    # ── telemetry ──
    def test_telemetry_append_and_order(self):
        seq1 = self.backend.append_telemetry({"type": "A"})
        seq2 = self.backend.append_telemetry({"type": "B"})
        self.assertGreater(seq2, seq1)
        logs = self.backend.get_telemetry_logs()
        self.assertEqual(logs[0]["type"], "B")  # newest first
        self.assertEqual(logs[1]["type"], "A")
        self.assertEqual(logs[0]["_seq"], seq2)

    def test_telemetry_limit(self):
        for i in range(5):
            self.backend.append_telemetry({"type": f"T{i}"})
        self.assertEqual(len(self.backend.get_telemetry_logs(limit=3)), 3)

    # ── lineage trees ──
    def test_lineage_tree_create_and_update(self):
        lid = 0xABCDEF
        self.backend.update_lineage_tree(lid, lambda t: t.__setitem__("threat_count", 1))
        self.backend.update_lineage_tree(
            lid, lambda t: t["nodes"].__setitem__("42", {"pid": 42, "comm": "ls"}))
        trees = self.backend.get_lineage_trees()
        self.assertIn(lid, trees)
        self.assertEqual(trees[lid]["threat_count"], 1)
        self.assertIn("42", trees[lid]["nodes"])

    # ── blocked / trusted ──
    def test_blocked_lineage_lifecycle(self):
        lid = 0x1234
        self.assertNotIn(lid, self.backend.get_blocked_lineages())
        self.backend.add_blocked_lineage(lid)
        self.assertIn(lid, self.backend.get_blocked_lineages())
        self.backend.remove_blocked_lineage(lid)
        self.assertNotIn(lid, self.backend.get_blocked_lineages())

    def test_trusted_lineage_lifecycle(self):
        lid = 0x5678
        self.backend.add_trusted_lineage(lid)
        self.assertIn(lid, self.backend.get_trusted_lineages())
        self.backend.remove_trusted_lineage(lid)
        self.assertNotIn(lid, self.backend.get_trusted_lineages())

    # ── connected nodes ──
    def test_connected_nodes(self):
        self.backend.update_connected_node(
            "web-01", {"last_seen": time.time(), "ip": "10.0.0.1"})
        nodes = self.backend.get_connected_nodes()
        self.assertIn("web-01", nodes)
        self.assertEqual(nodes["web-01"]["ip"], "10.0.0.1")

    # ── login throttle ──
    def test_login_failures_roundtrip(self):
        ip = "10.1.2.3"
        self.assertEqual(self.backend.get_login_failures(ip), (0, 0))
        self.backend.set_login_failures(ip, 3, time.time() + 60)
        fails, until = self.backend.get_login_failures(ip)
        self.assertEqual(fails, 3)
        self.assertGreater(until, time.time())
        self.backend.clear_login_failures(ip)
        self.assertEqual(self.backend.get_login_failures(ip), (0, 0))

    # ── aggregates ──
    def test_stats_shape(self):
        self.backend.append_telemetry({"type": "EXEC_THREAT", "severity": "CRITICAL"})
        st = self.backend.get_stats()
        for key in ("active_nodes", "total_events", "exec_threats",
                    "critical_threats", "uptime_seconds", "lineage", "mode"):
            self.assertIn(key, st)
        self.assertIn("total_lineages", st["lineage"])
        self.assertGreaterEqual(st["exec_threats"], 1)

    # ── health ──
    def test_health_check_shape(self):
        h = self.backend.health_check()
        self.assertIn("status", h)
        self.assertIn("checks", h)


class TestInMemoryBackend(StateBackendContract, unittest.TestCase):
    def make_backend(self):
        return state_mod.InMemoryState()


class TestRedisBackendStub(StateBackendContract, unittest.TestCase):
    """RedisState logic, exercised via the in-process stand-in (no server needed)."""

    def make_backend(self):
        # `import redis` may have failed at import time, so the module-level
        # name can be absent entirely — fetch defensively.
        had_redis = hasattr(state_mod, "redis")
        orig_mod = getattr(state_mod, "redis", None)
        orig_avail = state_mod.REDIS_AVAILABLE
        state_mod.redis = _stub_redis_module()
        state_mod.REDIS_AVAILABLE = True
        try:
            return state_mod.RedisState("redis://stub/0")
        finally:
            # RedisState holds the value; restore module globals for other tests
            state_mod.REDIS_AVAILABLE = orig_avail
            if had_redis:
                state_mod.redis = orig_mod
            else:
                delattr(state_mod, "redis")


def _real_redis_or_none():
    url = os.getenv("SENTINEL_TEST_REDIS_URL")
    if not url or not state_mod.REDIS_AVAILABLE:
        return None
    try:
        b = state_mod.RedisState(url)
        b._redis.ping()
        return b
    except Exception:
        return None


if _real_redis_or_none() is not None:
    class TestRedisBackendReal(StateBackendContract, unittest.TestCase):
        def make_backend(self):
            return state_mod.RedisState(os.environ["SENTINEL_TEST_REDIS_URL"])
else:
    @unittest.skip("set SENTINEL_TEST_REDIS_URL + install redis to exercise a real server")
    class TestRedisBackendReal(unittest.TestCase):
        def test_skipped(self):
            pass


if __name__ == "__main__":
    unittest.main(verbosity=2)

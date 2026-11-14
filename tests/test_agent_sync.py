#!/usr/bin/env python3
"""Hub -> agent directive tests (GET /api/v1/agent/commands).

Covers the response structure the hub emits and how the agent verifies and applies it:
  * structure and signature of the directive
  * operator blocks reach the agent; rule-KILL telemetry does not escalate into blocks
  * the agent rejects tampered, replayed and unknown-schema directives
  * block commands are applied in Enforce mode only

Drives the real hub (Flask test client) and the real agent module (loader stubbed).
Run: python3 tests/test_agent_sync.py
"""
import os
import sys
import tempfile
import types
import unittest
from pathlib import Path
from unittest.mock import MagicMock

REPO = Path(__file__).resolve().parent.parent
_tmp = tempfile.mkdtemp(prefix="sentinel-sync-test-")

os.environ.update({
    "SENTINEL_AGENT_KEY": "test-agent-key",
    "SENTINEL_SESSION_SECRET": "test-session-secret",
    "SENTINEL_ALLOWLIST_KEY": "test-allowlist-key",
    "SENTINEL_ADMIN_PASSWORD": "test-admin-pw",
    "SENTINEL_DB_PATH": os.path.join(_tmp, "sentinel.db"),
    "SENTINEL_DB": os.path.join(_tmp, "lineage_db.json"),
    "SENTINEL_CONFIG": str(REPO / "config" / "rules.yaml"),
})

# Stub bcc module so the agent can import (it no longer uses bcc, but imports may remain)
_bcc = types.ModuleType("bcc"); _bcc.BPF = object
_bcc_utils = types.ModuleType("bcc.utils"); _bcc_utils.printb = lambda *a, **k: None
sys.modules.setdefault("bcc", _bcc)
sys.modules.setdefault("bcc.utils", _bcc_utils)

# Stub ctypes so path_key.so loading doesn't fail
_ctypes = types.ModuleType("ctypes")
_ctypes.CDLL = lambda *a, **k: None
sys.modules.setdefault("ctypes", _ctypes)

sys.path.insert(0, str(REPO / "collector"))
sys.path.insert(0, str(REPO / "agent"))

import sentinel_hub_lineage as hub  # noqa: E402
import sentinel_lineage_agent as A  # noqa: E402

AGENT = {"X-Sentinel-Key": "test-agent-key"}


class HubDirective(unittest.TestCase):
    def setUp(self):
        self.c = hub.app.test_client()

    def _admin(self):
        r = self.c.post("/api/v1/login", json={"username": "admin", "password": "test-admin-pw"})
        self.assertEqual(r.status_code, 200)
        return {"X-CSRF-Token": r.get_json()["csrf"]}

    def test_requires_agent_key(self):
        self.assertEqual(self.c.get("/api/v1/agent/commands").status_code, 401)
        self.assertEqual(self.c.get("/api/v1/agent/commands", headers={"X-Sentinel-Key": "wrong"}).status_code, 401)

    def test_structure(self):
        d = self.c.get("/api/v1/agent/commands", headers=AGENT).get_json()
        self.assertEqual(d["schema"], 1)
        self.assertIn(d["mode"], ("learn", "enforce"))
        self.assertIsInstance(d["server_time"], float)
        self.assertIsInstance(d["commands"], list)
        self.assertIsInstance(d["allowlist"], list)
        self.assertEqual(len(d["revision"]), 16)
        self.assertTrue(d["signature"])

    def test_signature_matches_agent_verifier(self):
        d = self.c.get("/api/v1/agent/commands", headers=AGENT).get_json()
        sig = d.pop("signature")
        self.assertTrue(A.verify_allowlist_blob(d, sig))

    def test_operator_block_is_distributed_but_rule_kill_is_not(self):
        h = self._admin()
        self.assertEqual(self.c.post("/api/v1/lineage/0xAAAA/block", headers=h).status_code, 200)
        # a rule KILL reported by an agent marks the lineage blocked on the hub only
        self.c.post("/api/v1/telemetry", headers=AGENT, json={
            "type": "EXEC_THREAT", "rule_id": 1, "pid": 9, "ppid": 1, "lineage_id": 0xBBBB,
            "comm": "x", "severity": "HIGH", "action": "KILL"})
        ids = {c["lineage_id"] for c in self.c.get("/api/v1/agent/commands", headers=AGENT)
               .get_json()["commands"] if c["type"] == "block_lineage"}
        self.assertIn("0x000000000000AAAA", ids)
        self.assertNotIn("0x000000000000BBBB", ids)

    def test_login_cookie_is_hardened_and_errors_are_generic(self):
        c = hub.app.test_client()
        bad = c.post("/api/v1/login", json={"username": "admin", "password": "wrong-password"})
        self.assertEqual(bad.status_code, 401)
        self.assertEqual(bad.get_json()["error"], "invalid credentials")

        ok = c.post("/api/v1/login", json={"username": "admin", "password": "test-admin-pw"})
        self.assertEqual(ok.status_code, 200)
        cookie = ok.headers.get("Set-Cookie", "")
        self.assertIn("HttpOnly", cookie)
        self.assertIn("SameSite=Strict", cookie)
        self.assertIn("Max-Age=", cookie)

        out = c.post("/api/v1/logout")
        self.assertEqual(out.status_code, 200)
        self.assertIn("sentinel_session=;", out.headers.get("Set-Cookie", ""))

    def test_logout_revokes_the_token_server_side(self):
        c = hub.app.test_client()
        r = c.post("/api/v1/login", json={"username": "admin", "password": "test-admin-pw"})
        token = r.headers["Set-Cookie"].split("sentinel_session=")[1].split(";")[0]
        self.assertEqual(c.post("/api/v1/logout").status_code, 200)

        replay = hub.app.test_client().get(
            "/api/v1/csrf", headers={"Cookie": f"sentinel_session={token}"})
        self.assertEqual(replay.status_code, 401)

    def test_mode_change_is_reflected(self):
        h = self._admin()
        self.c.post("/api/v1/mode", json={"mode": "learn"}, headers=h)
        self.assertEqual(self.c.get("/api/v1/agent/commands", headers=AGENT).get_json()["mode"], "learn")
        self.c.post("/api/v1/mode", json={"mode": "enforce"}, headers=h)
        self.assertEqual(self.c.get("/api/v1/agent/commands", headers=AGENT).get_json()["mode"], "enforce")


class AgentApplies(unittest.TestCase):
    def setUp(self):
        self.c = hub.app.test_client()
        self.killed = []
        A.os.kill = lambda pid, sig: self.killed.append(pid)
        # Mock _start_time so the agent thinks fake PIDs are alive
        self._orig_pst = A._start_time
        A._start_time = lambda pid: 42
        # Create a mock loader
        self.mock_loader = MagicMock()
        self.mock_loader.block = MagicMock()
        self.mock_loader.unblock = MagicMock()
        self.mock_loader.trust = MagicMock()
        self.mock_loader.untrust = MagicMock()
        A.loader = self.mock_loader
        A.blocked_lineages.clear()
        A.lineage_tree.clear()
        A._last_sync_time = 0.0
        A.ENFORCEMENT_MODE = "enforce"
        r = self.c.post("/api/v1/login", json={"username": "admin", "password": "test-admin-pw"})
        self.h = {"X-CSRF-Token": r.get_json()["csrf"]}
        self.c.post("/api/v1/mode", json={"mode": "enforce"}, headers=self.h)

    def tearDown(self):
        A._start_time = self._orig_pst

    def _directive(self):
        return self.c.get("/api/v1/agent/commands", headers=AGENT).get_json()

    def test_operator_block_reaches_kernel_map_and_kills_live_processes(self):
        lid = 0x1234ABCD
        A.lineage_tree[777] = A.LineageEntry(
            lineage_id=lid, parent_lineage_id=0, pid=777, ppid=1, uid=0, gid=0, ns_pid=777,
            comm="x", binary_path="/tmp/x", cmdline="x", exec_timestamp=0.0, flags=0, start_time=42)
        self.c.post(f"/api/v1/lineage/{lid:#x}/block", headers=self.h)
        self.assertTrue(A.apply_directive(self._directive()))
        self.assertIn(lid, A.blocked_lineages)
        # Verify loader.block was called with the correct lineage ID
        self.mock_loader.block.assert_called_with(lid)
        self.assertIn(777, self.killed)

    def test_operator_unblock_clears_kernel_map_and_set(self):
        self.c.post("/api/v1/mode", json={"mode": "enforce"}, headers=self.h)
        lid = 0x0BADF00D
        A.lineage_tree[778] = A.LineageEntry(
            lineage_id=lid, parent_lineage_id=0, pid=778, ppid=1, uid=0, gid=0, ns_pid=778,
            comm="x", binary_path="/tmp/x", cmdline="x", exec_timestamp=0.0, flags=0, start_time=42)
        self.c.post(f"/api/v1/lineage/{lid:#x}/block", headers=self.h)
        self.assertTrue(A.apply_directive(self._directive()))
        self.assertIn(lid, A.blocked_lineages)

        r = self.c.post(f"/api/v1/lineage/{lid:#x}/unblock", headers=self.h)
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json()["status"], "unblocked")
        self.assertTrue(A.apply_directive(self._directive()))
        self.assertNotIn(lid, A.blocked_lineages)
        self.mock_loader.unblock.assert_any_call(lid)

    def test_learn_mode_does_not_block(self):
        self.c.post("/api/v1/lineage/0x5555/block", headers=self.h)
        self.c.post("/api/v1/mode", json={"mode": "learn"}, headers=self.h)
        self.assertTrue(A.apply_directive(self._directive()))
        self.assertEqual(A.ENFORCEMENT_MODE, "learn")
        self.assertNotIn(0x5555, A.blocked_lineages)

    def test_tampered_directive_is_rejected(self):
        d = self._directive()
        d["mode"] = "learn" if d["mode"] == "enforce" else "enforce"
        before = A.ENFORCEMENT_MODE
        self.assertFalse(A.apply_directive(d))
        self.assertEqual(A.ENFORCEMENT_MODE, before)

    def test_unsigned_directive_is_rejected(self):
        d = self._directive(); d.pop("signature")
        self.assertFalse(A.apply_directive(d))

    def test_replayed_directive_is_rejected(self):
        old = self._directive()
        self.c.post("/api/v1/mode", json={"mode": "learn"}, headers=self.h)
        self.assertTrue(A.apply_directive(self._directive()))     # newer, mode=learn
        self.assertFalse(A.apply_directive(old))                  # replay of older enforce
        self.assertEqual(A.ENFORCEMENT_MODE, "learn")

    def test_unknown_schema_is_rejected(self):
        d = self._directive(); d["schema"] = 2
        d["signature"] = hub.sa.allowlist_sign({k: v for k, v in d.items() if k != "signature"})
        self.assertFalse(A.apply_directive(d))


class MetricsAuth(unittest.TestCase):
    def setUp(self):
        self.c = hub.app.test_client()

    def test_metrics_requires_auth(self):
        self.assertEqual(self.c.get("/metrics").status_code, 401)

    def test_metrics_accepts_agent_key_and_bearer(self):
        self.assertEqual(self.c.get("/metrics", headers=AGENT).status_code, 200)
        key = AGENT["X-Sentinel-Key"]
        self.assertEqual(self.c.get("/metrics", headers={"Authorization": "Bearer " + key}).status_code, 200)
        self.assertEqual(self.c.get("/metrics", headers={"Authorization": "Bearer wrong"}).status_code, 401)

    def test_health_stays_public(self):
        self.assertEqual(self.c.get("/health").status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)
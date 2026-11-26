#!/usr/bin/env python3
"""Aggregate stats are not public: /api/v1/stats needs a session or the agent key.

Covers Task 5 of SENTINEL-FIX-TASKS.md. /health stays public; /metrics and
/api/v1/stats share the same _metrics_ok gate.

Run: python3 tests/test_stats_auth.py
     python3 -m pytest tests/test_stats_auth.py -q
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_tmp = tempfile.mkdtemp(prefix="sentinel-stats-test-")

os.environ.update({
    "SENTINEL_AGENT_KEY": os.environ.get("SENTINEL_AGENT_KEY", "test-agent-key"),
    "SENTINEL_SESSION_SECRET": os.environ.get("SENTINEL_SESSION_SECRET", "test-session-secret"),
    "SENTINEL_ALLOWLIST_KEY": os.environ.get("SENTINEL_ALLOWLIST_KEY", "test-allowlist-key"),
    "SENTINEL_ADMIN_PASSWORD": os.environ.get("SENTINEL_ADMIN_PASSWORD", "test-admin-pw"),
    "SENTINEL_DB_PATH": os.environ.get("SENTINEL_DB_PATH", os.path.join(_tmp, "sentinel.db")),
    "SENTINEL_DB": os.environ.get("SENTINEL_DB", os.path.join(_tmp, "lineage_db.json")),
    "SENTINEL_CONFIG": str(REPO / "config" / "rules.yaml"),
})
# Never let the metrics-public switch (or a leftover env) weaken these assertions.
os.environ.pop("SENTINEL_METRICS_PUBLIC", None)

sys.path.insert(0, str(REPO / "collector"))

import sentinel_hub_lineage as hub  # noqa: E402

AGENT = {"X-Sentinel-Key": os.environ["SENTINEL_AGENT_KEY"]}
ADMIN_PW = os.environ["SENTINEL_ADMIN_PASSWORD"]


class StatsAuth(unittest.TestCase):
    def setUp(self):
        self.c = hub.app.test_client()

    def _login(self):
        r = self.c.post("/api/v1/login",
                        json={"username": "admin", "password": ADMIN_PW})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))

    def test_stats_without_credentials_is_401(self):
        r = self.c.get("/api/v1/stats")
        self.assertEqual(r.status_code, 401)
        self.assertEqual(r.get_json()["error"], "unauthorized")

    def test_stats_with_wrong_key_is_401(self):
        r = self.c.get("/api/v1/stats", headers={"X-Sentinel-Key": "wrong"})
        self.assertEqual(r.status_code, 401)

    def test_stats_with_agent_key_is_200(self):
        r = self.c.get("/api/v1/stats", headers=AGENT)
        self.assertEqual(r.status_code, 200)
        body = r.get_json()
        self.assertIn("total_events", body)
        self.assertIn("lineage", body)

    def test_stats_with_session_is_200(self):
        self._login()
        r = self.c.get("/api/v1/stats")
        self.assertEqual(r.status_code, 200)
        self.assertIn("total_events", r.get_json())

    def test_health_stays_public(self):
        r = self.c.get("/health")
        self.assertEqual(r.status_code, 200)
        self.assertEqual(r.get_json(), {"status": "ok"})

    def test_metrics_gate_unchanged(self):
        self.assertEqual(self.c.get("/metrics").status_code, 401)
        self.assertEqual(self.c.get("/metrics", headers=AGENT).status_code, 200)


if __name__ == "__main__":
    unittest.main(verbosity=2)

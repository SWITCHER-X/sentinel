#!/usr/bin/env python3
"""Telemetry ingest must answer malformed bodies with 400, never 500.

Covers Task 1 of SENTINEL-FIX-TASKS.md: a list/string/number/null JSON body
used to reach lineage code expecting a dict (TypeError → HTTP 500).

Run: python3 tests/test_telemetry_validation.py
     python3 -m pytest tests/test_telemetry_validation.py -q
"""
import os
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_tmp = tempfile.mkdtemp(prefix="sentinel-telemetry-test-")

os.environ.update({
    "SENTINEL_AGENT_KEY": os.environ.get("SENTINEL_AGENT_KEY", "test-agent-key"),
    "SENTINEL_SESSION_SECRET": os.environ.get("SENTINEL_SESSION_SECRET", "test-session-secret"),
    "SENTINEL_ALLOWLIST_KEY": os.environ.get("SENTINEL_ALLOWLIST_KEY", "test-allowlist-key"),
    "SENTINEL_ADMIN_PASSWORD": os.environ.get("SENTINEL_ADMIN_PASSWORD", "test-admin-pw"),
    "SENTINEL_DB_PATH": os.environ.get("SENTINEL_DB_PATH", os.path.join(_tmp, "sentinel.db")),
    "SENTINEL_DB": os.environ.get("SENTINEL_DB", os.path.join(_tmp, "lineage_db.json")),
    "SENTINEL_CONFIG": str(REPO / "config" / "rules.yaml"),
})

sys.path.insert(0, str(REPO / "collector"))

import sentinel_hub_lineage as hub  # noqa: E402

AGENT = {"X-Sentinel-Key": os.environ["SENTINEL_AGENT_KEY"]}


class TelemetryValidation(unittest.TestCase):
    def setUp(self):
        self.c = hub.app.test_client()

    def _post_raw(self, body: str):
        return self.c.post("/api/v1/telemetry", data=body,
                           content_type="application/json", headers=AGENT)

    def test_non_object_bodies_are_400(self):
        for body in ("[1,2]", '"x"', "5", "null", "{not json"):
            with self.subTest(body=body):
                r = self._post_raw(body)
                self.assertEqual(r.status_code, 400, r.get_data(as_text=True))
                self.assertEqual(r.get_json()["error"], "body must be a JSON object")

    def test_empty_body_is_400(self):
        r = self.c.post("/api/v1/telemetry", data=b"",
                        content_type="application/json", headers=AGENT)
        self.assertEqual(r.status_code, 400)
        self.assertEqual(r.get_json()["error"], "body must be a JSON object")

    def test_valid_object_is_acknowledged(self):
        r = self.c.post("/api/v1/telemetry", headers=AGENT, json={
            "node_id": "node-valid", "type": "EXEC_THREAT", "pid": 4242, "ppid": 1,
            "comm": "curl", "cmdline": "curl -s http://127.0.0.1/x | bash",
            "mitre": ["T1059.004"], "severity": "HIGH", "lineage_id": 0x1234,
        })
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))
        body = r.get_json()
        self.assertEqual(body["status"], "acknowledged")
        self.assertIsInstance(body["timestamp"], float)

    def test_wrong_typed_numbers_are_400_not_5xx(self):
        for field in ("pid", "ppid"):
            for value in ("abc", {"nested": 1}, [1]):
                with self.subTest(field=field, value=value):
                    r = self.c.post("/api/v1/telemetry", headers=AGENT,
                                    json={field: value})
                    self.assertEqual(r.status_code, 400)
                    self.assertIn(field, r.get_json()["error"])

    def test_wrong_typed_fields_are_400_not_5xx(self):
        for payload in ({"mitre": "T1059"}, {"mitre": {"a": 1}},
                        {"cmdline": 123}, {"cmdline": ["ls"]},
                        {"node_id": 42}, {"node_id": {"x": 1}}):
            with self.subTest(payload=payload):
                r = self.c.post("/api/v1/telemetry", headers=AGENT, json=payload)
                self.assertEqual(r.status_code, 400, r.get_data(as_text=True))

    def test_valid_event_lands_in_log(self):
        node = "node-lands-in-log"
        r = self.c.post("/api/v1/telemetry", headers=AGENT, json={
            "node_id": node, "type": "EXEC_THREAT", "pid": 5150, "ppid": 50,
            "comm": "sh", "cmdline": "sh -c id", "mitre": ["T1059"],
            "severity": "CRITICAL", "lineage_id": 0xBEEF,
        })
        self.assertEqual(r.status_code, 200)

        logs = self.c.get("/api/v1/telemetry", headers=AGENT).get_json()
        mine = [e for e in logs if e.get("node_id") == node]
        self.assertTrue(mine, "posted event must be visible via GET /api/v1/telemetry")
        self.assertEqual(mine[0]["pid"], 5150)

    def test_overlong_fields_are_truncated(self):
        node = "n" * 300
        r = self.c.post("/api/v1/telemetry", headers=AGENT, json={
            "node_id": node, "type": "EXEC_THREAT", "pid": 6160,
            "cmdline": "x" * 5000, "severity": "HIGH",
        })
        self.assertEqual(r.status_code, 200)

        logs = self.c.get("/api/v1/telemetry", headers=AGENT).get_json()
        want = node[:hub.TELEMETRY_NODE_ID_MAX]
        mine = [e for e in logs if (e.get("node_id") or "") == want]
        self.assertTrue(mine, "truncated node_id must be the one stored")
        self.assertEqual(len(mine[0]["cmdline"]), hub.TELEMETRY_CMDLINE_MAX)

    def test_numeric_fields_are_coerced(self):
        r = self.c.post("/api/v1/telemetry", headers=AGENT, json={
            "node_id": "node-coerce", "type": "EXEC_THREAT",
            "pid": "7170", "ppid": "1", "mitre": ["T1059", 42],
        })
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))

    def test_telemetry_still_needs_the_agent_key(self):
        self.assertEqual(self.c.post("/api/v1/telemetry", json={"pid": 1}).status_code, 401)
        r = self.c.post("/api/v1/telemetry", data="[1,2]",
                        content_type="application/json",
                        headers={"X-Sentinel-Key": "wrong"})
        self.assertEqual(r.status_code, 401)


if __name__ == "__main__":
    unittest.main(verbosity=2)

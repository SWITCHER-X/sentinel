#!/usr/bin/env python3
"""CSP + clickjacking headers on every response, and no inline script in the HTML.

Covers Task 2 of SENTINEL-FIX-TASKS.md: the dashboard ships an external
theme.js / main.js / login.js so script-src 'self' works without 'unsafe-inline'.

Run: python3 tests/test_security_headers.py
     python3 -m pytest tests/test_security_headers.py -q
"""
import os
import re
import sys
import tempfile
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_tmp = tempfile.mkdtemp(prefix="sentinel-csp-test-")

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
ADMIN_PW = os.environ["SENTINEL_ADMIN_PASSWORD"]
COLLECTOR = REPO / "collector"


def _assert_security_headers(test, resp):
    headers = resp.headers
    test.assertEqual(headers.get("Content-Security-Policy"), hub.CSP_POLICY)
    test.assertIn("script-src 'self'", headers.get("Content-Security-Policy"))
    test.assertIn("frame-ancestors 'none'", headers.get("Content-Security-Policy"))
    test.assertNotIn("unsafe-inline'", headers.get("Content-Security-Policy").split("style-src")[0])
    test.assertEqual(headers.get("X-Frame-Options"), "DENY")
    test.assertEqual(headers.get("X-Content-Type-Options"), "nosniff")
    test.assertEqual(headers.get("Referrer-Policy"), "no-referrer")


class SecurityHeaders(unittest.TestCase):
    def setUp(self):
        self.c = hub.app.test_client()

    def _login(self):
        r = self.c.post("/api/v1/login",
                        json={"username": "admin", "password": ADMIN_PW})
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))

    def test_login_page_has_security_headers(self):
        r = self.c.get("/login")
        self.assertEqual(r.status_code, 200)
        _assert_security_headers(self, r)

    def test_dashboard_redirect_has_security_headers(self):
        r = self.c.get("/")
        self.assertEqual(r.status_code, 302)
        self.assertTrue(r.headers["Location"].endswith("/login"))
        _assert_security_headers(self, r)

    def test_dashboard_has_security_headers(self):
        self._login()
        r = self.c.get("/")
        self.assertEqual(r.status_code, 200)
        _assert_security_headers(self, r)

    def test_api_and_health_have_security_headers(self):
        _assert_security_headers(self, self.c.get("/health"))
        _assert_security_headers(self, self.c.get("/api/v1/stats", headers=AGENT))
        # login reply: CSP is safe everywhere, and no-store stays.
        r = self.c.post("/api/v1/login",
                        json={"username": "admin", "password": ADMIN_PW})
        _assert_security_headers(self, r)
        self.assertEqual(r.headers.get("Cache-Control"), "no-store")

    def test_external_scripts_are_served(self):
        for name in ("theme.js", "main.js", "login.js", "dashboard.js"):
            with self.subTest(asset=name):
                r = self.c.get("/" + name)
                self.assertEqual(r.status_code, 200)
                self.assertIn("javascript", r.headers["Content-Type"])

    def test_static_allowlist_unchanged_for_unknown_files(self):
        self.assertEqual(self.c.get("/not-a-real-file.js").status_code, 404)

    def test_sse_stream_connects(self):
        r = self.c.post("/api/v1/telemetry", headers=AGENT, json={
            "node_id": "node-sse", "type": "EXEC_THREAT", "pid": 8080,
            "comm": "sse-probe", "severity": "HIGH", "lineage_id": 0xCAFE,
        })
        self.assertEqual(r.status_code, 200, r.get_data(as_text=True))

        stream = self.c.get("/api/v1/stream", headers=AGENT, buffered=False)
        self.assertEqual(stream.status_code, 200)
        self.assertEqual(stream.headers["Content-Type"], "text/event-stream; charset=utf-8")
        _assert_security_headers(self, stream)
        first = next(iter(stream.response))
        self.assertIn(b"data:", first)
        stream.close()

    def test_sse_still_requires_auth(self):
        self.assertEqual(self.c.get("/api/v1/stream").status_code, 401)


class NoInlineScript(unittest.TestCase):
    INLINE_HANDLER = re.compile(
        r"\s(onclick|onload|onerror|onsubmit|onchange|oninput|onkeydown|onmouseover)\s*=",
        re.IGNORECASE)

    def _script_tags(self, name):
        return re.findall(r"<script\b[^>]*>", (COLLECTOR / name).read_text(), re.IGNORECASE)

    def test_every_script_tag_has_a_same_origin_src(self):
        for name in ("index.html", "login.html"):
            tags = self._script_tags(name)
            self.assertTrue(tags, name)
            for tag in tags:
                with self.subTest(page=name, tag=tag):
                    self.assertRegex(tag, r'src="(/|\./)[^"]+"')

    def test_pages_have_no_inline_event_handlers_or_javascript_urls(self):
        for name in ("index.html", "login.html"):
            html = (COLLECTOR / name).read_text()
            with self.subTest(page=name):
                self.assertIsNone(self.INLINE_HANDLER.search(html))
                self.assertNotIn("javascript:", html.lower())

    def test_external_entry_points_exist(self):
        for name in ("theme.js", "main.js", "login.js"):
            self.assertTrue((COLLECTOR / name).is_file(), name)
        main = (COLLECTOR / "main.js").read_text()
        self.assertIn("SentinelDashboard", main)
        self.assertIn("dashboard.js", main)


if __name__ == "__main__":
    unittest.main(verbosity=2)

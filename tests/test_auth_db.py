#!/usr/bin/env python3
"""Tests for the auth + SQLite layer (sentinel_auth) and hub auth wiring.
Run: python3 tests/test_auth_db.py"""
import json
import os
import sys
import tempfile
import time
import unittest
import urllib.request
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collector"))
os.environ.setdefault("SENTINEL_DB_PATH", tempfile.mktemp(suffix=".db"))
# sentinel_auth fails closed without these; tests supply their own.
os.environ.setdefault("SENTINEL_SESSION_SECRET", "test-session-secret")
os.environ.setdefault("SENTINEL_ALLOWLIST_KEY", "test-allowlist-key")

import sentinel_auth as sa  # noqa: E402


class TestPasswords(unittest.TestCase):
    def test_hash_verify_roundtrip(self):
        h = sa.hash_password("s3cret!")
        self.assertTrue(sa.verify_password("s3cret!", h))
        self.assertFalse(sa.verify_password("wrong", h))

    def test_hashes_are_salted(self):
        self.assertNotEqual(sa.hash_password("x"), sa.hash_password("x"))


class TestSessions(unittest.TestCase):
    def test_create_verify(self):
        tok = sa.session_create(ttl=60)
        self.assertTrue(sa.session_verify(tok))

    def test_expired_token_rejected(self):
        tok = sa.session_create(ttl=-10)
        self.assertFalse(sa.session_verify(tok))

    def test_tampered_token_rejected(self):
        tok = sa.session_create(ttl=60)
        self.assertFalse(sa.session_verify(tok[:-4] + "aaaa"))

    def test_csrf_binds_to_session(self):
        tok = sa.session_create(ttl=60)
        csrf = sa.csrf_for(tok)
        self.assertTrue(sa.csrf_verify(tok, csrf))
        self.assertFalse(sa.csrf_verify(tok, "nope"))
        self.assertFalse(sa.csrf_verify("other-session", csrf))


class TestLoginThrottle(unittest.TestCase):
    def test_lockout_after_five(self):
        ip = "10.9.9.9"
        for _ in range(5):
            sa.login_fail(ip)
        allowed, wait = sa.login_attempts(ip)
        self.assertFalse(allowed)
        self.assertGreater(wait, 0)
        sa.login_reset(ip)
        allowed, _ = sa.login_attempts(ip)
        self.assertTrue(allowed)


class TestUsersAndAudit(unittest.TestCase):
    def test_ensure_user_idempotent_and_check(self):
        sa.ensure_user("demo", "pw-one")
        self.assertTrue(sa.check_user("demo", "pw-one"))
        sa.ensure_user("demo", "pw-one")  # ON CONFLICT DO NOTHING → original pw
        self.assertTrue(sa.check_user("demo", "pw-one"))
        self.assertFalse(sa.check_user("demo", "pw-two"))

    def test_audit_written(self):
        sa.audit("tester", "test.action", "detail-1")
        rows = sa.db().execute(
            "SELECT actor, action FROM audit WHERE action='test.action'").fetchall()
        self.assertTrue(any(r["actor"] == "tester" for r in rows))


class TestAllowlist(unittest.TestCase):
    def test_add_get_remove(self):
        sa.allowlist_add("hash", "ab" * 32, "nginx pinned")
        sa.allowlist_add("publisher", "nginx-core", "distro pkg")
        entries = sa.allowlist_all()
        self.assertIn(("hash", "ab" * 32), [(e["tier"], e["value"]) for e in entries])
        sa.allowlist_remove("hash", "ab" * 32)
        entries = sa.allowlist_all()
        self.assertNotIn(("hash", "ab" * 32), [(e["tier"], e["value"]) for e in entries])

    def test_invalid_tier_rejected(self):
        with self.assertRaises(ValueError):
            sa.allowlist_add("bogus", "x")

    def test_signature_roundtrip_and_tamper(self):
        sa.allowlist_add("hash", "cd" * 32, "sig test")
        blob = {"entries": sa.allowlist_all(), "generated_at": 123.0}
        sig = sa.allowlist_sign(blob)
        self.assertTrue(sa.allowlist_verify(blob, sig))
        blob["entries"] = blob["entries"] + [{"tier": "hash", "value": "evil"}]
        self.assertFalse(sa.allowlist_verify(blob, sig))


class TestPersistence(unittest.TestCase):
    def test_meta_roundtrip(self):
        sa.meta_set("mode", "learn")
        self.assertEqual(sa.meta_get("mode"), "learn")
        sa.meta_set("mode", "enforce")
        self.assertEqual(sa.meta_get("mode"), "enforce")

    def test_event_persist_and_query(self):
        c = sa.db()
        seq = time.time_ns() // 1000
        c.execute("INSERT INTO events(seq,ts,type,severity,rule_id,mitre,pid,ppid,"
                  "lineage_id,comm,binary,cmdline,user,host,killed,action,raw) "
                  "VALUES(?,1,'EXEC_THREAT','CRITICAL','r','[]',1,0,'0x1','nc',"
                  "'nc','nc -e','root','h',1,'KILL','{}')", (seq,))
        c.commit()
        row = c.execute("SELECT * FROM events WHERE seq=?", (seq,)).fetchone()
        self.assertEqual(row["severity"], "CRITICAL")
        c.close()


if __name__ == "__main__":
    unittest.main(verbosity=1)
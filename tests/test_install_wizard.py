#!/usr/bin/env python3
"""Installer setup wizard: prompts, flags, validation, non-destructive re-runs.

Nothing here touches the system: every run uses --plan (prints the plan, exits)
or sources only the env-file helper functions against a temp file.

Run: python3 tests/test_install_wizard.py
"""
import os, pty, re, select, subprocess, tempfile, time, unittest
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
INSTALL = str(REPO / "install.sh")
ANSI = re.compile(rb"\x1b\[[0-9;?]*[a-zA-Z]")


def plain(args):
    r = subprocess.run(["bash", INSTALL, *args], stdin=subprocess.DEVNULL,
                       capture_output=True, text=True, timeout=30)
    return r.returncode, r.stdout + r.stderr


def tty(args, answers, idle=2.0, timeout=20):
    """Run the installer on a pseudo-terminal, typing `answers` at the prompts."""
    pid, fd = pty.fork()
    if pid == 0:
        os.execvp("bash", ["bash", INSTALL, *args])
    out, i, last, t0 = b"", 0, time.time(), time.time()
    while time.time() - t0 < timeout:
        r, _, _ = select.select([fd], [], [], 0.3)
        if r:
            try:
                d = os.read(fd, 4096)
            except OSError:
                break
            if not d:
                break
            out += d
            last = time.time()
        elif i < len(answers) and time.time() - last > 0.4:
            os.write(fd, (answers[i] + "\n").encode()); i += 1; last = time.time()
        elif i >= len(answers) and time.time() - last > idle:
            break
    try:
        os.waitpid(pid, 0)
    except ChildProcessError:
        pass
    return ANSI.sub(b"", out).decode(errors="replace").replace("\r", "")


class TestFlags(unittest.TestCase):
    def test_defaults_are_safe(self):
        rc, out = plain(["--plan"])
        self.assertEqual(rc, 0)
        self.assertIn("learn (log only, never kills)", out)
        self.assertIn("127.0.0.1:5000", out)
        self.assertIn("30 days", out)

    def test_flags_skip_questions(self):
        rc, out = plain(["--plan", "--enforce", "--lan", "--port", "8080", "--retention", "0", "--no-notify"])
        self.assertEqual(rc, 0)
        self.assertIn("ENFORCE", out); self.assertIn("0.0.0.0:8080", out)
        self.assertIn("forever", out); self.assertIn("pop-ups     : no", out)

    def test_hub_only(self):
        _, out = plain(["--plan", "--hub-only"])
        self.assertIn("hub only", out); self.assertNotIn("mode ", out)

    def test_bad_values_are_rejected(self):
        for args in (["--port", "abc"], ["--port", "70000"], ["--port"], ["--bogus"]):
            rc, out = plain(args)
            self.assertNotEqual(rc, 0, args)

    def test_plan_changes_nothing(self):
        rc, out = plain(["--plan"])
        self.assertIn("nothing was changed", out)


class TestWizard(unittest.TestCase):
    def test_full_walkthrough(self):
        out = tty(["--plan"], ["1", "2", "", "1", "8080", "14", "2", "short",
                               "MyStrongPass12.", "MyStrongPass12."])
        self.assertIn("ENFORCE", out)
        self.assertIn("127.0.0.1:8080", out)
        self.assertIn("14 days", out)
        self.assertIn("the one you typed", out)
        self.assertIn("too short or has unsupported characters", out)
        self.assertNotIn("MyStrongPass12.", out.split("Plan")[-1])   # never echoed back

    def test_invalid_choice_reprompts(self):
        out = tty(["--plan"], ["9", "x", "2", "", "1", "5000", "0", "1"])
        self.assertIn("please enter a number from 1 to 2", out)
        self.assertIn("hub only", out)

    def test_out_of_range_number_reprompts(self):
        out = tty(["--plan", "--hub-only"], ["1", "99999", "5000", "x", "7", "1"])
        self.assertIn("enter a number from 1 to 65535", out)
        self.assertIn("enter a number from 0 to 3650", out)
        self.assertIn(":5000", out); self.assertIn("7 days", out)

    def test_flags_skip_their_questions(self):
        out = tty(["--plan", "--learn", "--no-notify", "--port", "9000", "--retention", "5", "--lan"], ["1", "1"])
        self.assertNotIn("What should Sentinel do", out)
        self.assertNotIn("Dashboard port", out)
        self.assertIn("0.0.0.0:9000", out)

    def test_password_mismatch_reprompts(self):
        out = tty(["--plan", "--hub-only"], ["1", "1", "5000", "30", "2",
                  "MyStrongPass12.", "different-Pass12.", "MyStrongPass12.", "MyStrongPass12."])
        self.assertIn("those did not match", out)
        self.assertIn("the one you typed", out)


class TestEnvHelpers(unittest.TestCase):
    """set_secret / add_secret / put: explicit answers win, defaults only fill gaps."""

    def run_put(self, env_text, calls):
        src = Path(INSTALL).read_text()
        def grab(name):
            m = re.search(rf"^{name}\(\) \{{.*?^\}}", src, re.S | re.M)
            self.assertIsNotNone(m, name); return m.group(0)
        funcs = "\n".join(grab(n) for n in ("set_secret", "add_secret", "put"))
        with tempfile.NamedTemporaryFile("w+", delete=False) as f:
            f.write(env_text); path = f.name
        try:
            script = f'GEN_CAT="{path}"\n{funcs}\n{calls}\n'
            subprocess.run(["bash", "-c", script], check=True, timeout=10)
            return Path(path).read_text()
        finally:
            os.unlink(path)

    def test_rerun_keeps_existing_enforce(self):
        out = self.run_put("SENTINEL_DRY_RUN=0\n", 'put SENTINEL_DRY_RUN 1 0')
        self.assertIn("SENTINEL_DRY_RUN=0", out); self.assertNotIn("DRY_RUN=1", out)

    def test_explicit_answer_overrides(self):
        out = self.run_put("SENTINEL_DRY_RUN=0\n", 'put SENTINEL_DRY_RUN 1 1')
        self.assertIn("SENTINEL_DRY_RUN=1", out); self.assertNotIn("DRY_RUN=0", out)

    def test_missing_key_gets_default(self):
        out = self.run_put("# SENTINEL_DRY_RUN=0\nOTHER=1\n", 'put SENTINEL_DRY_RUN 1 0')
        self.assertIn("SENTINEL_DRY_RUN=1", out); self.assertIn("OTHER=1", out)


if __name__ == "__main__":
    unittest.main(verbosity=1)

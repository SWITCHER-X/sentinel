#!/usr/bin/env python3
"""Prove SENTINEL actually enforces.

Runs a harmless process whose command line matches a KILL rule, once in
enforce mode (it must die by SIGKILL) and once in learn mode (it must survive).
Also checks the hub recorded the kill. Restores the original mode afterwards.

Usage:
    sudo python3 tools/verify_enforcement.py
    python3 tools/verify_enforcement.py --url http://127.0.0.1:5000 \
        --password '...' --no-learn

Exit codes: 0 = all checks passed, 1 = a check failed, 2 = setup problem.
"""
from __future__ import annotations

import argparse
import http.cookiejar
import json
import os
import signal
import subprocess
import sys
import time
import urllib.error
import urllib.request

ENV_FILE = "/etc/sentinel/sentinel.env"
# Matches rule 1003 (Reverse Shell - /dev/tcp/). The echo makes the process
# live for 30s without opening any socket, so the test is harmless either way.
TRIGGER = ["bash", "-c", "echo /dev/tcp/127.0.0.1/4444; sleep 30"]


def load_env(path: str = ENV_FILE) -> dict:
    values = {}
    try:
        with open(path, "r", encoding="utf-8", errors="replace") as fh:
            for line in fh:
                line = line.strip()
                if not line or line.startswith("#") or "=" not in line:
                    continue
                key, value = line.split("=", 1)
                values[key.strip()] = value.strip()
    except OSError:
        pass
    return values


def classify_kill(returncode: int) -> bool:
    """Python reports signal deaths as negative codes; shells as 128+signo."""
    return returncode == -9 or returncode == 137


class Hub:
    def __init__(self, url: str):
        self.url = url.rstrip("/")
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar))
        self.csrf = ""

    def _request(self, method: str, path: str, payload=None, timeout=10):
        data = json.dumps(payload).encode() if payload is not None else None
        req = urllib.request.Request(self.url + path, data=data, method=method)
        if data is not None:
            req.add_header("Content-Type", "application/json")
        if self.csrf:
            req.add_header("X-CSRF-Token", self.csrf)
        try:
            with self.opener.open(req, timeout=timeout) as resp:
                return resp.status, json.loads(resp.read() or b"{}")
        except urllib.error.HTTPError as exc:
            body = exc.read().decode("utf-8", "replace")
            try:
                body = json.loads(body)
            except ValueError:
                pass
            return exc.code, body

    def login(self, username: str, password: str) -> bool:
        status, body = self._request("POST", "/api/v1/login",
                                     {"username": username, "password": password})
        if status == 200:
            self.csrf = (body or {}).get("csrf", "")
            return True
        return False

    def mode(self) -> str:
        _, body = self._request("GET", "/api/v1/mode")
        return (body or {}).get("mode", "?")

    def set_mode(self, mode: str) -> bool:
        status, _ = self._request("POST", "/api/v1/mode", {"mode": mode})
        return status == 200

    def stats(self) -> dict:
        _, body = self._request("GET", "/api/v1/stats")
        return body or {}

    def diagnostics(self) -> dict:
        _, body = self._request("GET", "/api/v1/diagnostics")
        return body or {}


def run_trigger(timeout: float) -> tuple:
    """Return (returncode, elapsed, survived_timeout).

    The child gets its own process group so a surviving test process is fully
    cleaned up instead of leaving a `sleep 30` orphan behind.
    """
    started = time.time()
    proc = subprocess.Popen(
        TRIGGER, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL,
        start_new_session=True,
    )
    try:
        returncode = proc.wait(timeout=timeout)
        return returncode, time.time() - started, False
    except subprocess.TimeoutExpired:
        try:
            os.killpg(proc.pid, signal.SIGKILL)
        except ProcessLookupError:
            pass
        proc.wait(timeout=5)
        return None, time.time() - started, True


class Reporter:
    def __init__(self):
        self.passed = 0
        self.failed = 0

    def check(self, ok: bool, label: str, detail: str = ""):
        if ok:
            self.passed += 1
            print(f"  PASS  {label}" + (f"  ({detail})" if detail else ""))
        else:
            self.failed += 1
            print(f"  FAIL  {label}" + (f"  ({detail})" if detail else ""))


def main() -> int:
    ap = argparse.ArgumentParser(description="Verify SENTINEL kills what it should")
    ap.add_argument("--url", default=os.getenv("SENTINEL_URL", "http://127.0.0.1:5000"))
    ap.add_argument("--username", default=os.getenv("SENTINEL_ADMIN_USER", "admin"))
    ap.add_argument("--password", default=os.getenv("SENTINEL_ADMIN_PASSWORD", ""))
    ap.add_argument("--env-file", default=ENV_FILE)
    ap.add_argument("--apply-delay", type=float, default=3.0,
                    help="seconds to wait for the agent to pick up a mode change")
    ap.add_argument("--skip-learn", action="store_true", help="skip the learn-mode control test")
    args = ap.parse_args()

    env = load_env(args.env_file)
    password = args.password or env.get("SENTINEL_ADMIN_PASSWORD", "")
    if not password:
        print("No admin password: pass --password or run as root with /etc/sentinel/sentinel.env", file=sys.stderr)
        return 2

    hub = Hub(args.url)
    if not hub.login(args.username, password):
        print(f"Cannot log in to {args.url}/api/v1/login — wrong password or hub down", file=sys.stderr)
        return 2

    rep = Reporter()
    original_mode = hub.mode()
    print(f"Hub {args.url} · mode={original_mode}")
    print("\nEnforcement test (must kill):")

    before = int(hub.stats().get("killed_processes") or 0)
    if original_mode != "enforce":
        rep.check(hub.set_mode("enforce"), "switch to enforce mode", f"was {original_mode}")
        time.sleep(args.apply_delay)
    else:
        print("  note  already in enforce mode")

    rc, elapsed, survived = run_trigger(timeout=12)
    rep.check(not survived and classify_kill(rc),
              "rule-matching process killed by SIGKILL",
              f"rc={rc}, {elapsed:.1f}s" if not survived else f"survived {elapsed:.1f}s")

    time.sleep(2)
    after = int(hub.stats().get("killed_processes") or 0)
    rep.check(after > before, "hub recorded the kill", f"killed_processes {before} → {after}")

    if not args.skip_learn:
        print("\nLearn-mode control test (must NOT kill):")
        rep.check(hub.set_mode("learn"), "switch to learn mode")
        time.sleep(args.apply_delay)
        rc, elapsed, survived = run_trigger(timeout=6)
        rep.check(survived, "process survived in learn mode",
                  f"alive after {elapsed:.1f}s" if survived else f"rc={rc}, {elapsed:.1f}s")
        if not survived:
            time.sleep(1)

    if original_mode and original_mode != hub.mode():
        hub.set_mode(original_mode)
        print(f"\nRestored mode: {hub.mode()}")

    print("\nResult:")
    print(f"  {rep.passed} passed, {rep.failed} failed")
    if rep.failed:
        diag = hub.diagnostics()
        print(f"\n  Troubleshooter says: {diag.get('title', '(no verdict)')}")
        for check in (diag.get("checks") or []):
            if check.get("status") != "ok":
                print(f"    [{check['status']}] {check['title']}: {check.get('fix') or ''}")
        return 1
    return 0


if __name__ == "__main__":
    sys.exit(main())

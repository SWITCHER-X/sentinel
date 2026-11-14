#!/usr/bin/env python3
"""Staged self-update — fetch, build and verify the new version, then cut over.

Flow (the old hub keeps serving the whole time):
  1. fetch the target ref into /var/lib/sentinel/update/src
  2. build the CO-RE object + loader in the new tree
  3. stage it in /opt/sentinel.staging and install Python deps
  4. start the staged hub on a spare port and wait for /health
  5. cut over: rsync the staged tree over /opt/sentinel and `systemctl reload`
     (gunicorn SIGHUP replaces workers without closing the listener). If the
     unit has no ExecReload yet, fall back to a restart.
  6. verify the live hub, clean up, write the status file.

State is written to /var/lib/sentinel/update.json for the dashboard to poll.

Invoked as root by sentinel-update.service. Manual use:
  sudo /opt/sentinel/.venv/bin/python /opt/sentinel/tools/self_update.py --check
"""
from __future__ import annotations

import argparse
import fcntl
import json
import os
import shutil
import subprocess
import sys
import tempfile
import time
import urllib.request
from pathlib import Path

HOME = Path(os.getenv("SENTINEL_HOME", "/opt/sentinel"))
VARLIB = Path(os.getenv("SENTINEL_VARLIB", "/var/lib/sentinel"))
ETC = Path(os.getenv("SENTINEL_ETC", "/etc/sentinel"))
STATUS_FILE = Path(os.getenv("SENTINEL_UPDATE_STATUS", str(VARLIB / "update.json")))
LOCK_FILE = VARLIB / "update.lock"
SRC_DIR = VARLIB / "update" / "src"
STAGING = Path(os.getenv("SENTINEL_STAGING", "/opt/sentinel.staging"))
META = HOME / ".install-meta"

REPO = os.getenv("SENTINEL_UPDATE_REPO", "https://github.com/SWITCHER-X/sentinel.git")
REF = os.getenv("SENTINEL_UPDATE_REF", "master")
PORT = int(os.getenv("SENTINEL_PORT", "5000"))
SPARE_PORT = int(os.getenv("SENTINEL_UPDATE_PORT", str(PORT + 1)))
SERVICE = os.getenv("SENTINEL_HUB_SERVICE", "sentinel-hub")
SERVICE_USER = os.getenv("SENTINEL_SERVICE_USER", "sentinel")

RUNNING_STATES = {"starting", "fetching", "building", "staging", "verifying", "cutover"}
_log: list[str] = []
_temp_proc: subprocess.Popen | None = None


# ── environment ───────────────────────────────────────────────────────────
def load_env_file(path: Path = ETC / "sentinel.env") -> None:
    """systemd passes EnvironmentFile=; a manual sudo run does not. Load it."""
    try:
        lines = path.read_text().splitlines()
    except OSError:
        return
    for line in lines:
        line = line.strip()
        if not line or line.startswith("#") or "=" not in line:
            continue
        key, _, value = line.partition("=")
        os.environ.setdefault(key.strip(), value.strip())


# ── status + logging ──────────────────────────────────────────────────────
def log(line: str) -> None:
    line = str(line).rstrip()
    if not line:
        return
    _log.append(line[-400:])
    del _log[:-80]
    print(line, flush=True)


def status(state: str, message: str = "", **extra) -> None:
    payload = {
        "state": state,
        "message": message,
        "pid": os.getpid(),
        "updated_at": time.time(),
        "ref": REF,
        "repo": REPO,
        "log": _log[-40:],
        **extra,
    }
    STATUS_FILE.parent.mkdir(parents=True, exist_ok=True)
    tmp = STATUS_FILE.with_suffix(".tmp")
    tmp.write_text(json.dumps(payload, indent=1))
    tmp.chmod(0o644)
    tmp.replace(STATUS_FILE)


def read_meta(path: Path = META) -> dict:
    out: dict[str, str] = {}
    try:
        for line in path.read_text().splitlines():
            if "=" in line:
                key, _, value = line.partition("=")
                out[key.strip()] = value.strip()
    except OSError:
        pass
    return out


# ── subprocess helpers ────────────────────────────────────────────────────
def run(cmd, cwd=None, env=None, check=True) -> subprocess.CompletedProcess:
    log("$ " + " ".join(str(c) for c in cmd))
    proc = subprocess.run(cmd, cwd=cwd, env=env, capture_output=True, text=True)
    for line in (proc.stdout or "").splitlines()[-25:]:
        log(line)
    for line in (proc.stderr or "").splitlines()[-25:]:
        log("! " + line)
    if check and proc.returncode != 0:
        raise RuntimeError(f"{cmd[0]} failed with exit {proc.returncode}")
    return proc


def health(port: int, timeout: float = 2.0) -> bool:
    try:
        with urllib.request.urlopen(f"http://127.0.0.1:{port}/health", timeout=timeout) as r:
            body = r.read().decode("utf-8", "replace")
        return r.status == 200 and ('"status":"ok"' in body or '"status":"healthy"' in body)
    except Exception:
        return False


def wait_health(port: int, seconds: float) -> bool:
    deadline = time.time() + seconds
    while time.time() < deadline:
        if health(port):
            return True
        time.sleep(0.5)
    return False


# ── update steps ──────────────────────────────────────────────────────────
def fetch() -> str:
    SRC_DIR.parent.mkdir(parents=True, exist_ok=True)
    if (SRC_DIR / ".git").exists():
        run(["git", "-C", str(SRC_DIR), "fetch", "--depth=1", "origin", REF])
        run(["git", "-C", str(SRC_DIR), "reset", "--hard", "FETCH_HEAD"])
        run(["git", "-C", str(SRC_DIR), "clean", "-fdx"])
    else:
        shutil.rmtree(SRC_DIR, ignore_errors=True)
        run(["git", "clone", "--depth=1", "--branch", REF, REPO, str(SRC_DIR)])
    return run(["git", "-C", str(SRC_DIR), "rev-parse", "HEAD"]).stdout.strip()


def build() -> None:
    if not (SRC_DIR / "Makefile").exists() or not (SRC_DIR / "ebpf").exists():
        log("no eBPF sources in this tree — skipping kernel build")
        return
    missing = [tool for tool in ("clang", "gcc", "make") if shutil.which(tool) is None]
    if missing:
        log("hub-only install (missing: %s) — skipping eBPF build" % ", ".join(missing))
        return
    run(["make", "-C", str(SRC_DIR), "build-core", "build-loader"])


def stage() -> None:
    shutil.rmtree(STAGING, ignore_errors=True)
    STAGING.mkdir(parents=True)
    run([
        "rsync", "-a", "--delete",
        "--exclude", ".git", "--exclude", ".venv", "--exclude", "dist",
        "--exclude", "__pycache__", "--exclude", "*.pyc", "--exclude", "runs",
        f"{SRC_DIR}/", f"{STAGING}/",
    ])
    run(["chown", "-R", f"{SERVICE_USER}:{SERVICE_USER}", str(STAGING)])


def install_deps() -> None:
    pip = HOME / ".venv" / "bin" / "pip"
    requirements = STAGING / "requirements.txt"
    if not requirements.exists():
        raise RuntimeError("staged tree has no requirements.txt — refusing to cut over")
    run([str(pip), "install", "--quiet", "--no-input", "-r", str(requirements)])
    run(["chown", "-R", f"{SERVICE_USER}:{SERVICE_USER}", str(HOME / ".venv")])


def start_staged() -> int:
    """Run the staged hub on a spare port and wait until it is healthy."""
    global _temp_proc
    env = dict(os.environ)
    env["SENTINEL_PORT"] = str(SPARE_PORT)
    env["SENTINEL_UPDATE_TEMPORARY"] = "1"
    python = HOME / ".venv" / "bin" / "python"
    # runuser may sanitise the environment, so pass the keys explicitly.
    pass_keys = [k for k in os.environ if k.startswith("SENTINEL_") or k.startswith("TELEGRAM_")]
    cmd = [
        "runuser", "-u", SERVICE_USER, "--", "env",
        *[f"{k}={os.environ[k]}" for k in pass_keys],
        f"SENTINEL_PORT={SPARE_PORT}",
        str(python), str(STAGING / "collector" / "sentinel_hub_lineage.py"),
    ]
    log(f"starting staged hub on :{SPARE_PORT}")
    _temp_proc = subprocess.Popen(cmd, env=env, stdout=subprocess.PIPE,
                                  stderr=subprocess.STDOUT, text=True)
    deadline = time.time() + 40
    while time.time() < deadline:
        if health(SPARE_PORT):
            return SPARE_PORT
        if _temp_proc.poll() is not None:
            out = (_temp_proc.stdout.read() or "")[-1500:] if _temp_proc.stdout else ""
            raise RuntimeError("staged hub exited during verification:\n" + out)
        time.sleep(0.5)
    raise RuntimeError(f"staged hub never became healthy on :{SPARE_PORT}")


def stop_staged() -> None:
    global _temp_proc
    if _temp_proc is not None and _temp_proc.poll() is None:
        _temp_proc.terminate()
        try:
            _temp_proc.wait(timeout=10)
        except subprocess.TimeoutExpired:
            _temp_proc.kill()
    _temp_proc = None


def cutover(commit: str) -> None:
    run([
        "rsync", "-a", "--delete",
        "--exclude", ".venv", "--exclude", ".install-meta",
        f"{STAGING}/", f"{HOME}/",
    ])
    tmp = META.with_suffix(".tmp")
    tmp.write_text(f"commit={commit}\ninstalled_at={time.strftime('%Y-%m-%dT%H:%M:%S%z')}\n")
    tmp.chmod(0o644)
    tmp.replace(META)
    run(["chown", f"{SERVICE_USER}:{SERVICE_USER}", str(META)])
    run(["chown", "-R", f"{SERVICE_USER}:{SERVICE_USER}", str(HOME)])

    reloaded = run(["systemctl", "reload", SERVICE], check=False)
    if reloaded.returncode != 0:
        log("reload unavailable — falling back to restart")
        run(["systemctl", "restart", SERVICE])
    if not wait_health(PORT, 45):
        log("hub unhealthy after cutover — restarting once")
        run(["systemctl", "restart", SERVICE])
        if not wait_health(PORT, 45):
            raise RuntimeError("hub is not healthy after cutover")


def report(installed: str, target: str, state: str, message: str) -> None:
    status(state, message, from_commit=installed or None, to_commit=target or None,
           spare_port=SPARE_PORT)


# ── entry point ───────────────────────────────────────────────────────────
def main(argv=None) -> int:
    global REF, REPO
    parser = argparse.ArgumentParser(description="Sentinel staged self-update")
    parser.add_argument("--check", action="store_true", help="only report if an update exists")
    parser.add_argument("--dry-run", action="store_true", help="fetch but do not build or cut over")
    parser.add_argument("--force", action="store_true", help="update even if the commit matches")
    parser.add_argument("--ref", default=REF, help="git ref to install (default: %(default)s)")
    parser.add_argument("--repo", default=REPO, help="git repository URL")
    args = parser.parse_args(argv)

    REF, REPO = args.ref, args.repo

    load_env_file()
    VARLIB.mkdir(parents=True, exist_ok=True)
    lock = open(LOCK_FILE, "w")
    try:
        fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
    except BlockingIOError:
        status("failed", "another update is already running")
        print("another update is already running", file=sys.stderr)
        return 1

    installed = read_meta().get("commit", "")
    try:
        report(installed, "", "starting", "fetching from git")
        if args.check:
            status("starting", "checking for updates")
        target = fetch()
        report(installed, target, "fetching", f"fetched {target[:12]}")
        if installed and target == installed and not args.force:
            status("up-to-date", f"already on {target[:12]}", to_commit=target,
                   from_commit=installed)
            print("already up to date")
            return 0
        if args.check or args.dry_run:
            status("dry-run", f"update available: {target[:12]}", to_commit=target,
                   from_commit=installed)
            print(f"update available: {target}")
            return 0

        report(installed, target, "building", "building eBPF objects")
        build()
        report(installed, target, "staging", "staging files and dependencies")
        stage()
        install_deps()
        report(installed, target, "verifying", f"checking staged hub on :{SPARE_PORT}")
        start_staged()
        stop_staged()
        report(installed, target, "cutover", "cutting over to the new version")
        cutover(target)
        report(installed, target, "done", f"updated to {target[:12]}")
        print(f"updated {installed[:12] or 'unknown'} -> {target[:12]}")
        return 0
    except Exception as exc:  # noqa: BLE001 - report every failure to the UI
        log(f"FAILED: {exc}")
        status("failed", str(exc)[:500], from_commit=installed or None)
        print(f"update failed: {exc}", file=sys.stderr)
        return 1
    finally:
        stop_staged()
        shutil.rmtree(STAGING, ignore_errors=True)
        fcntl.flock(lock, fcntl.LOCK_UN)
        lock.close()


if __name__ == "__main__":
    raise SystemExit(main())

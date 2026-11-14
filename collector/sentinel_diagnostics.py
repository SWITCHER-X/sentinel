"""Troubleshooting model for a console with no telemetry.

Read-only diagnosis: the hub gathers live facts (unit state, telemetry age,
kernel features, env), and this module turns them into ordered, actionable
checks. No side effects beyond read-only subprocess calls; everything is
injected so the logic is unit-testable without systemd.
"""

from __future__ import annotations

import os
import platform
import shutil
import subprocess
import time
from typing import Callable, Dict, List, Optional

Runner = Callable[[List[str]], tuple]  # (returncode, stdout, stderr)

BTF_PATH = "/sys/kernel/btf/vmlinux"
LSM_PATH = "/sys/kernel/security/lsm"
TRACEFS_PATHS = ("/sys/kernel/tracing", "/sys/kernel/debug/tracing")


def _default_runner(cmd: List[str], timeout: float = 3.0) -> tuple:
    try:
        p = subprocess.run(cmd, capture_output=True, text=True, timeout=timeout)
        return p.returncode, (p.stdout or "").strip(), (p.stderr or "").strip()
    except (FileNotFoundError, OSError, subprocess.SubprocessError):
        return 127, "", ""


def _unit_state(unit: str, runner: Runner) -> Dict[str, object]:
    rc_active, out_active, _ = runner(["systemctl", "is-active", unit])
    rc_cat, _, _ = runner(["systemctl", "cat", unit])
    rc_enabled, out_enabled, _ = runner(["systemctl", "is-enabled", unit])
    return {
        "exists": rc_cat == 0,
        "active": rc_active == 0 and out_active.startswith("active"),
        "enabled": rc_enabled == 0 and out_enabled.startswith("enabled"),
    }


def _journal_tail(unit: str, runner: Runner, lines: int = 8) -> List[str]:
    rc, out, _ = runner([
        "journalctl", "-u", unit, "-n", str(lines), "--no-pager", "-o", "cat",
    ])
    if rc != 0 or not out:
        return []
    return [ln for ln in out.splitlines() if ln.strip()][-lines:]


def _env_problem(env: Dict[str, Optional[str]]) -> Optional[str]:
    key = (env.get("SENTINEL_AGENT_KEY") or "").strip()
    if not key or key.startswith("CHANGE_ME"):
        return "SENTINEL_AGENT_KEY is missing or still a placeholder"
    if len(key) < 32:
        return "SENTINEL_AGENT_KEY is shorter than 32 characters"
    return None


def _db_problem(db_path: Optional[str]) -> Optional[str]:
    if not db_path:
        return "SENTINEL_DB_PATH is not set in the hub environment"
    directory = os.path.dirname(db_path) or "."
    if not os.path.isdir(directory):
        return f"state directory {directory} does not exist"
    if not os.access(directory, os.W_OK):
        return f"state directory {directory} is not writable by the hub user"
    if os.path.exists(db_path) and not os.access(db_path, os.W_OK):
        return f"{db_path} is not writable by the hub user"
    return None


def _disk_low(path: str) -> Optional[str]:
    try:
        usage = shutil.disk_usage(path)
    except OSError:
        return None
    free_mb = usage.free / (1024 * 1024)
    if free_mb < 200:
        return f"only {free_mb:.0f} MB free on the state volume"
    return None


def _tracefs_ready(paths) -> bool:
    return any(os.path.isdir(os.path.join(p, "events")) for p in paths)


def _lsm_has_bpf(lsm_path: str) -> Optional[bool]:
    try:
        with open(lsm_path, "r", encoding="utf-8", errors="replace") as fh:
            lsm = fh.read().strip()
    except OSError:
        return None
    return "bpf" in [x.strip() for x in lsm.split(",")]


def diagnose(
    *,
    now: Optional[float] = None,
    total_events: int = 0,
    telemetry_last_ts: Optional[float] = None,
    db_path: Optional[str] = None,
    env: Optional[Dict[str, Optional[str]]] = None,
    btf_path: str = BTF_PATH,
    lsm_path: str = LSM_PATH,
    tracefs_paths=TRACEFS_PATHS,
    runner: Optional[Runner] = None,
    kernel_release: Optional[str] = None,
    stale_after: float = 300.0,
) -> Dict[str, object]:
    """Return a stable, renderable diagnosis of the ingest pipeline."""
    now = time.time() if now is None else now
    env = env or {}
    runner = runner or _default_runner
    kernel = kernel_release or platform.release()

    checks: List[Dict[str, object]] = []

    def add(cid, title, status, detail, fix=None, command=None):
        checks.append({
            "id": cid, "title": title, "status": status,
            "detail": detail, "fix": fix, "command": command,
        })

    # ── who is supposed to be sending ────────────────────────────────────────
    agent = _unit_state("sentinel-agent", runner)
    hub = _unit_state("sentinel-hub", runner)
    journal = _journal_tail("sentinel-agent", runner) if agent["exists"] and not agent["active"] else []

    if not agent["exists"]:
        add(
            "agent.unit", "Agent is not installed on this host",
            "fail",
            "This looks like a hub-only install: no sentinel-agent.service exists, "
            "so no process is reporting telemetry.",
            "Run the full installer on the host you want to monitor.",
            "sudo ./install.sh",
        )
    elif not agent["active"]:
        detail = "sentinel-agent.service exists but is not running, so nothing is sent to the hub."
        if agent["enabled"]:
            detail += " It is enabled at boot but failed to stay up."
        add(
            "agent.active", "Agent is not running", "fail", detail,
            "Start it and check the last log lines.",
            "sudo systemctl start sentinel-agent && sudo journalctl -u sentinel-agent -n 50 --no-pager",
            )
        if journal:
            checks[-1]["detail"] += " Recent log: " + " | ".join(journal[-3:])
    else:
        detail = "sentinel-agent.service is running"
        detail += " and enabled at boot." if agent["enabled"] else " but NOT enabled at boot."
        add("agent.active", "Agent is running", "ok", detail,
            None if agent["enabled"] else "Enable it so it survives a reboot.",
            None if agent["enabled"] else "sudo systemctl enable sentinel-agent")

    if not hub["exists"]:
        add("hub.unit", "Hub is not installed as a service", "warn",
            "The hub is answering this request but no sentinel-hub.service was found; "
            "it may have been started by hand and will not return after a reboot.",
            "Re-run the installer to install the unit.",
            "sudo ./install.sh")
    elif not hub["enabled"]:
        add("hub.enabled", "Hub is not enabled at boot", "warn",
            "sentinel-hub.service is active but not enabled, so it will not start after a reboot.",
            "Enable it.", "sudo systemctl enable sentinel-hub")
    else:
        add("hub.enabled", "Hub runs at boot", "ok", "sentinel-hub.service is enabled and active.")

    # ── is anything arriving ─────────────────────────────────────────────────
    if total_events <= 0:
        add("telemetry.any", "No telemetry has ever arrived", "fail",
            "The hub has accepted a login but has zero events in its store.",
            "Confirm the agent is talking to this hub: compare the collector URL and key, "
            "then watch both logs.",
            "sudo journalctl -u sentinel-agent -u sentinel-hub -n 80 --no-pager")
    elif telemetry_last_ts and now - telemetry_last_ts > stale_after:
        age = now - telemetry_last_ts
        add("telemetry.fresh", "Telemetry has stopped", "fail",
            f"Last event was {age / 60:.0f} minutes ago ({total_events} stored).",
            "Check whether the agent died or lost its hub connection.",
            "sudo systemctl status sentinel-agent --no-pager && sudo journalctl -u sentinel-agent -n 50 --no-pager")
    elif telemetry_last_ts:
        age = max(0.0, now - telemetry_last_ts)
        add("telemetry.fresh", "Telemetry is live", "ok",
            f"Last event {age:.0f}s ago, {total_events} stored.")
    else:
        add("telemetry.fresh", "Telemetry is present", "ok",
            f"{total_events} events stored (age unknown).")

    # ── can the agent work at all on this host ───────────────────────────────
    if not os.path.exists(btf_path):
        add("kernel.btf", "Kernel has no BTF information", "fail",
            "CO-RE needs CONFIG_DEBUG_INFO_BTF=y (/sys/kernel/btf/vmlinux). "
            "Without it the loader cannot attach and the agent cannot report.",
            "Boot a kernel built with BTF (mainline/distro kernels since 5.4 have it).",
            None)
    else:
        add("kernel.btf", "Kernel exposes BTF", "ok", "CO-RE metadata is available.")

    if _tracefs_ready(tracefs_paths):
        add("kernel.tracefs", "Trace filesystem is available", "ok",
            "Tracepoints can attach (tracefs events are present).")
    else:
        add("kernel.tracefs", "Trace filesystem is not mounted", "fail",
            "eBPF tracepoints attach through tracefs; without it the loader reports "
            "'not all programs attached' and the agent restarts in a loop.",
            "Mount tracefs and restart the agent.",
            "sudo mount -t tracefs tracefs /sys/kernel/tracing && sudo systemctl restart sentinel-agent")

    lsm = _lsm_has_bpf(lsm_path)
    if lsm is False:
        add("kernel.lsm", "BPF LSM hook is not active", "warn",
            "The kernel supports eBPF but 'bpf' is not in the active LSM list: "
            "enforcement hooks will not attach. Telemetry may still flow.",
            "Add bpf to the LSM order (e.g. lsm=lockdown,yama,integrity,apparmor,bpf) and reboot.",
            None)
    elif lsm is True:
        add("kernel.lsm", "BPF LSM hook is active", "ok", "Kernel-level enforcement can attach.")

    # ── configuration ────────────────────────────────────────────────────────
    key_problem = _env_problem(env)
    if key_problem:
        add("config.key", "Agent key is not usable", "fail", key_problem,
            "The hub and agent must share one SENTINEL_AGENT_KEY; re-install or edit the env file.",
            "sudo grep '^SENTINEL_AGENT_KEY=' /etc/sentinel/sentinel.env")
    else:
        add("config.key", "Agent key is configured", "ok",
            "The shared key is present and looks valid.")

    db_problem = _db_problem(db_path)
    if db_problem:
        add("config.db", "State store is not writable", "fail", db_problem,
            "Fix ownership of the state directory, then restart the hub.",
            "sudo chown -R sentinel:sentinel /var/lib/sentinel && sudo systemctl restart sentinel-hub")
    else:
        add("config.db", "State store is writable", "ok", db_path)

    if db_path:
        disk = _disk_low(os.path.dirname(db_path) or ".")
        if disk:
            add("config.disk", "State volume is nearly full", "warn", disk,
                "Free space so SQLite can write its WAL.", "df -h")

    fails = [c for c in checks if c["status"] == "fail"]
    warns = [c for c in checks if c["status"] == "warn"]
    verdict = "fail" if fails else ("warn" if warns else "ok")

    recommend = None
    for c in checks:
        if c["status"] == "fail" and c.get("fix"):
            recommend = {
                "check": c["id"],
                "title": c["title"],
                "recommendation": c["fix"],
                "command": c.get("command"),
            }
            break

    if verdict == "ok":
        title = "Ingest pipeline looks healthy"
        summary = "The agent is reporting and the hub is storing. If the feed is still empty, the filter or time range is hiding events."
        command = None
    elif recommend:
        title = recommend["title"]
        summary = recommend.get("recommendation") or "Work top-down through the failing checks below."
        command = recommend.get("command")
    else:
        title = "Something in the ingest path needs attention"
        summary = "Work top-down through the failing checks below."
        command = None

    return {
        "verdict": verdict,
        "title": title,
        "summary": summary,
        "command": command,
        "checks": checks,
        "context": {
            "kernel": kernel,
            "btf": os.path.exists(btf_path),
            "lsm_bpf": lsm,
            "tracefs": _tracefs_ready(tracefs_paths),
            "total_events": total_events,
            "last_event_age": None if not telemetry_last_ts else round(now - telemetry_last_ts, 1),
        },
        "generated_at": now,
    }

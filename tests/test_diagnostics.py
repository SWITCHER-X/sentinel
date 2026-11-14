"""Troubleshooter tests: the diagnosis must be specific and actionable."""

import os
import sys
import time
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "collector"))

import sentinel_diagnostics as diag  # noqa: E402


def unit_runner(units):
    """Fake systemctl/journalctl: units maps name -> {active, enabled}."""

    def runner(cmd):
        if cmd[0] == "systemctl":
            action, unit = cmd[1], cmd[2]
            state = units.get(unit)
            if state is None:
                return (1, "", f"Unit {unit} not found")
            if action == "is-active":
                return (0, "active", "") if state.get("active") else (3, "inactive", "")
            if action == "is-enabled":
                return (0, "enabled", "") if state.get("enabled") else (1, "disabled", "")
            if action == "cat":
                return (0, "[Service]", "")
            return (0, "", "")
        if cmd[0] == "journalctl":
            return (0, "agent: failed to load BPF object", "")
        return (127, "", "not found")

    return runner


def env_ok():
    return {"SENTINEL_AGENT_KEY": "a" * 64}


def healthy_units():
    return {
        "sentinel-hub": {"active": True, "enabled": True},
        "sentinel-agent": {"active": True, "enabled": True},
    }


def base_kwargs(tmp_path, **over):
    btf = tmp_path / "vmlinux"
    btf.write_bytes(b"\0")
    lsm = tmp_path / "lsm"
    lsm.write_text("lockdown,yama,integrity,apparmor,bpf")
    state = tmp_path / "state"
    state.mkdir()
    trace = tmp_path / "tracing" / "events"
    trace.mkdir(parents=True)
    kw = dict(
        now=1_700_000_000,
        total_events=120,
        telemetry_last_ts=1_699_999_990,
        db_path=str(state / "sentinel.db"),
        env=env_ok(),
        btf_path=str(btf),
        lsm_path=str(lsm),
        tracefs_paths=(str(tmp_path / "tracing"),),
        runner=unit_runner(healthy_units()),
        kernel_release="6.8.0-test",
    )
    kw.update(over)
    return kw


def status_of(result, check_id):
    return next(c["status"] for c in result["checks"] if c["id"] == check_id)


def test_healthy_pipeline_is_ok(tmp_path):
    result = diag.diagnose(**base_kwargs(tmp_path))
    assert result["verdict"] == "ok"
    assert "healthy" in result["title"].lower()
    assert status_of(result, "agent.active") == "ok"
    assert status_of(result, "telemetry.fresh") == "ok"
    assert status_of(result, "kernel.btf") == "ok"
    assert status_of(result, "config.db") == "ok"


def test_agent_missing_is_first_failure(tmp_path):
    result = diag.diagnose(**base_kwargs(tmp_path, runner=unit_runner({})))
    assert result["verdict"] == "fail"
    assert "not installed" in result["title"].lower()
    assert result["command"] == "sudo ./install.sh"
    assert status_of(result, "agent.unit") == "fail"


def test_agent_inactive_reports_start_command(tmp_path):
    units = healthy_units()
    units["sentinel-agent"] = {"active": False, "enabled": True}
    result = diag.diagnose(**base_kwargs(tmp_path, runner=unit_runner(units)))
    assert result["verdict"] == "fail"
    assert "not running" in result["title"].lower()
    assert "systemctl start sentinel-agent" in result["command"]
    # the journal tail is folded into the detail so the cause is visible
    assert "failed to load BPF" in result["checks"][0]["detail"]


def test_no_telemetry_names_the_pipeline(tmp_path):
    result = diag.diagnose(**base_kwargs(tmp_path, total_events=0, telemetry_last_ts=None))
    assert result["verdict"] == "fail"
    assert status_of(result, "telemetry.any") == "fail"
    assert result["command"].startswith("sudo journalctl")


def test_stale_telemetry(tmp_path):
    result = diag.diagnose(**base_kwargs(tmp_path, now=1_700_000_000, telemetry_last_ts=1_699_000_000))
    assert status_of(result, "telemetry.fresh") == "fail"
    assert result["verdict"] == "fail"


def test_missing_tracefs_names_the_actual_loader_error(tmp_path):
    result = diag.diagnose(**base_kwargs(tmp_path, tracefs_paths=(str(tmp_path / "none"),)))
    assert status_of(result, "kernel.tracefs") == "fail"
    check = next(c for c in result["checks"] if c["id"] == "kernel.tracefs")
    assert "not all programs attached" in check["detail"]
    assert "mount -t tracefs" in check["command"]
    assert result["verdict"] == "fail"


def test_missing_btf_blocks_agent(tmp_path):
    result = diag.diagnose(**base_kwargs(tmp_path, btf_path=str(tmp_path / "nope")))
    assert status_of(result, "kernel.btf") == "fail"
    assert result["verdict"] == "fail"


def test_missing_bpf_lsm_is_a_warning_not_a_blocker(tmp_path):
    lsm = tmp_path / "lsm-no-bpf"
    lsm.write_text("lockdown,yama,apparmor")
    result = diag.diagnose(**base_kwargs(tmp_path, lsm_path=str(lsm)))
    assert status_of(result, "kernel.lsm") == "warn"
    assert result["verdict"] == "warn"
    assert any("bpf" in (c.get("fix") or "").lower() for c in result["checks"])


def test_placeholder_key_is_a_failure(tmp_path):
    env = {"SENTINEL_AGENT_KEY": "CHANGE_ME"}
    result = diag.diagnose(**base_kwargs(tmp_path, env=env))
    assert status_of(result, "config.key") == "fail"


def test_unwritable_state_dir(tmp_path):
    result = diag.diagnose(
        **base_kwargs(tmp_path, db_path=str(tmp_path / "missing" / "sentinel.db"))
    )
    assert status_of(result, "config.db") == "fail"
    assert result["verdict"] == "fail"


def test_hub_not_enabled_is_a_warning(tmp_path):
    units = healthy_units()
    units["sentinel-hub"] = {"active": True, "enabled": False}
    result = diag.diagnose(**base_kwargs(tmp_path, runner=unit_runner(units)))
    assert status_of(result, "hub.enabled") == "warn"


def test_context_is_renderable(tmp_path):
    result = diag.diagnose(**base_kwargs(tmp_path))
    ctx = result["context"]
    assert ctx["kernel"] == "6.8.0-test"
    assert ctx["btf"] is True
    assert ctx["total_events"] == 120
    assert isinstance(ctx["last_event_age"], (int, float))
    assert all(c["status"] in ("ok", "warn", "fail") for c in result["checks"])
    assert all(c["title"] and c["detail"] for c in result["checks"])

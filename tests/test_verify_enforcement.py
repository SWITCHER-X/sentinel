"""The enforcement verifier's pure parts must be trustworthy."""

import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))

import verify_enforcement as ve  # noqa: E402


def test_sigkill_is_recognised():
    assert ve.classify_kill(-9) is True      # Python: signal 9
    assert ve.classify_kill(137) is True     # shell: 128 + 9
    assert ve.classify_kill(0) is False
    assert ve.classify_kill(1) is False
    assert ve.classify_kill(143) is False    # SIGTERM, not the kill-switch


def test_env_file_parsing(tmp_path):
    env = tmp_path / "sentinel.env"
    env.write_text(
        "# comment\n"
        "SENTINEL_PORT=5000\n"
        "SENTINEL_ADMIN_PASSWORD=p@ss=word\n"
        "EMPTY=\n"
        "not a pair\n"
    )
    values = ve.load_env(str(env))
    assert values["SENTINEL_PORT"] == "5000"
    assert values["SENTINEL_ADMIN_PASSWORD"] == "p@ss=word"   # '=' kept in value
    assert values["EMPTY"] == ""


def test_trigger_matches_a_kill_rule():
    # The verifier is only meaningful if its trigger matches a shipped KILL rule.
    import yaml
    rules_path = Path(__file__).resolve().parent.parent / "config" / "rules.yaml"
    data = yaml.safe_load(rules_path.read_text())
    rules = data["rules"] if isinstance(data, dict) else data
    cmdline = " ".join(ve.TRIGGER)
    matches = [r for r in rules if r.get("action", "").upper() == "KILL"
               and r.get("pattern") and r["pattern"] in cmdline]
    assert matches, f"no KILL rule pattern matches trigger: {cmdline}"

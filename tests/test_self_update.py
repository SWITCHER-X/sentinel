"""Unit tests for tools/self_update.py — no root, no network, no systemd."""

import json
import sys
import threading
from http.server import BaseHTTPRequestHandler, HTTPServer
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parent.parent / "tools"))
import self_update as su  # noqa: E402


def test_status_file_roundtrip(tmp_path, monkeypatch):
    monkeypatch.setattr(su, "STATUS_FILE", tmp_path / "update.json")
    su.status("done", "updated", to_commit="abc123")
    data = json.loads((tmp_path / "update.json").read_text())
    assert data["state"] == "done"
    assert data["to_commit"] == "abc123"
    assert isinstance(data["updated_at"], float)


def test_read_meta_parses_install_meta(tmp_path):
    meta = tmp_path / ".install-meta"
    meta.write_text("commit=deadbeef\ninstalled_at=2026-01-01T00:00:00+0000\n")
    parsed = su.read_meta(meta)
    assert parsed["commit"] == "deadbeef"
    assert parsed["installed_at"].startswith("2026-01-01")


def test_read_meta_missing_file_is_empty(tmp_path):
    assert su.read_meta(tmp_path / "nope") == {}


def test_health_probe_against_a_live_server():
    class Handler(BaseHTTPRequestHandler):
        def do_GET(self):
            body = b'{"status":"ok"}'
            self.send_response(200)
            self.send_header("Content-Length", str(len(body)))
            self.end_headers()
            self.wfile.write(body)

        def log_message(self, *args):
            pass

    server = HTTPServer(("127.0.0.1", 0), Handler)
    port = server.server_address[1]
    thread = threading.Thread(target=server.serve_forever, daemon=True)
    thread.start()
    try:
        assert su.health(port) is True
        assert su.wait_health(port, 2) is True
    finally:
        server.shutdown()


def test_health_probe_reports_dead_port():
    assert su.health(1) is False  # nothing listens on :1


def test_build_skips_when_tree_has_no_ebpf(tmp_path, monkeypatch):
    monkeypatch.setattr(su, "SRC_DIR", tmp_path)
    su.build()  # must not raise


def test_build_skips_without_toolchain(tmp_path, monkeypatch):
    (tmp_path / "Makefile").write_text("all:\n")
    (tmp_path / "ebpf").mkdir()
    monkeypatch.setattr(su, "SRC_DIR", tmp_path)
    monkeypatch.setattr(su.shutil, "which", lambda name: None)
    su.build()  # hub-only install: no clang/gcc/make


def test_completed_states_are_not_running():
    assert "cutover" in su.RUNNING_STATES
    for done in ("done", "failed", "up-to-date", "idle"):
        assert done not in su.RUNNING_STATES


def test_load_env_file_sets_missing_keys(tmp_path, monkeypatch):
    env_file = tmp_path / "sentinel.env"
    env_file.write_text('SENTINEL_TEST_KEY=from-file\n# comment\nBAD_LINE\n')
    monkeypatch.delenv("SENTINEL_TEST_KEY", raising=False)
    su.load_env_file(env_file)
    import os

    assert os.environ["SENTINEL_TEST_KEY"] == "from-file"

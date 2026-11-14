#!/usr/bin/env python3
"""Gunicorn launcher for the hub.

Why a launcher instead of the Flask dev server:
  • ``reuse_port`` lets a new master bind the same port while the old one is
    still serving, which is what makes the staged update cut over without
    dropping connections on kernels/filesystems that support SO_REUSEPORT;
  • SIGHUP (``systemctl reload``) gracefully replaces workers, so new code is
    picked up without closing the listening socket.
"""
from __future__ import annotations

import os
import sys
from pathlib import Path

HARNESS_LABEL = "sentinel-hub"


def _collector_dir() -> str:
    here = Path(__file__).resolve().parent
    return str(here.parent / "collector")


class HubApp:
    def __init__(self, app):
        self.app = app

    def load(self):
        return self.app


def main() -> int:
    try:
        from gunicorn.app.base import BaseApplication
    except ImportError:
        print("gunicorn is not installed: pip install -r requirements.txt", file=sys.stderr)
        return 1

    sys.path.insert(0, _collector_dir())
    from sentinel_hub_lineage import app

    bind = f"{os.getenv('SENTINEL_BIND', '127.0.0.1')}:{os.getenv('SENTINEL_PORT', '5000')}"
    reuse_port = os.getenv("SENTINEL_REUSE_PORT", "1") == "1"

    class Application(BaseApplication):
        def load_config(self):
            cfg = {
                "bind": bind,
                "workers": 1,
                "threads": int(os.getenv("SENTINEL_THREADS", "8")),
                "reuse_port": reuse_port,
                "worker_class": "gthread",
                "accesslog": "-",
                "errorlog": "-",
                "loglevel": os.getenv("SENTINEL_LOG_LEVEL", "info"),
                "proc_name": HARNESS_LABEL,
            }
            for key, value in cfg.items():
                if key in self.cfg.settings and value is not None:
                    self.cfg.set(key, value)

        def load(self):
            return app

    Application().run()
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

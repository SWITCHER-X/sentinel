#!/usr/bin/env python3
"""Sentinel — auth + SQLite layer.

One database (/var/lib/sentinel/sentinel.db or fallback next to this file):
  meta      — mode (learn/enforce), schema version
  events    — persisted telemetry
  lineages  — historical lineage trees
  allowlist — hash pins / publisher entries (tiered)
  audit     — who did what, when
  users     — dashboard admins (scrypt)

Auth model (local, single-node):
  • Dashboard: admin credential → signed session cookie (+ CSRF token)
  • Agents:    enrollment key (X-Sentinel-Key header)
  • Secrets come from env (SENTINEL_SESSION_SECRET / SENTINEL_AGENT_KEY /
    SENTINEL_ADMIN_PASSWORD); install.sh generates them.
"""
import hashlib
import hmac
import json
import os
import secrets
import sqlite3
import time
from functools import wraps

# ─── Paths ───
def _default_db_path():
    """State belongs in /var/lib/sentinel (systemd ReadWritePaths). Falls back
    to the module directory for dev runs where that dir doesn't exist."""
    env = os.getenv("SENTINEL_DB_PATH")
    if env:
        return env
    varlib = "/var/lib/sentinel/sentinel.db"
    d = os.path.dirname(varlib)
    if os.path.isdir(d) and os.access(d, os.W_OK):
        return varlib
    return os.path.join(os.path.dirname(os.path.abspath(__file__)), "sentinel.db")

_DB_PATH = _default_db_path()
_DB_READY = False

# ─── Database ───
_SCHEMA = """
CREATE TABLE IF NOT EXISTS meta (key TEXT PRIMARY KEY, value TEXT);
CREATE TABLE IF NOT EXISTS events (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  seq INTEGER, ts REAL, type TEXT, severity TEXT, rule_id TEXT, mitre TEXT,
  pid INTEGER, ppid INTEGER, lineage_id TEXT, comm TEXT, binary TEXT,
  cmdline TEXT, user TEXT, host TEXT, killed INTEGER, action TEXT, raw TEXT
);
CREATE INDEX IF NOT EXISTS idx_events_ts ON events(ts);
CREATE INDEX IF NOT EXISTS idx_events_lineage ON events(lineage_id);
CREATE TABLE IF NOT EXISTS lineages (
  lineage_id TEXT PRIMARY KEY, host TEXT, root_pid INTEGER,
  blocked INTEGER DEFAULT 0, trusted INTEGER DEFAULT 0,
  threats INTEGER DEFAULT 0, first_seen REAL, last_seen REAL, nodes TEXT
);
CREATE TABLE IF NOT EXISTS allowlist (
  id INTEGER PRIMARY KEY AUTOINCREMENT,
  tier TEXT NOT NULL,             -- 'hash' | 'publisher' | 'lineage'
  value TEXT NOT NULL,            -- sha256 hex / package name / lineage id
  label TEXT, added_at REAL, added_by TEXT,
  UNIQUE(tier, value)
);
CREATE TABLE IF NOT EXISTS audit (
  id INTEGER PRIMARY KEY AUTOINCREMENT, ts REAL, actor TEXT, action TEXT, detail TEXT
);
CREATE TABLE IF NOT EXISTS users (
  username TEXT PRIMARY KEY, pw_hash TEXT NOT NULL, created_at REAL
);
"""


def db_path():
    return _DB_PATH


def db_init(path=None):
    """Create schema + enable WAL. Safe to call on every start."""
    p = path or _DB_PATH
    os.makedirs(os.path.dirname(os.path.abspath(p)), exist_ok=True)
    conn = sqlite3.connect(p, timeout=10)
    conn.executescript(_SCHEMA)
    conn.execute("PRAGMA journal_mode=WAL")
    conn.execute("PRAGMA synchronous=NORMAL")
    conn.commit()
    conn.close()
    return p


def db():
    global _DB_READY
    # If the DB file was deleted at runtime (cleanup, tamper), rebuild schema
    if _DB_READY and not os.path.exists(_DB_PATH):
        _DB_READY = False
    if not _DB_READY:
        db_init()
        _DB_READY = True
    conn = sqlite3.connect(_DB_PATH, timeout=10)
    conn.row_factory = sqlite3.Row
    conn.execute("PRAGMA journal_mode=WAL")
    return conn


def meta_get(key, default=None):
    row = db().execute("SELECT value FROM meta WHERE key=?", (key,)).fetchone()
    return row["value"] if row else default


def meta_set(key, value):
    c = db()
    c.execute("INSERT INTO meta(key,value) VALUES(?,?) "
              "ON CONFLICT(key) DO UPDATE SET value=excluded.value", (key, str(value)))
    c.commit()
    c.close()


def audit(actor, action, detail=""):
    c = db()
    c.execute("INSERT INTO audit(ts,actor,action,detail) VALUES(?,?,?,?)",
              (time.time(), actor, action, str(detail)[:2000]))
    c.commit()
    c.close()


# ─── Passwords (scrypt — stdlib, no deps) ───
def hash_password(password: str) -> str:
    salt = secrets.token_bytes(16)
    h = hashlib.scrypt(password.encode(), salt=salt, n=2 ** 14, r=8, p=1, dklen=32)
    return f"scrypt${salt.hex()}${h.hex()}"


def verify_password(password: str, stored: str) -> bool:
    try:
        algo, salt_hex, h_hex = stored.split("$")
        if algo != "scrypt":
            return False
        h = hashlib.scrypt(password.encode(), salt=bytes.fromhex(salt_hex),
                           n=2 ** 14, r=8, p=1, dklen=32)
        return hmac.compare_digest(h.hex(), h_hex)
    except Exception:
        return False


def ensure_user(username: str, password: str, reset: bool = False):
    c = db()
    if reset:
        c.execute("INSERT INTO users(username,pw_hash,created_at) VALUES(?,?,?) "
                  "ON CONFLICT(username) DO UPDATE SET pw_hash=excluded.pw_hash",
                  (username, hash_password(password), time.time()))
    else:
        c.execute("INSERT INTO users(username,pw_hash,created_at) VALUES(?,?,?) "
                  "ON CONFLICT(username) DO NOTHING",
                  (username, hash_password(password), time.time()))
    c.commit()
    c.close()


def check_user(username: str, password: str):
    row = db().execute("SELECT pw_hash FROM users WHERE username=?",
                       (username,)).fetchone()
    return bool(row and verify_password(password, row["pw_hash"]))


# ─── Sessions (HMAC-signed tokens — stdlib) ───
def _secret():
    return (os.getenv("SENTINEL_SESSION_SECRET") or "dev-insecure-secret").encode()


def session_create(ttl: int = 12 * 3600) -> str:
    exp = int(time.time()) + ttl
    nonce = secrets.token_hex(8)
    body = f"{exp}.{nonce}"
    sig = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
    return f"{body}.{sig}"


def session_verify(token: str) -> bool:
    try:
        exp, nonce, sig = token.split(".")
        body = f"{exp}.{nonce}"
        want = hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()
        if not hmac.compare_digest(want, sig):
            return False
        return int(exp) > time.time()
    except Exception:
        return False


def csrf_for(token: str) -> str:
    """CSRF token derived from the session — no server-side storage."""
    return hmac.new(_secret(), f"csrf:{token}".encode(), hashlib.sha256).hexdigest()


def csrf_verify(session_token: str, provided: str) -> bool:
    return bool(session_token) and hmac.compare_digest(csrf_for(session_token), provided or "")


# ─── Login rate-limit (in-memory, per-IP) ──
_failures = {}


def login_attempts(ip: str):
    """Returns (allowed, retry_after). 5 failures → 60s lockout."""
    now = time.time()
    fails, until = _failures.get(ip, (0, 0))
    if until and now < until:
        return False, int(until - now)
    if fails >= 5:
        _failures[ip] = (0, now + 60)
        return False, 60
    return True, 0


def login_fail(ip: str):
    fails, until = _failures.get(ip, (0, 0))
    _failures[ip] = (fails + 1, until)


def login_reset(ip: str):
    _failures.pop(ip, None)


# ─── Allowlist (tiered) + signed distribution ───
def allowlist_add(tier: str, value: str, label: str = "", actor: str = "admin") -> bool:
    if tier not in ("hash", "publisher", "lineage"):
        raise ValueError("tier must be hash|publisher|lineage")
    c = db()
    c.execute("INSERT INTO allowlist(tier,value,label,added_at,added_by) VALUES(?,?,?,?,?) "
              "ON CONFLICT(tier,value) DO UPDATE SET label=excluded.label",
              (tier, value.lower() if tier == "hash" else value, label, time.time(), actor))
    c.commit()
    c.close()
    audit(actor, "allowlist.add", f"{tier}:{value[:24]}")


def allowlist_remove(tier: str, value: str, actor: str = "admin"):
    c = db()
    c.execute("DELETE FROM allowlist WHERE tier=? AND value=?",
              (tier, value.lower() if tier == "hash" else value))
    c.commit()
    c.close()
    audit(actor, "allowlist.remove", f"{tier}:{value[:24]}")


def allowlist_all() -> list:
    return [dict(r) for r in db().execute(
        "SELECT tier,value,label,added_at,added_by FROM allowlist ORDER BY tier,value").fetchall()]


def allowlist_secret() -> bytes:
    """Key used to sign the allowlist blob. From env or /etc/sentinel, else dev fallback."""
    path = os.getenv("SENTINEL_ALLOWLIST_KEY_FILE",
                     os.path.join(os.path.dirname(os.path.abspath(__file__)), "allowlist.key"))
    try:
        with open(path) as f:
            key = f.read().strip()
        if key:
            return key.encode()
    except OSError:
        pass
    return (os.getenv("SENTINEL_ALLOWLIST_KEY") or "dev-insecure-allowlist-key").encode()


def allowlist_sign(blob: dict) -> str:
    """Sign the allowlist distribution blob. HMAC now; Ed25519 upgrade point."""
    body = json.dumps(blob, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(allowlist_secret(), body, hashlib.sha256).hexdigest()


def allowlist_verify(blob: dict, signature: str) -> bool:
    body = json.dumps(blob, sort_keys=True, separators=(",", ":")).encode()
    return hmac.compare_digest(allowlist_sign(blob), signature or "")

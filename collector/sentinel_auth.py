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
CREATE TABLE IF NOT EXISTS revoked_sessions (
  jti TEXT PRIMARY KEY, exp REAL
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
# PHC-style: scrypt$n$r$p$salt$hash. Parameters travel with the hash so they can
# be raised later; needs_rehash() upgrades an account on its next good login.
SCRYPT_N = 2 ** 15
SCRYPT_R = 8
SCRYPT_P = 1
SCRYPT_MAXMEM = 128 * 1024 * 1024
MIN_PASSWORD_LEN = 12
_LEGACY_N = 2 ** 14
_dummy_hash = None


def hash_password(password: str, *, n: int = None, r: int = None, p: int = None) -> str:
    n, r, p = n or SCRYPT_N, r or SCRYPT_R, p or SCRYPT_P
    salt = secrets.token_bytes(16)
    digest = hashlib.scrypt(
        password.encode(), salt=salt, n=n, r=r, p=p, dklen=32, maxmem=SCRYPT_MAXMEM
    )
    return f"scrypt${n}${r}${p}${salt.hex()}${digest.hex()}"


def _parse_hash(stored: str):
    """Return (n, r, p, salt, digest_hex) or None. Accepts the legacy 3-field form."""
    try:
        parts = (stored or "").split("$")
        if not parts or parts[0] != "scrypt":
            return None
        if len(parts) == 6:
            _, n, r, p, salt_hex, digest_hex = parts
            return int(n), int(r), int(p), bytes.fromhex(salt_hex), digest_hex
        if len(parts) == 3:  # legacy BEFORE the upgrade: scrypt$salt$hash
            _, salt_hex, digest_hex = parts
            return _LEGACY_N, SCRYPT_R, SCRYPT_P, bytes.fromhex(salt_hex), digest_hex
    except (ValueError, TypeError):
        return None
    return None


def verify_password(password: str, stored: str) -> bool:
    parsed = _parse_hash(stored)
    if parsed is None:
        return False
    n, r, p, salt, digest_hex = parsed
    try:
        digest = hashlib.scrypt(
            (password or "").encode(), salt=salt, n=n, r=r, p=p, dklen=32,
            maxmem=SCRYPT_MAXMEM,
        )
    except (ValueError, MemoryError):
        return False
    return hmac.compare_digest(digest.hex(), digest_hex)


def needs_rehash(stored: str) -> bool:
    parsed = _parse_hash(stored)
    if parsed is None:
        return True
    n, r, p, _, _ = parsed
    return (n, r, p) != (SCRYPT_N, SCRYPT_R, SCRYPT_P)


def _timing_dummy() -> str:
    """A throwaway hash so an unknown username costs the same as a real one."""
    global _dummy_hash
    if _dummy_hash is None:
        _dummy_hash = hash_password(secrets.token_hex(16))
    return _dummy_hash


def ensure_user(username: str, password: str, reset: bool = False):
    if not username:
        raise ValueError("username is required")
    if len(password or "") < MIN_PASSWORD_LEN:
        raise ValueError(f"password must be at least {MIN_PASSWORD_LEN} characters")
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


def check_user(username: str, password: str) -> bool:
    """Constant-work lookup: unknown users still pay one scrypt verification.

    A good login with an outdated hash is rehashed with current parameters.
    """
    row = db().execute("SELECT pw_hash FROM users WHERE username=?",
                       (username,)).fetchone()
    if row is None:
        verify_password(password or "", _timing_dummy())
        return False
    ok = verify_password(password or "", row["pw_hash"])
    if ok and needs_rehash(row["pw_hash"]):
        try:
            c = db()
            c.execute("UPDATE users SET pw_hash=? WHERE username=?",
                      (hash_password(password), username))
            c.commit()
            c.close()
        except sqlite3.Error:
            pass
    return ok


# ─── Sessions (HMAC-signed, stateless) ───
# v2 token: v2.<iat>.<exp>.<idle>.<nonce>.<subject-b64>.<signature>
#   · absolute expiry (exp) and an idle timeout (idle) are both enforced
#   · the subject is carried in the token, so a login names a user
SESSION_TTL = 12 * 3600           # absolute
SESSION_IDLE_TTL = 45 * 60        # no activity for this long -> logout
SESSION_REFRESH_AFTER = 5 * 60    # re-issue the cookie on activity


def _secret():
    secret = os.getenv("SENTINEL_SESSION_SECRET")
    if not secret:
        raise RuntimeError("SENTINEL_SESSION_SECRET must be set in environment")
    return secret.encode()


def _sign(body: str) -> str:
    return hmac.new(_secret(), body.encode(), hashlib.sha256).hexdigest()


def _b64(data: bytes) -> str:
    import base64

    return base64.urlsafe_b64encode(data).decode().rstrip("=")


def _unb64(text: str) -> bytes:
    import base64

    return base64.urlsafe_b64decode(text + "=" * (-len(text) % 4))


def session_create(subject: str = "admin", ttl: int = SESSION_TTL,
                   idle_ttl: int = SESSION_IDLE_TTL) -> str:
    now = int(time.time())
    body = (
        f"v2.{now}.{now + ttl}.{idle_ttl}."
        f"{secrets.token_hex(16)}.{_b64((subject or 'admin').encode())}"
    )
    return f"{body}.{_sign(body)}"


def _is_revoked(jti: str) -> bool:
    try:
        return db().execute(
            "SELECT 1 FROM revoked_sessions WHERE jti=?", (jti,)
        ).fetchone() is not None
    except sqlite3.Error:
        return False


def session_claims(token: str):
    """Return {'sub','iat','exp','idle','jti'} for a valid token, else None."""
    claims = _claims_unrevoked(token)
    if claims and claims.get("jti") and _is_revoked(claims["jti"]):
        return None
    return claims


def _claims_unrevoked(token: str):
    if not token:
        return None
    parts = token.split(".")

    if len(parts) == 7 and parts[0] == "v2":
        body = ".".join(parts[:6])
        if not hmac.compare_digest(_sign(body), parts[6]):
            return None
        try:
            iat, exp, idle = int(parts[1]), int(parts[2]), int(parts[3])
            subject = _unb64(parts[5]).decode() or "admin"
        except (ValueError, UnicodeDecodeError):
            return None
        now = time.time()
        if now >= exp or now - iat > idle:
            return None
        return {"sub": subject, "iat": iat, "exp": exp, "idle": idle, "jti": parts[4]}

    if len(parts) == 3:  # v1 token issued by an older process
        exp, nonce, sig = parts
        if not hmac.compare_digest(_sign(f"{exp}.{nonce}"), sig):
            return None
        try:
            if int(exp) <= time.time():
                return None
        except ValueError:
            return None
        return {"sub": "admin", "iat": int(time.time()), "exp": int(exp),
                "idle": SESSION_TTL}

    return None


def session_verify(token: str) -> bool:
    return session_claims(token) is not None


def revoke_session(token: str) -> bool:
    """Invalidate one token server-side (logout). Survives cookie theft."""
    claims = _claims_unrevoked(token)
    if not claims or not claims.get("jti"):
        return False
    if _is_revoked(claims["jti"]):
        return False
    try:
        c = db()
        c.execute("INSERT OR REPLACE INTO revoked_sessions(jti, exp) VALUES(?,?)",
                  (claims["jti"], claims["exp"]))
        c.execute("DELETE FROM revoked_sessions WHERE exp < ?", (time.time(),))
        c.commit()
        c.close()
        return True
    except sqlite3.Error:
        return False


def session_refresh(token: str):
    """Sliding expiry: hand back a fresh token once it is old enough."""
    claims = session_claims(token)
    if not claims:
        return None
    if time.time() - claims["iat"] < SESSION_REFRESH_AFTER:
        return token
    return session_create(claims.get("sub") or "admin")


def csrf_for(token: str) -> str:
    """CSRF token derived from the session — no server-side storage."""
    return hmac.new(_secret(), f"csrf:{token}".encode(), hashlib.sha256).hexdigest()


def csrf_verify(session_token: str, provided: str) -> bool:
    return bool(session_token) and hmac.compare_digest(csrf_for(session_token), provided or "")


# ─── Login rate-limit (per-IP and per-username) ──
# Counters live in-process by default. When a StateBackend is attached (the hub
# attaches one at boot) they are shared, so a multi-worker deployment throttles
# an attacker consistently instead of per worker.
_failures = {}
_user_failures = {}
_state_backend = None


def set_state_backend(backend) -> None:
    """Attach a StateBackend so login throttling is shared across workers."""
    global _state_backend
    _state_backend = backend


def _load_fail(ip):
    if _state_backend is not None:
        return _state_backend.get_login_failures(ip)
    return _failures.get(ip, (0, 0))


def _save_fail(ip, fails, until):
    if _state_backend is not None:
        _state_backend.set_login_failures(ip, fails, until)
    else:
        _failures[ip] = (fails, until)


def _clear_fail(ip: str, username: str = None):
    if _state_backend is not None:
        _state_backend.clear_login_failures(ip, username)
    else:
        _failures.pop(ip, None)
        if username:
            _user_failures.pop(username, None)


def _load_user_fail(username: str):
    """Load failure count and lockout for a username."""
    if _state_backend is not None:
        return _state_backend.get_login_failures(username)
    return _user_failures.get(username, (0, 0.0))


def _save_user_fail(username: str, fails: int, until: float = 0.0):
    if _state_backend is not None:
        _state_backend.set_login_failures(username, fails, until)
    else:
        _user_failures[username] = (fails, until)


LOCK_BASE = 30        # seconds for the 5th consecutive failure
LOCK_MAX = 15 * 60    # cap for repeated failures


def _lockout_seconds(fails: int) -> int:
    return min(LOCK_BASE * (2 ** max(0, fails - 5)), LOCK_MAX)


def login_attempts(ip: str, username: str = None):
    """Returns (allowed, retry_after). 5 failures lock the IP/username out for
    LOCK_BASE seconds, doubling on every further failure up to LOCK_MAX."""
    now = time.time()

    fails, until = _load_fail(ip)
    if until and now < until:
        return False, max(1, int(until - now))
    if fails >= 5 and not until:
        # the 5th failure starts the lockout; after it expires one attempt is
        # allowed and the next failure doubles the wait
        wait = _lockout_seconds(fails)
        _save_fail(ip, fails, now + wait)
        return False, wait

    if username:
        u_fails, u_until = _load_user_fail(username)
        if u_until and now < u_until:
            return False, max(1, int(u_until - now))
        if u_fails >= 5 and not u_until:
            wait = _lockout_seconds(u_fails)
            _save_user_fail(username, u_fails, now + wait)
            return False, wait

    return True, 0


def login_fail(ip: str, username: str = None):
    fails, until = _load_fail(ip)
    _save_fail(ip, fails + 1, until)
    if username:
        u_fails, u_until = _load_user_fail(username)
        _save_user_fail(username, u_fails + 1, u_until)


def login_reset(ip: str, username: str = None):
    _clear_fail(ip, username)


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
    """Key used to sign the allowlist blob. From env or /etc/sentinel."""
    path = os.getenv("SENTINEL_ALLOWLIST_KEY_FILE",
                     os.path.join(os.path.dirname(os.path.abspath(__file__)), "allowlist.key"))
    try:
        with open(path) as f:
            key = f.read().strip()
        if key:
            return key.encode()
    except OSError:
        pass
    env_key = os.getenv("SENTINEL_ALLOWLIST_KEY")
    if not env_key:
        raise RuntimeError("SENTINEL_ALLOWLIST_KEY must be set in environment")
    return env_key.encode()


def allowlist_sign(blob: dict) -> str:
    """Sign the allowlist distribution blob. HMAC now; Ed25519 upgrade point."""
    body = json.dumps(blob, sort_keys=True, separators=(",", ":")).encode()
    return hmac.new(allowlist_secret(), body, hashlib.sha256).hexdigest()


def allowlist_verify(blob: dict, signature: str) -> bool:
    body = json.dumps(blob, sort_keys=True, separators=(",", ":")).encode()
    return hmac.compare_digest(allowlist_sign(blob), signature or "")

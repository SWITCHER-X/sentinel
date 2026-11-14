#!/usr/bin/env python3
"""
Project SENTINEL Collector Hub - Enhanced with Lineage Tracking
Central telemetry collector with lineage tree visualization and SOC dashboard

State lives behind collector/state.py (StateBackend). With SENTINEL_REDIS_URL
set, the hub is safe to run under gunicorn with multiple workers; without it,
the in-memory backend preserves single-node behaviour (-w 1 only).
"""

import os
import json
import time
import yaml
import hmac
import hashlib
import urllib.request
import functools
import subprocess
import threading
from collections import defaultdict
from flask import Flask, request, jsonify, Response, send_file, abort, redirect, make_response

app = Flask(__name__)
# Dashboard is same-origin, so no CORS: cross-origin pages must not reach this API.

# Limit request body size to 1MB to prevent DoS
app.config["MAX_CONTENT_LENGTH"] = 1 * 1024 * 1024

# ─── Auth + persistence (sentinel_auth) ───
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sentinel_auth as sa  # noqa: E402
import sentinel_diagnostics as diag  # noqa: E402

# ─── State Backend ───
from state import create_state_backend  # noqa: E402
STATE = create_state_backend()
STATE_BACKEND_NAME = getattr(STATE, "name", "inmemory")
sa.set_state_backend(STATE)  # share login throttling across workers when Redis is used

# TLS/cookie hardening (see TASK-002). Defaults to today's behaviour (plain HTTP);
# SENTINEL_REQUIRE_TLS enforces Secure cookies + proxy header checks.
SESSION_COOKIE_SECURE = os.getenv("SENTINEL_SESSION_COOKIE_SECURE", "0") == "1"

SESSION_COOKIE = "sentinel_session"

# ─── Self-update plumbing (tools/self_update.py writes the status file) ───
UPDATE_STATUS_FILE = os.getenv("SENTINEL_UPDATE_STATUS", "/var/lib/sentinel/update.json")
UPDATE_SERVICE = "sentinel-update.service"
UPDATE_REF = os.getenv("SENTINEL_UPDATE_REF", "master")
UPDATE_RUNNING_STATES = {"starting", "fetching", "building", "staging", "verifying", "cutover"}


def _update_status() -> dict:
    try:
        with open(UPDATE_STATUS_FILE, encoding="utf-8") as fh:
            data = json.load(fh)
        return data if isinstance(data, dict) else {"state": "idle"}
    except (OSError, ValueError):
        return {"state": "idle", "message": "no update has run yet"}


def _installed_meta() -> dict:
    out: dict = {}
    try:
        with open("/opt/sentinel/.install-meta", encoding="utf-8") as fh:
            for line in fh:
                if "=" in line:
                    key, _, value = line.partition("=")
                    out[key.strip()] = value.strip()
    except OSError:
        pass
    return out


def _set_session_cookie(resp, token: str):
    """One place that decides cookie flags: HttpOnly, SameSite=Strict, TLS-aware."""
    resp.set_cookie(
        SESSION_COOKIE, token, httponly=True, samesite="Strict",
        secure=SESSION_COOKIE_SECURE, max_age=sa.SESSION_TTL, path="/",
    )
    return resp


# ─── Fail closed: require all secrets at boot ───
REQUIRED_SECRETS = [
    "SENTINEL_AGENT_KEY",
    "SENTINEL_SESSION_SECRET",
    "SENTINEL_ALLOWLIST_KEY",
    "SENTINEL_ADMIN_PASSWORD",
]
for _sec in REQUIRED_SECRETS:
    if not os.getenv(_sec):
        raise RuntimeError(f"Missing required secret: {_sec}")
    if os.getenv(_sec, "").startswith("CHANGE_ME"):
        raise RuntimeError(f"Secret {_sec} still has default CHANGE_ME value — please configure it")

AGENT_KEY = os.getenv("SENTINEL_AGENT_KEY")
_admin_user = os.getenv("SENTINEL_ADMIN_USER", "admin")
_admin_pw = os.getenv("SENTINEL_ADMIN_PASSWORD")
sa.ensure_user(_admin_user, _admin_pw)

PUBLIC_PATHS = ("/login", "/health", "/favicon.ico")   # /metrics needs auth, see _metrics_ok
ADMIN_WRITE_PREFIXES = ("/api/v1/rules", "/api/v1/geo", "/api/v1/lineage/")
OPEN_API = ("/api/v1/stats",)  # monitoring endpoints stay open (read-only counters)


def _is_agent(req):
    return hmac.compare_digest(
        req.headers.get("X-Sentinel-Key", ""), AGENT_KEY or "")


def _session_ok(req):
    tok = req.cookies.get("sentinel_session", "")
    return bool(tok) and sa.session_verify(tok)


def _metrics_ok(req):
    """/metrics exposes event, severity and node counts: require a session, the agent key
    (X-Sentinel-Key), or `Authorization: Bearer <key>` (what Prometheus can send).
    Set SENTINEL_METRICS_PUBLIC=1 to restore the old open behaviour."""
    if os.getenv("SENTINEL_METRICS_PUBLIC") == "1":
        return True
    auth = req.headers.get("Authorization", "")
    if AGENT_KEY and auth.startswith("Bearer ") and hmac.compare_digest(
            auth[7:].encode(), AGENT_KEY.encode()):
        return True
    return _is_agent(req) or _session_ok(req)


# ─── Rate limiting for agent endpoints ───
_telemetry_rate_limits: dict[str, list[float]] = {}
_telemetry_rate_lock = threading.Lock()
TELEMETRY_MAX_PER_MINUTE = 1000  # per agent key

def _check_telemetry_rate_limit(agent_key: str) -> bool:
    """Return True if under limit, False if rate limited."""
    now = time.time()
    with _telemetry_rate_lock:
        window_start = now - 60
        timestamps = _telemetry_rate_limits.get(agent_key, [])
        # Keep only timestamps within the last minute
        timestamps = [ts for ts in timestamps if ts > window_start]
        if len(timestamps) >= TELEMETRY_MAX_PER_MINUTE:
            return False
        timestamps.append(now)
        _telemetry_rate_limits[agent_key] = timestamps
        return True


# ─── Configuration ───
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID")
RULES_FILE = os.getenv("SENTINEL_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "rules.yaml"))
GEO_RULES_FILE = os.getenv("SENTINEL_GEO_RULES", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "geo_rules.json"))
LINEAGE_DB_FILE = os.getenv("SENTINEL_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "lineage_db.json"))
TRUSTED_BINARIES_FILE = os.getenv("SENTINEL_TRUSTED", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "trusted_binaries.json"))
DASHBOARD_FILE = os.path.join(os.path.dirname(__file__), "index.html")
COLLECTOR_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── GeoIP (optional) ───
try:
    import geoip2.database
    GEOIP_READER = geoip2.database.Reader('/usr/share/GeoIP/GeoLite2-Country.mmdb')
except Exception:
    GEOIP_READER = None


# ─── Utility Functions ───
def load_rules():
    if not os.path.exists(RULES_FILE):
        return {"version": "2.0", "rules": [], "trusted_lineages": [], "blocked_lineages": []}
    with open(RULES_FILE, "r") as f:
        return yaml.safe_load(f)

def save_rules(data):
    with open(RULES_FILE, "w") as f:
        yaml.dump(data, f)

def load_geo_rules():
    if os.path.exists(GEO_RULES_FILE):
        with open(GEO_RULES_FILE, "r") as f:
            return json.load(f)
    return {"ALLOW": [], "BLOCK": [], "MONITOR": []}


def load_lineage_db():
    """Seed the state backend from the persisted JSON snapshot (in-memory runs).
    Redis deployments already hold their own state, so this is a no-op there."""
    if not isinstance(STATE_BACKEND_NAME, str):  # pragma: no cover - defensive
        return
    if STATE_BACKEND_NAME != "inmemory":
        return
    if not os.path.exists(LINEAGE_DB_FILE):
        return
    try:
        with open(LINEAGE_DB_FILE, "r") as f:
            data = json.load(f)
    except Exception:
        return

    def _to_int(x):
        try:
            s = str(x).strip()
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except (ValueError, TypeError):
            return None

    for k, v in (data.get("trees") or {}).items():
        lid = _to_int(k)
        if lid is None or not isinstance(v, dict):
            continue
        def _seed(tree, _v=v):
            tree.update({kk: vv for kk, vv in _v.items() if kk != "nodes"})
            tree["nodes"] = {str(p): n for p, n in (_v.get("nodes") or {}).items()}
        STATE.update_lineage_tree(lid, _seed)

    for x in data.get("blocked_lineages") or []:
        lid = _to_int(x)
        if lid is not None:
            STATE.add_blocked_lineage(lid)
    for x in data.get("trusted_lineages") or []:
        lid = _to_int(x)
        if lid is not None:
            STATE.add_trusted_lineage(lid)


def save_lineage_db():
    """Persist a snapshot. In-memory runs write the JSON file + SQLite mirror;
    Redis runs only mirror into SQLite (Redis is already durable)."""
    trees = STATE.get_lineage_trees()
    blocked = STATE.get_blocked_lineages()
    trusted = STATE.get_trusted_lineages()

    if STATE_BACKEND_NAME == "inmemory":
        data = {
            "trees": {str(k): v for k, v in trees.items()},
            "blocked_lineages": list(blocked),
            "trusted_lineages": list(trusted),
            "saved_at": time.time()
        }
        try:
            os.makedirs(os.path.dirname(os.path.abspath(LINEAGE_DB_FILE)), exist_ok=True)
            with open(LINEAGE_DB_FILE, "w") as f:
                json.dump(data, f, indent=2, default=str)
        except OSError as e:
            print(f"[-] lineage DB save failed (ingestion continues): {e}", flush=True)

    # mirror lineage trees into SQLite (historical queries)
    try:
        _c = sa.db()
        now = time.time()
        for k, t in trees.items():
            _c.execute(
                "INSERT INTO lineages(lineage_id,host,root_pid,blocked,trusted,"
                "threats,first_seen,last_seen,nodes) VALUES(?,?,?,?,?,?,?,?,?) "
                "ON CONFLICT(lineage_id) DO UPDATE SET host=excluded.host,"
                "blocked=excluded.blocked,trusted=excluded.trusted,"
                "threats=excluded.threats,last_seen=excluded.last_seen,"
                "nodes=excluded.nodes",
                (f"0x{k:016X}", t.get("host"), t.get("root_pid"),
                 1 if t.get("blocked") else 0, 1 if t.get("trusted") else 0,
                 t.get("threat_count", 0), t.get("first_seen", now),
                 t.get("last_seen", now), json.dumps(t.get("nodes", {}), default=str)))
        _c.commit()
        _c.close()
    except Exception as _e:
        print(f"[-] lineage sqlite mirror failed: {_e}", flush=True)


def get_country(ip):
    if not GEOIP_READER:
        return "UNKNOWN"
    try:
        return GEOIP_READER.country(ip).country.iso_code
    except Exception:
        return "UNKNOWN"

def is_blocked_country(ip):
    geo = load_geo_rules()
    country = get_country(ip)
    return country in geo.get("BLOCK", [])


def telegram_enabled():
    """True only when a real bot token + chat id are configured."""
    return bool(TELEGRAM_BOT_TOKEN and TELEGRAM_CHAT_ID
                and "YOUR_BOT_TOKEN" not in TELEGRAM_BOT_TOKEN)


def send_telegram_alert(data):
    if not telegram_enabled():
        return
    # lineage_id may arrive as int or 0x-hex string (wire format) — format safely
    _lid = data.get("lineage_id")
    if isinstance(_lid, int) and not isinstance(_lid, bool):
        lid_str = f"{_lid:#x}"
    else:
        lid_str = str(_lid) if _lid is not None else "N/A"
    # Only claim containment when the agent reported it actually killed something.
    if data.get("killed"):
        status_line = "*Status:* `TERMINATED (agent-confirmed)`"
    else:
        status_line = "*Status:* `DETECTED (no containment confirmed)`"
    msg = (
        f"🚨 *Project SENTINEL Alert*\n"
        f"*Node:* `{data.get('node_id', 'local-agent')}`\n"
        f"*Type:* `{data.get('type', 'EXEC_THREAT')}`\n"
        f"{status_line}\n"
        f"*Rule:* `{data.get('rule_id', 'N/A')} - {data.get('rule_name', 'N/A')}`\n"
        f"*Lineage:* `{lid_str}`\n"
        f"*PID:* `{data.get('pid')}` | *PPID:* `{data.get('ppid')}`\n"
        f"*Binary:* `{data.get('binary') or data.get('filename')}`\n"
        f"*Cmdline:* `{data.get('cmdline')}`"
    )
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"}).encode('utf-8')
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=3)
    except Exception as e:
        print(f"[-] Telegram dispatch error: {e}", flush=True)


def _norm_lineage_id(x):
    """Accept int, 0x-hex string or decimal string → int (or None)."""
    if isinstance(x, int) and not isinstance(x, bool):
        return x
    try:
        s = str(x).strip()
        if not s:
            return None
        return int(s, 16) if s.lower().startswith("0x") else int(s)
    except (ValueError, TypeError):
        return None


def update_lineage_tree(data):
    """Update the lineage tree for an ingested event (backend-agnostic)."""
    lineage_id = _norm_lineage_id(data.get("lineage_id"))
    if not lineage_id:
        return
    parent_id = _norm_lineage_id(data.get("parent_lineage_id"))
    try:
        pid = int(data.get("pid")) if data.get("pid") is not None else None
    except (ValueError, TypeError):
        pid = None
    ppid = _norm_lineage_id(data.get("ppid"))
    comm = data.get("comm")
    binary = data.get("binary") or data.get("filename")
    recv_at = data.get("received_at", time.time())

    blocked = STATE.get_blocked_lineages()
    trusted = STATE.get_trusted_lineages()

    def _apply(tree):
        if tree.get("parent_lineage_id") is None and parent_id is not None:
            tree["parent_lineage_id"] = parent_id
        if tree.get("root_pid") is None and pid is not None:
            tree["root_pid"] = pid
        if data.get("host"):
            tree["host"] = data["host"]
        tree.setdefault("nodes", {})
        tree["nodes"][str(pid)] = {
            "pid": pid,
            "ppid": ppid,
            "comm": comm,
            "binary": binary,
            "cmdline": data.get("cmdline"),
            "uid": data.get("uid", 0),
            "severity": data.get("severity", "INFO"),
            "killed": data.get("killed", False),
            "timestamp": recv_at,
        }
        tree["last_seen"] = recv_at
        if not tree.get("first_seen"):
            tree["first_seen"] = recv_at

        # Detect the true chain root: the node whose ppid is not in the tree
        for npid, n in tree["nodes"].items():
            p = n.get("ppid")
            if p is None or str(p) not in tree["nodes"]:
                tree["root_pid"] = n.get("pid", tree.get("root_pid"))
                break

        if data.get("type") == "EXEC_THREAT":
            tree["threat_count"] = tree.get("threat_count", 0) + 1

        # Enforcement state is owned by the agent; the hub only reflects it.
        if lineage_id in blocked:
            tree["blocked"] = True
        if lineage_id in trusted:
            tree["trusted"] = True

    STATE.update_lineage_tree(lineage_id, _apply)
    save_lineage_db()


def get_lineage_stats():
    return STATE.get_stats().get("lineage", {
        "total_lineages": 0, "blocked_lineages": 0, "trusted_lineages": 0,
        "total_processes": 0, "total_threats": 0,
    })


# ─── API Routes ───
@app.route("/")
def index():
    return send_file(DASHBOARD_FILE)


# ─── Static files (explicit allowlist) ───
DASHBOARD_STATIC = {
    "dashboard.js",
    "login.html",
    "index.html",
    "d3.v7.min.js",
}

@functools.lru_cache(maxsize=32)
def _is_allowed_static(fname: str) -> bool:
    return fname in DASHBOARD_STATIC

@app.route("/<path:filename>")
def static_files(filename):
    """Serve dashboard assets (dashboard.js etc.) same-origin."""
    if not _is_allowed_static(filename):
        abort(404)
    from flask import send_from_directory
    target = os.path.normpath(os.path.join(COLLECTOR_DIR, filename))
    if not target.startswith(COLLECTOR_DIR):
        abort(403)
    return send_from_directory(COLLECTOR_DIR, filename)

@app.before_request
def _auth_gate():
    p = request.path
    # Admin writes (rules, geo policy, lineage block/trust) need a dashboard session
    # AND a CSRF token. The shared agent key must never be enough to change policy.
    if request.method in ("POST", "PUT", "DELETE") and p.startswith(ADMIN_WRITE_PREFIXES):
        tok = request.cookies.get("sentinel_session", "")
        if not (sa.session_verify(tok) and sa.csrf_verify(tok, request.headers.get("X-CSRF-Token", ""))):
            return jsonify({"error": "forbidden"}), 403
        return None
    if p == "/metrics":
        return None if _metrics_ok(request) else (jsonify({"error": "unauthorized"}), 401)
    if p in PUBLIC_PATHS or p.startswith(("/login", "/api/v1/login")):
        return None
    if any(p.startswith(o) for o in OPEN_API):
        return None
    if p == "/" or p.startswith("/api/v1/"):
        if _session_ok(request) or _is_agent(request):
            return None
        # agents authenticate with the key; browsers get redirected to login
        if p.startswith("/api/v1/"):
            return jsonify({"error": "unauthorized"}), 401
        return redirect("/login")
    return None


TRUST_PROXY = os.environ.get("SENTINEL_TRUST_PROXY", "0") == "1"


def _client_ip() -> str:
    """Real client for lockout/audit. X-Forwarded-For is only honoured when the
    operator declares a trusted reverse proxy (spoofable otherwise)."""
    if TRUST_PROXY:
        forwarded = request.headers.get("X-Forwarded-For", "")
        if forwarded:
            return forwarded.split(",")[0].strip()
    return request.remote_addr or "?"


@app.route("/login", methods=["GET"])
def login_page():
    return send_file(os.path.join(COLLECTOR_DIR, "login.html"))


@app.route("/api/v1/login", methods=["POST"])
def api_login():
    ip = _client_ip()
    body = request.get_json(silent=True) or {}
    username = (body.get("username") or "").strip()
    password = body.get("password") or ""

    allowed, retry = sa.login_attempts(ip, username)
    if not allowed:
        resp = jsonify({"error": "too many attempts", "retry_after": retry})
        resp.headers["Retry-After"] = str(retry)
        return resp, 429

    if sa.check_user(username, password):
        sa.login_reset(ip, username)
        token = sa.session_create(subject=username)
        sa.audit(username, "login", f"ip={ip}")
        resp = make_response(jsonify({"ok": True, "csrf": sa.csrf_for(token)}))
        _set_session_cookie(resp, token)
        resp.headers["Cache-Control"] = "no-store"
        return resp

    sa.login_fail(ip, username)
    sa.audit(username or "-", "login.failed", f"ip={ip}")
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/api/v1/logout", methods=["POST"])
def api_logout():
    token = request.cookies.get(SESSION_COOKIE, "")
    claims = sa.session_claims(token)
    if claims:
        sa.revoke_session(token)  # server-side: a copied cookie stops working
        sa.audit(claims.get("sub", "admin"), "logout", "")
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie(SESSION_COOKIE, path="/")
    resp.headers["Cache-Control"] = "no-store"
    return resp


@app.after_request
def _session_and_security_headers(resp):
    """Sliding expiry + baseline headers. Never touches the login/logout replies."""
    if request.path.startswith("/api/"):
        resp.headers.setdefault("Cache-Control", "no-store")
        resp.headers.setdefault("X-Content-Type-Options", "nosniff")
    if request.path in ("/api/v1/login", "/api/v1/logout"):
        return resp
    token = request.cookies.get(SESSION_COOKIE, "")
    if token:
        claims = sa.session_claims(token)
        if claims and time.time() - claims["iat"] >= sa.SESSION_REFRESH_AFTER:
            _set_session_cookie(resp, sa.session_create(claims.get("sub") or "admin"))
    return resp


@app.route("/api/v1/system/update", methods=["GET", "POST"])
def api_system_update():
    """GET: update status + installed version. POST: start a staged update."""
    token = request.cookies.get(SESSION_COOKIE, "")

    if request.method == "GET":
        if not sa.session_verify(token):
            return jsonify({"error": "unauthorized"}), 401
        state = _update_status()
        return jsonify({**state, "installed": _installed_meta(), "ref": UPDATE_REF})

    if not (sa.session_verify(token) and
            sa.csrf_verify(token, request.headers.get("X-CSRF-Token", ""))):
        return jsonify({"error": "forbidden"}), 403

    state = _update_status()
    if state.get("state") in UPDATE_RUNNING_STATES:
        return jsonify({"error": "an update is already running", "state": state}), 409

    try:
        proc = subprocess.run(
            ["sudo", "-n", "systemctl", "start", "--no-block", UPDATE_SERVICE],
            capture_output=True, text=True, timeout=15,
        )
    except (OSError, subprocess.SubprocessError) as exc:
        return jsonify({"error": "cannot start the updater", "detail": str(exc)[:300]}), 503
    if proc.returncode != 0:
        detail = (proc.stderr or proc.stdout or "").strip()[-300:]
        return jsonify({"error": "cannot start the updater", "detail": detail}), 503

    sa.audit("admin", "system.update", f"ref={UPDATE_REF}")
    return jsonify({"ok": True, "state": "starting"}), 202


@app.route("/api/v1/csrf", methods=["GET"])
def api_csrf():
    tok = request.cookies.get("sentinel_session", "")
    if not sa.session_verify(tok):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"csrf": sa.csrf_for(tok)})


@app.route("/api/v1/mode", methods=["GET", "POST"])
def api_mode():
    if request.method == "GET":
        return jsonify({"mode": STATE.get_mode()})
    tok = request.cookies.get("sentinel_session", "")
    if not (sa.session_verify(tok) and sa.csrf_verify(tok, request.headers.get("X-CSRF-Token", ""))):
        return jsonify({"error": "forbidden"}), 403
    mode = (request.json or {}).get("mode")
    if mode not in ("learn", "enforce"):
        return jsonify({"error": "mode must be learn|enforce"}), 400
    STATE.set_mode(mode)
    sa.meta_set("mode", mode)  # persist across restarts
    sa.audit("admin", f"mode.{mode}", "")
    return jsonify({"mode": mode})


@app.route("/api/v1/allowlist", methods=["GET", "POST", "DELETE"])
def api_allowlist():
    tok = request.cookies.get("sentinel_session", "")
    if request.method == "GET":
        if not (sa.session_verify(tok) or _is_agent(request)):
            return jsonify({"error": "unauthorized"}), 401
        entries = sa.allowlist_all()
        blob = {"entries": entries, "generated_at": time.time()}
        return jsonify({**blob, "signature": sa.allowlist_sign(blob)})
    # mutations require admin session + CSRF
    if not (sa.session_verify(tok) and sa.csrf_verify(tok, request.headers.get("X-CSRF-Token", ""))):
        return jsonify({"error": "forbidden"}), 403
    body = request.json or {}
    try:
        if request.method == "POST":
            sa.allowlist_add(body.get("tier", ""), body.get("value", ""),
                             body.get("label", ""), "admin")
            return jsonify({"ok": True})
        sa.allowlist_remove(body.get("tier", ""), body.get("value", ""), "admin")
        return jsonify({"ok": True})
    except ValueError as e:
        return jsonify({"error": str(e)}), 400


@app.route("/api/v1/telemetry", methods=["GET", "POST"])
def telemetry():
    if request.method == "POST":
        # Require agent authentication for telemetry ingestion
        if not _is_agent(request):
            return jsonify({"error": "unauthorized"}), 401

        # Rate limit per agent key
        agent_key = request.headers.get("X-Sentinel-Key", "")
        if not _check_telemetry_rate_limit(agent_key):
            return jsonify({"error": "rate limited"}), 429

        data = request.json or {}
        data["received_at"] = time.time()

        # Geo-blocking check
        if data.get("type") == "NETWORK_THREAT" or data.get("daddr"):
            daddr = data.get("daddr")
            if daddr and is_blocked_country(daddr):
                data["type"] = "GEO_BLOCK"
                data["action"] = "BLOCK"
                data["severity"] = "HIGH"
                data["rule_id"] = "GEO_BLOCK"
                data["rule_name"] = f"Blocked Country: {get_country(daddr)}"

        # Node tracking
        node_id = data.get("node_id", request.remote_addr)
        STATE.update_connected_node(node_id, {
            "last_seen": time.time(),
            "ip": request.remote_addr,
            "status": "HEALTHY",
        })

        # Update lineage tree
        update_lineage_tree(data)

        # Store telemetry with a monotonic sequence for SSE delivery
        seq = STATE.append_telemetry(data)

        # Persist (SQLite) — best-effort, ingestion never fails on DB issues
        try:
            _c = sa.db()
            _c.execute(
                "INSERT INTO events(seq,ts,type,severity,rule_id,mitre,pid,ppid,"
                "lineage_id,comm,binary,cmdline,user,host,killed,action,raw) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (seq, data.get("received_at"), data.get("type"),
                 data.get("severity"), data.get("rule_id"),
                 json.dumps(data.get("mitre", [])), data.get("pid"),
                 data.get("ppid"), str(data.get("lineage_id") or ""),
                 data.get("comm"), data.get("binary") or data.get("filename"),
                 data.get("cmdline"), data.get("user"), data.get("host"),
                 1 if data.get("killed") else 0, data.get("action", "LOG"),
                 json.dumps(data, default=str)))
            _c.commit()
            _c.close()
        except Exception as _e:
            print(f"[-] event persist failed: {_e}", flush=True)

        # Alert
        send_telegram_alert(data)
        return jsonify({"status": "acknowledged", "timestamp": data["received_at"]}), 200

    return jsonify([_wire_event(e) for e in STATE.get_telemetry_logs()])



@app.route("/api/v1/diagnostics", methods=["GET"])
def api_diagnostics():
    """Why is the feed empty? Read-only diagnosis; never mutates state."""
    token = request.cookies.get(SESSION_COOKIE, "")
    if not sa.session_verify(token):
        return jsonify({"error": "unauthorized"}), 401

    stats = STATE.get_stats()
    last = None
    for event in STATE.get_telemetry_logs(limit=200):
        ts = event.get("received_at") or event.get("ts")
        if ts:
            last = max(last or 0, float(ts))

    result = diag.diagnose(
        total_events=int(stats.get("total_events") or 0),
        telemetry_last_ts=last,
        db_path=os.environ.get("SENTINEL_DB_PATH"),
        env={
            "SENTINEL_AGENT_KEY": os.environ.get("SENTINEL_AGENT_KEY"),
            "SENTINEL_COLLECTOR_URL": os.environ.get("SENTINEL_COLLECTOR_URL"),
        },
    )
    return jsonify(result)


@app.route("/api/v1/stats", methods=["GET"])
def stats():
    return jsonify(STATE.get_stats())


def _wire_tree(tree, lineage_id):
    """Lineage tree copy with all dict keys stringified (Flask jsonify requires
    string keys at every depth; nodes are keyed by pid)."""
    t = dict(tree)
    t["lineage_id"] = f"0x{lineage_id:016X}"
    t["nodes"] = {str(pid): node for pid, node in (t.get("nodes") or {}).items()}
    return t

@app.route("/api/v1/lineage", methods=["GET"])
def get_lineages():
    """Get all lineage trees. IDs emitted as 0x-hex strings — 64-bit ints
    lose precision in JS Numbers (>2^53)."""
    return jsonify({f"0x{k:016X}": _wire_tree(v, k) for k, v in STATE.get_lineage_trees().items()})

def _admin_blocked() -> set:
    """Lineages an operator blocked from the dashboard (persisted, survives restarts)."""
    try:
        return {int(x, 16) for x in json.loads(sa.meta_get("admin_blocked", "[]"))}
    except (ValueError, TypeError):
        return set()


def _admin_block_add(lineage_id: int) -> None:
    ids = _admin_blocked()
    ids.add(lineage_id)
    sa.meta_set("admin_blocked", json.dumps(sorted(f"0x{x:016X}" for x in ids)))
    _admin_unblock_remove(lineage_id)


def _admin_block_remove(lineage_id: int) -> None:
    ids = _admin_blocked()
    if lineage_id in ids:
        ids.discard(lineage_id)
        sa.meta_set("admin_blocked", json.dumps(sorted(f"0x{x:016X}" for x in ids)))


def _admin_unblocked() -> set:
    """Lineages an operator explicitly unblocked; agents poll these as commands."""
    try:
        return {int(x, 16) for x in json.loads(sa.meta_get("admin_unblocked", "[]"))}
    except (ValueError, TypeError):
        return set()


def _admin_unblock_add(lineage_id: int) -> None:
    ids = _admin_unblocked()
    ids.add(lineage_id)
    sa.meta_set("admin_unblocked", json.dumps(sorted(f"0x{x:016X}" for x in ids)))


def _admin_unblock_remove(lineage_id: int) -> None:
    ids = _admin_unblocked()
    if lineage_id in ids:
        ids.discard(lineage_id)
        sa.meta_set("admin_unblocked", json.dumps(sorted(f"0x{x:016X}" for x in ids)))


def _parse_lineage_id(lid):
    """Accept 0x-hex, bare hex, or decimal lineage ids.
    Pure-digit strings parse as DECIMAL (a 9+ digit decimal is not valid hex
    shorthand); 0x-prefixed strings parse as hex; anything else tries hex then
    decimal."""
    return _norm_lineage_id(lid)

@app.route("/api/v1/lineage/<string:lid>", methods=["GET"])
def get_lineage(lid):
    """Get specific lineage tree"""
    lineage_id = _parse_lineage_id(lid)
    if lineage_id is None:
        return jsonify({"error": "invalid lineage id"}), 400
    tree = STATE.get_lineage_trees().get(lineage_id)
    if tree is not None:
        return jsonify(_wire_tree(tree, lineage_id))
    return jsonify({"error": "Lineage not found"}), 404

@app.route("/api/v1/lineage/<string:lid>/block", methods=["POST"])
def block_lineage(lid):
    """Block entire lineage - records intent for the agent to pick up."""
    tok = request.cookies.get("sentinel_session", "")
    if not (sa.session_verify(tok) and sa.csrf_verify(tok, request.headers.get("X-CSRF-Token", ""))):
        return jsonify({"error": "forbidden"}), 403

    lineage_id = _parse_lineage_id(lid)
    if lineage_id is None:
        return jsonify({"error": "invalid lineage id"}), 400

    STATE.add_blocked_lineage(lineage_id)
    _admin_block_add(lineage_id)
    STATE.update_lineage_tree(lineage_id, lambda t: t.__setitem__("blocked", True))
    # Block direct child lineages too
    for child_id, tree in STATE.get_lineage_trees().items():
        if tree.get("parent_lineage_id") == lineage_id:
            STATE.add_blocked_lineage(child_id)
            STATE.update_lineage_tree(child_id, lambda t: t.__setitem__("blocked", True))
    save_lineage_db()
    sa.audit("admin", "lineage.block", f"{lineage_id:#x}")
    return jsonify({"status": "blocked", "lineage_id": f"0x{lineage_id:016X}"})


@app.route("/api/v1/lineage/<string:lid>/unblock", methods=["POST"])
def unblock_lineage(lid):
    """Lift an operator block - a false positive must always be reversible."""
    tok = request.cookies.get("sentinel_session", "")
    if not (sa.session_verify(tok) and sa.csrf_verify(tok, request.headers.get("X-CSRF-Token", ""))):
        return jsonify({"error": "forbidden"}), 403

    lineage_id = _parse_lineage_id(lid)
    if lineage_id is None:
        return jsonify({"error": "invalid lineage id"}), 400

    STATE.remove_blocked_lineage(lineage_id)
    _admin_block_remove(lineage_id)
    _admin_unblock_add(lineage_id)
    STATE.update_lineage_tree(lineage_id, lambda t: t.__setitem__("blocked", False))
    save_lineage_db()
    sa.audit("admin", "lineage.unblock", f"{lineage_id:#x}")
    return jsonify({"status": "unblocked", "lineage_id": f"0x{lineage_id:016X}"})


@app.route("/api/v1/lineage/<string:lid>/trust", methods=["POST"])
def trust_lineage(lid):
    """Mark lineage as trusted"""
    tok = request.cookies.get("sentinel_session", "")
    if not (sa.session_verify(tok) and sa.csrf_verify(tok, request.headers.get("X-CSRF-Token", ""))):
        return jsonify({"error": "forbidden"}), 403

    lineage_id = _parse_lineage_id(lid)
    if lineage_id is None:
        return jsonify({"error": "invalid lineage id"}), 400

    STATE.add_trusted_lineage(lineage_id)
    STATE.update_lineage_tree(lineage_id, lambda t: t.__setitem__("trusted", True))
    save_lineage_db()
    sa.audit("admin", "lineage.trust", f"{lineage_id:#x}")
    return jsonify({"status": "trusted", "lineage_id": f"0x{lineage_id:016X}"})

@app.route("/api/v1/rules", methods=["GET", "POST"])
def handle_rules():
    if request.method == "POST":
        tok = request.cookies.get("sentinel_session", "")
        if not (sa.session_verify(tok) and sa.csrf_verify(tok, request.headers.get("X-CSRF-Token", ""))):
            return jsonify({"error": "forbidden"}), 403
        new_rules = request.json
        try:
            save_rules(new_rules)
            sa.audit("admin", "rules.update", "")
            return jsonify({"status": "updated", "rules": new_rules}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify(load_rules())

@app.route("/api/v1/geo", methods=["GET", "POST"])
def handle_geo():
    if request.method == "POST":
        tok = request.cookies.get("sentinel_session", "")
        if not (sa.session_verify(tok) and sa.csrf_verify(tok, request.headers.get("X-CSRF-Token", ""))):
            return jsonify({"error": "forbidden"}), 403
        geo = request.json
        with open(GEO_RULES_FILE, "w") as f:
            json.dump(geo, f, indent=2)
        sa.audit("admin", "geo.update", "")
        return jsonify({"status": "updated", "geo": geo}), 200
    return jsonify(load_geo_rules())

@app.route("/api/v1/agent/commands", methods=["GET"])
def agent_commands():
    """Signed directive the agent polls: mode, operator commands and the allowlist in one response.

    Shape (schema 1):
      {"schema": 1, "server_time": <epoch float>, "revision": "<16 hex>",
       "mode": "learn" | "enforce",
       "commands": [{"type": "block_lineage", "lineage_id": "0x...", "action": "kill"},
                    {"type": "unblock_lineage", "lineage_id": "0x..."},
                    {"type": "trust_lineage", "lineage_id": "0x..."}],
       "allowlist": [{"tier", "value", "label", "added_at", "added_by"}, ...],
       "signature": "<HMAC-SHA256 hex over the canonical JSON of every other field>"}

    The agent verifies the signature, rejects a server_time older than the last one it
    applied (replay), and only applies block commands while mode == "enforce".
    """
    if not _is_agent(request):
        return jsonify({"error": "unauthorized"}), 401

    commands = [{"type": "block_lineage", "lineage_id": f"0x{lid:016X}", "action": "kill"}
                for lid in sorted(_admin_blocked())]
    commands += [{"type": "unblock_lineage", "lineage_id": f"0x{lid:016X}"}
                 for lid in sorted(_admin_unblocked())]
    commands += [{"type": "trust_lineage", "lineage_id": f"0x{lid:016X}"}
                 for lid in sorted(STATE.get_trusted_lineages())]
    body = {
        "schema": 1,
        "server_time": time.time(),
        "mode": STATE.get_mode(),
        "commands": commands,
        "allowlist": sa.allowlist_all(),
    }
    state = {k: body[k] for k in ("mode", "commands", "allowlist")}
    body["revision"] = hashlib.sha256(
        json.dumps(state, sort_keys=True, separators=(",", ":")).encode()).hexdigest()[:16]
    return jsonify({**body, "signature": sa.allowlist_sign(body)})


def _wire_event(evt):
    """Copy of an event with 64-bit ids emitted as 0x-hex strings (JS-safe)."""
    e = {k: v for k, v in evt.items() if not k.startswith("_")}
    lid = e.get("lineage_id")
    if isinstance(lid, int):
        e["lineage_id"] = f"0x{lid:016X}"
    plid = e.get("parent_lineage_id")
    if isinstance(plid, int):
        e["parent_lineage_id"] = f"0x{plid:016X}"
    return e

@app.route("/api/v1/stream")
def event_stream():
    def generate():
        last_seq = 0
        while True:
            # Deliver every event newer than last_seq (newest-first from backend).
            # Survives ring wrap: delivery keys off _seq, not length.
            fresh = [e for e in STATE.get_telemetry_logs() if e.get("_seq", 0) > last_seq]
            for evt in reversed(fresh):  # oldest-first
                last_seq = evt["_seq"]
                yield f"data: {json.dumps(_wire_event(evt))}\n\n"
            time.sleep(0.3)
    return Response(generate(), mimetype="text/event-stream")



# ─── Health Check Endpoint ───
@app.route("/health")
def health_check():
    """Health check endpoint for load balancers and monitoring.
    Unauthenticated minimal check for load balancers. Detailed info requires auth."""
    # Check if request has auth (agent key or session)
    has_auth = _is_agent(request) or _session_ok(request)
    
    # Minimal response for unauthenticated requests (load balancer probes)
    if not has_auth:
        return jsonify({"status": "ok"}), 200
    
    # Detailed response for authenticated requests
    checks = STATE.health_check()
    checks.setdefault("checks", {})

    # Check database
    try:
        with open(LINEAGE_DB_FILE, 'r') as f:
            json.load(f)
        checks["checks"]["database"] = {"status": "ok", "writable": True}
    except FileNotFoundError:
        checks["checks"]["database"] = {"status": "ok", "writable": True, "note": "no snapshot yet"}
    except Exception as e:
        checks["checks"]["database"] = {"status": "failed", "error": str(e)}
        checks["status"] = "degraded"

    # Check rules file
    try:
        load_rules()
        checks["checks"]["rules"] = {"status": "ok"}
    except Exception as e:
        checks["checks"]["rules"] = {"status": "failed", "error": str(e)}
        checks["status"] = "degraded"

    # Check GeoIP
    checks["checks"]["geoip"] = {"status": "ok" if GEOIP_READER else "unavailable"}

    status_code = 200 if checks["status"] == "healthy" else 503
    return jsonify(checks), status_code


# ─── Metrics Endpoint (Prometheus) ───
@app.route("/metrics")
def metrics():
    """Prometheus metrics endpoint - requires agent key or session"""
    if not _metrics_ok(request):
        return jsonify({"error": "unauthorized"}), 401
    st = STATE.get_stats()
    lin = st.get("lineage", {})
    logs = STATE.get_telemetry_logs()
    uptime = st.get("uptime_seconds", 0)
    lines = [
        f'sentinel_uptime_seconds {uptime}',
        f'sentinel_telemetry_events_total {st.get("total_events", len(logs))}',
        f'sentinel_lineage_trees_total {lin.get("total_lineages", 0)}',
        f'sentinel_lineage_trees_blocked {lin.get("blocked_lineages", 0)}',
        f'sentinel_lineage_trees_trusted {lin.get("trusted_lineages", 0)}',
        f'sentinel_connected_nodes_total {st.get("active_nodes", 0)}',
    ]

    event_types = defaultdict(int)
    severity_counts = defaultdict(int)
    for log in logs:
        event_types[log.get("type", "UNKNOWN")] += 1
        severity_counts[log.get("severity", "UNKNOWN")] += 1

    for event_type, count in event_types.items():
        lines.append(f'sentinel_events_type{{type="{event_type}"}} {count}')
    for severity, count in severity_counts.items():
        lines.append(f'sentinel_events_severity{{severity="{severity}"}} {count}')

    return Response("\n".join(lines), mimetype="text/plain")


# ─── Production serving ───
# State lives behind state.StateBackend:
#   • SENTINEL_REDIS_URL unset → in-memory state. Serve with EXACTLY ONE worker:
#       gunicorn -w 1 --threads 8 -b 0.0.0.0:5000 sentinel_hub_lineage:app
#   • SENTINEL_REDIS_URL set   → shared state. Scale workers freely:
#       gunicorn -w 4 --threads 8 -b 0.0.0.0:5000 sentinel_hub_lineage:app

if __name__ == "__main__":
    load_lineage_db()
    _port = int(os.getenv("SENTINEL_PORT", "5000"))
    _host = os.getenv("SENTINEL_BIND", "127.0.0.1")
    print(f"[*] Project SENTINEL Hub & SOC Web UI online at http://{_host}:{_port}...")
    if _host not in ("127.0.0.1", "::1", "localhost"):
        print("[!] Listening beyond localhost with the Flask dev server and no TLS. "
              "For production use gunicorn behind a TLS proxy (see comments above).")
    app.run(host=_host, port=_port)

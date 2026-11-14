# Kernel verification — K1/K2 on a live kernel

This records the first run of `tests/kernel/selftest.c` against the K1–K6 eBPF
patch on a **real kernel**, not just the verifier. Earlier attempts could not run
it: the phone's Android/proot kernel has no BTF, no BPF LSM and no `CAP_BPF`, and
GitHub-hosted runners observe no events from the tracepoints.

## Environment

| | |
|---|---|
| Host | QEMU x86_64 guest (TCG) on an arm64 phone — no KVM |
| Guest OS | Ubuntu 24.04.5 cloud image |
| Kernel | `6.8.0-147-generic` |
| BTF | present (`/sys/kernel/btf/vmlinux`) |
| LSM on that boot | `lockdown,capability,landlock,yama,apparmor` — **no `bpf`** |
| Object | `ebpf/sentinel_lineage_core.bpf.c` @ `b1033eb` (patched blob `80db8c5`) |
| Command | `sudo ./selftest ./sentinel_patched.o` |

The guest was booted **without** `lsm=bpf`, so LSM programs could be verified and
loaded but not attached/triggered. The selftest's `alarm(40)` was raised to 1800 s
**in the guest only** because verifier loads take tens of seconds under TCG; this
is not in the tree.

## Result — 22 checks, 0 failed

```
[1] verifier: load each program on its own
  PASS  trace_execve passes the verifier
  PASS  trace_execveat passes the verifier
  PASS  bprm_check_security_lsm passes the verifier
  PASS  task_kill_lsm passes the verifier
  PASS  file_open_lsm passes the verifier
  PASS  trace_connect passes the verifier
  PASS  trace_openat passes the verifier
  PASS  trace_exit_execve passes the verifier
  PASS  on_fork passes the verifier
  PASS  trace_sched_exit passes the verifier
  PASS  trace_sendmsg passes the verifier
  PASS  bpf_lsm passes the verifier
  PASS  kernel_module_request_lsm passes the verifier
  PASS  kernel_read_file_lsm passes the verifier
[2] attach tracepoints and trace real execs
  PASS  all tracepoint programs attach (is tracefs mounted?)
  PASS  exec of /bin/ls observed
  PASS  full argv captured ("/bin/ls -la /tmp")
  PASS  child's parent_lineage_id == parent's lineage_id
  PASS  child gets its own lineage_id
  PASS  second child argv captured ("/bin/echo a b")
[3] block a lineage: its next child must die at exec
  PASS  child of the blocked lineage was SIGKILLed at exec (status 137)
  PASS  BLOCKED_LINEAGE alert emitted for /bin/true

22 checks, 0 failed
```

## What this proves

- **K1** — fork/exec lineage chains: children carry the parent's `lineage_id`
  until exec, then get their own; a blocked lineage's next exec is killed.
- **K2** — exec is committed on success: real execs produce events with the new
  argv and comm, and only successful execs are recorded.
- Every program, including the LSM hooks, passes the BPF verifier.

## What this does not prove

- **LSM paths** (`bprm_check_security`, `task_kill`) were not attached because the
  guest booted without `lsm=bpf`. **K4** (`kill -0`, self-signals, PID 1) and the
  LSM half of K1 remain unverified.
- **K3** (entry removed on last-thread exit), **K5** (ringbuf drop counters) and
  **K6** (container-local `ns_pid`) are not asserted by the selftest.
- Single kernel version (6.8.0) and architecture (x86_64); no arm64 kernel run.

Reproduce with a BTF kernel booted with `lsm=...,bpf`, `CAP_BPF`/root, tracefs,
then `make kernel-test`.

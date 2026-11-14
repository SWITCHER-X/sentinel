/*
 * Project SENTINEL eBPF Module — CO-RE (Compile Once, Run Everywhere)
 * Signature-based process lineage tracking with instant kill-switch
 * Uses vmlinux.h + libbpf CO-RE helpers — no kernel headers required at compile time
 */

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

#define MAX_LINEAGE_ENTRIES 65536
#define MAX_PATH_LEN 256
#define CMDLINE_LEN 512
#define MAX_ARGS 12
#define ARG_CHUNK 96
#define LINEAGE_ID_SEED 0x9e3779b97f4a7c15ULL

// Missing constants from kernel headers
#ifndef EPERM
#define EPERM 1
#endif
#ifndef SIGKILL
#define SIGKILL 9
#endif
#ifndef AF_INET
#define AF_INET 2
#endif
#ifndef AT_FDCWD
#define AT_FDCWD -100
#endif

struct lineage_entry_t {
    u64 lineage_id;
    u64 parent_lineage_id;
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 ns_pid;
    char comm[16];
    char binary_path[MAX_PATH_LEN];
    char cmdline[512];
    u64 exec_timestamp;
    u32 flags;
    u32 rule_matched;
};

struct conn_event_t {
    u32 pid;
    u32 ns_pid;
    char comm[16];
    u32 daddr;
    u16 dport;
    u16 family;
    u64 lineage_id;
};

struct file_event_t {
    u32 pid;
    u32 ns_pid;
    char comm[16];
    char path[MAX_PATH_LEN];
    int flags;
    u64 lineage_id;
};

struct alert_event_t {
    u64 lineage_id;
    u32 pid;
    u32 ns_pid;
    u32 rule_id;
    u32 action;
    char comm[16];
    char binary_path[MAX_PATH_LEN];
    char matched_pattern[128];
    u64 timestamp;
};

struct proc_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 ns_pid;
    u64 lineage_id;
    u64 parent_lineage_id;
    char comm[16];
    char filename[MAX_PATH_LEN];
    char cmdline[512];
};

struct icmp_event_t {
    u32 pid;
    u32 ns_pid;
    char comm[16];
    u32 type;
    u32 code;
    u32 daddr;
    u16 id;
    u16 seq;
    u32 data_len;
    u64 lineage_id;
};

enum lineage_flags {
    LINEAGE_FLAG_ROOT       = 1 << 0,
    LINEAGE_FLAG_SUID       = 1 << 1,
    LINEAGE_FLAG_CONTAINER  = 1 << 2,
    LINEAGE_FLAG_SUSPICIOUS = 1 << 3,
    LINEAGE_FLAG_KILLED     = 1 << 4,
    LINEAGE_FLAG_TRUSTED    = 1 << 5,
    LINEAGE_FLAG_ANONYMOUS  = 1 << 6,
};

enum rule_action {
    ACTION_LOG      = 0,
    ACTION_ALERT    = 1,
    ACTION_KILL     = 2,
    ACTION_BLOCK    = 3,
    ACTION_QUARANTINE = 4,
};

// BPF Maps
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_LINEAGE_ENTRIES);
    __type(key, u32);
    __type(value, struct lineage_entry_t);
} lineage_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, MAX_LINEAGE_ENTRIES);
    __type(key, u64);
    __type(value, struct lineage_entry_t);
} lineage_by_id SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, u32);
    __type(value, struct rule_entry_t);
} rule_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, u8);
} trusted_binaries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 4096);
    __type(key, u64);
    __type(value, u8);
} blocked_lineages SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} dns_queries SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 10240);
    __type(key, u32);
    __type(value, u64);
} data_volume SEC(".maps");

// Ring buffers
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 1024 * 1024);   // exec is the event we can least afford to lose
} exec_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} conn_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} alert_events SEC(".maps");

// Ring buffer drop counters (per CPU). Read with: bpftool map dump name ringbuf_drops
enum { DROP_EXEC, DROP_CONN, DROP_FILE, DROP_ALERT, DROP_MAX };

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, DROP_MAX);
    __type(key, u32);
    __type(value, u64);
} ringbuf_drops SEC(".maps");

static __always_inline void count_drop(u32 which) {
    u64 *v = bpf_map_lookup_elem(&ringbuf_drops, &which);
    if (v) (*v)++;
}

#define RB_OUT(map, data, len, which) \
    do { if (bpf_ringbuf_output(&(map), (data), (len), 0)) count_drop(which); } while (0)

// Rule entry matching userspace structure
struct rule_entry_t {
    u32 id;
    u32 action;
    u32 severity;
    char pattern[128];
    char binary_pattern[256];
    u64 lineage_id;
    u32 flags;
    u32 uid_min;
    u32 uid_max;
};

enum rule_flags {
    RULE_FLAG_REGEX       = 1 << 0,
    RULE_FLAG_CMDLINE     = 1 << 1,
    RULE_FLAG_BINARY      = 1 << 2,
    RULE_FLAG_LINEAGE     = 1 << 3,
    RULE_FLAG_UID_RANGE   = 1 << 4,
    RULE_FLAG_NETWORK     = 1 << 5,
    RULE_FLAG_FILE_WRITE  = 1 << 6,
};

// ─── Per-CPU scratch space ───
// The BPF stack is limited to 512 bytes. The event structs below are larger,
// so every program builds them here instead of on the stack.
struct scratch_t {
    struct lineage_entry_t entry;
    struct proc_event_t    pe;
    struct alert_event_t   alert;
    struct file_event_t    fe;
    struct conn_event_t    ce;
};

struct {
    __uint(type, BPF_MAP_TYPE_PERCPU_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, struct scratch_t);
} scratch SEC(".maps");


static __always_inline struct scratch_t *get_scratch(void) {
    u32 zero = 0;
    return bpf_map_lookup_elem(&scratch, &zero);
}

// Exec attempts waiting for sys_exit_execve to say whether they succeeded (key: tgid).
struct {
    __uint(type, BPF_MAP_TYPE_LRU_HASH);
    __uint(max_entries, 8192);
    __type(key, u32);
    __type(value, struct lineage_entry_t);
} pending_exec SEC(".maps");

// Hash function for lineage_id generation
static __always_inline u64 lineage_hash(u64 parent_id, const char *path, u32 uid, u64 ts) {
    u64 h = parent_id ^ LINEAGE_ID_SEED;
    h ^= uid + 0x9e3779b9 + (h << 6) + (h >> 2);
    h ^= ts + 0x9e3779b9 + (h << 6) + (h >> 2);

    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++) {
        char c = path[i];
        if (c == 0) break;
        h ^= c + 0x9e3779b9 + (h << 6) + (h >> 2);
    }
    return h;
}

// Check if binary is in trusted list (keyed on a hash of the path string)
static __always_inline int is_trusted_binary(const char *path) {
    u64 key = 0;
    #pragma unroll
    for (int i = 0; i < MAX_PATH_LEN; i++) {
        char c = path[i];
        if (c == 0) break;
        key ^= c + 0x9e3779b9 + (key << 6) + (key >> 2);
    }
    return bpf_map_lookup_elem(&trusted_binaries, &key) != NULL;
}

static __always_inline int is_lineage_blocked(u64 lineage_id) {
    return lineage_id != 0 && bpf_map_lookup_elem(&blocked_lineages, &lineage_id) != NULL;
}

// Lineage of whoever launched this process: its own entry (copied at fork, or left by an
// earlier exec), else the parent's entry. Using the process's own entry first keeps the chain
// intact across fork-without-exec intermediates and when the parent has exited (re-parenting).
static __always_inline struct lineage_entry_t *launcher_entry(u32 pid, u32 ppid) {
    struct lineage_entry_t *e = bpf_map_lookup_elem(&lineage_map, &pid);
    return e ? e : bpf_map_lookup_elem(&lineage_map, &ppid);
}

static __always_inline u32 get_ns_pid(struct task_struct *task) {
    // PID as seen from inside the task's own PID namespace (equals the host PID on the host).
    struct pid *tp = BPF_CORE_READ(task, group_leader, thread_pid);
    if (!tp) return 0;
    unsigned int lvl = BPF_CORE_READ(tp, level);
    if (lvl > 31) return 0;
    u32 nr = 0;
    bpf_core_read(&nr, sizeof(nr), &tp->numbers[lvl].nr);
    return nr;
}

// Join argv[0..MAX_ARGS) with spaces into out (NUL-terminated, CMDLINE_LEN bytes).
static __always_inline void read_argv(char *out, const char *const *argv) {
    u32 off = 0;
    out[0] = 0;
    #pragma unroll
    for (int i = 0; i < MAX_ARGS; i++) {
        const char *arg = NULL;
        if (bpf_probe_read_user(&arg, sizeof(arg), &argv[i]) != 0 || !arg)
            break;
        if (off > CMDLINE_LEN - ARG_CHUNK)
            break;
        long n = bpf_probe_read_user_str(&out[off], ARG_CHUNK, arg);
        if (n <= 1)
            break;
        off += (u32)n;                       // n counts the trailing NUL
        if (off > 0 && off <= CMDLINE_LEN)
            out[(off - 1) & (CMDLINE_LEN - 1)] = ' ';
    }
    if (off > 0 && off <= CMDLINE_LEN)
        out[(off - 1) & (CMDLINE_LEN - 1)] = 0;   // drop trailing space
}

// Copy a short NUL-terminated tag; stops at the terminator so it never reads past the literal.
static __always_inline void set_tag(char *dst, const char *src) {
    #pragma unroll
    for (int i = 0; i < 32; i++) {
        dst[i] = src[i];
        if (!src[i]) break;
    }
}

static __always_inline void emit_blocked_alert(struct scratch_t *s, u64 lineage_id, u32 pid,
                                                u32 ns_pid, u64 ts, const char *tag, u32 tag_len) {
    struct alert_event_t *a = &s->alert;
    a->lineage_id = lineage_id;
    a->pid = pid;
    a->ns_pid = ns_pid;
    a->rule_id = 0xFFFFFFFF;
    a->action = ACTION_KILL;
    bpf_get_current_comm(&a->comm, sizeof(a->comm));
    bpf_probe_read_kernel_str(a->binary_path, MAX_PATH_LEN, s->entry.binary_path);
    set_tag(a->matched_pattern, tag);
    a->timestamp = ts;
    RB_OUT(alert_events, a, sizeof(*a), DROP_ALERT);
}

// Shared by execve and execveat: create the lineage entry, enforce blocks, emit the event.
static __always_inline int handle_exec(const char *filename, const char *const *argv, int fd_exec) {
    struct scratch_t *s = get_scratch();
    if (!s) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u64 uid_gid = bpf_get_current_uid_gid();
    u32 uid = (u32)uid_gid;
    u32 gid = uid_gid >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    u32 ns_pid = get_ns_pid(task);

    struct lineage_entry_t *parent_ptr = launcher_entry(pid, ppid);
    u64 parent_lineage_id = parent_ptr ? parent_ptr->lineage_id : 0;

    struct lineage_entry_t *e = &s->entry;
    long plen = bpf_probe_read_user_str(e->binary_path, MAX_PATH_LEN, filename);
    if (fd_exec && plen <= 1)
        __builtin_memcpy(e->binary_path, "<fd-exec>", 10);   // fexecve / memfd: no path available
    read_argv(e->cmdline, argv);

    u64 ts = bpf_ktime_get_ns();
    u64 lineage_id = lineage_hash(parent_lineage_id, e->binary_path, uid, ts);

    // Children of a blocked lineage die at exec. The child's own ID is blocked too,
    // so the block follows the whole descendant chain, not just one generation.
    if (is_lineage_blocked(parent_lineage_id)) {
        u8 one = 1;
        bpf_map_update_elem(&blocked_lineages, &lineage_id, &one, BPF_ANY);
        bpf_send_signal(SIGKILL);
        emit_blocked_alert(s, lineage_id, pid, ns_pid, ts, "BLOCKED_LINEAGE", 16);
        return 0;
    }

    u32 flags = 0;
    if (uid == 0) flags |= LINEAGE_FLAG_ROOT;
    if (is_trusted_binary(e->binary_path)) flags |= LINEAGE_FLAG_TRUSTED;
    if (parent_lineage_id == 0) flags |= LINEAGE_FLAG_ANONYMOUS;
    if (fd_exec && plen <= 1) flags |= LINEAGE_FLAG_SUSPICIOUS;

    e->lineage_id = lineage_id;
    e->parent_lineage_id = parent_lineage_id;
    e->pid = pid;
    e->ppid = ppid;
    e->uid = uid;
    e->gid = gid;
    e->ns_pid = ns_pid;
    e->exec_timestamp = ts;
    e->flags = flags;
    e->rule_matched = 0;
    bpf_get_current_comm(&e->comm, sizeof(e->comm));

    // Do not publish yet: the exec may still fail. sys_exit_execve commits it on success.
    // The pre-exec entry stays in lineage_map until then, so a failed exec changes nothing.
    bpf_map_update_elem(&pending_exec, &pid, e, BPF_ANY);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    return handle_exec((const char *)ctx->args[0], (const char *const *)ctx->args[1], 0);
}

SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx) {
    int dfd = (int)ctx->args[0];
    return handle_exec((const char *)ctx->args[1], (const char *const *)ctx->args[2],
                       dfd != AT_FDCWD);
}

// LSM: bprm_check_security — defense in depth, deny exec under a blocked lineage.
SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security_lsm, struct linux_binprm *bprm) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct lineage_entry_t *parent = launcher_entry(pid, ppid);
    if (!parent || !is_lineage_blocked(parent->lineage_id))
        return 0;

    struct scratch_t *s = get_scratch();
    if (!s) return -EPERM;
    bpf_probe_read_kernel_str(s->entry.binary_path, MAX_PATH_LEN, BPF_CORE_READ(bprm, filename));
    emit_blocked_alert(s, parent->lineage_id, pid, pid, bpf_ktime_get_ns(), "BLOCKED_LINEAGE_LSM", 20);
    return -EPERM;
}

SEC("lsm/task_kill")
int BPF_PROG(task_kill_lsm, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred) {
    if (sig == 0) return 0;   // kill(pid, 0) is only an existence probe
    u32 pid = BPF_CORE_READ(p, tgid);
    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;

    if (entry->flags & LINEAGE_FLAG_TRUSTED) {
        u32 sender_pid = bpf_get_current_pid_tgid() >> 32;
        if (sender_pid == pid || sender_pid == 1) return 0;   // self, or init/systemd stopping a service
        struct lineage_entry_t *sender = bpf_map_lookup_elem(&lineage_map, &sender_pid);
        if (!sender || !(sender->flags & LINEAGE_FLAG_TRUSTED))
            return -EPERM;
    }
    return 0;
}

static __always_inline void fill_file_path(char *dst, struct file *file) {
    const unsigned char *name = BPF_CORE_READ(file, f_path.dentry, d_name.name);
    bpf_probe_read_kernel_str(dst, MAX_PATH_LEN, name);
}

SEC("lsm/file_open")
int BPF_PROG(file_open_lsm, struct file *file) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;
    struct scratch_t *s = get_scratch();
    if (!s) return 0;

    struct file_event_t *f = &s->fe;
    f->pid = pid;
    f->ns_pid = entry->ns_pid;
    f->lineage_id = entry->lineage_id;
    f->flags = BPF_CORE_READ(file, f_flags);
    bpf_get_current_comm(&f->comm, sizeof(f->comm));
    fill_file_path(f->path, file);
    RB_OUT(file_events, f, sizeof(*f), DROP_FILE);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    const struct sockaddr *uservaddr = (const struct sockaddr *)ctx->args[1];
    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family);
    if (family != AF_INET) return 0;

    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;
    struct scratch_t *s = get_scratch();
    if (!s) return 0;

    const struct sockaddr_in *addr = (const struct sockaddr_in *)uservaddr;
    struct conn_event_t *c = &s->ce;
    c->pid = pid;
    c->ns_pid = entry->ns_pid;
    c->lineage_id = entry->lineage_id;
    bpf_get_current_comm(&c->comm, sizeof(c->comm));
    bpf_probe_read_user(&c->daddr, sizeof(c->daddr), &addr->sin_addr.s_addr);
    bpf_probe_read_user(&c->dport, sizeof(c->dport), &addr->sin_port);
    c->family = family;
    RB_OUT(conn_events, c, sizeof(*c), DROP_CONN);
    return 0;
}

SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;
    struct scratch_t *s = get_scratch();
    if (!s) return 0;

    struct file_event_t *f = &s->fe;
    f->pid = pid;
    f->ns_pid = entry->ns_pid;
    f->lineage_id = entry->lineage_id;
    f->flags = ctx->args[2];
    bpf_get_current_comm(&f->comm, sizeof(f->comm));
    bpf_probe_read_user_str(f->path, MAX_PATH_LEN, (const char *)ctx->args[1]);
    RB_OUT(file_events, f, sizeof(*f), DROP_FILE);
    return 0;
}

// Commit a pending exec only if it succeeded. Doing this at exit (not at sys_enter) means
// failed execve() calls (every PATH miss) no longer create phantom events or lineage entries,
// and comm is the NEW program's name instead of the pre-exec one.
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exit_execve(struct trace_event_raw_sys_exit *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct lineage_entry_t *e = bpf_map_lookup_elem(&pending_exec, &pid);
    if (!e) return 0;
    struct scratch_t *s = get_scratch();
    if (ctx->ret < 0 || !s) {
        bpf_map_delete_elem(&pending_exec, &pid);
        return 0;
    }

    bpf_get_current_comm(&e->comm, sizeof(e->comm));
    bpf_map_update_elem(&lineage_map, &pid, e, BPF_ANY);
    bpf_map_update_elem(&lineage_by_id, &e->lineage_id, e, BPF_ANY);

    struct proc_event_t *pe = &s->pe;
    pe->pid = e->pid;
    pe->ppid = e->ppid;
    pe->uid = e->uid;
    pe->ns_pid = e->ns_pid;
    pe->lineage_id = e->lineage_id;
    pe->parent_lineage_id = e->parent_lineage_id;
    bpf_probe_read_kernel_str(pe->comm, sizeof(pe->comm), e->comm);
    bpf_probe_read_kernel_str(pe->filename, MAX_PATH_LEN, e->binary_path);
    bpf_probe_read_kernel_str(pe->cmdline, CMDLINE_LEN, e->cmdline);
    RB_OUT(exec_events, pe, sizeof(*pe), DROP_EXEC);
    bpf_map_delete_elem(&pending_exec, &pid);
    return 0;
}

// A new process inherits its parent's lineage at fork. Without this, a process that forks and
// never execs breaks the chain, and a blocked lineage escapes with a double fork or by
// outliving its parent.
SEC("tp_btf/sched_process_fork")
int BPF_PROG(on_fork, struct task_struct *parent, struct task_struct *child) {
    u32 ctgid = BPF_CORE_READ(child, tgid);
    if (ctgid != BPF_CORE_READ(child, pid)) return 0;   // new thread, not a new process
    u32 ptgid = BPF_CORE_READ(parent, tgid);
    struct lineage_entry_t *pe = bpf_map_lookup_elem(&lineage_map, &ptgid);
    if (!pe) return 0;
    if (bpf_map_update_elem(&lineage_map, &ctgid, pe, BPF_ANY) != 0) return 0;
    struct lineage_entry_t *ce = bpf_map_lookup_elem(&lineage_map, &ctgid);
    if (ce) {
        ce->pid = ctgid;
        ce->ppid = ptgid;
    }
    return 0;
}

// Drop the entry when the last thread of a process exits, so a recycled PID cannot inherit a
// dead process's lineage or TRUSTED flag. lineage_by_id keeps the history.
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_exit(struct trace_event_raw_sched_process_template *ctx) {
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    if (BPF_CORE_READ(task, signal, live.counter) > 0) return 0;   // other threads still running
    u32 tgid = bpf_get_current_pid_tgid() >> 32;
    bpf_map_delete_elem(&lineage_map, &tgid);
    bpf_map_delete_elem(&pending_exec, &tgid);
    return 0;
}

// Counts sendmsg() calls per PID (byte counting would need msghdr parsing).
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    if (!bpf_map_lookup_elem(&lineage_map, &pid)) return 0;
    u64 *vol = bpf_map_lookup_elem(&data_volume, &pid);
    u64 n = (vol ? *vol : 0) + 1;
    bpf_map_update_elem(&data_volume, &pid, &n, BPF_ANY);
    return 0;
}

static __always_inline void emit_simple_alert(struct scratch_t *s, struct lineage_entry_t *entry,
                                               u32 pid, u32 rule_id, const char *tag) {
    struct alert_event_t *a = &s->alert;
    a->lineage_id = entry->lineage_id;
    a->pid = pid;
    a->ns_pid = entry->ns_pid;
    a->rule_id = rule_id;
    a->action = ACTION_ALERT;
    bpf_get_current_comm(&a->comm, sizeof(a->comm));
    a->binary_path[0] = 0;
    set_tag(a->matched_pattern, tag);
    a->timestamp = bpf_ktime_get_ns();
}

SEC("lsm/bpf")
int BPF_PROG(bpf_lsm, int cmd, union bpf_attr *attr, unsigned int size) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;
    if ((cmd != 5 && cmd != 2) || (entry->flags & LINEAGE_FLAG_TRUSTED)) return 0;   // PROG_LOAD / MAP_CREATE
    struct scratch_t *s = get_scratch();
    if (!s) return 0;
    emit_simple_alert(s, entry, pid, 0xFFFFFFFE, cmd == 5 ? "BPF_PROG_LOAD" : "BPF_MAP_CREATE");
    RB_OUT(alert_events, &s->alert, sizeof(s->alert), DROP_ALERT);
    return 0;
}

SEC("lsm/kernel_module_request")
int BPF_PROG(kernel_module_request_lsm, char *kmod_name) {
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;
    struct scratch_t *s = get_scratch();
    if (!s) return 0;
    emit_simple_alert(s, entry, pid, 0xFFFFFFFD, "KERNEL_MODULE_LOAD");
    bpf_probe_read_kernel_str(s->alert.binary_path, MAX_PATH_LEN, kmod_name);
    RB_OUT(alert_events, &s->alert, sizeof(s->alert), DROP_ALERT);
    return 0;
}

SEC("lsm/kernel_read_file")
int BPF_PROG(kernel_read_file_lsm, struct file *file, enum kernel_read_file_id id) {
    if (id != READING_MODULE) return 0;
    u32 pid = bpf_get_current_pid_tgid() >> 32;
    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;
    struct scratch_t *s = get_scratch();
    if (!s) return 0;
    emit_simple_alert(s, entry, pid, 0xFFFFFFFD, "MODULE_READ_FILE");
    fill_file_path(s->alert.binary_path, file);
    RB_OUT(alert_events, &s->alert, sizeof(s->alert), DROP_ALERT);
    return 0;
}

char _license[] SEC("license") = "GPL";

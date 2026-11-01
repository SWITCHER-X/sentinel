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
#define LINEAGE_ID_SEED 0x9e3779b97f4a7c15

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
    __uint(max_entries, 256 * 1024);
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

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 64 * 1024);
} icmp_events SEC(".maps");

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

// Check if binary is in trusted list
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

// Check if lineage is blocked
static __always_inline int is_lineage_blocked(u64 lineage_id) {
    return bpf_map_lookup_elem(&blocked_lineages, &lineage_id) != NULL;
}

// Get current namespace PID (CO-RE compatible)
static __always_inline u32 get_ns_pid(struct task_struct *task) {
    struct pid_namespace *ns = BPF_CORE_READ(task, nsproxy, pid_ns_for_children);
    if (!ns) return 0;
    return BPF_CORE_READ(task, tgid);
}

// LSM hook: task_kill - intercept kill signals to protect Sentinel processes
SEC("lsm/task_kill")
int BPF_PROG(task_kill_lsm, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred) {
    u32 pid = BPF_CORE_READ(p, tgid);
    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;

    if (entry->flags & LINEAGE_FLAG_TRUSTED) {
        u32 sender_pid = bpf_get_current_pid_tgid() >> 32;
        struct lineage_entry_t *sender = bpf_map_lookup_elem(&lineage_map, &sender_pid);
        if (!sender || !(sender->flags & LINEAGE_FLAG_TRUSTED)) {
            return -EPERM;
        }
    }
    return 0;
}

// LSM hook: file_open - monitor sensitive file access
SEC("lsm/file_open")
int BPF_PROG(file_open_lsm, struct file *file) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;

    struct file_event_t event = {};
    event.pid = pid;
    event.ns_pid = entry->ns_pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.lineage_id = entry->lineage_id;
    event.flags = BPF_CORE_READ(file, f_flags);

    // Read path from file->f_path (struct path, not pointer)
    struct path path = {};
    bpf_core_read(&path, sizeof(path), &file->f_path);
    struct dentry *dentry = BPF_CORE_READ(&path, dentry);
    bpf_core_read_user_str(&event.path, MAX_PATH_LEN, dentry->d_name.name);

    bpf_ringbuf_output(&file_events, &event, sizeof(event), 0);
    return 0;
}

// Tracepoint: sys_enter_execve - main lineage creation point
SEC("tracepoint/syscalls/sys_enter_execve")
int trace_execve(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();
    u32 gid = bpf_get_current_uid_gid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    u32 ns_pid = get_ns_pid(task);

    struct lineage_entry_t *parent_ptr = bpf_map_lookup_elem(&lineage_map, &ppid);
    u64 parent_lineage_id = 0;
    if (parent_ptr) {
        parent_lineage_id = parent_ptr->lineage_id;
    }

    // Read binary path from tracepoint args
    const char *filename = (const char *)ctx->args[0];
    char binary_path[MAX_PATH_LEN] = {};
    bpf_probe_read_user_str(&binary_path, MAX_PATH_LEN, filename);

    // Read argv for cmdline
    const char *const *argv = (const char *const *)ctx->args[1];
    const char *arg0;
    char cmdline[512] = {};
    if (bpf_probe_read_user(&arg0, sizeof(arg0), argv) == 0 && arg0) {
        bpf_probe_read_user_str(&cmdline, 512, arg0);
    }

    // Generate lineage ID
    u64 timestamp = bpf_ktime_get_ns();
    u64 lineage_id = lineage_hash(parent_lineage_id, binary_path, uid, timestamp);

    // Check if this lineage is blocked
    if (is_lineage_blocked(lineage_id) || (parent_ptr && is_lineage_blocked(parent_lineage_id))) {
        bpf_send_signal(SIGKILL);

        struct alert_event_t alert = {};
        alert.lineage_id = lineage_id;
        alert.pid = pid;
        alert.ns_pid = ns_pid;
        alert.rule_id = 0xFFFFFFFF;
        alert.action = ACTION_KILL;
        bpf_get_current_comm(&alert.comm, sizeof(alert.comm));
        bpf_probe_read_user_str(&alert.binary_path, MAX_PATH_LEN, filename);
        __builtin_memcpy(&alert.matched_pattern, "BLOCKED_LINEAGE", 16);
        alert.timestamp = timestamp;
        bpf_ringbuf_output(&alert_events, &alert, sizeof(alert), 0);

        return 0;
    }

    // Check trusted binary list
    u32 flags = 0;
    if (uid == 0) flags |= LINEAGE_FLAG_ROOT;
    if (is_trusted_binary(binary_path)) flags |= LINEAGE_FLAG_TRUSTED;
    if (parent_lineage_id == 0) flags |= LINEAGE_FLAG_ANONYMOUS;

    // Create lineage entry
    struct lineage_entry_t entry = {};
    entry.lineage_id = lineage_id;
    entry.parent_lineage_id = parent_lineage_id;
    entry.pid = pid;
    entry.ppid = ppid;
    entry.uid = uid;
    entry.gid = gid;
    entry.ns_pid = ns_pid;
    entry.exec_timestamp = timestamp;
    entry.flags = flags;
    bpf_get_current_comm(&entry.comm, sizeof(entry.comm));
    bpf_probe_read_user_str(&entry.binary_path, MAX_PATH_LEN, filename);
    bpf_probe_read_user_str(&entry.cmdline, 512, arg0);

    bpf_map_update_elem(&lineage_map, &pid, &entry, BPF_ANY);
    bpf_map_update_elem(&lineage_by_id, &lineage_id, &entry, BPF_ANY);

    // Emit exec event
    struct proc_event_t proc_event = {};
    proc_event.pid = pid;
    proc_event.ppid = ppid;
    proc_event.uid = uid;
    proc_event.lineage_id = lineage_id;
    proc_event.parent_lineage_id = parent_lineage_id;
    bpf_get_current_comm(&proc_event.comm, sizeof(proc_event.comm));
    bpf_probe_read_user_str(&proc_event.filename, MAX_PATH_LEN, filename);
    bpf_probe_read_user_str(&proc_event.cmdline, 512, arg0);

    bpf_ringbuf_output(&exec_events, &proc_event, sizeof(proc_event), 0);

    return 0;
}

// Tracepoint: sys_enter_connect - network with lineage
SEC("tracepoint/syscalls/sys_enter_connect")
int trace_connect(struct trace_event_raw_sys_enter *ctx) {
    const struct sockaddr *uservaddr = (const struct sockaddr *)ctx->args[1];
    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &uservaddr->sa_family);
    if (family != AF_INET) return 0;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;

    const struct sockaddr_in *addr = (const struct sockaddr_in *)uservaddr;
    struct conn_event_t event = {};
    event.pid = pid;
    event.ns_pid = entry->ns_pid;
    event.lineage_id = entry->lineage_id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user(&event.daddr, sizeof(event.daddr), &addr->sin_addr.s_addr);
    bpf_probe_read_user(&event.dport, sizeof(event.dport), &addr->sin_port);
    event.family = family;

    bpf_ringbuf_output(&conn_events, &event, sizeof(event), 0);
    return 0;
}

// Tracepoint: sys_enter_openat - file access with lineage
SEC("tracepoint/syscalls/sys_enter_openat")
int trace_openat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;

    struct file_event_t event = {};
    event.pid = pid;
    event.ns_pid = entry->ns_pid;
    event.lineage_id = entry->lineage_id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.flags = ctx->args[2];

    const char *filename = (const char *)ctx->args[1];
    bpf_probe_read_user_str(&event.path, MAX_PATH_LEN, filename);

    bpf_ringbuf_output(&file_events, &event, sizeof(event), 0);
    return 0;
}

// Tracepoint: sys_exit_execve - cleanup on exec failure
SEC("tracepoint/syscalls/sys_exit_execve")
int trace_exit_execve(struct trace_event_raw_sys_exit *ctx) {
    long ret = ctx->ret;
    if (ret < 0) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        bpf_map_delete_elem(&lineage_map, &pid);
    }
    return 0;
}

// Sched_process_exit - cleanup lineage on process exit
SEC("tracepoint/sched/sched_process_exit")
int trace_sched_exit(struct trace_event_raw_sched_process_template *ctx) {
    u32 pid = ctx->pid;
    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (entry) {
        entry->flags |= LINEAGE_FLAG_KILLED;
        bpf_map_update_elem(&lineage_map, &pid, entry, BPF_ANY);
    }
    return 0;
}

// LSM hook: bprm_check_security - enforce blocked lineage at execve (defense-in-depth)
SEC("lsm/bprm_check_security")
int BPF_PROG(bprm_check_security_lsm, struct linux_binprm *bprm) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);

    struct lineage_entry_t *parent_ptr = bpf_map_lookup_elem(&lineage_map, &ppid);
    u64 parent_lineage_id = 0;
    if (parent_ptr) {
        parent_lineage_id = parent_ptr->lineage_id;
    }

    // Read binary path
    char binary_path[MAX_PATH_LEN] = {};
    bpf_probe_read_user_str(&binary_path, MAX_PATH_LEN, bprm->filename);

    // Generate lineage ID (same logic as tracepoint)
    u64 timestamp = bpf_ktime_get_ns();
    u64 lineage_id = lineage_hash(parent_lineage_id, binary_path, uid, timestamp);

    // Check if this lineage is blocked
    if (is_lineage_blocked(lineage_id) || (parent_ptr && is_lineage_blocked(parent_lineage_id))) {
        struct alert_event_t alert = {};
        alert.lineage_id = lineage_id;
        alert.pid = pid;
        alert.ns_pid = BPF_CORE_READ(task, tgid);
        alert.rule_id = 0xFFFFFFFF;
        alert.action = ACTION_KILL;
        bpf_get_current_comm(&alert.comm, sizeof(alert.comm));
        bpf_probe_read_user_str(&alert.binary_path, MAX_PATH_LEN, bprm->filename);
        __builtin_memcpy(&alert.matched_pattern, "BLOCKED_LINEAGE_LSM", 19);
        alert.timestamp = timestamp;
        bpf_ringbuf_output(&alert_events, &alert, sizeof(alert), 0);

        return -EPERM;
    }

    return 0;
}

// Tracepoint: sys_enter_execveat - catches fexecve, memfd_create execve
SEC("tracepoint/syscalls/sys_enter_execveat")
int trace_execveat(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();
    u32 gid = bpf_get_current_uid_gid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = BPF_CORE_READ(task, real_parent, tgid);
    u32 ns_pid = get_ns_pid(task);

    struct lineage_entry_t *parent_ptr = bpf_map_lookup_elem(&lineage_map, &ppid);
    u64 parent_lineage_id = 0;
    if (parent_ptr) {
        parent_lineage_id = parent_ptr->lineage_id;
    }

    int dfd = ctx->args[0];
    const char *filename = (const char *)ctx->args[1];
    char binary_path[MAX_PATH_LEN] = {};
    char cmdline[512] = {};

    if (dfd == AT_FDCWD) {
        bpf_probe_read_user_str(&binary_path, MAX_PATH_LEN, filename);
    } else {
        char fd_path[64];
        bpf_probe_read_user_str(&fd_path, 64, filename);
        bpf_probe_read_user_str(&binary_path, MAX_PATH_LEN, fd_path);
    }

    const char *const *argv = (const char *const *)ctx->args[2];
    const char *arg0;
    if (bpf_probe_read_user(&arg0, sizeof(arg0), argv) == 0 && arg0) {
        bpf_probe_read_user_str(&cmdline, 512, arg0);
    }

    u64 timestamp = bpf_ktime_get_ns();
    u64 lineage_id = lineage_hash(parent_lineage_id, binary_path, uid, timestamp);

    if (is_lineage_blocked(lineage_id) || (parent_ptr && is_lineage_blocked(parent_lineage_id))) {
        bpf_send_signal(SIGKILL);

        struct alert_event_t alert = {};
        alert.lineage_id = lineage_id;
        alert.pid = pid;
        alert.ns_pid = ns_pid;
        alert.rule_id = 0xFFFFFFFF;
        alert.action = ACTION_KILL;
        bpf_get_current_comm(&alert.comm, sizeof(alert.comm));
        bpf_probe_read_user_str(&alert.binary_path, MAX_PATH_LEN, filename);
        __builtin_memcpy(&alert.matched_pattern, "BLOCKED_LINEAGE_EXECVEAT", 24);
        alert.timestamp = timestamp;
        bpf_ringbuf_output(&alert_events, &alert, sizeof(alert), 0);

        return 0;
    }

    u32 flags = 0;
    if (uid == 0) flags |= LINEAGE_FLAG_ROOT;
    if (is_trusted_binary(binary_path)) flags |= LINEAGE_FLAG_TRUSTED;
    if (parent_lineage_id == 0) flags |= LINEAGE_FLAG_ANONYMOUS;

    struct lineage_entry_t entry = {};
    entry.lineage_id = lineage_id;
    entry.parent_lineage_id = parent_lineage_id;
    entry.pid = pid;
    entry.ppid = ppid;
    entry.uid = uid;
    entry.gid = gid;
    entry.ns_pid = ns_pid;
    entry.exec_timestamp = timestamp;
    entry.flags = flags;
    bpf_get_current_comm(&entry.comm, sizeof(entry.comm));
    bpf_probe_read_user_str(&entry.binary_path, MAX_PATH_LEN, filename);
    bpf_probe_read_user_str(&entry.cmdline, 512, arg0);

    bpf_map_update_elem(&lineage_map, &pid, &entry, BPF_ANY);
    bpf_map_update_elem(&lineage_by_id, &lineage_id, &entry, BPF_ANY);

    struct proc_event_t proc_event = {};
    proc_event.pid = pid;
    proc_event.ppid = ppid;
    proc_event.uid = uid;
    proc_event.lineage_id = lineage_id;
    proc_event.parent_lineage_id = parent_lineage_id;
    bpf_get_current_comm(&proc_event.comm, sizeof(proc_event.comm));
    bpf_probe_read_user_str(&proc_event.filename, MAX_PATH_LEN, filename);
    bpf_probe_read_user_str(&proc_event.cmdline, 512, arg0);

    bpf_ringbuf_output(&exec_events, &proc_event, sizeof(proc_event), 0);

    return 0;
}

// Tracepoint: sys_enter_sendmsg - catch ICMP raw sockets (covert channels)
SEC("tracepoint/syscalls/sys_enter_sendmsg")
int trace_sendmsg(struct trace_event_raw_sys_enter *ctx) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;

    // Note: msghdr structure varies by kernel version; skip iov tracking for compatibility
    // Just track data volume via sendmsg entry
    u64 *vol = bpf_map_lookup_elem(&data_volume, &pid);
    u64 new_vol = (vol ? *vol : 0) + 1; // Count sendmsg calls
    bpf_map_update_elem(&data_volume, &pid, &new_vol, BPF_ANY);

    return 0;
}

// LSM hook: bpf - monitor eBPF program loads (prevent malicious BPF)
SEC("lsm/bpf")
int BPF_PROG(bpf_lsm, int cmd, union bpf_attr *attr, unsigned int size) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;

    if (cmd == 5 || cmd == 2) { // BPF_PROG_LOAD, BPF_MAP_CREATE
        if (!(entry->flags & LINEAGE_FLAG_TRUSTED)) {
            struct alert_event_t alert = {};
            alert.lineage_id = entry->lineage_id;
            alert.pid = pid;
            alert.ns_pid = entry->ns_pid;
            alert.rule_id = 0xFFFFFFFE;
            alert.action = ACTION_ALERT;
            bpf_get_current_comm(&alert.comm, sizeof(alert.comm));
            alert.timestamp = bpf_ktime_get_ns();
            char msg[32];
            __builtin_memcpy(&msg, cmd == 5 ? "BPF_PROG_LOAD" : "BPF_MAP_CREATE", 16);
            __builtin_memcpy(&alert.matched_pattern, msg, 16);
            bpf_ringbuf_output(&alert_events, &alert, sizeof(alert), 0);
        }
    }

    return 0;
}

// LSM hook: kernel_module_request - monitor kernel module loads
SEC("lsm/kernel_module_request")
int BPF_PROG(kernel_module_request_lsm, char *kmod_name) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
    if (!entry) return 0;

    struct alert_event_t alert = {};
    alert.lineage_id = entry->lineage_id;
    alert.pid = pid;
    alert.ns_pid = entry->ns_pid;
    alert.rule_id = 0xFFFFFFFD;
    alert.action = ACTION_ALERT;
    bpf_get_current_comm(&alert.comm, sizeof(alert.comm));
    bpf_probe_read_user_str(&alert.binary_path, MAX_PATH_LEN, kmod_name);
    __builtin_memcpy(&alert.matched_pattern, "KERNEL_MODULE_LOAD", 18);
    alert.timestamp = bpf_ktime_get_ns();
    bpf_ringbuf_output(&alert_events, &alert, sizeof(alert), 0);

    return 0;
}

// LSM hook: init_module - finit_module syscall
SEC("lsm/kernel_read_file")
int BPF_PROG(kernel_read_file_lsm, struct file *file, enum kernel_read_file_id id) {
    if (id == 6) { // READING_MODULE
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;

        struct lineage_entry_t *entry = bpf_map_lookup_elem(&lineage_map, &pid);
        if (!entry) return 0;

        struct alert_event_t alert = {};
        alert.lineage_id = entry->lineage_id;
        alert.pid = pid;
        alert.ns_pid = entry->ns_pid;
        alert.rule_id = 0xFFFFFFFD;
        alert.action = ACTION_ALERT;
        bpf_get_current_comm(&alert.comm, sizeof(alert.comm));

        // Read path from file->f_path
        struct path path = {};
        bpf_core_read(&path, sizeof(path), &file->f_path);
        struct dentry *dentry = BPF_CORE_READ(&path, dentry);
        bpf_probe_read_user_str(&alert.binary_path, MAX_PATH_LEN, dentry->d_name.name);
        __builtin_memcpy(&alert.matched_pattern, "MODULE_READ_FILE", 16);
        alert.timestamp = bpf_ktime_get_ns();
        bpf_ringbuf_output(&alert_events, &alert, sizeof(alert), 0);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";
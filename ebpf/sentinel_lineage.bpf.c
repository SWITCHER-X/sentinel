/*
 * Sentinel Lineage eBPF Module
 * Signature-based process lineage tracking with instant kill-switch
 * 
 * Design:
 * - Each process gets a 64-bit lineage_id at execve
 * - lineage_id = hash(parent_lineage_id, binary_path, uid, timestamp)
 * - Stored in BPF LRU hash map (pid -> lineage_entry)
 * - Children inherit parent's lineage_id
 * - Rules match against lineage_id + binary + cmdline
 * - LSM hooks for root-resistant kill (bpf_lsm_task_kill)
 */

#include <uapi/linux/ptrace.h>
#include <linux/sched.h>
#include <uapi/linux/in.h>
#include <linux/fs.h>
#include <linux/nsproxy.h>
#include <linux/pid_namespace.h>

#define MAX_LINEAGE_ENTRIES 65536
#define MAX_PATH_LEN 256
#define LINEAGE_ID_SEED 0x9e3779b97f4a7c15

struct lineage_entry_t {
    u64 lineage_id;           // Unique signature for this process tree
    u64 parent_lineage_id;    // Parent's lineage_id (0 for init)
    u32 pid;
    u32 ppid;
    u32 uid;
    u32 gid;
    u32 ns_pid;               // PID in init namespace
    char comm[16];
    char binary_path[MAX_PATH_LEN];
    char cmdline[512];
    u64 exec_timestamp;
    u32 flags;                // LINEAGE_FLAG_*
    u32 rule_matched;         // Rule ID that matched (0 = none)
};

struct conn_event_t {
    u32 pid;
    u32 ns_pid;
    char comm[16];
    u32 daddr;
    u16 dport;
    u16 family;
    u64 lineage_id;           // Lineage context for network events
};

struct file_event_t {
    u32 pid;
    u32 ns_pid;
    char comm[16];
    char path[MAX_PATH_LEN];
    int flags;                // O_RDONLY, O_WRONLY, etc.
    u64 lineage_id;
};

struct alert_event_t {
    u64 lineage_id;
    u32 pid;
    u32 ns_pid;
    u32 rule_id;
    u32 action;               // KILL, BLOCK, ALERT
    char comm[16];
    char binary_path[MAX_PATH_LEN];
    char matched_pattern[128];
    u64 timestamp;
};

enum lineage_flags {
    LINEAGE_FLAG_ROOT       = 1 << 0,  // Running as root
    LINEAGE_FLAG_SUID       = 1 << 1,  // SUID binary
    LINEAGE_FLAG_CONTAINER  = 1 << 2,  // In container namespace
    LINEAGE_FLAG_SUSPICIOUS = 1 << 3,  // Matched suspicious pattern
    LINEAGE_FLAG_KILLED     = 1 << 4,  // Already killed
    LINEAGE_FLAG_TRUSTED    = 1 << 5,  // Trusted lineage (signed binary)
    LINEAGE_FLAG_ANONYMOUS  = 1 << 6,  // No parent (init, kernel thread)
};

enum rule_action {
    ACTION_LOG      = 0,
    ACTION_ALERT    = 1,
    ACTION_KILL     = 2,
    ACTION_BLOCK    = 3,
    ACTION_QUARANTINE = 4,
};

// BPF Maps
BPF_LRU_HASH(lineage_map, u32, struct lineage_entry_t, MAX_LINEAGE_ENTRIES);
BPF_LRU_HASH(lineage_by_id, u64, struct lineage_entry_t, MAX_LINEAGE_ENTRIES);
BPF_HASH(rule_map, u32, struct rule_entry_t, 1024);
BPF_HASH(trusted_binaries, u64, u8, 4096);  // hash(binary_path) -> trusted
BPF_HASH(blocked_lineages, u64, u8, 4096);  // lineage_id -> blocked

// New maps for exfiltration detection
BPF_HASH(dns_queries, u32, u64, 10240);     // pid -> query count (rate limiting)
BPF_HASH(data_volume, u32, u64, 10240);     // pid -> bytes sent

// Event structs for ringbuf
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

// ICMP event for covert channel detection
struct icmp_event_t {
    u32 pid;
    u32 ns_pid;
    char comm[16];
    u32 type;           // ICMP type (8=echo request, 0=echo reply)
    u32 code;
    u32 daddr;          // Destination IP
    u16 id;             // ICMP identifier
    u16 seq;            // ICMP sequence
    u32 data_len;       // Payload length
    u64 lineage_id;
};

BPF_RINGBUF_OUTPUT(exec_events, 256);
BPF_RINGBUF_OUTPUT(conn_events, 256);
BPF_RINGBUF_OUTPUT(file_events, 256);
BPF_RINGBUF_OUTPUT(alert_events, 64);
BPF_RINGBUF_OUTPUT(icmp_events, 64);

// Rule entry matching userspace structure
struct rule_entry_t {
    u32 id;
    u32 action;
    u32 severity;  // 0=info, 1=low, 2=medium, 3=high, 4=critical
    char pattern[128];
    char binary_pattern[256];
    u64 lineage_id;       // Match specific lineage (0 = any)
    u32 flags;            // RULE_FLAG_*
    u32 uid_min;          // Min UID to match (0 = any)
    u32 uid_max;          // Max UID to match (0 = any)
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
    return trusted_binaries.lookup(&key) != NULL;
}

// Check if lineage is blocked
static __always_inline int is_lineage_blocked(u64 lineage_id) {
    return blocked_lineages.lookup(&lineage_id) != NULL;
}

// Get current namespace PID
static __always_inline u32 get_ns_pid(struct task_struct *task) {
    struct pid_namespace *ns = task->nsproxy->pid_ns_for_children;
    if (!ns) return 0;
    // This is simplified - in reality need pid_vnr
    return task->tgid;
}

// LSM hook: task_kill - intercept kill signals to protect Sentinel processes
LSM_PROBE(task_kill, struct task_struct *p, struct kernel_siginfo *info, int sig, const struct cred *cred) {
    u32 pid = p->tgid;
    struct lineage_entry_t *entry = lineage_map.lookup(&pid);
    if (!entry) return 0;
    
    // Protect Sentinel's own lineage from being killed
    if (entry->flags & LINEAGE_FLAG_TRUSTED) {
        // Allow only if sender is also trusted Sentinel process
        u32 sender_pid = bpf_get_current_pid_tgid() >> 32;
        struct lineage_entry_t *sender = lineage_map.lookup(&sender_pid);
        if (!sender || !(sender->flags & LINEAGE_FLAG_TRUSTED)) {
            return -EPERM;  // Block kill
        }
    }
    return 0;
}

// LSM hook: file_open - monitor sensitive file access
LSM_PROBE(file_open, struct file *file) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    struct lineage_entry_t *entry = lineage_map.lookup(&pid);
    if (!entry) return 0;
    
    // Check for sensitive file access
    struct file_event_t event = {};
    event.pid = pid;
    event.ns_pid = entry->ns_pid;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.lineage_id = entry->lineage_id;
    event.flags = file->f_flags;
    
    struct path *path = &file->f_path;
    struct dentry *dentry = path->dentry;
    bpf_probe_read_user_str(&event.path, MAX_PATH_LEN, (void *)dentry->d_name.name);
    
    // Check rules for file access
    // ... rule matching logic ...
    
    file_events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

// Tracepoint: sys_enter_execve - main lineage creation point
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();
    u32 gid = bpf_get_current_uid_gid() >> 32;
    
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;
    u32 ns_pid = get_ns_pid(task);
    
    struct lineage_entry_t parent_entry = {};
    struct lineage_entry_t *parent_ptr = lineage_map.lookup(&ppid);
    u64 parent_lineage_id = 0;
    
    if (parent_ptr) {
        parent_lineage_id = parent_ptr->lineage_id;
        parent_entry = *parent_ptr;
    } else {
        // No parent in map - could be init or first process we see
        parent_lineage_id = 0;
    }
    
    // Read binary path and cmdline
    char binary_path[MAX_PATH_LEN] = {};
    char cmdline[512] = {};
    bpf_probe_read_user_str(&binary_path, MAX_PATH_LEN, (void *)args->filename);
    
    // Read argv for cmdline (simplified)
    const char __user *const __user *argv = (const char __user *const __user *)args->argv;
    const char __user *arg0;
    if (bpf_probe_read_user(&arg0, sizeof(arg0), argv) == 0 && arg0) {
        bpf_probe_read_user_str(&cmdline, 512, (void *)arg0);
    }
    
    // Generate lineage ID
    u64 timestamp = bpf_ktime_get_ns();
    u64 lineage_id = lineage_hash(parent_lineage_id, binary_path, uid, timestamp);
    
    // Check if this lineage is blocked
        // Check if this lineage is blocked
    if (is_lineage_blocked(lineage_id) || (parent_ptr && is_lineage_blocked(parent_lineage_id))) {
        // Lineage is blocked - KILL IMMEDIATELY FROM KERNEL
        bpf_send_signal(SIGKILL);

        struct alert_event_t alert = {};
        alert.lineage_id = lineage_id;
        alert.pid = pid;
        alert.ns_pid = ns_pid;
        alert.rule_id = 0xFFFFFFFF;  // BLOCKED_LINEAGE
        alert.action = ACTION_KILL;
        bpf_get_current_comm(&alert.comm, sizeof(alert.comm));
        bpf_probe_read_user_str(&alert.binary_path, MAX_PATH_LEN, (void *)args->filename);
        __builtin_memcpy(&alert.matched_pattern, "BLOCKED_LINEAGE", 16);
        alert.timestamp = timestamp;
        alert_events.ringbuf_output(&alert, sizeof(alert), 0);

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
    bpf_probe_read_user_str(&entry.binary_path, MAX_PATH_LEN, (void *)args->filename);
    bpf_probe_read_user_str(&entry.cmdline, 512, (void *)arg0);
    
    // Store in maps
    lineage_map.update(&pid, &entry);
    lineage_by_id.update(&lineage_id, &entry);
    
    // Emit exec event with lineage
        struct proc_event_t proc_event = {};
        proc_event.pid = pid;
        proc_event.ppid = ppid;
        proc_event.uid = uid;
        proc_event.lineage_id = lineage_id;
        proc_event.parent_lineage_id = parent_lineage_id;
        bpf_get_current_comm(&proc_event.comm, sizeof(proc_event.comm));
        bpf_probe_read_user_str(&proc_event.filename, MAX_PATH_LEN, (void *)args->filename);

        // Read argv for cmdline
        const char __user *const __user *argv = (const char __user *const __user *)args->argv;
        const char __user *arg0;
        if (bpf_probe_read_user(&arg0, sizeof(arg0), argv) == 0 && arg0) {
            bpf_probe_read_user_str(&proc_event.cmdline, 512, (void *)arg0);
        }

        exec_events.ringbuf_output(&proc_event, sizeof(proc_event), 0);
    
    return 0;
}

// Tracepoint: sys_enter_connect - network with lineage
TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct sockaddr_in *addr = (struct sockaddr_in *)args->uservaddr;
    u16 family = 0;
    bpf_probe_read_user(&family, sizeof(family), &addr->sin_family);
    if (family != AF_INET) return 0;
    
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    struct lineage_entry_t *entry = lineage_map.lookup(&pid);
    if (!entry) return 0;
    
    struct conn_event_t event = {};
    event.pid = pid;
    event.ns_pid = entry->ns_pid;
    event.lineage_id = entry->lineage_id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user(&event.daddr, sizeof(event.daddr), &addr->sin_addr.s_addr);
    bpf_probe_read_user(&event.dport, sizeof(event.dport), &addr->sin_port);
    event.family = family;
    
    conn_events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

// Tracepoint: sys_enter_openat - file access with lineage
TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    
    struct lineage_entry_t *entry = lineage_map.lookup(&pid);
    if (!entry) return 0;
    
    struct file_event_t event = {};
    event.pid = pid;
    event.ns_pid = entry->ns_pid;
    event.lineage_id = entry->lineage_id;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    event.flags = args->flags;
    bpf_probe_read_user_str(&event.path, MAX_PATH_LEN, (void *)args->filename);
    
    file_events.ringbuf_output(&event, sizeof(event), 0);
    return 0;
}

// Tracepoint: sys_exit_execve - cleanup on exec failure
TRACEPOINT_PROBE(syscalls, sys_exit_execve) {
    long ret = args->ret;
    if (ret < 0) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;
        lineage_map.delete(&pid);
    }
    return 0;
}

// Sched_process_exit - cleanup lineage on process exit
TRACEPOINT_PROBE(sched, sched_process_exit) {
    u32 pid = args->pid;
    struct lineage_entry_t *entry = lineage_map.lookup(&pid);
    if (entry) {
        // Don't delete immediately - keep for lineage tracking
        // Mark as exited
        entry->flags |= LINEAGE_FLAG_KILLED;
        lineage_map.update(&pid, entry);
    }
    return 0;
}

// LSM hook: bprm_check_security - enforce blocked lineage at execve (defense-in-depth)
LSM_PROBE(bprm_check_security, struct linux_binprm *bprm) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;

    struct lineage_entry_t *parent_ptr = lineage_map.lookup(&ppid);
    u64 parent_lineage_id = 0;
    if (parent_ptr) {
        parent_lineage_id = parent_ptr->lineage_id;
    }

    // Read binary path
    char binary_path[MAX_PATH_LEN] = {};
    bpf_probe_read_user_str(&binary_path, MAX_PATH_LEN, (void *)bprm->filename);

    // Generate lineage ID (same logic as tracepoint)
    u64 timestamp = bpf_ktime_get_ns();
    u64 lineage_id = lineage_hash(parent_lineage_id, binary_path, uid, timestamp);

    // Check if this lineage is blocked
    if (is_lineage_blocked(lineage_id) || (parent_ptr && is_lineage_blocked(parent_lineage_id))) {
        // Block execve at LSM level
        struct alert_event_t alert = {};
        alert.lineage_id = lineage_id;
        alert.pid = pid;
        alert.ns_pid = task->tgid;
        alert.rule_id = 0xFFFFFFFF;  // BLOCKED_LINEAGE
        alert.action = ACTION_KILL;
        bpf_get_current_comm(&alert.comm, sizeof(alert.comm));
        bpf_probe_read_user_str(&alert.binary_path, MAX_PATH_LEN, (void *)bprm->filename);
        __builtin_memcpy(&alert.matched_pattern, "BLOCKED_LINEAGE_LSM", 19);
        alert.timestamp = timestamp;
        alert_events.ringbuf_output(&alert, sizeof(alert), 0);

        return -EPERM;  // Deny execve
    }

    return 0;
}

// Tracepoint: sys_enter_execveat - catches fexecve, memfd_create execve
TRACEPOINT_PROBE(syscalls, sys_enter_execveat) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();
    u32 gid = bpf_get_current_uid_gid() >> 32;

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    u32 ppid = task->real_parent->tgid;
    u32 ns_pid = get_ns_pid(task);

    struct lineage_entry_t *parent_ptr = lineage_map.lookup(&ppid);
    u64 parent_lineage_id = 0;
    if (parent_ptr) {
        parent_lineage_id = parent_ptr->lineage_id;
    }

    // Read binary path (from fd or filename)
    char binary_path[MAX_PATH_LEN] = {};
    char cmdline[512] = {};

    int dfd = args->dfd;
    const char __user *filename = (const char __user *)args->filename;

    if (dfd == AT_FDCWD) {
        bpf_probe_read_user_str(&binary_path, MAX_PATH_LEN, (void *)filename);
    } else {
        // execveat with fd - read from /proc/self/fd/
        char fd_path[64];
        bpf_probe_read_user_str(&fd_path, 64, (void *)filename);
        bpf_probe_read_user_str(&binary_path, MAX_PATH_LEN, (void *)fd_path);
    }

    // Read argv for cmdline
    const char __user *const __user *argv = (const char __user *const __user *)args->argv;
    const char __user *arg0;
    if (bpf_probe_read_user(&arg0, sizeof(arg0), argv) == 0 && arg0) {
        bpf_probe_read_user_str(&cmdline, 512, (void *)arg0);
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
        bpf_probe_read_user_str(&alert.binary_path, MAX_PATH_LEN, (void *)filename);
        __builtin_memcpy(&alert.matched_pattern, "BLOCKED_LINEAGE_EXECVEAT", 24);
        alert.timestamp = timestamp;
        alert_events.ringbuf_output(&alert, sizeof(alert), 0);

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
    bpf_probe_read_user_str(&entry.binary_path, MAX_PATH_LEN, (void *)filename);
    bpf_probe_read_user_str(&entry.cmdline, 512, (void *)arg0);

    // Store in maps
    lineage_map.update(&pid, &entry);
    lineage_by_id.update(&lineage_id, &entry);

    // Emit exec event
    struct proc_event_t proc_event = {};
    proc_event.pid = pid;
    proc_event.ppid = ppid;
    proc_event.uid = uid;
    proc_event.lineage_id = lineage_id;
    proc_event.parent_lineage_id = parent_lineage_id;
    bpf_get_current_comm(&proc_event.comm, sizeof(proc_event.comm));
    bpf_probe_read_user_str(&proc_event.filename, MAX_PATH_LEN, (void *)filename);

    const char __user *const __user *argv2 = (const char __user *const __user *)args->argv;
    const char __user *arg0_2;
    if (bpf_probe_read_user(&arg0_2, sizeof(arg0_2), argv2) == 0 && arg0_2) {
        bpf_probe_read_user_str(&proc_event.cmdline, 512, (void *)arg0_2);
    }

    exec_events.ringbuf_output(&proc_event, sizeof(proc_event), 0);

    return 0;
}

// Tracepoint: sys_enter_sendmsg - catch ICMP raw sockets (covert channels)
TRACEPOINT_PROBE(syscalls, sys_enter_sendmsg) {
    int fd = args->fd;
    struct msghdr __user *msg = (struct msghdr __user *)args->msg;
    int flags = args->flags;

    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct lineage_entry_t *entry = lineage_map.lookup(&pid);
    if (!entry) return 0;

    // Check if this is a raw socket (likely ICMP)
    // We can't easily check socket type here, but we can track sendmsg volume
    // For ICMP detection, we'd need socket lookup which is complex in BPF
    // Instead, we'll track data volume per PID for anomaly detection

    struct iovec __user *iov = msg->msg_iov;
    unsigned long iovlen = msg->msg_iovlen;

    u64 total_len = 0;
    #pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i >= iovlen) break;
        struct iovec iov_entry;
        if (bpf_probe_read_user(&iov_entry, sizeof(iov_entry), &iov[i]) != 0) break;
        total_len += iov_entry.iov_len;
    }

    if (total_len > 0) {
        u64 *vol = data_volume.lookup(&pid);
        u64 new_vol = (vol ? *vol : 0) + total_len;
        data_volume.update(&pid, &new_vol);
    }

    return 0;
}

// LSM hook: bpf - monitor eBPF program loads (prevent malicious BPF)
LSM_PROBE(bpf, int cmd, union bpf_attr *attr, unsigned int size) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;
    u32 uid = bpf_get_current_uid_gid();

    struct lineage_entry_t *entry = lineage_map.lookup(&pid);
    if (!entry) return 0;

    // Alert on BPF_PROG_LOAD, BPF_MAP_CREATE by untrusted processes
    if (cmd == 5 /* BPF_PROG_LOAD */ || cmd == 2 /* BPF_MAP_CREATE */) {
        if (!(entry->flags & LINEAGE_FLAG_TRUSTED)) {
            struct alert_event_t alert = {};
            alert.lineage_id = entry->lineage_id;
            alert.pid = pid;
            alert.ns_pid = entry->ns_pid;
            alert.rule_id = 0xFFFFFFFE;  // BPF_LOAD
            alert.action = ACTION_ALERT;
            bpf_get_current_comm(&alert.comm, sizeof(alert.comm));
            alert.timestamp = bpf_ktime_get_ns();
            char msg[32];
            __builtin_memcpy(&msg, cmd == 5 ? "BPF_PROG_LOAD" : "BPF_MAP_CREATE", 16);
            __builtin_memcpy(&alert.matched_pattern, msg, 16);
            alert_events.ringbuf_output(&alert, sizeof(alert), 0);
        }
    }

    return 0;
}

// LSM hook: kernel_module_request - monitor kernel module loads
LSM_PROBE(kernel_module_request, char *kmod_name) {
    u64 pid_tgid = bpf_get_current_pid_tgid();
    u32 pid = pid_tgid >> 32;

    struct lineage_entry_t *entry = lineage_map.lookup(&pid);
    if (!entry) return 0;

    struct alert_event_t alert = {};
    alert.lineage_id = entry->lineage_id;
    alert.pid = pid;
    alert.ns_pid = entry->ns_pid;
    alert.rule_id = 0xFFFFFFFD;  // KERNEL_MODULE
    alert.action = ACTION_ALERT;
    bpf_get_current_comm(&alert.comm, sizeof(alert.comm));
    bpf_probe_read_user_str(&alert.binary_path, MAX_PATH_LEN, (void *)kmod_name);
    __builtin_memcpy(&alert.matched_pattern, "KERNEL_MODULE_LOAD", 18);
    alert.timestamp = bpf_ktime_get_ns();
    alert_events.ringbuf_output(&alert, sizeof(alert), 0);

    return 0;
}

// LSM hook: init_module - finit_module syscall
LSM_PROBE(kernel_read_file, struct file *file, enum kernel_read_file_id id) {
    if (id == 6 /* READING_MODULE */) {
        u64 pid_tgid = bpf_get_current_pid_tgid();
        u32 pid = pid_tgid >> 32;

        struct lineage_entry_t *entry = lineage_map.lookup(&pid);
        if (!entry) return 0;

        struct alert_event_t alert = {};
        alert.lineage_id = entry->lineage_id;
        alert.pid = pid;
        alert.ns_pid = entry->ns_pid;
        alert.rule_id = 0xFFFFFFFD;  // KERNEL_MODULE
        alert.action = ACTION_ALERT;
        bpf_get_current_comm(&alert.comm, sizeof(alert.comm));
        struct path *path = &file->f_path;
        struct dentry *dentry = path->dentry;
        bpf_probe_read_user_str(&alert.binary_path, MAX_PATH_LEN, (void *)dentry->d_name.name);
        __builtin_memcpy(&alert.matched_pattern, "MODULE_READ_FILE", 16);
        alert.timestamp = bpf_ktime_get_ns();
        alert_events.ringbuf_output(&alert, sizeof(alert), 0);
    }
    return 0;
}

char _license[] SEC("license") = "GPL";

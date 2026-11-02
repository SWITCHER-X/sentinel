/*
 * sentinel-loader — libbpf loader for Project SENTINEL CO-RE object.
 *
 * Usage: sentinel-loader <path/to/sentinel_lineage_core.o>
 *
 * Protocol:
 *   stdout: JSON lines, one per event (exec, conn, file, alert, info, error)
 *   stdin:  commands (block, unblock, trust, untrust, quit)
 *
 * Event JSON shapes (matching agent/sentinel_lineage_agent.py expectations):
 *   {"t":"exec","pid":1,"ppid":1,"uid":0,"ns_pid":1,"lineage_id":"0x00000000000000AB","parent_lineage_id":"0x0000000000000000","comm":"ls","filename":"/bin/ls","cmdline":"/bin/ls -la /tmp"}
 *   {"t":"conn","pid":1,"ns_pid":1,"lineage_id":"0x...","comm":"curl","daddr":16777343,"dport":20480,"family":2}
 *   {"t":"file","pid":1,"ns_pid":1,"lineage_id":"0x...","comm":"cat","path":"/etc/passwd","flags":0}
 *   {"t":"alert","lineage_id":"0x...","pid":1,"ns_pid":1,"rule_id":4294967295,"action":2,"comm":"true","binary_path":"/bin/true","matched_pattern":"BLOCKED_LINEAGE","timestamp":123456789}
 *
 * Commands (one per line):
 *   block 0x<hex>    -> blocked_lineages[id] = 1
 *   unblock 0x<hex>  -> delete from blocked_lineages
 *   trust <16 hex>   -> trusted_binaries[key] = 1 (key = u64 from hex)
 *   untrust <16 hex> -> delete from trusted_binaries
 *   quit             -> clean exit
 *
 * Replies (one per command):
 *   {"t":"ack","cmd":"block","ok":true}
 *   {"t":"ack","cmd":"...","ok":false} (for unknown/malformed commands)
 */

#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdbool.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/poll.h>
#include <unistd.h>

/* ---- Event structs (must match eBPF exactly) ---- */
struct proc_event_t {
    uint32_t pid, ppid, uid, ns_pid;
    uint64_t lineage_id, parent_lineage_id;
    char comm[16];
    char filename[256];
    char cmdline[512];
};

struct conn_event_t {
    uint32_t pid, ns_pid;
    char comm[16];
    uint32_t daddr;
    uint16_t dport;
    uint16_t family;
    uint64_t lineage_id;
};

struct file_event_t {
    uint32_t pid, ns_pid;
    char comm[16];
    char path[256];
    int flags;
    uint64_t lineage_id;
};

struct alert_event_t {
    uint64_t lineage_id;
    uint32_t pid, ns_pid, rule_id, action;
    char comm[16];
    char binary_path[256];
    char matched_pattern[128];
    uint64_t timestamp;
};

/* ---- JSON helpers ---- */
static void json_escape(const char *in, char *out, size_t out_sz) {
    char *o = out;
    char *end = out + out_sz - 1;
    for (const char *p = in; *p && o < end; p++) {
        unsigned char c = *p;
        switch (c) {
            case '"':  if (o + 1 < end) { *o++ = '\\'; *o++ = '"'; } break;
            case '\\': if (o + 1 < end) { *o++ = '\\'; *o++ = '\\'; } break;
            case '\b': if (o + 1 < end) { *o++ = '\\'; *o++ = 'b'; } break;
            case '\f': if (o + 1 < end) { *o++ = '\\'; *o++ = 'f'; } break;
            case '\n': if (o + 1 < end) { *o++ = '\\'; *o++ = 'n'; } break;
            case '\r': if (o + 1 < end) { *o++ = '\\'; *o++ = 'r'; } break;
            case '\t': if (o + 1 < end) { *o++ = '\\'; *o++ = 't'; } break;
            default:
                if (c < 0x20) {
                    if (o + 5 < end) { o += snprintf(o, end - o, "\\u%04x", c); }
                } else if (c >= 0x80) {
                    *o++ = '?';  /* replace invalid UTF-8 */
                } else {
                    *o++ = c;
                }
        }
    }
    *o = '\0';
}

static void print_info(bool lsm, int programs) {
    printf("{\"t\":\"info\",\"lsm\":%s,\"programs\":%d}\n", lsm ? "true" : "false", programs);
    fflush(stdout);
}

static void print_error(const char *msg) {
    char buf[256];
    json_escape(msg, buf, sizeof(buf));
    printf("{\"t\":\"error\",\"msg\":\"%s\"}\n", buf);
    fflush(stdout);
}

static void print_ack(const char *cmd, bool ok) {
    printf("{\"t\":\"ack\",\"cmd\":\"%s\",\"ok\":%s}\n", cmd, ok ? "true" : "false");
    fflush(stdout);
}

static void print_exec(const struct proc_event_t *e) {
    char comm[32], filename[512], cmdline[1024];
    json_escape(e->comm, comm, sizeof(comm));
    json_escape(e->filename, filename, sizeof(filename));
    json_escape(e->cmdline, cmdline, sizeof(cmdline));
    printf("{\"t\":\"exec\",\"pid\":%u,\"ppid\":%u,\"uid\":%u,\"ns_pid\":%u,\"lineage_id\":\"0x%016llX\",\"parent_lineage_id\":\"0x%016llX\",\"comm\":\"%s\",\"filename\":\"%s\",\"cmdline\":\"%s\"}\n",
           e->pid, e->ppid, e->uid, e->ns_pid,
           (unsigned long long)e->lineage_id,
           (unsigned long long)e->parent_lineage_id,
           comm, filename, cmdline);
    fflush(stdout);
}

static void print_conn(const struct conn_event_t *e) {
    char comm[32];
    json_escape(e->comm, comm, sizeof(comm));
    printf("{\"t\":\"conn\",\"pid\":%u,\"ns_pid\":%u,\"lineage_id\":\"0x%016llX\",\"comm\":\"%s\",\"daddr\":%u,\"dport\":%u,\"family\":%u}\n",
           e->pid, e->ns_pid, (unsigned long long)e->lineage_id,
           comm, e->daddr, e->dport, e->family);
    fflush(stdout);
}

static void print_file(const struct file_event_t *e) {
    char comm[32], path[512];
    json_escape(e->comm, comm, sizeof(comm));
    json_escape(e->path, path, sizeof(path));
    printf("{\"t\":\"file\",\"pid\":%u,\"ns_pid\":%u,\"lineage_id\":\"0x%016llX\",\"comm\":\"%s\",\"path\":\"%s\",\"flags\":%d}\n",
           e->pid, e->ns_pid, (unsigned long long)e->lineage_id,
           comm, path, e->flags);
    fflush(stdout);
}

static void print_alert(const struct alert_event_t *e) {
    char comm[32], binary_path[512], matched_pattern[256];
    json_escape(e->comm, comm, sizeof(comm));
    json_escape(e->binary_path, binary_path, sizeof(binary_path));
    json_escape(e->matched_pattern, matched_pattern, sizeof(matched_pattern));
    printf("{\"t\":\"alert\",\"lineage_id\":\"0x%016llX\",\"pid\":%u,\"ns_pid\":%u,\"rule_id\":%u,\"action\":%u,\"comm\":\"%s\",\"binary_path\":\"%s\",\"matched_pattern\":\"%s\",\"timestamp\":%llu}\n",
           (unsigned long long)e->lineage_id,
           e->pid, e->ns_pid, e->rule_id, e->action,
           comm, binary_path, matched_pattern,
           (unsigned long long)e->timestamp);
    fflush(stdout);
}

/* ---- LSM detection ---- */
static bool has_bpf_lsm(void) {
    FILE *f = fopen("/sys/kernel/security/lsm", "r");
    if (!f) return false;
    char buf[256];
    bool found = fgets(buf, sizeof(buf), f) && strstr(buf, "bpf");
    fclose(f);
    return found;
}

/* ---- libbpf print callback ---- */
static int libbpf_print_fn(enum libbpf_print_level l, const char *f, va_list a) {
    return l == LIBBPF_DEBUG ? 0 : vfprintf(stderr, f, a);
}

/* ---- Map helpers ---- */
static int get_map_fd(struct bpf_object *obj, const char *name) {
    struct bpf_map *map = bpf_object__find_map_by_name(obj, name);
    if (!map) return -1;
    return bpf_map__fd(map);
}

static int update_blocked(struct bpf_object *obj, uint64_t id, bool add) {
    int fd = get_map_fd(obj, "blocked_lineages");
    if (fd < 0) return -1;
    uint8_t one = 1;
    if (add) return bpf_map_update_elem(fd, &id, &one, BPF_ANY);
    return bpf_map_delete_elem(fd, &id);
}

static int update_trusted(struct bpf_object *obj, uint64_t key, bool add) {
    int fd = get_map_fd(obj, "trusted_binaries");
    if (fd < 0) return -1;
    uint8_t one = 1;
    if (add) return bpf_map_update_elem(fd, &key, &one, BPF_ANY);
    return bpf_map_delete_elem(fd, &key);
}

/* ---- Ring buffer callbacks ---- */
static int on_exec(void *ctx, void *data, size_t size) {
    print_exec(data);
    return 0;
}
static int on_conn(void *ctx, void *data, size_t size) {
    print_conn(data);
    return 0;
}
static int on_file(void *ctx, void *data, size_t size) {
    print_file(data);
    return 0;
}
static int on_alert(void *ctx, void *data, size_t size) {
    print_alert(data);
    return 0;
}

/* ---- Command parsing ---- */
static bool parse_hex64(const char *s, uint64_t *out) {
    if (!s) return false;
    char *end;
    unsigned long long v = strtoull(s, &end, 16);
    if (end == s || *end != '\0') return false;
    *out = v;
    return true;
}

static void handle_command(struct bpf_object *obj, const char *line) {
    if (!line || !*line) return;

    if (strncmp(line, "block ", 6) == 0) {
        uint64_t id;
        if (parse_hex64(line + 6, &id) && update_blocked(obj, id, true) == 0) {
            print_ack("block", true);
        } else {
            print_ack("block", false);
        }
    } else if (strncmp(line, "unblock ", 8) == 0) {
        uint64_t id;
        if (parse_hex64(line + 8, &id) && update_blocked(obj, id, false) == 0) {
            print_ack("unblock", true);
        } else {
            print_ack("unblock", false);
        }
    } else if (strncmp(line, "trust ", 6) == 0) {
        uint64_t key;
        if (parse_hex64(line + 6, &key) && update_trusted(obj, key, true) == 0) {
            print_ack("trust", true);
        } else {
            print_ack("trust", false);
        }
    } else if (strncmp(line, "untrust ", 8) == 0) {
        uint64_t key;
        if (parse_hex64(line + 8, &key) && update_trusted(obj, key, false) == 0) {
            print_ack("untrust", true);
        } else {
            print_ack("untrust", false);
        }
    } else if (strcmp(line, "quit") == 0) {
        print_ack("quit", true);
        exit(0);
    } else {
        print_ack(line, false);
    }
}

/* ---- Main ---- */
static volatile sig_atomic_t running = 1;

static void on_sigterm(int sig) { (void)sig; running = 0; }

int main(int argc, char **argv) {
    if (argc < 2) {
        fprintf(stderr, "usage: %s <core.o>\n", argv[0]);
        return 2;
    }

    signal(SIGTERM, on_sigterm);
    signal(SIGINT, on_sigterm);

    /* Line-buffered stdout for real-time JSON streaming */
    setvbuf(stdout, NULL, _IONBF, 0);

    /* Silence libbpf debug output */
    libbpf_set_print(libbpf_print_fn);

    /* Detect BPF LSM support */
    bool lsm_ok = has_bpf_lsm();

    /* Load object */
    struct bpf_object *obj = bpf_object__open_file(argv[1], NULL);
    if (!obj) {
        print_error("cannot open BPF object");
        return 1;
    }

    /* Disable LSM programs if kernel doesn't support BPF LSM */
    int total_programs = 0, autoload_programs = 0;
    struct bpf_program *prog;
    bpf_object__for_each_program(prog, obj) {
        total_programs++;
        if (!lsm_ok && (strstr(bpf_program__name(prog), "_lsm") || !strcmp(bpf_program__name(prog), "bpf_lsm"))) {
            bpf_program__set_autoload(prog, false);
        } else {
            bpf_program__set_autoload(prog, true);
            autoload_programs++;
        }
    }

    print_info(lsm_ok, autoload_programs);

    if (bpf_object__load(obj)) {
        print_error("bpf_object__load failed");
        bpf_object__close(obj);
        return 1;
    }

    /* Attach programs */
    int attached = 0;
    bpf_object__for_each_program(prog, obj) {
        if (bpf_program__autoload(prog)) {
            if (bpf_program__attach(prog) == 0) attached++;
        }
    }
    if (attached != autoload_programs) {
        print_error("not all programs attached (tracefs mounted?)");
        bpf_object__close(obj);
        return 1;
    }

    /* Open ring buffers */
    struct ring_buffer *rb = ring_buffer__new(get_map_fd(obj, "exec_events"), on_exec, NULL, NULL);
    if (!rb) { print_error("ring_buffer__new exec_events failed"); bpf_object__close(obj); return 1; }
    if (ring_buffer__add(rb, get_map_fd(obj, "conn_events"), on_conn, NULL) < 0) { print_error("add conn_events failed"); }
    if (ring_buffer__add(rb, get_map_fd(obj, "file_events"), on_file, NULL) < 0) { print_error("add file_events failed"); }
    if (ring_buffer__add(rb, get_map_fd(obj, "alert_events"), on_alert, NULL) < 0) { print_error("add alert_events failed"); }
    /* icmp_events is intentionally skipped - nothing writes it */

    /* Main loop: poll ring buffers and stdin */
    struct pollfd pfd = { .fd = STDIN_FILENO, .events = POLLIN };
    while (running) {
        int ret = ring_buffer__poll(rb, 100);
        if (ret < 0 && ret != -EINTR) {
            print_error("ring_buffer__poll error");
            break;
        }

        if (poll(&pfd, 1, 0) > 0 && (pfd.revents & POLLIN)) {
            char line[1024];
            if (fgets(line, sizeof(line), stdin)) {
                /* Strip newline */
                char *nl = strchr(line, '\n');
                if (nl) *nl = '\0';
                handle_command(obj, line);
            } else {
                /* EOF on stdin */
                break;
            }
        }
    }

    /* Cleanup */
    ring_buffer__free(rb);
    bpf_object__close(obj);
    return 0;
}
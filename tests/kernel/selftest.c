// Kernel self-test for the CO-RE object. Needs root, a BTF kernel, tracefs, libbpf.
//   make kernel-test
// Verifies, on the running kernel: every program passes the verifier, tracepoints attach,
// lineage chains parent->child, argv is captured, and a blocked lineage's child dies at exec.
// BPF-LSM programs are reported SKIP when the kernel has no BPF LSM (boot with lsm=...,bpf).
#define _GNU_SOURCE
#include <bpf/libbpf.h>
#include <bpf/bpf.h>
#include <errno.h>
#include <signal.h>
#include <stdint.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/wait.h>
#include <unistd.h>

struct proc_event_t  { uint32_t pid, ppid, uid, ns_pid; uint64_t lineage_id, parent_lineage_id;
                       char comm[16]; char filename[256]; char cmdline[512]; };
struct alert_event_t { uint64_t lineage_id; uint32_t pid, ns_pid, rule_id, action;
                       char comm[16]; char binary_path[256]; char matched_pattern[128]; uint64_t timestamp; };

static int failures, checks;
#define CHECK(cond, msg) do { checks++; if (cond) printf("  PASS  %s\n", msg); \
                              else { failures++; printf("  FAIL  %s\n", msg); } } while (0)

static int is_lsm(const char *n) { return strstr(n, "_lsm") || !strcmp(n, "bpf_lsm"); }
static int pf(enum libbpf_print_level l, const char *f, va_list a) { return l == LIBBPF_DEBUG ? 0 : 0; }

// ---- captured events ----
#define MAXEV 256
static struct proc_event_t ev[MAXEV]; static int nev;
static struct alert_event_t al[16]; static int nal;
static int blocked_fd = -1; static pid_t target = 0; static int block_armed, pipe_wr = -1;

static int on_exec(void *c, void *d, size_t n) {
    struct proc_event_t *e = d;
    if (nev < MAXEV) ev[nev++] = *e;
    if (block_armed && e->pid == (uint32_t)target) {
        uint8_t one = 1; bpf_map_update_elem(blocked_fd, &e->lineage_id, &one, BPF_ANY);
        if (write(pipe_wr, "go\n", 3) < 0) {}
        block_armed = 0;
    }
    return 0;
}
static int on_alert(void *c, void *d, size_t n) { if (nal < 16) al[nal++] = *(struct alert_event_t *)d; return 0; }

static const struct proc_event_t *find(const char *file) {
    for (int i = nev - 1; i >= 0; i--) if (!strcmp(ev[i].filename, file)) return &ev[i];
    return NULL;
}

int main(int argc, char **argv) {
    if (argc < 2) { fprintf(stderr, "usage: %s <core.o>\n", argv[0]); return 2; }
    setvbuf(stdout, NULL, _IONBF, 0); alarm(40); libbpf_set_print(pf);

    printf("[1] verifier: load each program on its own\n");
    struct bpf_object *probe = bpf_object__open_file(argv[1], NULL);
    if (!probe) { printf("  cannot open object\n"); return 1; }
    char names[64][64]; int n = 0; struct bpf_program *p;
    bpf_object__for_each_program(p, probe) snprintf(names[n++], 64, "%s", bpf_program__name(p));
    bpf_object__close(probe);
    for (int i = 0; i < n; i++) {
        struct bpf_object *o = bpf_object__open_file(argv[1], NULL);
        bpf_object__for_each_program(p, o) bpf_program__set_autoload(p, !strcmp(bpf_program__name(p), names[i]));
        int rc = bpf_object__load(o);
        if (rc == -EPERM && is_lsm(names[i])) printf("  SKIP  %-28s (no BPF LSM on this kernel)\n", names[i]);
        else { char m[120]; snprintf(m, sizeof m, "%.60s passes the verifier", names[i]); CHECK(rc == 0, m); }
        bpf_object__close(o);
    }

    printf("[2] attach tracepoints and trace real execs\n");
    struct bpf_object *o = bpf_object__open_file(argv[1], NULL);
    bpf_object__for_each_program(p, o) bpf_program__set_autoload(p, !is_lsm(bpf_program__name(p)));
    if (bpf_object__load(o)) { printf("  FAIL  load\n"); return 1; }
    int attached = 0, want = 0;
    bpf_object__for_each_program(p, o) if (bpf_program__autoload(p)) { want++; if (bpf_program__attach(p)) attached++; }
    CHECK(attached == want, "all tracepoint programs attach (is tracefs mounted?)");
    if (attached != want) return 1;
    blocked_fd = bpf_map__fd(bpf_object__find_map_by_name(o, "blocked_lineages"));
    struct ring_buffer *rb = ring_buffer__new(bpf_map__fd(bpf_object__find_map_by_name(o, "exec_events")), on_exec, NULL, NULL);
    ring_buffer__add(rb, bpf_map__fd(bpf_object__find_map_by_name(o, "alert_events")), on_alert, NULL);

    pid_t c = fork();
    if (c == 0) { execl("/bin/sh", "sh", "-c", "/bin/ls -la /tmp >/dev/null; /bin/echo a b", (char *)NULL); _exit(127); }
    waitpid(c, NULL, 0); ring_buffer__poll(rb, 300);
    const struct proc_event_t *ls = find("/bin/ls"), *sh = NULL;
    CHECK(ls != NULL, "exec of /bin/ls observed");
    if (ls) {
        CHECK(!strcmp(ls->cmdline, "/bin/ls -la /tmp"), "full argv captured (\"/bin/ls -la /tmp\")");
        for (int i = 0; i < nev; i++) if (ev[i].pid == ls->ppid) sh = &ev[i];
        CHECK(sh && ls->parent_lineage_id == sh->lineage_id, "child's parent_lineage_id == parent's lineage_id");
        CHECK(ls->lineage_id != 0 && ls->lineage_id != ls->parent_lineage_id, "child gets its own lineage_id");
    }
    const struct proc_event_t *echo = find("/bin/echo");
    CHECK(echo && !strcmp(echo->cmdline, "/bin/echo a b"), "second child argv captured (\"/bin/echo a b\")");

    printf("[3] block a lineage: its next child must die at exec\n");
    int p2[2]; if (pipe(p2)) return 1; pipe_wr = p2[1]; block_armed = 1; nal = 0;
    c = fork();
    if (c == 0) { dup2(p2[0], 0); close(p2[1]);
                  execl("/bin/sh", "sh", "-c", "read x; /bin/true; exit $?", (char *)NULL); _exit(127); }
    close(p2[0]); target = c;
    for (int i = 0; i < 20 && block_armed; i++) ring_buffer__poll(rb, 100);
    int st = 0; waitpid(c, &st, 0); ring_buffer__poll(rb, 300);
    CHECK(WIFEXITED(st) && WEXITSTATUS(st) == 137, "child of the blocked lineage was SIGKILLed at exec (status 137)");
    int found = 0; for (int i = 0; i < nal; i++) if (!strcmp(al[i].matched_pattern, "BLOCKED_LINEAGE") && !strcmp(al[i].binary_path, "/bin/true")) found = 1;
    CHECK(found, "BLOCKED_LINEAGE alert emitted for /bin/true");

    printf("\n%d checks, %d failed\n", checks, failures);
    return failures ? 1 : 0;
}

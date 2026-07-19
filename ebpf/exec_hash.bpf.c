#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} target_cgroup_map SEC(".maps");

#define MAX_PATH_LEN 256
#define MAX_ARG_COUNT 8
#define MAX_ARG_LEN 128

struct exec_approval_key {
    char path[MAX_PATH_LEN];
};

/* One-use approvals written by aegisd after the synchronous AI verdict. */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, struct exec_approval_key);
    __type(value, u64); /* CLOCK_MONOTONIC expiry in ns */
} approved_exec_map SEC(".maps");

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u32);
} exec_gate_enabled_map SEC(".maps");

/*
 * Exec telemetry is captured at sys_enter_execve, while filename and argv
 * still point into the calling process' valid userspace memory. Reading argv
 * later from linux_binprm::p in bprm_check_security is not portable and was
 * observed to produce empty arguments on the target kernel.
 */
struct exec_event {
    u32 pid;
    u32 argc;
    u64 cgroup_id;
    u64 timestamp_ns;
    u64 inode; /* unavailable at syscall entry; kept for userspace ABI */
    char path[MAX_PATH_LEN];
    char args[MAX_ARG_COUNT][MAX_ARG_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_events SEC(".maps");

SEC("tracepoint/syscalls/sys_enter_execve")
int aegis_exec(struct trace_event_raw_sys_enter *ctx)
{
    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    u32 key = 0;
    u64 *target_cgroup_id = bpf_map_lookup_elem(&target_cgroup_map, &key);

    if (!target_cgroup_id || (*target_cgroup_id != 0 && *target_cgroup_id != current_cgroup_id)) {
        return 0;
    }

    struct exec_event *event = bpf_ringbuf_reserve(&exec_events, sizeof(*event), 0);
    if (!event) {
        /* Tracepoints cannot deny the syscall; record loss is surfaced by userspace. */
        return 0;
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->argc = 0;
    event->cgroup_id = current_cgroup_id;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->inode = 0;

    const char *filename = (const char *)ctx->args[0];
    const char *const *argv = (const char *const *)ctx->args[1];
    bpf_probe_read_user_str(event->path, MAX_PATH_LEN, filename);

#pragma unroll
    for (int i = 0; i < MAX_ARG_COUNT; i++) {
        const char *argp = 0;
        if (bpf_probe_read_user(&argp, sizeof(argp), &argv[i]) < 0 || !argp) {
            break;
        }
        if (bpf_probe_read_user_str(event->args[i], MAX_ARG_LEN, argp) < 0) {
            break;
        }
        event->argc++;
    }

    bpf_ringbuf_submit(event, 0);
    return 0;
}

/*
 * Backstop for the entire target cgroup. Descendants of aegis-gate are held
 * by seccomp user notification, but docker exec creates a separate process
 * that does not inherit that filter. This LSM hook allows only an exact,
 * one-use approval token written by aegisd immediately before Continue.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(aegis_exec_guard, struct linux_binprm *bprm, int ret)
{
    if (ret != 0) return ret;

    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    u32 zero = 0;
    u64 *target_cgroup_id = bpf_map_lookup_elem(&target_cgroup_map, &zero);
    if (!target_cgroup_id || (*target_cgroup_id != 0 && *target_cgroup_id != current_cgroup_id)) {
        return 0;
    }

    u32 *enabled = bpf_map_lookup_elem(&exec_gate_enabled_map, &zero);
    if (!enabled || *enabled == 0) return 0;

    struct exec_approval_key key = {};
    const char *filename = NULL;
    bpf_core_read(&filename, sizeof(filename), &bprm->filename);
    if (filename) {
        bpf_probe_read_kernel_str(key.path, MAX_PATH_LEN, filename);
    }

    u64 *approved = bpf_map_lookup_elem(&approved_exec_map, &key);
    if (!approved) return -1; /* -EPERM: no gate approval */

    if (bpf_ktime_get_ns() > *approved) {
        bpf_map_delete_elem(&approved_exec_map, &key);
        return -1;
    }

    /* Consume the token so it cannot approve a later exec. */
    bpf_map_delete_elem(&approved_exec_map, &key);
    return 0;
}

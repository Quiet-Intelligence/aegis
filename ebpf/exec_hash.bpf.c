#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} target_cgroup_map SEC(".maps");

#define MAX_PATH_LEN 256
#define MAX_ARGS_LEN 256
#define PAGE_SIZE 4096

/**
 * @brief Exec event structure.
 * Note on constraints (L1-3): Computing a full SHA-256 of the binary in-kernel
 * violates eBPF stack (512B) and loop complexity constraints. We stream the
 * inode, mtime, and path to userspace, where the Go daemon reads the file,
 * computes the hash, and caches it keyed by (inode + mtime) for performance.
 */
struct exec_event {
    u32 pid;
    u32 argc;
    u64 cgroup_id;
    u64 timestamp_ns;
    u64 inode;
    char path[MAX_PATH_LEN];
    // NUL-separated argv captured from bprm->p (kernel VA of the new
    // stack's top page, already populated by copy_strings() at
    // bprm_check_security time). Empty on read failure.
    char args[MAX_ARGS_LEN];
};

struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} exec_events SEC(".maps");

/**
 * @brief LSM hook for bprm_check_security.
 */
SEC("lsm/bprm_check_security")
int BPF_PROG(aegis_exec, struct linux_binprm *bprm)
{
    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    u32 key = 0;
    u64 *target_cgroup_id = bpf_map_lookup_elem(&target_cgroup_map, &key);

    // A target of 0 is the wildcard: monitor every cgroup.
    if (!target_cgroup_id || (*target_cgroup_id != 0 && *target_cgroup_id != current_cgroup_id)) {
        return 0;
    }

    struct exec_event *event;
    event = bpf_ringbuf_reserve(&exec_events, sizeof(struct exec_event), 0);
    if (!event) {
        // Backpressure rule: fail-closed for exec
        return -1; // -EPERM
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->cgroup_id = current_cgroup_id;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->argc = BPF_CORE_READ(bprm, argc);

    struct inode *inode = bprm->file->f_inode;
    event->inode = inode->i_ino;
    // mtime is intentionally NOT read here: its struct layout changed
    // across kernel versions (i_mtime -> __i_mtime -> split sec/nsec),
    // and userspace can stat the path instead. i_ino is stable forever.

    bpf_d_path(&bprm->file->f_path, event->path, MAX_PATH_LEN);

    // argv capture: [bprm->p, end of its page) holds NUL-separated
    // argv/envp strings. probe_read faults are graceful (args stays
    // zeroed), so a bad read degrades to old behavior instead of
    // breaking exec.
    unsigned long p = BPF_CORE_READ(bprm, p);
    u32 alen = PAGE_SIZE - (p & (PAGE_SIZE - 1));
    alen &= (MAX_ARGS_LEN - 1); // bound to 255 for the verifier
    if (alen > 0) {
        bpf_probe_read_kernel(event->args, alen, (const void *)p);
    }

    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_core_read.h>

char LICENSE[] SEC("license") = "Dual BSD/GPL";

/**
 * @brief Config map to store the target cgroup ID to monitor.
 */
struct {
    __uint(type, BPF_MAP_TYPE_ARRAY);
    __uint(max_entries, 1);
    __type(key, u32);
    __type(value, u64);
} target_cgroup_map SEC(".maps");

#define MAX_PATH_LEN 256

#define AEGIS_O_ACCMODE 3
#define AEGIS_O_WRONLY  1
#define AEGIS_O_RDWR    2
#define AEGIS_O_APPEND  02000

static __always_inline int path_boundary(const char *p, const char *prefix, int len)
{
#pragma unroll
    for (int i = 0; i < 16; i++) {
        if (i >= len) return p[i] == '\0' || p[i] == '/';
        if (p[i] != prefix[i]) return 0;
    }
    return 0;
}

static __always_inline int writable_sandbox_path(const char *p)
{
    if (path_boundary(p, "/workspace", 10)) return 1;
    /* Device endpoints are required for normal terminal I/O, not storage. */
    if (path_boundary(p, "/dev/null", 9)) return 1;
    if (path_boundary(p, "/dev/tty", 8)) return 1;
    if (path_boundary(p, "/dev/fd", 7)) return 1;
    return 0;
}

/**
 * @brief Policy map populated by the Go control plane.
 * Stores paths that have been explicitly denied (L1-5).
 */
struct {
    __uint(type, BPF_MAP_TYPE_HASH);
    __uint(max_entries, 1024);
    __type(key, char[MAX_PATH_LEN]);
    __type(value, u32); // 1 = denied
} denied_paths_map SEC(".maps");

/**
 * @brief Event structure emitted to userspace on file open.
 */
struct file_open_event {
    u32 pid;
    u64 cgroup_id;
    u64 timestamp_ns;
    int flags;
    char path[MAX_PATH_LEN];
};

/**
 * @brief Ring buffer to stream file open events to userspace.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} file_events SEC(".maps");

/**
 * @brief LSM hook for file_open (observability + policy enforcement).
 */
SEC("lsm/file_open")
int BPF_PROG(aegis_file_open, struct file *file)
{
    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    u32 key = 0;
    u64 *target_cgroup_id = bpf_map_lookup_elem(&target_cgroup_map, &key);

    if (!target_cgroup_id || *target_cgroup_id != current_cgroup_id) {
        return 0; 
    }

    struct file_open_event *event;
    event = bpf_ringbuf_reserve(&file_events, sizeof(struct file_open_event), 0);
    
    char path_buf[MAX_PATH_LEN] = {};
    bpf_d_path(&file->f_path, path_buf, MAX_PATH_LEN);

    // Write to observability ring buffer if we got a slot
    if (event) {
        event->pid = bpf_get_current_pid_tgid() >> 32;
        event->cgroup_id = current_cgroup_id;
        event->timestamp_ns = bpf_ktime_get_ns();
        event->flags = file->f_flags;
        __builtin_memcpy(event->path, path_buf, MAX_PATH_LEN);
        bpf_ringbuf_submit(event, 0);
    } else {
        // Backpressure rule (H-9): file_open uses fail-closed
        return -1; // -EPERM
    }

    // L1-5: Check policy map and block if matched
    u32 *denied = bpf_map_lookup_elem(&denied_paths_map, path_buf);
    if (denied && *denied == 1) {
        return -1; // -EPERM
    }

    // Defense in depth: commands are free to read system files, but writes
    // are confined to /workspace (plus terminal device endpoints). This protects
    // shell builtins such as `echo > file` which never issue execve and
    // therefore cannot be mediated by the command gate.
    int access_mode = file->f_flags & AEGIS_O_ACCMODE;
    int is_write = access_mode == AEGIS_O_WRONLY || access_mode == AEGIS_O_RDWR || (file->f_flags & AEGIS_O_APPEND);
    if (is_write && !writable_sandbox_path(path_buf)) {
        return -1; // -EPERM
    }
    
    return 0;
}

SEC("lsm/path_unlink")
int BPF_PROG(aegis_path_unlink, struct path *dir, struct dentry *dentry)
{
    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    u32 key = 0;
    u64 *target_cgroup_id = bpf_map_lookup_elem(&target_cgroup_map, &key);

    if (!target_cgroup_id || *target_cgroup_id != current_cgroup_id) {
        return 0; 
    }

    struct file_open_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) return 0;

    char path_buf[MAX_PATH_LEN] = {};
    long ret = bpf_d_path(dir, path_buf, MAX_PATH_LEN);
    if (ret > 0 && ret < MAX_PATH_LEN - 2) {
        u32 len = ret;
        len &= (MAX_PATH_LEN - 1);
        if (len > 0) {
            if (path_buf[len - 1] != '/') {
                path_buf[len] = '/';
                len++;
                len &= (MAX_PATH_LEN - 1);
            }
            const unsigned char *name = NULL;
            bpf_core_read(&name, sizeof(name), &dentry->d_name.name);
            if (name) {
                bpf_probe_read_kernel_str(&path_buf[len], MAX_PATH_LEN - len, name);
            }
        }
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->cgroup_id = current_cgroup_id;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->flags = -1; // Special flag for unlink
    __builtin_memcpy(event->path, path_buf, MAX_PATH_LEN);
    bpf_ringbuf_submit(event, 0);

    return 0;
}

SEC("lsm/path_rmdir")
int BPF_PROG(aegis_path_rmdir, struct path *dir, struct dentry *dentry)
{
    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    u32 key = 0;
    u64 *target_cgroup_id = bpf_map_lookup_elem(&target_cgroup_map, &key);

    if (!target_cgroup_id || *target_cgroup_id != current_cgroup_id) {
        return 0; 
    }

    struct file_open_event *event = bpf_ringbuf_reserve(&file_events, sizeof(*event), 0);
    if (!event) return 0;

    char path_buf[MAX_PATH_LEN] = {};
    long ret = bpf_d_path(dir, path_buf, MAX_PATH_LEN);
    if (ret > 0 && ret < MAX_PATH_LEN - 2) {
        u32 len = ret;
        len &= (MAX_PATH_LEN - 1);
        if (len > 0) {
            if (path_buf[len - 1] != '/') {
                path_buf[len] = '/';
                len++;
                len &= (MAX_PATH_LEN - 1);
            }
            const unsigned char *name = NULL;
            bpf_core_read(&name, sizeof(name), &dentry->d_name.name);
            if (name) {
                bpf_probe_read_kernel_str(&path_buf[len], MAX_PATH_LEN - len, name);
            }
        }
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->cgroup_id = current_cgroup_id;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->flags = -2; // Special flag for rmdir
    __builtin_memcpy(event->path, path_buf, MAX_PATH_LEN);
    bpf_ringbuf_submit(event, 0);

    return 0;
}

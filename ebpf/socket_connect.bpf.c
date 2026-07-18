#include "vmlinux.h"
#include <bpf/bpf_helpers.h>
#include <bpf/bpf_tracing.h>
#include <bpf/bpf_endian.h>
#include <bpf/bpf_core_read.h>

#ifndef AF_INET
#define AF_INET 2
#endif

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

/**
 * @brief Event structure emitted to userspace on socket connect.
 * Fixed-size, flat struct mirrored exactly in Go.
 */
struct net_event {
    u32 pid;
    u64 cgroup_id;
    u64 timestamp_ns;
    u32 daddr;
    u16 dport;
    u16 protocol;
};

/**
 * @brief Ring buffer to stream outbound connection attempts.
 */
struct {
    __uint(type, BPF_MAP_TYPE_RINGBUF);
    __uint(max_entries, 256 * 1024);
} net_events SEC(".maps");

/**
 * @brief LSM hook for socket_connect.
 * 
 * Attaches to socket_connect to stream network events (L1-2).
 */
SEC("lsm/socket_connect")
int BPF_PROG(aegis_socket_connect, struct socket *sock, struct sockaddr *address, int addrlen)
{
    u64 current_cgroup_id = bpf_get_current_cgroup_id();
    u32 key = 0;
    u64 *target_cgroup_id = bpf_map_lookup_elem(&target_cgroup_map, &key);

    if (!target_cgroup_id || *target_cgroup_id != current_cgroup_id) {
        return 0;
    }

    if (address->sa_family != AF_INET) {
        return 0; // Only tracking IPv4 for now to maintain fixed struct size
    }

    struct sockaddr_in *addr_in = (struct sockaddr_in *)address;
    
    struct net_event *event;
    event = bpf_ringbuf_reserve(&net_events, sizeof(struct net_event), 0);
    if (!event) {
        return 0; // Drop event if ring buffer is full (fail-open for telemetry)
    }

    event->pid = bpf_get_current_pid_tgid() >> 32;
    event->cgroup_id = current_cgroup_id;
    event->timestamp_ns = bpf_ktime_get_ns();
    event->daddr = addr_in->sin_addr.s_addr;
    event->dport = bpf_ntohs(addr_in->sin_port);
    
    struct sock *sk = sock->sk;
    u16 protocol = 0;
    bpf_core_read(&protocol, sizeof(protocol), &sk->sk_protocol);
    event->protocol = protocol;

    bpf_ringbuf_submit(event, 0);
    
    return 0;
}

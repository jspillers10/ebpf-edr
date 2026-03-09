#include <uapi/linux/ptrace.h>
#include <linux/in.h>
#include <linux/in6.h>

struct connect_event_t {
    u32  pid;
    u32  ppid;
    u32  uid;
    u16  dport;
    u16  af;
    u32  daddr;     // IPv4 Destination
    u8   daddr6[16]; // IPv6 Destination
    char comm[16];

};

BPF_PERF_OUTPUT(connect_events);

TRACEPOINT_PROBE(syscalls, sys_enter_connect) {
    struct connect_event_t event = {};

    // Standard process context — same pattern as syscall_monitor.c
    u64 pid_tgid      = bpf_get_current_pid_tgid();
    event.pid         = pid_tgid >> 32;
    event.uid         = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    bpf_get_current_comm(&event.comm, sizeof(event.comm));

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.ppid = task->real_parent->tgid;

    u16 af = 0;
    bpf_probe_read_user(&af, sizeof(af), (void *)args->uservaddr);
    event.af = af;

    if (af == AF_INET) {
        // IPv4: sockaddr_in has sin_port (2 bytes) then sin_addr (4 bytes)
        // Ports in sockaddr are big-endian (network byte order).
        // bswap16 converts to little-endian so Python reads it correctly.
        struct sockaddr_in sa = {};
        bpf_probe_read_user(&sa, sizeof(sa), (void *)args->uservaddr);
        event.dport = __builtin_bswap16(sa.sin_port);
        event.daddr = sa.sin_addr.s_addr;

    } else if (af == AF_INET6) {
        // IPv6: sockaddr_in6 has sin6_port (2 bytes) then sin6_addr (16 bytes)
        struct sockaddr_in6 sa6 = {};
        bpf_probe_read_user(&sa6, sizeof(sa6), (void *)args->uservaddr);
        event.dport = __builtin_bswap16(sa6.sin6_port);
        __builtin_memcpy(event.daddr6, sa6.sin6_addr.in6_u.u6_addr8, 16);

    } else {
        return 0;
    }

    if (event.dport == 0) return 0;

    connect_events.perf_submit(args, &event, sizeof(event));
    return 0;

}


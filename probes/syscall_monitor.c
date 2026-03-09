// probes/syscall_monitor.c
#include <uapi/linux/ptrace.h>
#include <linux/sched.h>

// Define the event structure we will send to userspace
struct execv_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    char comm[16];      // current process name
    char filename[256]; // binary being executed
};

// Create a ring buffer output channel
BPF_PERF_OUTPUT(execve_events);

// Attach to the execve tracepoint
TRACEPOINT_PROBE(syscalls, sys_enter_execve) {
    struct execv_event_t event = {};
    
    // Grab PID and PPID
    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid  = bpf_get_current_pid_tgid() >> 32;
    event.ppid = task->real_parent->tgid;
    event.uid  = bpf_get_current_uid_gid() & 0xFFFFFFFF;

    // Grav the process name and filename being executed
    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    execve_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

struct ptrace_event_t {
    u32 pid;        // the process calling ptrace (the attacker)
    u32 ppid;
    u32 uid;
    u32 target_id;  // the process being attached to (the victim)
    u32 request;    // what ptrace operation is being requested
    char comm[16];  // name of the calling process 
};

BPF_PERF_OUTPUT(ptrace_events);

TRACEPOINT_PROBE(syscalls, sys_enter_ptrace) {
    struct ptrace_event_t event = {};

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid       = bpf_get_current_pid_tgid() >> 32;
    event.ppid      = task->real_parent->tgid;
    event.uid       = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.request   = args->request;
    event.target_id = args->pid;    // ptrace's first arg is the target pid

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    

    // Kernal-side filter
    // Only submit events we actually care about. PTRACE_GETREGSET (16910)
    // and PTRACE_SYSCALL (24) fire hundreds of times per traced process —
    // they're normal debugger operation, not indicators of attack.
    // Filtering here means these events never leave the kernel at all,
    // which is dramatically more efficient than filtering in Python.
    u32 r = args->request;
    if (r == 24 || r == 16910 || r == 16897 || r == 16898) {
        return 0;  // drop it right here in the kernal
    }

    ptrace_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

struct openat_event_t {
    u32 pid;
    u32 ppid;
    u32 uid;
    int flags;          // O_RDONLY, O_WRONLY, O_RDWR etc.
    char comm[16];      
    char filename[256]; 
};

BPF_PERF_OUTPUT(openat_events);

TRACEPOINT_PROBE(syscalls, sys_enter_openat) {
    struct openat_event_t event = {};

    struct task_struct *task = (struct task_struct *)bpf_get_current_task();
    event.pid   = bpf_get_current_pid_tgid() >> 32;
    event.ppid  = task->real_parent->tgid;
    event.uid   = bpf_get_current_uid_gid() & 0xFFFFFFFF;
    event.flags = args->flags;

    bpf_get_current_comm(&event.comm, sizeof(event.comm));
    bpf_probe_read_user_str(&event.filename, sizeof(event.filename), args->filename);

    // ── Kernel-side pre-filter ────────────────────────────────────────
    // We only want to surface events where the path starts with
    // /etc/ or /proc/ or /root/ — everything else we drop here.
    //
    // eBPF can't do dynamic string searching, but it CAN compare fixed
    // byte offsets. We check the first 5 characters of the filename
    // against our target prefixes.
    
    char etc[]  = "/etc/";
    char proc[] = "/proc";
    char root[] = "/root";
    char ssh[]  = "/.ssh";

    if (__builtin_memcmp(event.filename, etc,  5) != 0 &&
        __builtin_memcmp(event.filename, proc, 5) != 0 &&
        __builtin_memcmp(event.filename, root, 5) != 0) {
        return 0;  // not a path we care about, drop in kernel
    }

    openat_events.perf_submit(args, &event, sizeof(event));
    return 0;
}

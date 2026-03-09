from bcc import BPF
import ctypes
import os
import sys
import threading
from datetime import datetime
from anomaly_engine import AnomalyEngine
from network_analyzer import NetworkAnalyzer
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from dashboard.cli import Dashboard

engine           = AnomalyEngine()
network_analyzer = NetworkAnalyzer()
dashboard        = Dashboard()

PTRACE_ATTACH   = 16
PTRACE_POKETEXT = 4
PTRACE_POKEDATA = 5

O_WRONLY = 1
O_RDWR   = 2

PTRACE_DANGER = {
    16:    "ATTACH",
    4:     "MEMORY_WRITE (POKETEXT)",
    5:     "MEMORY_WRITE (POKEDATA)",
    16896: "SEIZE",
    16900: "INTERRUPT",
    16902: "SEIZE+OPTIONS",
}

bpf_syscall = BPF(src_file="probes/syscall_monitor.c")
bpf_network = BPF(src_file="probes/network_monitor.c")

class ExecveEvent(ctypes.Structure):
    _fields_ = [
        ("pid",      ctypes.c_uint32),
        ("ppid",     ctypes.c_uint32),
        ("uid",      ctypes.c_uint32),
        ("comm",     ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
    ]

class PtraceEvent(ctypes.Structure):
    _fields_ = [
        ("pid",        ctypes.c_uint32),
        ("ppid",       ctypes.c_uint32),
        ("uid",        ctypes.c_uint32),
        ("target_pid", ctypes.c_uint32),
        ("request",    ctypes.c_uint32),
        ("comm",       ctypes.c_char * 16),
    ]

class OpenatEvent(ctypes.Structure):
    _fields_ = [
        ("pid",      ctypes.c_uint32),
        ("ppid",     ctypes.c_uint32),
        ("uid",      ctypes.c_uint32),
        ("flags",    ctypes.c_int32),
        ("comm",     ctypes.c_char * 16),
        ("filename", ctypes.c_char * 256),
    ]

class ConnectEvent(ctypes.Structure):
    # Must mirror connect_event_t in network_monitor.c exactly.
    # af tells us which address field to read — daddr for IPv4, daddr6 for IPv6.
    _fields_ = [
        ("pid",    ctypes.c_uint32),
        ("ppid",   ctypes.c_uint32),
        ("uid",    ctypes.c_uint32),
        ("dport",  ctypes.c_uint16),
        ("af",     ctypes.c_uint16),
        ("daddr",  ctypes.c_uint32),
        ("daddr6", ctypes.c_uint8 * 16),
        ("comm",   ctypes.c_char * 16),
    ]

def handle_execve_event(cpu, data, size):
    event    = ctypes.cast(data, ctypes.POINTER(ExecveEvent)).contents
    pid      = event.pid
    ppid     = event.ppid
    uid      = event.uid
    comm     = event.comm.decode("utf-8", errors="replace")
    filename = event.filename.decode("utf-8", errors="replace")
    dashboard.push({
        "type":     "EXECVE",
        "severity": "INFO",
        "score":    0,
        "comm":     comm,
        "detail":   f"{comm} -> {filename}",
        "time":     datetime.now().strftime("%H:%M:%S"),
    })

def handle_ptrace_event(cpu, data, size):
    event      = ctypes.cast(data, ctypes.POINTER(PtraceEvent)).contents
    pid        = event.pid
    ppid       = event.ppid
    uid        = event.uid
    target_pid = event.target_pid
    request    = event.request
    comm       = event.comm.decode("utf-8", errors="replace")
    operation  = PTRACE_DANGER.get(request, f"request={request}")
    severity   = "HIGH" if request in PTRACE_DANGER else "INFO"
    dashboard.push({
        "type":     "PTRACE",
        "severity": severity,
        "score":    0,
        "comm":     comm,
        "detail":   f"target={target_pid} op={operation}",
        "time":     datetime.now().strftime("%H:%M:%S"),
    })

def handle_openat_event(cpu, data, size):
    event    = ctypes.cast(data, ctypes.POINTER(OpenatEvent)).contents
    pid      = event.pid
    ppid     = event.ppid
    uid      = event.uid
    flags    = event.flags
    comm     = event.comm.decode("utf-8", errors="replace")
    filename = event.filename.decode("utf-8", errors="replace")
    is_write = bool((flags & O_WRONLY) or (flags & O_RDWR))
    verdict  = engine.evaluate_openat(pid, ppid, uid, comm, filename, is_write)
    if verdict is None:
        return
    severity = verdict["severity"]
    score    = verdict["score"]
    reasons  = " | ".join(verdict["reasons"])
    access   = "WRITE" if is_write else "READ"
    dashboard.push({
        "type":     "OPENAT",
        "severity": severity,
        "score":    score,
        "comm":     comm,
        "detail":   f"{filename} [{access}] | {reasons}",
        "time":     datetime.now().strftime("%H:%M:%S"),
    })

def handle_connect_event(cpu, data, size):
    try:
        event = ctypes.cast(data, ctypes.POINTER(ConnectEvent)).contents
        pid   = event.pid
        ppid  = event.ppid
        uid   = event.uid
        af    = event.af
        dport = event.dport
        comm  = event.comm.decode("utf-8", errors="replace")
        daddr = event.daddr if af == 2 else bytes(event.daddr6)
        verdict = network_analyzer.evaluate_connect(pid, ppid, uid, comm, daddr, dport, af)
        if verdict is None:
            return
        severity = verdict["severity"]
        score    = verdict["score"]
        dst      = verdict["dst_str"]
        reasons  = " | ".join(verdict["reasons"])
        dashboard.push({
            "type":     "CONNECT",
            "severity": severity,
            "score":    score,
            "comm":     comm,
            "detail":   f"{dst} | {reasons}",
            "time":     datetime.now().strftime("%H:%M:%S"),
        })
    except Exception as e:
        print(f"[CONNECT ERROR] {e}")

bpf_syscall["execve_events"].open_perf_buffer(handle_execve_event)
bpf_syscall["ptrace_events"].open_perf_buffer(handle_ptrace_event)
bpf_syscall["openat_events"].open_perf_buffer(handle_openat_event)
bpf_network["connect_events"].open_perf_buffer(handle_connect_event)

def poll_loop():
    while True:
        bpf_syscall.perf_buffer_poll(timeout=100)
        bpf_network.perf_buffer_poll(timeout=100)

poll_thread = threading.Thread(target=poll_loop, daemon=True)
poll_thread.start()

dashboard.run()

#!/usr/bin/env python3
"""
syscall_sim.py — Simulates attack-relevant syscall patterns to validate
the EDR's execve and ptrace detection.

Run this while collector.py is active and verify alerts fire correctly.

Simulations:
  1. Suspicious process execution (mimics malware dropping a binary)
  2. ptrace injection attempt (mimics a process attaching to another)
  3. Rapid /proc enumeration (mimics recon scanning all running processes)
"""

import os
import sys
import time
import ctypes
import ctypes.util
import subprocess
import tempfile

SEPARATOR = "=" * 60

def sim1_suspicious_execution():
    """
    Drop a shell script to /tmp and execute it.
    Real malware almost always writes a payload to /tmp or /dev/shm
    before executing — these paths are writable by any user and
    don't require elevated privileges.

    Expected EDR output:
      [EXECVE] showing the script spawned from /tmp
    """

    print(f"\n{SEPARATOR}")
    print("SIM 1: Suspicious execution from /tmp")
    print("Dropping payload to /tmp and executing...")
    print(SEPARATOR)

    payload = "/tmp/edr_test_payload.sh"

    with open(payload, "w") as f:
        f.write("#!/bin/bash\n")
        f.write("whoami\n")
        f.write("id\n")
        f.write("hostname\n")

    os.chmod(payload, 0o755)
    result = subprocess.run([payload], capture_output=True, text=True)

    print(f"Payload Output:\n{result.stdout.strip()}")
    print(f"Check collector for [EXECVE] alert showing execution from /tmp")

    os.unlink(payload)
    time.sleep(2)


def sim2_ptrace_injection():
    """
    Attempt to ptrace-attach to another process.
    We target our own parent process (the shell that launched us)
    so we don't need to guess a pid — and attaching to your own
    parent is suspicious enough to trigger the alert.

    PTRACE_ATTACH = 16. We call it directly via ctypes so it hits
    the tracepoint exactly like real injection tooling would.

    Expected EDR output:
      [PTRACE] HIGH | op=ATTACH
    """
    print(f"\n{SEPARATOR}")
    print("SIM 2: ptrace injection attempt")
    print(f"Attempting PTRACE_ATTACH against parent pid={os.getppid()}...")
    print(SEPARATOR)

    libc = ctypes.CDLL(ctypes.util.find_library("c"), use_errno=True)
    PTRACE_ATTACH = 16
    target_pid    = os.getppid()

    ret = libc.ptrace(PTRACE_ATTACH, target_pid, 0, 0)

    if ret == 0:
        print (f"ptrace attached to pid {target_pid} - detaching cleanly")
        # Wait for the stop signal then detach so we don't leave the
        # target process frozen
        os.waitpid(target_pid, 0)
        PTRACE_DETACH = 17
        libc.ptrace(PTRACE_DETACH, target_pid, 0, 0)
    else:
        errno = ctypes.get_errno()
        print(f"ptrace returned {ret}, errno={errno} (permission denied is expected if not root)")

    print("Check collector for [PTRACE] HIGH alert")
    time.sleep(2)


def sim3_proc_enumeration():
    """
    Rapidly enumerate /proc/<pid>/ entries for all running processes.
    This mimics the recon phase of process injection — an attacker
    scans all running processes looking for a suitable target.

    We do 200 reads in a tight loop which crosses both the LOW (50)
    and HIGH (150) thresholds in the 30-second window.

    Expected EDR output:
      [OPENAT] HIGH  — once rate crosses PROC_RATE_LOW (50)
      [OPENAT] HIGH  — escalating as rate crosses PROC_RATE_HIGH (150)
    """
    print(f"\n{SEPARATOR}")
    print("SIM 3: /proc enumeration — process recon")
    print("Reading /proc/<pid>/status for all running processes...")
    print(SEPARATOR)

    pids = [p for p in os.listdir("/proc") if p.isdigit()]
    count = 0

    for pid in pids * 5:  # loop the list to guarantee we exceed the HIGH threshold
        try:
            path = f"/proc/{pid}/status"
            with open(path, "r") as f:
                f.read(1)  # just trigger the openat, don't need the content
            count += 1
        except (PermissionError, FileNotFoundError):
            pass

        if count >= 200:
            break

    print(f"Opened {count} /proc entries")
    print("Check collector for [OPENAT] HIGH alert with proc enumeration reason")
    time.sleep(2)

def main():
    print("EDR Attack Simulator - syscall edition")
    print("Run sudo python3 agent/collector.py in another terminal first.\n")

    sim1_suspicious_execution()
    sim2_ptrace_injection()
    sim3_proc_enumeration()

    print(f"\n{SEPARATOR}")
    print("All simulations complete.")
    print(SEPARATOR)


if __name__ == "__main__":
    main()

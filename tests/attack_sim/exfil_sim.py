#!/usr/bin/env python3
"""
exfil_sim.py — Simulates network-based attack patterns to validate
the EDR's connect() and beaconing detection.

Simulations:
  1. C2 beaconing — single process makes repeated connections to the
     same destination on a schedule, mimicking an implant checking in
  2. High-frequency connections — rapid outbound connections to many
     destinations, mimicking a port scanner or data exfiltration burst
  3. Sensitive port connection — outbound connection to port 4444
     (default Metasploit listener port)
"""

import socket
import time
import threading

SEPARATOR = "=" * 60

# A reliable public IP for testing — Cloudflare DNS.
# We're not sending data, just completing the TCP connect() call.
TEST_HOST = "1.1.1.1"
TEST_PORT = 80


def sim1_c2_beaconing():
    """
    Make 6 connections to the same (host, port) with 3-second gaps.
    This mimics a C2 implant that checks in on a schedule.

    The beaconing detector keys on (comm, ip, port) — since we're
    one persistent python3 process hitting the same destination
    repeatedly, we'll cross BEACON_MIN_HITS=4 and trigger an alert.

    Expected EDR output:
      [CONNECT] HIGH score=60 | BEACONING: N connections to 1.1.1.1:80
    """
    print(f"\n{SEPARATOR}")
    print("SIM 1: C2 beaconing simulation")
    print(f"Making 6 connections to {TEST_HOST}:{TEST_PORT} with 3s gaps...")
    print(SEPARATOR)

    for i in range(6):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(3)
            s.connect((TEST_HOST, TEST_PORT))
            s.close()
            print(f"  connection {i+1}/6")
        except Exception as e:
            print(f"  connection {i+1}/6 failed: {e}")
        time.sleep(3)

    print("Check collector for [CONNECT] HIGH BEACONING alert")
    time.sleep(2)


def sim2_high_frequency():
    """
    Make 25 rapid connections to different ports on the same host.
    This mimics a port scanner or a process dumping data to many
    destinations quickly — both are exfiltration indicators.

    We vary the port so the beaconing detector doesn't fire (that
    keys on same dst:port). What triggers here is the per-process
    total connection rate crossing FREQ_THRESHOLD=20 in 30 seconds.

    Expected EDR output:
      [CONNECT] HIGH score=40 | HIGH_FREQUENCY: N connections in 30s
    """
    print(f"\n{SEPARATOR}")
    print("SIM 2: High-frequency connection burst")
    print(f"Making 25 rapid connections to {TEST_HOST} on varying ports...")
    print(SEPARATOR)

    # Ports 1-25 — most will be refused but the connect() syscall
    # still fires and gets caught by the eBPF probe before the
    # kernel returns ECONNREFUSED
    for i, port in enumerate(range(1, 26)):
        try:
            s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            s.settimeout(1)
            s.connect((TEST_HOST, port))
            s.close()
        except Exception:
            pass  # connection refused is expected — we only care that connect() fired
        print(f"  attempt {i+1}/25 -> port {port}")

    print("Check collector for [CONNECT] HIGH HIGH_FREQUENCY alert")
    time.sleep(2)


def sim3_sensitive_port():
    """
    Connect to port 4444 — the default Metasploit meterpreter
    listener port. This is in the SENSITIVE_PORTS list in
    network_analyzer.py and adds score regardless of frequency.

    The connection will be refused since nothing is listening,
    but the connect() syscall fires before the kernel returns
    ECONNREFUSED — the eBPF probe catches it at the syscall
    boundary, not at connection success.

    Expected EDR output:
      [CONNECT] score includes +30 for sensitive port 4444
    """
    print(f"\n{SEPARATOR}")
    print("SIM 3: Sensitive port connection (port 4444 — Metasploit default)")
    print(f"Connecting to {TEST_HOST}:4444...")
    print(SEPARATOR)

    try:
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.settimeout(3)
        s.connect((TEST_HOST, 4444))
        s.close()
        print("  connected (unexpected)")
    except Exception as e:
        print(f"  refused as expected: {e}")

    print("Check collector for [CONNECT] alert with sensitive port score")
    time.sleep(2)


def main():
    print("EDR Attack Simulator — network exfil edition")
    print("Run sudo python3 agent/collector.py in another terminal first.\n")

    sim1_c2_beaconing()
    sim2_high_frequency()
    sim3_sensitive_port()

    print(f"\n{SEPARATOR}")
    print("All simulations complete.")
    print(SEPARATOR)


if __name__ == "__main__":
    main()
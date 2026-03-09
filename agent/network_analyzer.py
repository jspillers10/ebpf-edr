import time
import socket
from collections import defaultdict, deque
from config_loader import CONFIG

# This module sits between the raw connect() events from network_monitor.c
# and the alert stream. It looks for two threat patterns:
#
# 1. BEACONING — a process connects to the same destination repeatedly
#    at regular intervals. This is the C2 (command and control) pattern:
#    malware "calls home" on a timer to receive instructions or exfiltrate
#    data. A browser loading a page hits many different IPs once each.
#    Malware hits ONE IP over and over on a schedule.
#
# 2. HIGH-FREQUENCY CONNECTIONS — a process makes a large number of
#    outbound connections in a short window. This covers port scanning,
#    brute force attempts, and data exfiltration bursts.

SENSITIVE_PORTS = {
    entry["port"]: entry["label"] for entry in CONFIG["sensitive_ports"]
}

# Processes that make lots of outbound connections legitimately.
# Browsers, package managers, update daemons
NOISY_PROCESSES = set(CONFIG["noisy_processes"])

class ConnectionTracker:
    BEACON_WINDOW        = CONFIG["thresholds"]["beacon_window_seconds"]
    BEACON_MIN_HITS      = CONFIG["thresholds"]["beacon_min_hits"]
    FREQ_WINDOW          = CONFIG["thresholds"]["freq_window_seconds"]
    FREQ_THRESHOLD       = CONFIG["thresholds"]["freq_threshold"]
    FREQ_THRESHOLD_NOISY = CONFIG["thresholds"]["freq_threshold_noisy"]

    def __init__(self):
        # (pid, daddr, dport) -> deque of timestamps
        self.dst_history  = defaultdict(deque)
        # pid -> deque of timestamps (all connections)
        self.freq_history = defaultdict(deque)
        self.last_cleanup = time.time()

    def record(self, pid, comm, daddr, dport):
        now = time.time()
        key = (comm, daddr, dport)
        self.dst_history[key].append(now)
        self.freq_history[pid].append(now)

    def beacon_count(self, comm, daddr, dport):
        # Expire entries outside the window, return count of remaining
        now = time.time()
        key = (comm, daddr, dport)
        d   = self.dst_history[key]
        while d and now - d[0] > self.BEACON_WINDOW:
            d.popleft()
        return len(d)

    def freq_count(self, pid):
        now = time.time()
        d   = self.freq_history[pid]
        while d and now - d[0] > self.FREQ_WINDOW:
            d.popleft()
        return len(d)

    def cleanup(self):
        # Drop empty deques to prevent memory growth from dead processes
        self.dst_history  = defaultdict(deque, {k: v for k, v in self.dst_history.items()  if v})
        self.freq_history = defaultdict(deque, {k: v for k, v in self.freq_history.items() if v})

class NetworkAnalyzer:

    def __init__(self):
        self.tracker      = ConnectionTracker()
        self.last_cleanup = time.time()
        # Track already alerted beaconing keys so we do not repeat every hit
        self.alerted_beacons = set()

    def evaluate_connect(self, pid, ppid, uid, comm, daddr, dport, af):
        """
        Called for every connect() event from network_monitor.c.
        Returns a verdict dict or None if nothing notable.

        Verdict keys:
          score    - int, higher = more suspicious
          reasons  - list of strings
          severity - INFO / HIGH / CRITICAL
          dst_str  - human readable destination (IP:port)
        """

        verdict = {
            "score":   0,
            "reasons": [],
            "severity": "INFO",
            "dst_str":  "",
        }

        # Format Destination String
        # socket.inet_ntoa() handles IPv4, socket.inet_ntop() handles IPv6.
        # build "ip:port" for IPv4 and "[ip]:port" for IPv6 (RFC 3986).

        try:
            if af == 2:     # AF_INET
                ip_str = socket.inet_ntoa(daddr.to_bytes(4, 'little'))
                verdict["dst_str"] = f"{ip_str}:{dport}"
            else:
                ip_str = socket.inet_ntop(socket.AF_INET6, daddr)
                verdict["dst_str"] = f"[{ip_str}]:{dport}"
        except Exception:
            verdict["dst_str"] = f"<unknown>:{dport}"
            ip_str = "<unknown>"

        # Check 1: Sensitive Port
        # Connecting to SSH/RDP/known backdoor ports is always worth logging.
        # We don't immediately score it high — context matters. curl hitting
        # port 22 during a legit SSH session is fine. An unknown process
        # hitting port 4444 at 3am is not.

        if dport in SENSITIVE_PORTS:
            verdict["score"] += 30
            verdict["reasons"].append(
                f"Connection to sensitive port {dport} ({SENSITIVE_PORTS[dport]})"
            )

        # Check 2: High Frequency Connections
        # Record this connection and check the rate against the window.
        # Noisy processes (browsers, package managers) get a higher threshold
        # so normal update checks don't flood the alert stream.
        self.tracker.record(pid, comm, ip_str, dport)
        freq = self.tracker.freq_count(pid)

        threshold = (
            self.tracker.FREQ_THRESHOLD_NOISY
            if comm in NOISY_PROCESSES
            else self.tracker.FREQ_THRESHOLD
        )

        if freq > threshold:
            verdict["score"] += 40
            verdict["reasons"].append(
                f"High-frequency connections: {freq} in {self.tracker.FREQ_WINDOW}s"
            )
        
        # Check 3: Beaconing Detection
        # If this process has connected to the exact same ip:port multiple
        # times within the beacon window, that's a C2 pattern.
        # We use a (pid, ip, port) key so we're specifically looking for
        # repeated connections to ONE destination — not just high volume.

        beacon_hits = self.tracker.beacon_count(comm, ip_str, dport)
        beacon_key  = (comm, ip_str, dport)

        if beacon_hits >= self.tracker.BEACON_MIN_HITS:
            if beacon_key not in self.alerted_beacons:
                self.alerted_beacons.add(beacon_key)
                verdict["score"] += 60
                verdict["reasons"].append(
                    f"BEACONING: {beacon_hits} connections to {verdict['dst_str']}"
                    f" in {self.tracker.BEACON_WINDOW}s"
                )

        # Severity Assignment

        if verdict["score"] >= 80:
            verdict["severity"] = "CRITICAL"
        elif verdict["score"] >= 40:
            verdict["severity"] = "HIGH"
        elif verdict["score"] > 0:
            verdict["severity"] = "INFO"

        # Periodic Cleanup

        now = time.time()
        if now - self.last_cleanup > 60:
            self.tracker.cleanup()
            self.last_cleanup = now

        if verdict["score"] == 0:
            return None

        return verdict
import time
from collections import defaultdict, deque
from config_loader import CONFIG

# "TRUSTED" means: this behavior from this binary is expected and normal.
#                  Don't suppress the event entirely, but downgrade severity.
#
# "MONITOR" means: this binary is known but the behavior is worth watching.
#                  Log it but don't alert unless rate thresholds are exceeded.


PROCESS_REPUTATION = {}
for _name in CONFIG["reputation"]["trusted"]:
    PROCESS_REPUTATION[_name] = "TRUSTED"
for _name in CONFIG["reputation"]["monitored"]:
    PROCESS_REPUTATION[_name] = "MONITOR"
for _name in CONFIG["reputation"]["suspicious"]:
    PROCESS_REPUTATION[_name] = "SUSPICIOUS"

# These files are so sensitive that ANY unexpected access is worth alerting
# on, regardless of rate. There's almost no legitimate reason for an
# arbitrary process to read /etc/shadow or an SSH private key.
HIGH_VALUE_FILES = {}
for _path in CONFIG["high_value_files"]["credential_files"]:
    HIGH_VALUE_FILES[_path] = "CREDENTIAL_ACCESS"
for _path in CONFIG["high_value_files"]["secret_stores"]:
    HIGH_VALUE_FILES[_path] = "SECRET_STORE"
for _path in CONFIG["high_value_files"]["system_integrity"]:
    HIGH_VALUE_FILES[_path] = "SYSTEM_INTEGRITY"

NOISY_PROCESSES = set(CONFIG["noisy_processes"])

class SlidingWindowCounter:
    def __init__(self, window_seconds=30):
        self.window = window_seconds
        self.events = defaultdict(deque)

    def record(self, pid):
        """Record an event for this pid right now"""
        now = time.time()
        self.events[pid].append(now)

    def count(self, pid):
        """How many events has this pid had in the last window_seconds?"""
        now = time.time()
        dq = self.events[pid]

        # Pop expired timestamps off the left side
        # (the deque is time-ordered, so the oldest are always on the left)
        while dq and (now - dq[0]) > self.window:
            dq.popleft()

        return len(dq)

    def cleanup(self):
        """Remove pids with empty deques to prevent memory growth."""
        empty = [pid for pid, dq in self.events.items() if not dq]
        for pid in empty:
            del self.events[pid]


# The key design decision here is that we return a SCORE, not just a
# boolean. This is how real detection systems work — a score lets you
# tune sensitivity without rewriting logic. A score of 0 means totally
# normal. 100 means drop everything and look at this right now.
#
# Scores are additive. Each suspicious signal adds to the score:
#   - Unknown process touching /proc = +20
#   - Rate above low threshold      = +30
#   - Rate above high threshold     = +50
#   - High-value file accessed      = +60
#   - Write to sensitive file       = +40 on top of that

class AnomalyEngine:
    # Thresholds for /proc enumeration rate (per 30-second window)
    # Below LOW  = normal, no rate penalty
    # Above LOW  = suspicious, add to score
    # Above HIGH = strong recon signal, major score increase
    PROC_RATE_LOW  = CONFIG["thresholds"]["proc_rate_low"]
    PROC_RATE_HIGH = CONFIG["thresholds"]["proc_rate_high"]

    def __init__(self):
        # One sliding window counter for /proc enumeration per process
        self.proc_counter = SlidingWindowCounter(window_seconds=CONFIG["thresholds"]["proc_window_seconds"])

        # Track which pids we've already alerted on for high-value files
        self.alerted_file_access = set()

        # Track the last time we ran cleanup
        self.last_cleanup = time.time()

    def evaluate_openat(self, pid, ppid, uid, comm, filename, iswrite):
        """
        Called for every openat event that passes the collector's filter.
        Returns a dict describing the verdict, or None if nothing notable.

        The return dict has:
          score    - int 0-100+ (higher = more suspicious)
          reasons  - list of strings explaining why the score is what it is
          severity - "INFO", "HIGH", or "CRITICAL"
          suppress - bool, True if we should log quietly instead of alerting
        """

        verdict = {
            "score":    0,
            "reasons":  [],
            "severity": "INFO",
            "suppress":  False,
        }

        # Check 1: Process Reputation
        reputation = None
        for path, rep in PROCESS_REPUTATION.items():
            if comm == path.split("/")[-1]:
                reputation = rep  # basename comparison
                break
        
        if reputation == "TRUSTED":
            return None
        
        if reputation == "MONITOR":
            verdict["reasons"].append(f"{comm} is a monitored tool (known debugger/profiler)")
        
        if reputation is None:
            # Unknown process
            verdict["score"] += 20
            verdict["reasons"].append(f"Unknown process '{comm}' (not in reputation list)")

        # Check 2: High Value File Access
        target_type = None
        for hv_path, access_type in HIGH_VALUE_FILES.items():
            if filename.startswith(hv_path):
                target_type = access_type
                break

        if target_type:
            alert_key = (pid, filename)

            if alert_key not in self.alerted_file_access:
                self.alerted_file_access.add(alert_key)
                verdict["score"] += 60
                verdict["reasons"].append(
                    f"Accessed high-value file: {filename} [{target_type}]"
                )

                if iswrite:
                    verdict["score"] += 40
                    verdict["reasons"].append(
                        f"WRITE access to sensitive file - potential tampering"
                    )

        # Check 3: /proc Enumeration Rate
        # If this is a /proc/<pid>/ access, record it in our sliding window
        # and check if the rate looks like recon behavior.
        #
        # We only count /proc/<numeric_pid>/ paths — not /proc/self/ or
        # /proc/meminfo, which are normal single-target reads.
        # The recon pattern is specifically iterating over OTHER processes.

        if filename.startswith("/proc/"):
            parts = filename.split("/")
            # parts looks like ['', 'proc', '1234', 'maps']
            # We want parts[2] to be a numeric pid (not 'self', 'sys', etc.)
            if len(parts) >= 3 and parts[2].isdigit():
                target_pid = int(parts[2])

                # Don't count a process reading its own /proc entry
                if target_pid != pid:
                    self.proc_counter.record(pid)
                    rate = self.proc_counter.count(pid)

                    if comm in NOISY_PROCESSES:
                        noisy_threshold = CONFIG["thresholds"]["proc_rate_noisy"]
                        if rate > noisy_threshold:
                            verdict["score"] += 50
                            verdict["reasons"].append(
                                f"/proc enumeration rate CRITICAL: {rate} reads in 30s"
                                f" (threshold: {noisy_threshold})"
                            )
                    else:
                        if rate > self.PROC_RATE_HIGH:
                            verdict["score"] += 50
                            verdict["reasons"].append(
                                f"/proc enumeration rate CRITICAL: {rate} reads in 30s"
                                f" (threshold: {self.PROC_RATE_HIGH})"
                            )
                        elif rate > self.PROC_RATE_LOW:
                            verdict["score"] += 30
                            verdict["reasons"].append(
                                f"/proc enumeration rate elevated: {rate} reads in 30s"
                                f" (threshold: {self.PROC_RATE_LOW})"
                            )
        
        # Assign Final Severity
        if verdict["score"] >= 80:
            verdict["severity"] = "CRITICAL"
        elif verdict["score"] >= 40:
            verdict["severity"] = "HIGH"
        elif verdict["score"] > 0:
            verdict["severity"] = "INFO"

        
        # Periodic Cleanup
        now = time.time()
        if now - self.last_cleanup > 60:
            self.proc_counter.cleanup()
            self.last_cleanup = now

        # Only return a verdict if there's actually something to report
        if verdict["score"] == 0 and not verdict["reasons"]:
            return None

        return verdict
    

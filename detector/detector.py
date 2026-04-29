import time
import threading
from collections import defaultdict, deque

class AnomalyDetector:
    def __init__(self, config: dict, baseline_tracker):
        self.config = config
        self.baseline = baseline_tracker
        self.lock = threading.Lock()

        # Sliding window settings
        self.ip_window_seconds = config["window"]["per_ip_seconds"]
        self.global_window_seconds = config["window"]["global_seconds"]

        # Detection thresholds from config
        self.zscore_threshold = config["detection"]["zscore_threshold"]
        self.rate_multiplier = config["detection"]["rate_multiplier"]
        self.error_rate_multiplier = config["detection"]["error_rate_multiplier"]

        # Per-IP sliding windows
        # Each IP gets a deque of request timestamps
        # deque automatically evicts old entries when maxlen is hit
        # but we use time-based eviction so no maxlen here
        self.ip_request_times = defaultdict(deque)  # {ip: deque([t1, t2, t3...])}
        self.ip_error_times = defaultdict(deque)     # {ip: deque([t1, t2...])}

        # Global sliding window — all requests regardless of IP
        self.global_request_times = deque()

        # Track how many times each IP has been banned (for backoff schedule)
        self.ip_ban_count = defaultdict(int)

        print("[detector] Initialized. Monitoring traffic...")

    def record_request(self, source_ip: str, status_code: int):
        """
        Record a new request. Called for every log line parsed.
        Updates both per-IP and global sliding windows.
        """
        now = time.time()

        with self.lock:
            # Add this request's timestamp to the IP's deque
            self.ip_request_times[source_ip].append(now)
            self.global_request_times.append(now)

            # Track errors per IP
            if status_code >= 400:
                self.ip_error_times[source_ip].append(now)

            # Evict old entries from all windows
            self._evict_old(source_ip, now)

    def _evict_old(self, source_ip: str, now: float):
        """
        Remove timestamps that are outside the sliding window.
        This is the core of the deque-based sliding window.

        We popleft() (remove from front) while the oldest timestamp
        is more than window_seconds ago. The deque stays sorted
        because we always append to the right (newest at right).
        """
        ip_cutoff = now - self.ip_window_seconds
        global_cutoff = now - self.global_window_seconds

        # Evict old IP requests
        while (self.ip_request_times[source_ip] and
               self.ip_request_times[source_ip][0] < ip_cutoff):
            self.ip_request_times[source_ip].popleft()

        # Evict old IP errors
        while (self.ip_error_times[source_ip] and
               self.ip_error_times[source_ip][0] < ip_cutoff):
            self.ip_error_times[source_ip].popleft()

        # Evict old global requests
        while (self.global_request_times and
               self.global_request_times[0] < global_cutoff):
            self.global_request_times.popleft()

    def get_ip_rate(self, source_ip: str) -> int:
        """How many requests has this IP made in the last 60 seconds?"""
        with self.lock:
            return len(self.ip_request_times[source_ip])

    def get_global_rate(self) -> int:
        """How many total requests in the last 60 seconds?"""
        with self.lock:
            return len(self.global_request_times)

    def get_ip_error_rate(self, source_ip: str) -> int:
        """How many errors has this IP triggered in the last 60 seconds?"""
        with self.lock:
            return len(self.ip_error_times[source_ip])

    def check_ip(self, source_ip: str) -> dict | None:
        """
        Check if a specific IP is behaving anomalously.
        Returns a dict describing the anomaly, or None if all is fine.
        """
        baseline = self.baseline.get_baseline()
        mean = baseline["effective_mean"]
        stddev = baseline["effective_stddev"]
        error_mean = baseline["error_mean"]

        ip_rate = self.get_ip_rate(source_ip)
        ip_errors = self.get_ip_error_rate(source_ip)

        # Check if this IP has a high error rate
        # If so, tighten the detection thresholds
        error_surge = False
        effective_zscore_threshold = self.zscore_threshold
        effective_rate_multiplier = self.rate_multiplier

        if error_mean > 0 and ip_errors >= self.error_rate_multiplier * error_mean:
            error_surge = True
            # Tighten thresholds — easier to trigger a ban
            effective_zscore_threshold = self.zscore_threshold * 0.6
            effective_rate_multiplier = self.rate_multiplier * 0.6

        # Calculate z-score for this IP's rate
        zscore = self.baseline.get_zscore(ip_rate)

        # Check both conditions — whichever fires first triggers the anomaly
        anomaly = None

        if zscore > effective_zscore_threshold:
            anomaly = {
                "type": "ip",
                "source_ip": source_ip,
                "condition": "zscore",
                "rate": ip_rate,
                "baseline_mean": mean,
                "baseline_stddev": stddev,
                "zscore": round(zscore, 2),
                "error_surge": error_surge,
            }
        elif ip_rate > effective_rate_multiplier * mean:
            anomaly = {
                "type": "ip",
                "source_ip": source_ip,
                "condition": "rate_multiplier",
                "rate": ip_rate,
                "baseline_mean": mean,
                "baseline_stddev": stddev,
                "zscore": round(zscore, 2),
                "error_surge": error_surge,
            }

        return anomaly

    def check_global(self) -> dict | None:
        """
        Check if overall traffic is anomalous.
        Returns anomaly dict or None.
        """
        baseline = self.baseline.get_baseline()
        mean = baseline["effective_mean"]
        stddev = baseline["effective_stddev"]

        global_rate = self.get_global_rate()
        zscore = self.baseline.get_zscore(global_rate)

        if zscore > self.zscore_threshold:
            return {
                "type": "global",
                "condition": "zscore",
                "rate": global_rate,
                "baseline_mean": mean,
                "baseline_stddev": stddev,
                "zscore": round(zscore, 2),
            }
        elif global_rate > self.rate_multiplier * mean:
            return {
                "type": "global",
                "condition": "rate_multiplier",
                "rate": global_rate,
                "baseline_mean": mean,
                "baseline_stddev": stddev,
                "zscore": round(zscore, 2),
            }

        return None

    def get_top_ips(self, n: int = 10) -> list:
        """Return top N IPs by request count in the current window."""
        with self.lock:
            ip_counts = {
                ip: len(times)
                for ip, times in self.ip_request_times.items()
                if times
            }
            sorted_ips = sorted(ip_counts.items(), key=lambda x: x[1], reverse=True)
            return sorted_ips[:n]

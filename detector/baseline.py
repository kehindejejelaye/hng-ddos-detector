import time
import math
import threading
from collections import deque

class BaselineTracker:
    def __init__(self, config: dict):
        self.config = config
        self.lock = threading.Lock()

        # How many minutes of history to keep
        window_minutes = config["baseline"]["window_minutes"]
        self.max_seconds = window_minutes * 60  # 30 min = 1800 seconds

        # A deque of (timestamp, count) tuples — one entry per second
        # maxlen automatically evicts old entries when full
        self.per_second_counts = deque(maxlen=self.max_seconds)

        # Per-hour slots: store mean/stddev for each hour of the day (0-23)
        # This lets us have different baselines for busy vs quiet hours
        self.hourly_slots = {}  # {hour: {"mean": x, "stddev": y, "count": n}}

        # The current computed baseline values
        self.effective_mean = config["baseline"]["floor_mean"]
        self.effective_stddev = config["baseline"]["floor_stddev"]

        # For error rate baseline
        self.error_mean = 0.0
        self.error_stddev = 0.0

        # When we last recalculated
        self.last_recalc = time.time()
        self.recalc_interval = config["baseline"]["recalc_interval"]

        # Minimum requests before we trust the baseline
        self.min_requests = config["baseline"]["min_requests"]

        # Floor values — never go below these
        self.floor_mean = config["baseline"]["floor_mean"]
        self.floor_stddev = config["baseline"]["floor_stddev"]

        # Track requests per second in real time
        self.current_second = int(time.time())
        self.current_count = 0
        self.current_error_count = 0

        # Per-second error counts for error baseline
        self.per_second_errors = deque(maxlen=self.max_seconds)

        print("[baseline] Initialized. Learning traffic patterns...")

    def record_request(self, status_code: int):
        """
        Called for every incoming request.
        Buckets requests into per-second counts.
        """
        with self.lock:
            now = int(time.time())

            if now != self.current_second:
                # We've moved to a new second — save the previous second's count
                self.per_second_counts.append((self.current_second, self.current_count))
                self.per_second_errors.append((self.current_second, self.current_error_count))

                # Reset for the new second
                self.current_second = now
                self.current_count = 0
                self.current_error_count = 0

            self.current_count += 1

            # Track errors (4xx and 5xx status codes)
            if status_code >= 400:
                self.current_error_count += 1

        # Recalculate baseline if enough time has passed
        if time.time() - self.last_recalc >= self.recalc_interval:
            self._recalculate()

    def _recalculate(self):
        """
        Recompute mean and stddev from the rolling window.
        Called every 60 seconds automatically.
        """
        with self.lock:
            self.last_recalc = time.time()
            current_hour = int(time.strftime("%H"))

            counts = [count for _, count in self.per_second_counts]
            errors = [count for _, count in self.per_second_errors]

            if len(counts) < self.min_requests:
                # Not enough data yet — keep floor values
                print(f"[baseline] Not enough data yet ({len(counts)} samples). Using floor values.")
                return

            # Calculate mean and stddev from the rolling window
            mean = sum(counts) / len(counts)
            variance = sum((x - mean) ** 2 for x in counts) / len(counts)
            stddev = math.sqrt(variance)

            # Apply floor values so we never divide by zero or get absurd sensitivity
            mean = max(mean, self.floor_mean)
            stddev = max(stddev, self.floor_stddev)

            # Save to hourly slot
            self.hourly_slots[current_hour] = {
                "mean": mean,
                "stddev": stddev,
                "count": len(counts)
            }

            # Prefer current hour's baseline if it has enough data
            if len(counts) >= self.min_requests:
                self.effective_mean = mean
                self.effective_stddev = stddev
            elif current_hour in self.hourly_slots:
                self.effective_mean = self.hourly_slots[current_hour]["mean"]
                self.effective_stddev = self.hourly_slots[current_hour]["stddev"]

            # Calculate error baseline
            if errors:
                error_mean = sum(errors) / len(errors)
                error_variance = sum((x - error_mean) ** 2 for x in errors) / len(errors)
                self.error_mean = max(error_mean, 0.1)
                self.error_stddev = max(math.sqrt(error_variance), 0.1)

            print(f"[baseline] Recalculated — mean={self.effective_mean:.2f} "
                  f"stddev={self.effective_stddev:.2f} "
                  f"samples={len(counts)} "
                  f"hour={current_hour}")

    def get_zscore(self, rate: float) -> float:
        """
        Calculate how abnormal a given rate is.
        Z-score = (value - mean) / stddev
        Above 3.0 = very unusual
        """
        with self.lock:
            return (rate - self.effective_mean) / self.effective_stddev

    def get_baseline(self) -> dict:
        """Return current baseline values for display and logging."""
        with self.lock:
            return {
                "effective_mean": round(self.effective_mean, 2),
                "effective_stddev": round(self.effective_stddev, 2),
                "error_mean": round(self.error_mean, 2),
                "hourly_slots": dict(self.hourly_slots),
                "sample_count": len(self.per_second_counts),
            }

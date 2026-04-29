import requests
import time
import threading
import logging
import os

class AuditLogger:
    def __init__(self, audit_path: str):
        self.lock = threading.Lock()
        self.audit_path = audit_path

        # Set up Python logger writing to audit file
        self.logger = logging.getLogger("audit")
        self.logger.setLevel(logging.INFO)

        # Create directory if it doesn't exist
        os.makedirs(os.path.dirname(audit_path), exist_ok=True)

        handler = logging.FileHandler(audit_path)
        handler.setFormatter(logging.Formatter("%(message)s"))
        self.logger.addHandler(handler)

        print(f"[audit] Writing audit log to {audit_path}")

    def log_ban(self, ip: str, condition: str, rate: float, baseline: float, duration: str):
        """Write a structured ban entry to the audit log."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        entry = (
            f"[{timestamp}] BAN "
            f"ip={ip} | "
            f"condition={condition} | "
            f"rate={rate} | "
            f"baseline={baseline:.2f} | "
            f"duration={duration}"
        )
        with self.lock:
            self.logger.info(entry)
        print(f"[audit] {entry}")

    def log_unban(self, ip: str, condition: str, rate: float, baseline: float):
        """Write a structured unban entry to the audit log."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        entry = (
            f"[{timestamp}] UNBAN "
            f"ip={ip} | "
            f"condition={condition} | "
            f"rate={rate} | "
            f"baseline={baseline:.2f} | "
            f"duration=expired"
        )
        with self.lock:
            self.logger.info(entry)
        print(f"[audit] {entry}")

    def log_baseline_recalc(self, mean: float, stddev: float, samples: int):
        """Write a baseline recalculation entry to the audit log."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        entry = (
            f"[{timestamp}] BASELINE_RECALC "
            f"ip=N/A | "
            f"condition=recalculation | "
            f"rate=N/A | "
            f"baseline={mean:.2f} | "
            f"stddev={stddev:.2f} | "
            f"samples={samples}"
        )
        with self.lock:
            self.logger.info(entry)
        print(f"[audit] {entry}")


class Notifier:
    def __init__(self, config: dict, audit_logger: AuditLogger):
        self.webhook_url = config["slack"]["webhook_url"]
        self.audit = audit_logger
        print("[notifier] Initialized. Slack alerts ready.")

    def _send(self, message: str):
        """
        Send a message to Slack via webhook.
        Just a simple HTTP POST — no SDK needed.
        """
        try:
            response = requests.post(
                self.webhook_url,
                json={"text": message},
                timeout=5,
            )
            if response.status_code != 200:
                print(f"[notifier] Slack error: {response.status_code} {response.text}")
        except requests.RequestException as e:
            print(f"[notifier] Failed to send Slack alert: {e}")

    def send_ban_alert(self, anomaly: dict, duration: str):
        """Send a Slack alert when an IP is banned."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        ip = anomaly.get("source_ip", "unknown")
        condition = anomaly.get("condition", "unknown")
        rate = anomaly.get("rate", 0)
        baseline = anomaly.get("baseline_mean", 0)
        zscore = anomaly.get("zscore", 0)
        error_surge = anomaly.get("error_surge", False)

        error_note = " Error surge detected — thresholds tightened." if error_surge else ""

        message = (
            f"*IP BANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Condition:* {condition}\n"
            f"*Current Rate:* {rate} req/60s\n"
            f"*Baseline Mean:* {baseline:.2f} req/s\n"
            f"*Z-Score:* {zscore}\n"
            f"*Ban Duration:* {duration}\n"
            f"*Timestamp:* {timestamp}"
            f"{error_note}"
        )

        self._send(message)

    def send_unban_alert(self, ip: str, ban_info: dict):
        """Send a Slack alert when an IP is unbanned."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        duration = ban_info.get("duration", "unknown")
        ban_count = ban_info.get("ban_count", 1)

        message = (
            f"*IP UNBANNED*\n"
            f"*IP:* `{ip}`\n"
            f"*Ban Duration Served:* {duration}s\n"
            f"*Total Bans for this IP:* {ban_count}\n"
            f"*Timestamp:* {timestamp}"
        )

        self._send(message)

    def send_global_alert(self, anomaly: dict):
        """Send a Slack alert for a global traffic anomaly."""
        timestamp = time.strftime("%Y-%m-%dT%H:%M:%S")
        condition = anomaly.get("condition", "unknown")
        rate = anomaly.get("rate", 0)
        baseline = anomaly.get("baseline_mean", 0)
        zscore = anomaly.get("zscore", 0)

        message = (
            f"*GLOBAL TRAFFIC ANOMALY*\n"
            f"*Condition:* {condition}\n"
            f"*Current Global Rate:* {rate} req/60s\n"
            f"*Baseline Mean:* {baseline:.2f} req/s\n"
            f"*Z-Score:* {zscore}\n"
            f"*Action:* Alert only (no IP to block)\n"
            f"*Timestamp:* {timestamp}"
        )

        self._send(message)

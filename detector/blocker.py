import subprocess
import threading
import time
from collections import defaultdict

class Blocker:
    def __init__(self, config: dict, notifier, audit_logger):
        self.config = config
        self.notifier = notifier
        self.audit = audit_logger
        self.lock = threading.Lock()

        # Ban durations from config: [600, 1800, 7200] seconds
        self.ban_durations = config["ban"]["durations"]

        # Currently banned IPs
        # {ip: {"banned_at": timestamp, "duration": seconds, "ban_count": n}}
        self.banned_ips = {}

        # How many times each IP has been banned (persists across unbans)
        self.ban_counts = defaultdict(int)

        print("[blocker] Initialized. Ready to block IPs.")

    def ban_ip(self, anomaly: dict):
        """
        Add an iptables DROP rule for the given IP.
        Called when detector flags an IP anomaly.
        """
        source_ip = anomaly["source_ip"]

        with self.lock:
            # Don't double-ban an already banned IP
            if source_ip in self.banned_ips:
                return

            # Increment ban count to determine duration (backoff schedule)
            self.ban_counts[source_ip] += 1
            ban_number = self.ban_counts[source_ip]

            # Pick duration based on how many times this IP has been banned
            # 1st ban: 600s, 2nd ban: 1800s, 3rd ban: 7200s, 4th+: permanent
            if ban_number <= len(self.ban_durations):
                duration = self.ban_durations[ban_number - 1]
                permanent = False
            else:
                duration = None
                permanent = True

            # Run the iptables command to block the IP
            success = self._add_iptables_rule(source_ip)

            if not success:
                print(f"[blocker] Failed to add iptables rule for {source_ip}")
                return

            # Record the ban
            self.banned_ips[source_ip] = {
                "banned_at": time.time(),
                "duration": duration,
                "permanent": permanent,
                "ban_count": ban_number,
                "condition": anomaly.get("condition", "unknown"),
                "rate": anomaly.get("rate", 0),
                "baseline_mean": anomaly.get("baseline_mean", 0),
            }

            duration_str = "permanent" if permanent else f"{duration}s"
            print(f"[blocker] Banned {source_ip} | duration={duration_str} | ban #{ban_number}")

            # Write to audit log
            self.audit.log_ban(
                ip=source_ip,
                condition=anomaly.get("condition"),
                rate=anomaly.get("rate"),
                baseline=anomaly.get("baseline_mean"),
                duration=duration_str,
            )

            # Send Slack alert
            self.notifier.send_ban_alert(anomaly, duration_str)

    def unban_ip(self, source_ip: str):
        """
        Remove the iptables DROP rule for an IP.
        Called by the unbanner on schedule.
        """
        with self.lock:
            if source_ip not in self.banned_ips:
                return

            ban_info = self.banned_ips[source_ip]

            # Remove the iptables rule
            success = self._remove_iptables_rule(source_ip)

            if success:
                del self.banned_ips[source_ip]
                print(f"[blocker] Unbanned {source_ip}")

                # Write to audit log
                self.audit.log_unban(
                    ip=source_ip,
                    condition=ban_info.get("condition"),
                    rate=ban_info.get("rate"),
                    baseline=ban_info.get("baseline_mean"),
                )

                # Send Slack alert
                self.notifier.send_unban_alert(source_ip, ban_info)
            else:
                print(f"[blocker] Failed to remove iptables rule for {source_ip}")

    def _add_iptables_rule(self, ip: str) -> bool:
        """Run iptables to DROP all packets from this IP."""
        try:
            subprocess.run(
                ["iptables", "-I", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"[blocker] iptables error: {e.stderr.decode()}")
            return False

    def _remove_iptables_rule(self, ip: str) -> bool:
        """Run iptables to remove the DROP rule for this IP."""
        try:
            subprocess.run(
                ["iptables", "-D", "INPUT", "-s", ip, "-j", "DROP"],
                check=True,
                capture_output=True,
            )
            return True
        except subprocess.CalledProcessError as e:
            print(f"[blocker] iptables remove error: {e.stderr.decode()}")
            return False

    def get_banned_ips(self) -> dict:
        """Return currently banned IPs for the dashboard."""
        with self.lock:
            return dict(self.banned_ips)

    def is_banned(self, ip: str) -> bool:
        """Check if an IP is currently banned."""
        with self.lock:
            return ip in self.banned_ips

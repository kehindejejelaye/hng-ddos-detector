import time
import threading

class Unbanner:
    def __init__(self, blocker):
        self.blocker = blocker
        self.running = False
        print("[unbanner] Initialized. Will check bans every 30 seconds.")

    def start(self):
        """Start the unbanner in a background thread."""
        self.running = True
        thread = threading.Thread(target=self._run, daemon=True)
        thread.start()
        print("[unbanner] Background thread started.")

    def _run(self):
        """
        Main loop — runs forever, checking every 30 seconds
        whether any banned IPs should be released.
        """
        while self.running:
            self._check_bans()
            time.sleep(30)

    def _check_bans(self):
        """
        Look at every banned IP and unban those whose time is up.
        Permanent bans are never released automatically.
        """
        now = time.time()

        # Get a snapshot of banned IPs
        # We copy the dict so we can iterate while potentially modifying it
        banned = self.blocker.get_banned_ips()

        for ip, ban_info in banned.items():
            # Skip permanent bans
            if ban_info.get("permanent", False):
                continue

            banned_at = ban_info.get("banned_at", now)
            duration = ban_info.get("duration", 600)

            # Check if the ban duration has elapsed
            elapsed = now - banned_at
            if elapsed >= duration:
                print(f"[unbanner] Ban expired for {ip} "
                      f"(duration={duration}s, elapsed={elapsed:.0f}s)")
                self.blocker.unban_ip(ip)

    def stop(self):
        self.running = False

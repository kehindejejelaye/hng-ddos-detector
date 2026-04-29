import queue
import threading
import time
import yaml

from monitor import tail_log
from baseline import BaselineTracker
from detector import AnomalyDetector
from blocker import Blocker
from unbanner import Unbanner
from notifier import Notifier, AuditLogger
from dashboard import Dashboard

def load_config(path: str = "config.yaml") -> dict:
    with open(path, "r") as f:
        return yaml.safe_load(f)

def main():
    print("=" * 50)
    print("  HNG DDoS Detection Engine Starting...")
    print("=" * 50)

    config = load_config()
    print("[main] Config loaded.")

    audit = AuditLogger(config["log"]["audit_path"])
    baseline = BaselineTracker(config)
    notifier = Notifier(config, audit)
    blocker = Blocker(config, notifier, audit)
    detector = AnomalyDetector(config, baseline)
    unbanner = Unbanner(blocker)
    dashboard = Dashboard(config, detector, blocker, baseline)

    log_queue = queue.Queue()

    monitor_thread = threading.Thread(
        target=tail_log,
        args=(config["log"]["path"], log_queue),
        daemon=True,
        name="monitor",
    )
    monitor_thread.start()
    print("[main] Monitor thread started.")

    unbanner.start()
    dashboard.start()

    def baseline_audit_loop():
        while True:
            time.sleep(60)
            info = baseline.get_baseline()
            audit.log_baseline_recalc(
                mean=info["effective_mean"],
                stddev=info["effective_stddev"],
                samples=info["sample_count"],
            )

    audit_thread = threading.Thread(
        target=baseline_audit_loop,
        daemon=True,
        name="baseline-audit",
    )
    audit_thread.start()

    recently_flagged = {}
    flag_cooldown = 30
    global_alert_cooldown = 60
    last_global_alert = 0
    processed_count = 0

    print("[main] All systems running. Watching for anomalies...")
    print(f"[main] Dashboard: http://0.0.0.0:{config['dashboard']['port']}")
    print("[main] Waiting for log entries...\n")

    while True:
        try:
            entry = log_queue.get(timeout=1)
            processed_count += 1

            source_ip = entry["source_ip"]
            status_code = entry["status"]

            # Debug every 10th entry
            if processed_count % 10 == 0:
                print(f"[main] Processed {processed_count} entries. "
                      f"Last IP: {source_ip} "
                      f"Queue size: {log_queue.qsize()}")

            baseline.record_request(status_code)
            detector.record_request(source_ip, status_code)

            if _is_private_ip(source_ip):
                continue

            now = time.time()
            last_flagged = recently_flagged.get(source_ip, 0)

            if now - last_flagged > flag_cooldown:
                anomaly = detector.check_ip(source_ip)
                if anomaly and not blocker.is_banned(source_ip):
                    recently_flagged[source_ip] = now
                    print(f"[main] ⚠️  IP anomaly detected: {source_ip} "
                          f"rate={anomaly['rate']} "
                          f"zscore={anomaly['zscore']}")
                    blocker.ban_ip(anomaly)

            if now - last_global_alert > global_alert_cooldown:
                global_anomaly = detector.check_global()
                if global_anomaly:
                    last_global_alert = now
                    print(f"[main] 🌍 Global anomaly detected: "
                          f"rate={global_anomaly['rate']} "
                          f"zscore={global_anomaly['zscore']}")
                    notifier.send_global_alert(global_anomaly)

        except queue.Empty:
            continue
        except KeyboardInterrupt:
            print("\n[main] Shutting down...")
            unbanner.stop()
            break
        except Exception as e:
            print(f"[main] Unexpected error: {e}")
            continue

def _is_private_ip(ip: str) -> bool:
    private_prefixes = (
        "10.", "172.", "192.168.", "127.", "::1", "unknown"
    )
    return ip.startswith(private_prefixes)

if __name__ == "__main__":
    main()

import json
import time
import queue
import os

def tail_log(log_path: str, log_queue: queue.Queue):
    while not os.path.exists(log_path):
        print(f"[monitor] Waiting for log file: {log_path}")
        time.sleep(2)

    print(f"[monitor] Log file found. Starting to tail: {log_path}")

    with open(log_path, "r") as f:
        # Read last 200 lines to bootstrap baseline
        print("[monitor] Bootstrapping baseline from recent log history...")
        lines = f.readlines()
        recent = lines[-200:] if len(lines) > 200 else lines
        bootstrap_count = 0
        for line in recent:
            line = line.strip()
            if not line:
                continue
            entry = parse_line(line)
            if entry:
                log_queue.put(entry)
                bootstrap_count += 1
        print(f"[monitor] Bootstrapped {bootstrap_count} historical entries.")

        # Now tail from end for new lines
        f.seek(0, 2)
        while True:
            line = f.readline()
            if not line:
                time.sleep(0.05)
                continue
            line = line.strip()
            if not line:
                continue
            entry = parse_line(line)
            if entry:
                log_queue.put(entry)

def parse_line(line: str) -> dict:
    try:
        data = json.loads(line)

        source_ip = data.get("source_ip", "").strip()
        if not source_ip or source_ip == "-" or source_ip == "":
            source_ip = data.get("remote_addr", "unknown").strip()

        if "," in source_ip:
            source_ip = source_ip.split(",")[0].strip()

        if not source_ip:
            source_ip = "unknown"

        return {
            "source_ip": source_ip,
            "timestamp": data.get("timestamp", ""),
            "method": data.get("method", ""),
            "path": data.get("path", ""),
            "status": int(data.get("status", 0)),
            "response_size": int(data.get("response_size", 0)),
        }

    except (json.JSONDecodeError, ValueError):
        return None

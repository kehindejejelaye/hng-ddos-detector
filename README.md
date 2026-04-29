# HNG DDoS Detection Engine

A real-time anomaly detection and DDoS mitigation daemon built alongside a Nextcloud deployment. It watches Nginx access logs, learns normal traffic patterns, and automatically blocks suspicious IPs using iptables — all without any rate-limiting libraries.

---

## Live URLs
- **Metrics Dashboard:** http://kehinde-jejelaye.ddns.net
- **Nextcloud:** http://167.172.134.69 (accessible by IP only)

---

## Language Choice
**Python** — chosen for its readable syntax, excellent standard library support for threading and queues, and the `collections.deque` data structure which maps perfectly to a sliding window implementation. The goal was to write detection logic from scratch without leaning on external rate-limiting libraries, and Python made that straightforward.

---

## Architecture Overview

```
Internet Traffic
      ↓
   [Nginx] — reverse proxy, writes JSON access logs to shared Docker volume
      ↓
   [Nextcloud] — the protected application
      ↓
   [Detector Daemon] — tails the log, runs detection, manages bans
      ↓               ↓                    ↓
  [iptables]     [Slack Alerts]       [Dashboard]
  (blocks IPs)   (ban/unban/global)   (live metrics)
```

---

## How the Sliding Window Works

Every IP gets its own `collections.deque` storing request timestamps:

```python
self.ip_request_times = defaultdict(deque)
```

When a request arrives, its timestamp is appended to the right. On every check, we evict old entries from the left:

```python
while self.ip_request_times[ip][0] < now - 60:
    self.ip_request_times[ip].popleft()
```

The length of the deque at any moment = requests from that IP in the last 60 seconds. No counters, no libraries — just timestamps and time comparison. A separate global deque tracks all requests across all IPs.

---

## How the Baseline Works

- **Window size:** 30 minutes of per-second request counts stored in a deque
- **Recalculation interval:** Every 60 seconds, mean and stddev are recomputed from the window
- **Hourly slots:** Each hour of the day (0–23) gets its own baseline slot, so midnight traffic and peak-hour traffic are judged separately
- **Floor values:** mean floors at 0.1, stddev floors at 0.1 — prevents division by zero and avoids oversensitivity during quiet periods
- **Bootstrap:** On startup, the last 200 Nginx log lines are replayed to seed the baseline immediately rather than waiting for live traffic

---

## How Detection Works

For every request processed, two conditions are checked:

1. **Z-score check:** `(current_rate - mean) / stddev > 2.0`
2. **Rate multiplier check:** `current_rate > 3x mean`

Whichever fires first triggers the response. Additionally, if an IP's 4xx/5xx error rate exceeds 2x the baseline error rate, its detection thresholds are automatically tightened (multiplied by 0.6) — making it easier to ban repeat offenders causing errors.

---

## How iptables Blocking Works

When an IP is flagged as anomalous:

```bash
iptables -I INPUT -s <IP> -j DROP
```

This inserts a DROP rule at the top of the kernel's INPUT chain. All packets from that IP are silently discarded before they reach Nginx — the attacker gets no response at all.

Bans are released automatically on a progressive backoff schedule:
- 1st offence → 10 minutes
- 2nd offence → 30 minutes  
- 3rd offence → 2 hours
- 4th+ offence → permanent

Every ban and unban triggers a Slack notification.

---

## Repository Structure

```
detector/
  main.py          # Entry point, main processing loop
  monitor.py       # Tails and parses Nginx JSON logs
  baseline.py      # Rolling baseline tracker (mean, stddev, hourly slots)
  detector.py      # Sliding window + anomaly detection logic
  blocker.py       # iptables ban/unban management
  unbanner.py      # Background thread for auto-unban on schedule
  notifier.py      # Slack alerts + structured audit logging
  dashboard.py     # Flask web dashboard (port 5000)
  config.yaml      # All thresholds and settings (no hardcoded values)
  requirements.txt # Python dependencies
nginx/
  nginx.conf       # Reverse proxy config with JSON logging
docs/
  architecture.png
screenshots/
README.md
```

---

## Setup Instructions

### Prerequisites
- Ubuntu 24.04 VPS (minimum 2 vCPU, 2GB RAM)
- Docker and Docker Compose v2
- A Slack incoming webhook URL
- A domain or subdomain pointing to your server IP

### 1. Clone the repository
```bash
git clone https://github.com/kehindejejelaye/hng-ddos-detector.git
cd hng-ddos-detector
```

### 2. Add your Slack webhook URL
```bash
nano detector/config.yaml
# Replace YOUR_SLACK_WEBHOOK_URL with your actual webhook URL
```

### 3. Start the full stack
```bash
docker compose up -d
```

### 4. Trust your server IP in Nextcloud
```bash
docker exec -u www-data nextcloud php occ config:system:set trusted_domains 0 --value="YOUR_SERVER_IP"
```

### 5. Configure your domain
Point your domain/subdomain to your server IP, then update `nginx/nginx.conf` with your domain in the second server block. Restart Nginx:
```bash
docker compose restart nginx
```

### 6. Verify everything is running
```bash
docker compose ps
docker compose logs detector -f
```

The dashboard will be live at your domain. The detector starts processing logs immediately.

---

## Configuration Reference

All thresholds live in `detector/config.yaml` — nothing is hardcoded:

| Setting | Default | Description |
|---|---|---|
| `window.per_ip_seconds` | 60 | Sliding window size per IP |
| `window.global_seconds` | 60 | Global sliding window size |
| `baseline.window_minutes` | 30 | Rolling baseline history |
| `baseline.recalc_interval` | 60 | Seconds between recalculations |
| `detection.zscore_threshold` | 2.0 | Z-score trigger threshold |
| `detection.rate_multiplier` | 3.0 | Rate multiple trigger threshold |
| `ban.durations` | [600, 1800, 7200] | Ban backoff schedule in seconds |

---

## Blog Post
[Your Server Is Under Attack. Here's How I Built Something That Fights Back.](https://kehindejejelaye.hashnode.dev/your-server-is-under-attack-here-s-how-i-built-something-that-fights-back)

---

## GitHub Repository
https://github.com/kehindejejelaye/hng-ddos-detector

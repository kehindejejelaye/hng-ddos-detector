import time
import threading
import psutil
from flask import Flask, jsonify, render_template_string

# HTML template for the dashboard
# This is served at http://YOUR_IP:5000
DASHBOARD_HTML = """
<!DOCTYPE html>
<html>
<head>
    <title>HNG DDoS Detector</title>
    <meta charset="utf-8">
    <style>
        * { box-sizing: border-box; margin: 0; padding: 0; }
        body {
            font-family: 'Courier New', monospace;
            background: #0a0a0a;
            color: #00ff41;
            padding: 20px;
        }
        h1 {
            font-size: 1.5em;
            margin-bottom: 20px;
            border-bottom: 1px solid #00ff41;
            padding-bottom: 10px;
        }
        .grid {
            display: grid;
            grid-template-columns: repeat(auto-fit, minmax(300px, 1fr));
            gap: 20px;
            margin-bottom: 20px;
        }
        .card {
            background: #111;
            border: 1px solid #00ff41;
            border-radius: 4px;
            padding: 15px;
        }
        .card h2 {
            font-size: 0.9em;
            color: #888;
            margin-bottom: 10px;
            text-transform: uppercase;
        }
        .card .value {
            font-size: 2em;
            color: #00ff41;
        }
        .card .sub {
            font-size: 0.8em;
            color: #666;
            margin-top: 5px;
        }
        table {
            width: 100%;
            border-collapse: collapse;
            font-size: 0.85em;
        }
        th {
            color: #888;
            text-align: left;
            padding: 5px;
            border-bottom: 1px solid #333;
        }
        td {
            padding: 5px;
            border-bottom: 1px solid #1a1a1a;
        }
        .banned { color: #ff4444; }
        .status-bar {
            font-size: 0.75em;
            color: #444;
            margin-top: 20px;
        }
        .blink {
            animation: blink 1s step-end infinite;
        }
        @keyframes blink { 50% { opacity: 0; } }
    </style>
</head>
<body>
    <h1>HNG DDoS Detection Engine <span class="blink">█</span></h1>

    <div class="grid">
        <div class="card">
            <h2>Global Req/s</h2>
            <div class="value" id="global-rate">--</div>
            <div class="sub">requests in last 60s</div>
        </div>
        <div class="card">
            <h2>Baseline Mean</h2>
            <div class="value" id="baseline-mean">--</div>
            <div class="sub">stddev: <span id="baseline-stddev">--</span></div>
        </div>
        <div class="card">
            <h2>CPU Usage</h2>
            <div class="value" id="cpu">--</div>
            <div class="sub">Memory: <span id="memory">--</span></div>
        </div>
        <div class="card">
            <h2>Uptime</h2>
            <div class="value" id="uptime">--</div>
            <div class="sub">Banned IPs: <span id="banned-count">--</span></div>
        </div>
    </div>

    <div class="grid">
        <div class="card">
            <h2>Banned IPs</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Condition</th>
                        <th>Rate</th>
                        <th>Time Left</th>
                    </tr>
                </thead>
                <tbody id="banned-table">
                    <tr><td colspan="4" style="color:#444">No banned IPs</td></tr>
                </tbody>
            </table>
        </div>

        <div class="card">
            <h2>Top 10 Source IPs</h2>
            <table>
                <thead>
                    <tr>
                        <th>IP</th>
                        <th>Requests (60s)</th>
                        <th>Status</th>
                    </tr>
                </thead>
                <tbody id="top-ips-table">
                    <tr><td colspan="3" style="color:#444">No data yet</td></tr>
                </tbody>
            </table>
        </div>
    </div>

    <div class="status-bar">
        Last updated: <span id="last-updated">--</span> |
        Refresh: every 3s |
        Samples: <span id="samples">--</span>
    </div>

    <script>
        function formatDuration(seconds) {
            if (seconds < 0) return "expired";
            if (seconds < 60) return seconds + "s";
            if (seconds < 3600) return Math.floor(seconds/60) + "m " + (seconds%60) + "s";
            return Math.floor(seconds/3600) + "h " + Math.floor((seconds%3600)/60) + "m";
        }

        function fetchAndUpdate() {
            fetch('/api/metrics')
                .then(r => r.json())
                .then(data => {
                    document.getElementById('global-rate').textContent = data.global_rate;
                    document.getElementById('baseline-mean').textContent = data.baseline_mean.toFixed(2);
                    document.getElementById('baseline-stddev').textContent = data.baseline_stddev.toFixed(2);
                    document.getElementById('cpu').textContent = data.cpu + '%';
                    document.getElementById('memory').textContent = data.memory + '%';
                    document.getElementById('uptime').textContent = data.uptime;
                    document.getElementById('banned-count').textContent = data.banned_count;
                    document.getElementById('samples').textContent = data.samples;
                    document.getElementById('last-updated').textContent = new Date().toLocaleTimeString();

                    // Update banned IPs table
                    const bannedTable = document.getElementById('banned-table');
                    if (data.banned_ips.length === 0) {
                        bannedTable.innerHTML = '<tr><td colspan="4" style="color:#444">No banned IPs</td></tr>';
                    } else {
                        bannedTable.innerHTML = data.banned_ips.map(b => `
                            <tr>
                                <td class="banned">${b.ip}</td>
                                <td>${b.condition}</td>
                                <td>${b.rate}</td>
                                <td>${b.permanent ? '♾️ permanent' : formatDuration(b.time_left)}</td>
                            </tr>
                        `).join('');
                    }

                    // Update top IPs table
                    const topTable = document.getElementById('top-ips-table');
                    if (data.top_ips.length === 0) {
                        topTable.innerHTML = '<tr><td colspan="3" style="color:#444">No data yet</td></tr>';
                    } else {
                        topTable.innerHTML = data.top_ips.map(([ip, count]) => `
                            <tr>
                                <td>${ip}</td>
                                <td>${count}</td>
                                <td>${data.banned_ip_set.includes(ip) ?
                                    '<span class="banned">BANNED</span>' :
                                    '<span style="color:#00ff41">OK</span>'}</td>
                            </tr>
                        `).join('');
                    }
                })
                .catch(err => console.error('Fetch error:', err));
        }

        // Fetch immediately then every 3 seconds
        fetchAndUpdate();
        setInterval(fetchAndUpdate, 3000);
    </script>
</body>
</html>
"""

class Dashboard:
    def __init__(self, config: dict, detector, blocker, baseline):
        self.config = config
        self.detector = detector
        self.blocker = blocker
        self.baseline = baseline
        self.port = config["dashboard"]["port"]
        self.start_time = time.time()

        self.app = Flask(__name__)
        self._register_routes()
        print(f"[dashboard] Initialized. Will serve on port {self.port}")

    def _register_routes(self):
        """Define the URL routes for the dashboard."""

        @self.app.route("/")
        def index():
            return render_template_string(DASHBOARD_HTML)

        @self.app.route("/api/metrics")
        def metrics():
            """JSON endpoint that the dashboard JS polls every 3 seconds."""
            now = time.time()

            # Get baseline info
            baseline_info = self.baseline.get_baseline()

            # Get banned IPs
            banned_ips = self.blocker.get_banned_ips()
            banned_list = []
            for ip, info in banned_ips.items():
                time_left = None
                if not info.get("permanent") and info.get("duration"):
                    elapsed = now - info.get("banned_at", now)
                    time_left = int(info["duration"] - elapsed)

                banned_list.append({
                    "ip": ip,
                    "condition": info.get("condition", "unknown"),
                    "rate": info.get("rate", 0),
                    "permanent": info.get("permanent", False),
                    "time_left": time_left,
                })

            # Get top IPs
            top_ips = self.detector.get_top_ips(10)

            # Calculate uptime
            elapsed = int(now - self.start_time)
            hours = elapsed // 3600
            minutes = (elapsed % 3600) // 60
            seconds = elapsed % 60
            uptime_str = f"{hours:02d}:{minutes:02d}:{seconds:02d}"

            return jsonify({
                "global_rate": self.detector.get_global_rate(),
                "baseline_mean": baseline_info["effective_mean"],
                "baseline_stddev": baseline_info["effective_stddev"],
                "cpu": psutil.cpu_percent(interval=None),
                "memory": psutil.virtual_memory().percent,
                "uptime": uptime_str,
                "banned_count": len(banned_ips),
                "banned_ips": banned_list,
                "banned_ip_set": list(banned_ips.keys()),
                "top_ips": top_ips,
                "samples": baseline_info["sample_count"],
            })

    def start(self):
        """Start the Flask dashboard in a background thread."""
        thread = threading.Thread(
            target=lambda: self.app.run(
                host="0.0.0.0",
                port=self.port,
                debug=False,
                use_reloader=False,
            ),
            daemon=True,
        )
        thread.start()
        print(f"[dashboard] Serving at http://0.0.0.0:{self.port}")

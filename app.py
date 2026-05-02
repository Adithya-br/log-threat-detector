# -*- coding: utf-8 -*-
"""
app.py
Flask dashboard for the Log Threat Detection System.
Now with MySQL database integration!
Run with: python app.py
"""

import os
from flask import Flask, render_template, jsonify, Response
from analyzer import LogAnalyzer
from generate_sample_logs import generate_ssh_logs, generate_apache_logs

# MySQL Import
try:
    from database import setup_database, save_alerts_to_db, get_all_alerts, get_scan_history, get_top_attacker_ips
    DB_AVAILABLE = True
    print("[+] database.py loaded successfully!")
except Exception as e:
    DB_AVAILABLE = False
    print(f"[!] database.py import failed: {e}")

app = Flask(__name__)

SSH_LOG    = "logs/auth.log"
APACHE_LOG = "logs/apache_access.log"
ALERTS_LOG = "logs/alerts.log"


def run_analysis():
    analyzer = LogAnalyzer(alerts_file=ALERTS_LOG)
    analyzer.parse_ssh_log(SSH_LOG)
    analyzer.parse_apache_log(APACHE_LOG)
    analyzer.detect()
    analyzer.save_alerts()
    if DB_AVAILABLE:
        try:
            save_alerts_to_db(analyzer.alerts, analyzer.get_stats())
            print("[+] Alerts saved to MySQL!")
        except Exception as e:
            print(f"[!] MySQL save error: {e}")
    return analyzer


@app.route("/")
def index():
    analyzer  = run_analysis()
    alerts    = [a.to_dict() for a in analyzer.alerts]
    stats     = analyzer.get_stats()
    db_status = "Connected" if DB_AVAILABLE else "Not Connected"
    db_alerts = get_all_alerts(50)      if DB_AVAILABLE else []
    scan_hist = get_scan_history(5)     if DB_AVAILABLE else []
    top_ips   = get_top_attacker_ips(5) if DB_AVAILABLE else []
    return render_template("dashboard.html",
        alerts=alerts, stats=stats, db_status=db_status,
        db_alerts=db_alerts, scan_history=scan_hist, top_ips=top_ips)


@app.route("/api/analyze")
def api_analyze():
    analyzer = run_analysis()
    return jsonify({"alerts": [a.to_dict() for a in analyzer.alerts], "stats": analyzer.get_stats()})


@app.route("/api/regenerate", methods=["POST"])
def api_regenerate():
    generate_ssh_logs(SSH_LOG)
    generate_apache_logs(APACHE_LOG)
    analyzer = run_analysis()
    return jsonify({"message": "Done", "alerts": [a.to_dict() for a in analyzer.alerts], "stats": analyzer.get_stats()})


@app.route("/api/db-history")
def api_db_history():
    if not DB_AVAILABLE:
        return jsonify({"error": "MySQL not connected"}), 503
    return jsonify({
        "alerts":       get_all_alerts(50),
        "scan_history": get_scan_history(10),
        "top_ips":      get_top_attacker_ips(5),
    })


@app.route("/log-raw/ssh")
def log_raw_ssh():
    content = open(SSH_LOG).read() if os.path.exists(SSH_LOG) else ""
    return Response(content, mimetype="text/plain")


@app.route("/log-raw/apache")
def log_raw_apache():
    content = open(APACHE_LOG).read() if os.path.exists(APACHE_LOG) else ""
    return Response(content, mimetype="text/plain")


@app.route("/alerts-log")
def view_alerts_log():
    content = open(ALERTS_LOG).read() if os.path.exists(ALERTS_LOG) else ""
    return f"<pre style='background:#0d1117;color:#58a6ff;padding:2rem;font-family:monospace;'>{content}</pre>"


if __name__ == "__main__":
    os.makedirs("logs", exist_ok=True)
    if DB_AVAILABLE:
        try:
            setup_database()
        except Exception as e:
            print(f"[!] MySQL setup failed: {e}")
    if not os.path.exists(SSH_LOG):
        generate_ssh_logs(SSH_LOG)
    if not os.path.exists(APACHE_LOG):
        generate_apache_logs(APACHE_LOG)
    print("\nThreatWatch --> http://127.0.0.1:5000\n")
    app.run(debug=True, port=5000)
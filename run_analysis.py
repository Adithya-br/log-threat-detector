"""
run_analysis.py
CLI entry point — generates sample logs and runs full threat detection.
Use this if you don't want to run the Flask dashboard.
"""

import os
from generate_sample_logs import generate_ssh_logs, generate_apache_logs
from analyzer import LogAnalyzer

SSH_LOG    = "logs/auth.log"
APACHE_LOG = "logs/apache_access.log"
ALERTS_LOG = "logs/alerts.log"

def main():
    print("=" * 60)
    print("  🔒 LOG THREAT DETECTION SYSTEM")
    print("=" * 60)

    os.makedirs("logs", exist_ok=True)

    print("\n[1/3] Generating sample logs...")
    generate_ssh_logs(SSH_LOG)
    generate_apache_logs(APACHE_LOG)

    print("\n[2/3] Parsing logs...")
    analyzer = LogAnalyzer(alerts_file=ALERTS_LOG)
    analyzer.parse_ssh_log(SSH_LOG)
    analyzer.parse_apache_log(APACHE_LOG)

    print("\n[3/3] Running threat detection rules...")
    analyzer.detect()

    analyzer.print_summary()
    analyzer.save_alerts()

    print(f"\n[✓] Done! Check '{ALERTS_LOG}' for the full report.\n")

if __name__ == "__main__":
    main()

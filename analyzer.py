# -*- coding: utf-8 -*-
"""
analyzer.py
Core threat detection engine — parses SSH & Apache logs, applies detection rules,
generates alerts, and saves them to alerts.log
"""

import re
import os
from datetime import datetime
from collections import defaultdict

# Detection Thresholds
SSH_BRUTE_FORCE_THRESHOLD = 5
APACHE_SCAN_THRESHOLD = 8
SUSPICIOUS_STATUS_CODES = {401, 403, 404, 500}
CRITICAL_PATHS = ["/.env", "/phpmyadmin", "/wp-login.php", "/admin", "/.git"]

# Regex Patterns
SSH_FAILED_RE   = re.compile(r"Failed password for (?:invalid user )?(\S+) from (\d+\.\d+\.\d+\.\d+)")
SSH_INVALID_RE  = re.compile(r"Invalid user (\S+) from (\d+\.\d+\.\d+\.\d+)")
SSH_ACCEPTED_RE = re.compile(r"Accepted (?:password|publickey) for (\S+) from (\d+\.\d+\.\d+\.\d+)")
APACHE_RE       = re.compile(
    r'(\d+\.\d+\.\d+\.\d+) .+ \[(.+?)\] "(\S+) (\S+) HTTP/[\d.]+" (\d{3}) (\d+)'
)


class Alert:
    SEVERITY_LEVELS = {"LOW": "🟡", "MEDIUM": "🟠", "HIGH": "🔴", "CRITICAL": "🚨"}

    def __init__(self, severity, alert_type, ip, description, count=None, events=None):
        self.timestamp   = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        self.severity    = severity
        self.alert_type  = alert_type
        self.ip          = ip
        self.description = description
        self.count       = count
        self.events      = events or []   # list of event detail dicts
        self.icon        = self.SEVERITY_LEVELS.get(severity, "⚠️")

    def __str__(self):
        count_str = f" [{self.count} events]" if self.count else ""
        return (
            f"[{self.timestamp}] {self.icon} [{self.severity}] {self.alert_type}{count_str}\n"
            f"    IP: {self.ip}\n"
            f"    {self.description}"
        )

    def to_dict(self):
        return {
            "timestamp":   self.timestamp,
            "severity":    self.severity,
            "type":        self.alert_type,
            "ip":          self.ip,
            "description": self.description,
            "count":       self.count,
            "icon":        self.icon,
            "events":      self.events,
        }


class LogAnalyzer:
    def __init__(self, alerts_file="logs/alerts.log"):
        self.alerts_file = alerts_file
        self.alerts = []

        # SSH state
        self.ssh_failed   = defaultdict(list)   # ip -> [usernames]
        self.ssh_invalid  = defaultdict(list)
        self.ssh_accepted = []

        # Apache state
        self.apache_suspicious = defaultdict(list)  # ip -> [(status, path)]
        self.apache_all        = []

    def parse_ssh_log(self, filepath):
        if not os.path.exists(filepath):
            print(f"[!] SSH log not found: {filepath}")
            return
        with open(filepath) as f:
            lines = f.readlines()
        print(f"[*] Parsing SSH log: {filepath} ({len(lines)} lines)")
        for line in lines:
            m = SSH_FAILED_RE.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                self.ssh_failed[ip].append(user)
                continue
            m = SSH_INVALID_RE.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                self.ssh_invalid[ip].append(user)
                continue
            m = SSH_ACCEPTED_RE.search(line)
            if m:
                user, ip = m.group(1), m.group(2)
                self.ssh_accepted.append({"ip": ip, "user": user})

    def parse_apache_log(self, filepath):
        if not os.path.exists(filepath):
            print(f"[!] Apache log not found: {filepath}")
            return
        with open(filepath) as f:
            lines = f.readlines()
        print(f"[*] Parsing Apache log: {filepath} ({len(lines)} lines)")
        for line in lines:
            m = APACHE_RE.search(line)
            if not m:
                continue
            ip, ts, method, path, status_str, size = m.groups()
            status = int(status_str)
            entry = {"ip": ip, "timestamp": ts, "method": method,
                     "path": path, "status": status, "size": int(size)}
            self.apache_all.append(entry)
            if status in SUSPICIOUS_STATUS_CODES:
                self.apache_suspicious[ip].append((status, path))

    # ── Detection Rules ────────────────────────────────────────────────────────

    def _rule_ssh_brute_force(self):
        for ip, users in self.ssh_failed.items():
            count = len(users)
            if count >= SSH_BRUTE_FORCE_THRESHOLD:
                unique_users = list(set(users))
                severity = "CRITICAL" if count >= 15 else "HIGH"
                # Build event list — each failed attempt as a row
                events = [
                    {"col1": f"Attempt #{i+1}", "col2": f"User: {u}", "col3": "Failed Password", "col4": ip}
                    for i, u in enumerate(users)
                ]
                self.alerts.append(Alert(
                    severity   = severity,
                    alert_type = "SSH Brute Force Attack",
                    ip         = ip,
                    description = (
                        f"Possible brute force attack from IP {ip} — "
                        f"{count} failed login attempts targeting users: {', '.join(unique_users[:5])}"
                        + (" ..." if len(unique_users) > 5 else "")
                    ),
                    count  = count,
                    events = events,
                ))

    def _rule_ssh_invalid_users(self):
        for ip, users in self.ssh_invalid.items():
            count = len(users)
            if count >= 3:
                unique_users = list(set(users))
                events = [
                    {"col1": f"Probe #{i+1}", "col2": f"Username: {u}", "col3": "Invalid User", "col4": ip}
                    for i, u in enumerate(users)
                ]
                self.alerts.append(Alert(
                    severity   = "HIGH",
                    alert_type = "SSH User Enumeration",
                    ip         = ip,
                    description = (
                        f"User enumeration detected from IP {ip} — "
                        f"probed {count} invalid usernames: {', '.join(unique_users)}"
                    ),
                    count  = count,
                    events = events,
                ))

    def _rule_apache_scan(self):
        for ip, evts in self.apache_suspicious.items():
            count = len(evts)
            if count >= APACHE_SCAN_THRESHOLD:
                status_counts = defaultdict(int)
                for status, _ in evts:
                    status_counts[status] += 1
                status_summary = ", ".join(f"{s}x{c}" for s, c in sorted(status_counts.items()))
                severity = "CRITICAL" if count >= 15 else "HIGH"
                events = [
                    {"col1": f"Request #{i+1}", "col2": path, "col3": f"HTTP {status}", "col4": ip}
                    for i, (status, path) in enumerate(evts)
                ]
                self.alerts.append(Alert(
                    severity   = severity,
                    alert_type = "Apache Directory/Auth Scan",
                    ip         = ip,
                    description = (
                        f"Possible web scan from IP {ip} — "
                        f"{count} suspicious responses ({status_summary})"
                    ),
                    count  = count,
                    events = events,
                ))

    def _rule_critical_path_access(self):
        hits = defaultdict(list)
        for entry in self.apache_all:
            if any(entry["path"].startswith(p) for p in CRITICAL_PATHS):
                hits[entry["ip"]].append(entry)

        for ip, entries in hits.items():
            paths = [e["path"] for e in entries]
            events = [
                {"col1": f"Access #{i+1}", "col2": e["path"], "col3": f"HTTP {e['status']}", "col4": e["method"]}
                for i, e in enumerate(entries)
            ]
            self.alerts.append(Alert(
                severity   = "CRITICAL",
                alert_type = "Sensitive Path Access",
                ip         = ip,
                description = (
                    f"Access to sensitive paths from IP {ip}: {', '.join(set(paths))}"
                ),
                count  = len(paths),
                events = events,
            ))

    def _rule_high_error_rate(self):
        error_entries = defaultdict(list)
        for entry in self.apache_all:
            if entry["status"] == 500:
                error_entries[entry["ip"]].append(entry)

        for ip, entries in error_entries.items():
            count = len(entries)
            if count >= 3:
                events = [
                    {"col1": f"Error #{i+1}", "col2": e["path"], "col3": "HTTP 500", "col4": e["method"]}
                    for i, e in enumerate(entries)
                ]
                self.alerts.append(Alert(
                    severity   = "MEDIUM",
                    alert_type = "HTTP 500 Error Spike",
                    ip         = ip,
                    description = (
                        f"Server error spike ({count} x HTTP 500) from IP {ip} — "
                        "possible injection or exploit attempt"
                    ),
                    count  = count,
                    events = events,
                ))

    def detect(self):
        print("\n[*] Running detection rules...\n")
        self._rule_ssh_brute_force()
        self._rule_ssh_invalid_users()
        self._rule_apache_scan()
        self._rule_critical_path_access()
        self._rule_high_error_rate()
        order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3}
        self.alerts.sort(key=lambda a: order.get(a.severity, 9))
        return self.alerts

    def save_alerts(self):
        os.makedirs(os.path.dirname(self.alerts_file), exist_ok=True)
        with open(self.alerts_file, "w") as f:
            f.write("=" * 70 + "\n")
            f.write(f"  LOG THREAT DETECTION REPORT — {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 70 + "\n\n")
            if not self.alerts:
                f.write("No threats detected.\n")
            else:
                for i, alert in enumerate(self.alerts, 1):
                    f.write(f"[Alert #{i}]\n{alert}\n\n")
            f.write("=" * 70 + "\n")
            f.write(f"Total Alerts: {len(self.alerts)}\n")
        print(f"\n[✓] Alerts saved to {self.alerts_file}")

    def print_summary(self):
        print("\n" + "=" * 70)
        print("  THREAT DETECTION SUMMARY")
        print("=" * 70)
        if not self.alerts:
            print("  No threats detected.")
        else:
            for i, alert in enumerate(self.alerts, 1):
                print(f"\n[Alert #{i}]\n{alert}")
        print("\n" + "=" * 70)

    def get_stats(self):
        all_ips = set(list(self.ssh_failed.keys()) +
                      list(self.ssh_invalid.keys()) +
                      list(self.apache_suspicious.keys()))
        return {
            "total_alerts":         len(self.alerts),
            "critical":             sum(1 for a in self.alerts if a.severity == "CRITICAL"),
            "high":                 sum(1 for a in self.alerts if a.severity == "HIGH"),
            "medium":               sum(1 for a in self.alerts if a.severity == "MEDIUM"),
            "ssh_failed_attempts":  sum(len(v) for v in self.ssh_failed.values()),
            "ssh_accepted":         len(self.ssh_accepted),
            "apache_requests":      len(self.apache_all),
            "apache_suspicious":    sum(len(v) for v in self.apache_suspicious.values()),
            "unique_attacker_ips":  len(all_ips),
        }

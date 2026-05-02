# -*- coding: utf-8 -*-
"""
database.py
Handles all MySQL database operations — creating tables, inserting alerts,
and fetching alert history.
"""

import mysql.connector
from datetime import datetime

# ─── MySQL Connection Settings ────────────────────────────────────────────────
# Change these to match your MySQL setup
DB_CONFIG = {
    "host":     "localhost",
    "port":     3307,
    "user":     "root",
    "password": "adithya2104",
    "database": "threatwatch"
}

def get_connection():
    """Create and return a MySQL connection."""
    return mysql.connector.connect(**DB_CONFIG)


def setup_database():
    """
    Creates the database and alerts table if they don't exist.
    Run this once when setting up the project.
    """
    try:
        # Connect without specifying database first
        conn = mysql.connector.connect(
            host=DB_CONFIG["host"],
            user=DB_CONFIG["user"],
            password=DB_CONFIG["password"]
        )
        cursor = conn.cursor()

        # Create database
        cursor.execute("CREATE DATABASE IF NOT EXISTS threatwatch")
        cursor.execute("USE threatwatch")

        # Create alerts table
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS alerts (
                id          INT AUTO_INCREMENT PRIMARY KEY,
                timestamp   DATETIME NOT NULL,
                severity    VARCHAR(20) NOT NULL,
                alert_type  VARCHAR(100) NOT NULL,
                ip_address  VARCHAR(50) NOT NULL,
                description TEXT NOT NULL,
                event_count INT DEFAULT NULL,
                created_at  DATETIME DEFAULT CURRENT_TIMESTAMP
            )
        """)

        # Create scan_sessions table (tracks each time analysis is run)
        cursor.execute("""
            CREATE TABLE IF NOT EXISTS scan_sessions (
                id             INT AUTO_INCREMENT PRIMARY KEY,
                scanned_at     DATETIME DEFAULT CURRENT_TIMESTAMP,
                total_alerts   INT DEFAULT 0,
                critical_count INT DEFAULT 0,
                high_count     INT DEFAULT 0,
                medium_count   INT DEFAULT 0,
                ssh_attempts   INT DEFAULT 0,
                web_requests   INT DEFAULT 0
            )
        """)

        conn.commit()
        cursor.close()
        conn.close()
        print("[+] Database 'threatwatch' and tables created successfully!")
        return True

    except mysql.connector.Error as e:
        print(f"[!] Database setup error: {e}")
        return False


def save_alerts_to_db(alerts, stats):
    """
    Saves all alerts from current analysis run into MySQL.
    Also logs the scan session summary.
    """
    try:
        conn = get_connection()
        cursor = conn.cursor()

        # Insert each alert
        for alert in alerts:
            cursor.execute("""
                INSERT INTO alerts (timestamp, severity, alert_type, ip_address, description, event_count)
                VALUES (%s, %s, %s, %s, %s, %s)
            """, (
                alert.timestamp,
                alert.severity,
                alert.alert_type,
                alert.ip,
                alert.description,
                alert.count
            ))

        # Insert scan session summary
        cursor.execute("""
            INSERT INTO scan_sessions (total_alerts, critical_count, high_count, medium_count, ssh_attempts, web_requests)
            VALUES (%s, %s, %s, %s, %s, %s)
        """, (
            stats["total_alerts"],
            stats["critical"],
            stats["high"],
            stats["medium"],
            stats["ssh_failed_attempts"],
            stats["apache_requests"]
        ))

        conn.commit()
        cursor.close()
        conn.close()
        print(f"[+] {len(alerts)} alerts saved to MySQL database!")
        return True

    except mysql.connector.Error as e:
        print(f"[!] Error saving to database: {e}")
        return False


def get_all_alerts(limit=100):
    """Fetch recent alerts from database for dashboard history tab."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM alerts
            ORDER BY id ASC
            LIMIT %s
        """, (limit,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        # Convert datetime objects to strings
        for row in rows:
            for key in ["timestamp", "created_at"]:
                if row.get(key) and hasattr(row[key], "strftime"):
                    row[key] = row[key].strftime("%Y-%m-%d %H:%M:%S")
        return rows
    except mysql.connector.Error as e:
        print(f"[!] Error fetching alerts: {e}")
        return []


def get_scan_history(limit=10):
    """Fetch recent scan sessions for trend display."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT * FROM scan_sessions
            ORDER BY scanned_at DESC
            LIMIT %s
        """, (limit,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        for row in rows:
            if row.get("scanned_at") and hasattr(row["scanned_at"], "strftime"):
                row["scanned_at"] = row["scanned_at"].strftime("%Y-%m-%d %H:%M:%S")
        return rows
    except mysql.connector.Error as e:
        print(f"[!] Error fetching scan history: {e}")
        return []


def get_top_attacker_ips(limit=5):
    """Get the most frequently appearing attacker IPs from database."""
    try:
        conn = get_connection()
        cursor = conn.cursor(dictionary=True)
        cursor.execute("""
            SELECT ip_address, COUNT(*) as alert_count, MAX(severity) as max_severity
            FROM alerts
            GROUP BY ip_address
            ORDER BY alert_count DESC
            LIMIT %s
        """, (limit,))
        rows = cursor.fetchall()
        cursor.close()
        conn.close()
        return rows
    except mysql.connector.Error as e:
        print(f"[!] Error fetching top IPs: {e}")
        return []


def clear_old_alerts(days=7):
    """Delete alerts older than X days to keep database clean."""
    try:
        conn = get_connection()
        cursor = conn.cursor()
        cursor.execute("""
            DELETE FROM alerts
            WHERE created_at < NOW() - INTERVAL %s DAY
        """, (days,))
        deleted = cursor.rowcount
        conn.commit()
        cursor.close()
        conn.close()
        print(f"[+] Cleared {deleted} old alerts (older than {days} days)")
        return deleted
    except mysql.connector.Error as e:
        print(f"[!] Error clearing old alerts: {e}")
        return 0


if __name__ == "__main__":
    print("Setting up ThreatWatch database...")
    setup_database()

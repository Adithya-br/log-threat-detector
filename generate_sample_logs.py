"""
generate_sample_logs.py
Generates realistic sample SSH and Apache access logs for testing.
"""

import random
from datetime import datetime, timedelta

# --- Config ---
SUSPICIOUS_IPS = ["192.168.1.105", "10.0.0.77", "45.33.32.156"]
LEGIT_IPS = ["203.0.113.10", "198.51.100.5", "192.0.2.20", "172.16.0.50"]
USERS = ["root", "admin", "ubuntu", "deploy", "user1", "postgres", "git"]
APACHE_PATHS = ["/", "/login", "/admin", "/wp-login.php", "/api/v1/users", "/dashboard", "/.env", "/phpmyadmin"]

def random_time(start, end):
    delta = end - start
    return start + timedelta(seconds=random.randint(0, int(delta.total_seconds())))

def generate_ssh_logs(filepath="logs/auth.log"):
    end = datetime.now()
    start = end - timedelta(hours=6)
    lines = []

    # Inject brute force attacks from suspicious IPs
    for attacker_ip in SUSPICIOUS_IPS:
        attack_start = random_time(start, end - timedelta(minutes=10))
        attempts = random.randint(8, 20)
        for i in range(attempts):
            t = attack_start + timedelta(seconds=i * random.randint(2, 8))
            user = random.choice(["root", "admin", "ubuntu"])
            lines.append((t, f"{t.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000,9999)}]: Failed password for {user} from {attacker_ip} port {random.randint(40000,60000)} ssh2"))

    # Normal failed logins
    for _ in range(10):
        ip = random.choice(LEGIT_IPS)
        t = random_time(start, end)
        user = random.choice(USERS)
        lines.append((t, f"{t.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000,9999)}]: Failed password for {user} from {ip} port {random.randint(40000,60000)} ssh2"))

    # Successful logins
    for _ in range(5):
        ip = random.choice(LEGIT_IPS)
        t = random_time(start, end)
        user = random.choice(["ubuntu", "deploy"])
        lines.append((t, f"{t.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000,9999)}]: Accepted password for {user} from {ip} port {random.randint(40000,60000)} ssh2"))

    # Invalid user attempts
    for attacker_ip in SUSPICIOUS_IPS[:2]:
        for _ in range(random.randint(3, 7)):
            t = random_time(start, end)
            fake_user = random.choice(["oracle", "test", "guest", "ftp", "pi"])
            lines.append((t, f"{t.strftime('%b %d %H:%M:%S')} server sshd[{random.randint(1000,9999)}]: Invalid user {fake_user} from {attacker_ip} port {random.randint(40000,60000)}"))

    lines.sort(key=lambda x: x[0])

    with open(filepath, "w") as f:
        for _, line in lines:
            f.write(line + "\n")

    print(f"[+] Generated SSH log: {filepath} ({len(lines)} entries)")
    return filepath


def generate_apache_logs(filepath="logs/apache_access.log"):
    end = datetime.now()
    start = end - timedelta(hours=6)
    lines = []

    methods = ["GET", "POST", "PUT", "DELETE"]
    status_legit = [200, 301, 304]
    status_suspicious = [401, 403, 404, 500]

    # Normal traffic
    for _ in range(40):
        ip = random.choice(LEGIT_IPS)
        t = random_time(start, end)
        path = random.choice(APACHE_PATHS[:5])
        status = random.choice(status_legit)
        size = random.randint(500, 5000)
        lines.append((t, f'{ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "{random.choice(methods)} {path} HTTP/1.1" {status} {size}'))

    # Suspicious traffic from attacker IPs
    for attacker_ip in SUSPICIOUS_IPS:
        # Many 401/403 attempts (scanning)
        attack_start = random_time(start, end - timedelta(minutes=20))
        for i in range(random.randint(10, 18)):
            t = attack_start + timedelta(seconds=i * random.randint(1, 5))
            path = random.choice(APACHE_PATHS)
            status = random.choice(status_suspicious)
            size = random.randint(100, 800)
            lines.append((t, f'{attacker_ip} - - [{t.strftime("%d/%b/%Y:%H:%M:%S +0000")}] "GET {path} HTTP/1.1" {status} {size}'))

    lines.sort(key=lambda x: x[0])

    with open(filepath, "w") as f:
        for _, line in lines:
            f.write(line + "\n")

    print(f"[+] Generated Apache log: {filepath} ({len(lines)} entries)")
    return filepath


if __name__ == "__main__":
    generate_ssh_logs()
    generate_apache_logs()
    print("[✓] Sample logs generated in logs/ directory")

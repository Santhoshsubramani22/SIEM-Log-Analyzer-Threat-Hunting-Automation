import os
import re
from datetime import datetime

# ===============================
# Configuration
# ===============================
LOG_FILES = [
    "/var/log/auth.log",  # Debian/Ubuntu
    "/var/log/syslog",    # Debian/Ubuntu
    "/var/log/secure"     # RHEL/CentOS
]

OUTPUT_FILE = "siem_alerts.txt"
FAILED_LOGIN_LIMIT = 5

# ===============================
# Helper: Read Log File Safely
# ===============================
def read_log_file(path):
    if not os.path.exists(path):
        return []
    try:
        with open(path, "r", errors="ignore") as f:
            return f.readlines()
    except Exception:
        return []

# ===============================
# Detect Multiple Failed Logins
# ===============================
def detect_failed_logins(lines):
    failed = {}
    alerts = []
    for line in lines:
        if "Failed password" in line:
            match = re.search(r"from ([\d\.]+)", line)
            if match:
                ip = match.group(1)
                failed[ip] = failed.get(ip, 0) + 1

    for ip, count in failed.items():
        if count >= FAILED_LOGIN_LIMIT:
            alerts.append(f"Multiple failed login attempts from IP {ip} ({count} times)")

    return alerts

# ===============================
# Detect Root Logins
# ===============================
def detect_root_logins(lines):
    alerts = []
    for line in lines:
        if "session opened for user root" in line.lower():
            alerts.append("Root login session detected")
    return alerts

# ===============================
# Detect Sudo Usage
# ===============================
def detect_sudo_usage(lines):
    alerts = []
    for line in lines:
        if "sudo:" in line:
            alerts.append(f"Sudo command used: {line.strip()}")
    return alerts

# ===============================
# Detect System Reboots
# ===============================
def detect_reboots(lines):
    alerts = []
    for line in lines:
        if "reboot" in line.lower() or "systemd" in line.lower() and "reboot" in line.lower():
            alerts.append(f"System reboot detected: {line.strip()}")
    return alerts

# ===============================
# Run SIEM Analysis
# ===============================
def run_siem():
    all_lines = []
    for log_file in LOG_FILES:
        all_lines.extend(read_log_file(log_file))

    alerts = []
    alerts.extend(detect_failed_logins(all_lines))
    alerts.extend(detect_root_logins(all_lines))
    alerts.extend(detect_sudo_usage(all_lines))
    alerts.extend(detect_reboots(all_lines))

    with open(OUTPUT_FILE, "a") as f:
        header = (
            "\n" + "=" * 60 + "\n"
            "SIEM LOG ANALYZER & THREAT HUNTING SCRIPT\n"
            f"Analysis Time: {datetime.now()}\n"
            + "=" * 60 + "\n"
        )
        print(header)
        f.write(header)

        if not alerts:
            line = "No suspicious activity detected\n"
            print(line.strip())
            f.write(line)
        else:
            for alert in alerts:
                print(f"[ALERT] {alert}")
                f.write(f"[ALERT] {alert}\n")

        footer = "=" * 60 + f"\nTotal Alerts: {len(alerts)}\n"
        print(footer)
        f.write(footer)

# ===============================
# Entry Point
# ===============================
if __name__ == "__main__":
    run_siem()

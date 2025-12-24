# 🛡️ SIEM Log Analyzer & Threat Hunting Automation (Python)

![Python](https://img.shields.io/badge/Python-3.8%2B-blue)
![Platform](https://img.shields.io/badge/Platform-Linux-lightgrey)
![Security](https://img.shields.io/badge/Security-SIEM%20%26%20Threat%20Hunting-green)
![License](https://img.shields.io/badge/License-Educational-orange)

---

## 📘 Project Overview

The **SIEM Log Analyzer & Threat Hunting Automation** is a **Python-based, log-driven security monitoring tool** that simulates core SIEM (Security Information and Event Management) functionality.

It aggregates **local system logs** and detects suspicious activities, allowing students and security enthusiasts to safely practice **threat hunting** and **security monitoring** in a controlled, legal environment.

---

## ⚠️ Legal & Ethical Disclaimer

> This tool must be used **only on systems you own**.

- Read-only log analysis
- No system or configuration modifications
- No network scanning or attacks
- Designed strictly for **educational and lab use**

The author is not responsible for misuse.

---

## ✨ Key Features

- 📊 Aggregates logs from multiple sources:
  - `/var/log/auth.log`
  - `/var/log/syslog`
  - `/var/log/secure`
- 🚨 Detects common security events:
  - Multiple failed login attempts (brute-force indicators)
  - Root login sessions
  - Sudo command usage
  - System reboot events
- 📝 Append-only alert reporting
- 🧩 Lightweight and dependency-free (Python standard library only)
- 🕵️ Enables historical threat analysis

---

## 🛠️ System Requirements

- **Operating System:** Linux  
- **Python Version:** 3.8 or higher  
- **Dependencies:** None  

Optional (Windows support):
- `pywin32` for Windows Event Log access

Check Python version:
```bash
python3 --version
````

---

## 📂 Project Structure

```
siem_log_analyzer/
├── siem_analyzer.py     # Main SIEM analysis script
├── siem_alerts.txt      # Generated alert report
└── README.md            # Documentation
```

---

## ▶️ How to Run

Execute the analyzer:

```bash
python3 siem_analyzer.py
```

* Alerts are appended to `siem_alerts.txt`
* Can be scheduled with **cron jobs** for periodic monitoring

---

## 📄 Example Output (`siem_alerts.txt`)

```
============================================================
SIEM LOG ANALYZER & THREAT HUNTING SCRIPT
Analysis Time: 2025-12-22 19:15:10
============================================================
[ALERT] Multiple failed login attempts from IP 192.168.1.50 (6 times)
[ALERT] Root login session detected
[ALERT] Sudo command used: user1 : TTY=pts/0 ; PWD=/home/user1 ; USER=root ; COMMAND=/bin/apt update
[ALERT] System reboot detected: Dec 22 18:30:01 hostname systemd[1]: Rebooting system
============================================================
Total Alerts: 4
```

### Alert Explanation

* **Failed logins** → Possible brute-force attempt
* **Root login detected** → Privileged account access
* **Sudo usage** → Administrative command execution
* **System reboot** → System restart event
* **Total Alerts** → Number of detected events in this run

---

## 🔍 How It Works

1. Reads multiple local log files
2. Identifies suspicious patterns and security events
3. Generates alerts based on detection rules
4. Appends results for long-term threat tracking
5. Supports manual or scheduled execution

---

## 💡 Windows Compatibility

* Native implementation targets **Linux log files**
* Windows logs are stored in **Event Viewer**
* Windows support can be added by:

  * Replacing Linux log parsing
  * Using Python libraries such as `pywin32`

---

## 🔐 Safety & Legality Summary

| Feature                  | Status |
| ------------------------ | ------ |
| Read-only log access     | ✅      |
| No system modification   | ✅      |
| No network activity      | ✅      |
| Local system only        | ✅      |
| Safe for labs & students | ✅      |

---

## 🎯 Learning Outcomes

* Understanding SIEM fundamentals
* Log aggregation and analysis techniques
* Threat hunting workflows
* Python pattern detection in logs
* Ethical security monitoring practices

---

## 🔜 Future Enhancements

* Severity scoring (LOW / MEDIUM / HIGH)
* Email alert notifications (lab use)
* Time-based correlation analysis
* Cross-platform support (Linux & Windows)
* Dashboard or visualization integration

---

## 📜 License

This project is released **for educational purposes only**.
Use responsibly on systems you own. Unauthorized use is prohibited.

---

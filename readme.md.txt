#  Host-Based Intrusion Detection System (HIDS)

![Python](https://img.shields.io/badge/Python-3.x-blue?style=for-the-badge&logo=python)
![Security](https://img.shields.io/badge/Security-IDS-red?style=for-the-badge)

## Project Overview
This is a lightweight, signature-based Intrusion Detection System (IDS) built entirely in Python. 

It acts as a security camera for your computer's internal logs. It monitors system files in real-time, analyzes traffic patterns using Regular Expressions (Regex), and triggers alerts when it detects malicious activity like brute-force attacks or suspicious command execution.

**Key Features:**
* **Real-time Monitoring:** Continuously watches log files.
* **Brute Force Detection:** Tracks failed login attempts.
* **Signature Detection:** Identifies known malicious commands (e.g., `rm -rf`).
* **Simulation Mode:** Includes a built-in attack generator.

---

##  How It Works

1.  **File Stream Handling:** Uses pointer-based seeking for efficiency.
2.  **Regex Parsing:** Extracts IP addresses and users from logs.
3.  **State Management:** Uses a sliding time window for tracking failures.

---

## 🚀 How to Run

### 1. Prerequisites
You need Python 3 installed.

### 2. Run in Simulation Mode
To see the detection in action safely:

python py_hids.py --simulate

### 3. Production Mode
To monitor real Linux logs:
1. Open py_hids.py
2. Change LOG_FILE_TO_WATCH to /var/log/auth.log
3. Run with sudo: sudo python py_hids.py

---

## ⚠️ Disclaimer
This tool is for educational purposes.
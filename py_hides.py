import time
import re
import os
import logging
from collections import deque
from datetime import datetime
import threading
import sys


LOG_FILE_TO_WATCH = "dummy_auth.log"
Check_Interval = 0.5
failed_login_window = 60
max_failed_logins = 3


SUSPICIOUS_COMMANDS = [
    r"rm -rf /",
    r"cat /etc/shadow",
    r"nc -e",
    r"nmap",
    r"chmod 777"
]

# --- STATE TRACKING ---
# Stores timestamps of failed logins per IP
failed_login_attempts = {}

# --- LOGGING SETUP ---
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - [HIDS] - %(message)s',
    datefmt='%Y-%m-%d %H:%M:%S'
)


class TermColors:
    RED = '\033[91m'
    GREEN = '\033[92m'
    YELLOW = '\033[93m'
    BLUE = '\033[94m'
    RESET = '\033[0m'


def alert(message, severity="INFO"):
    """
    Trigger an alert. In a real app, this might send an email or Slack webhook.
    """
    color = TermColors.GREEN
    if severity == "WARNING": color = TermColors.YELLOW
    if severity == "CRITICAL": color = TermColors.RED

    print(f"{color}[!] ALERT ({severity}): {message}{TermColors.RESET}")
    logging.warning(f"{severity}: {message}")


def check_failed_logins(line):
    """
    Detects brute force attempts.
    Regex logic depends on standard Linux auth.log formats (SSHD).
    """
    match = re.search(r"Failed password for (?:invalid user )?(\w+) from ([\d\.]+)", line)

    if match:
        user = match.group(1)
        ip = match.group(2)
        now = time.time()

        if ip not in failed_login_attempts:
            failed_login_attempts[ip] = deque()

        failed_login_attempts[ip].append(now)

        while failed_login_attempts[ip] and failed_login_attempts[ip][0] < now - failed_login_window:
            failed_login_attempts[ip].popleft()

        count = len(failed_login_attempts[ip])
        alert(f"Failed login for user '{user}' from IP {ip} ({count}/{max_failed_logins})", "WARNING")

        if count >= max_failed_logins:
            alert(f"POTENTIAL BRUTE FORCE DETECTED FROM {ip}", "CRITICAL")


def check_new_user(line):
    """
    Detects user creation events.
    """
    if "new user: name=" in line:
        user = re.search(r"new user: name=(\w+)", line)
        if user:
            alert(f"New user account created: {user.group(1)}", "CRITICAL")

    if "usermod" in line and "sudo" in line:
        alert(f"User added to SUDO group detected in log: {line.strip()}", "CRITICAL")


def check_suspicious_commands(line):
    """
    Scans for signatures of malicious commands.
    """
    for cmd in SUSPICIOUS_COMMANDS:
        if re.search(cmd, line):
            alert(f"Suspicious command signature detected: '{cmd}'", "CRITICAL")


def monitor_log(filepath):
    """
    The main loop using the 'tail -f' concept.
    """
    print(f"{TermColors.BLUE}[*] Starting HIDS Monitor on {filepath}...{TermColors.RESET}")
    print(f"{TermColors.BLUE}[*] Press Ctrl+C to stop.{TermColors.RESET}")

    try:
        f = open(filepath, 'r')
        f.seek(0, 2)
    except FileNotFoundError:
        print(f"Log file {filepath} not found. Creating it for simulation...")
        open(filepath, 'w').close()
        f = open(filepath, 'r')
        f.seek(0, 2)

    while True:
        line = f.readline()
        if not line:
            time.sleep(Check_Interval)
            continue

        line = line.strip()
        if not line: continue

        # Run detection modules
        check_failed_logins(line)
        check_new_user(line)
        check_suspicious_commands(line)


def run_simulation():
    """
    Writes fake attacks to the log file to demonstrate functionality.
    """
    print(f"{TermColors.YELLOW}[SIMULATION] generating traffic in background...{TermColors.RESET}")
    time.sleep(2)

    attacks = [
        "Oct 10 10:00:01 server sshd[123]: Failed password for root from 192.168.1.105 port 22 ssh2",
        "Oct 10 10:00:02 server sshd[123]: Failed password for root from 192.168.1.105 port 22 ssh2",
        "Oct 10 10:00:03 server sshd[123]: Failed password for root from 192.168.1.105 port 22 ssh2",
        "Oct 10 10:05:00 server sudo:  hacker : TTY=pts/0 ; PWD=/home/hacker ; USER=root ; COMMAND=/bin/cat /etc/shadow",
        "Oct 10 10:10:00 server useradd[456]: new user: name=eviladmin, UID=1002, GID=1002, home=/home/eviladmin, shell=/bin/bash"
    ]

    with open(LOG_FILE_TO_WATCH, "a") as f:
        for attack in attacks:
            time.sleep(1.5)
            f.write(attack + "\n")
            f.flush()


if __name__ == "__main__":

    if not os.path.exists(LOG_FILE_TO_WATCH):
        open(LOG_FILE_TO_WATCH, "w").close()


    if len(sys.argv) > 1 and sys.argv[1] == "--simulate":
        sim_thread = threading.Thread(target=run_simulation)
        sim_thread.daemon = True
        sim_thread.start()

    try:
        monitor_log(LOG_FILE_TO_WATCH)
    except KeyboardInterrupt:
        print(f"\n{TermColors.RED}[*] HIDS Stopped.{TermColors.RESET}")
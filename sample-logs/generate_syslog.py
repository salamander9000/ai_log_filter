#!/usr/bin/env python3
"""
Synthetic syslog generator for PoC testing.

Generates realistic syslog entries at a configurable rate, with
periodic injection of anomalous events (brute force attempts,
OOM kills, segfaults, privilege escalation, etc.).

Output: appends to a file (default /var/log/synthetic/syslog),
which the AI service tails.
"""

import os
import sys
import time
import random
import signal
import datetime
import logging

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s [%(levelname)s] %(message)s",
    stream=sys.stdout,
)
log = logging.getLogger("log-generator")

# Config
OUTPUT_FILE = os.getenv("OUTPUT_FILE", "/var/log/synthetic/syslog")
EVENTS_PER_SEC = float(os.getenv("EVENTS_PER_SEC", "5"))
ANOMALY_RATIO = float(os.getenv("ANOMALY_RATIO", "0.05"))  # 5% anomalies

shutdown = False


def _handle_signal(signum, frame):
    global shutdown
    shutdown = True


signal.signal(signal.SIGINT, _handle_signal)
signal.signal(signal.SIGTERM, _handle_signal)

# ---------------------------------------------------------------------------
# Normal log templates
# ---------------------------------------------------------------------------
HOSTNAMES = ["web01", "web02", "app01", "app02", "db01", "db02", "lb01", "monitor01"]
NORMAL_USERS = ["alice", "bob", "charlie", "deploy", "www-data"]
NORMAL_IPS = ["10.0.1.10", "10.0.1.20", "10.0.1.30", "10.0.2.10", "10.0.2.20", "192.168.1.100"]

NORMAL_TEMPLATES = [
    # SSHD
    ("sshd", "Accepted publickey for {user} from {ip} port {port} ssh2"),
    ("sshd", "Received disconnect from {ip} port {port}:11: disconnected by user"),
    ("sshd", "pam_unix(sshd:session): session opened for user {user}(uid={uid}) by (uid=0)"),
    ("sshd", "pam_unix(sshd:session): session closed for user {user}"),
    # CRON
    ("CRON", "pam_unix(cron:session): session opened for user {user}(uid={uid}) by (uid=0)"),
    ("CRON", "pam_unix(cron:session): session closed for user {user}"),
    ("CRON", "(root) CMD (/usr/bin/find /tmp -type f -mtime +7 -delete)"),
    ("CRON", "(root) CMD (test -x /usr/sbin/anacron || ( cd / && run-parts --report /etc/cron.daily ))"),
    # systemd
    ("systemd", "Started Session {session} of User {user}."),
    ("systemd", "Removed slice User Slice of {user}."),
    ("systemd", "Created slice User Slice of {user}."),
    ("systemd", "Starting Cleanup of Temporary Directories..."),
    ("systemd", "Started Cleanup of Temporary Directories."),
    # kernel
    ("kernel", "[UFW BLOCK] IN=eth0 OUT= MAC={mac} SRC={ip} DST=10.0.1.{octet} LEN=40 TOS=0x00 PREC=0x00 TTL=245 ID={id} PROTO=TCP SPT={port} DPT=443 WINDOW=1024 RES=0x00 SYN URGP=0"),
    ("kernel", "audit: type=1400 audit(1711300000.000:1234): apparmor=\"ALLOWED\" operation=\"open\" profile=\"/usr/sbin/ntpd\" name=\"/etc/ntp.conf\" pid={pid} comm=\"ntpd\""),
    # nginx
    ("nginx", "{ip} - - [{timestamp}] \"GET /api/health HTTP/1.1\" 200 15 \"-\" \"kube-probe/1.28\""),
    ("nginx", "{ip} - - [{timestamp}] \"GET /api/v1/users HTTP/1.1\" 200 {size} \"-\" \"Mozilla/5.0\""),
    ("nginx", "{ip} - - [{timestamp}] \"POST /api/v1/data HTTP/1.1\" 201 {size} \"-\" \"python-requests/2.31\""),
    # postfix
    ("postfix/smtpd", "connect from mail-{id}.google.com[{ip}]"),
    ("postfix/smtpd", "disconnect from mail-{id}.google.com[{ip}] ehlo=1 mail=1 rcpt=1 data=1 quit=1 commands=5"),
    # rsyslog
    ("rsyslogd", "imuxsock: Acquired UNIX socket '/dev/log' (fd 3) from systemd."),
    ("rsyslogd", "[origin software=\"rsyslogd\" swVersion=\"8.2312.0\" x-pid=\"{pid}\"] start"),
    # ntpd
    ("ntpd", "Soliciting pool server {ip}"),
    ("ntpd", "receive: Unexpected origin timestamp {ip} does not match aorg"),
    # dhclient
    ("dhclient", "DHCPREQUEST for 10.0.1.{octet} on eth0 to 10.0.1.1 port 67"),
    ("dhclient", "DHCPACK of 10.0.1.{octet} from 10.0.1.1 (xid=0x{id})"),
]

# ---------------------------------------------------------------------------
# Anomalous log templates
# ---------------------------------------------------------------------------
ATTACK_IPS = ["185.220.101.42", "45.155.205.233", "103.143.8.71", "194.26.135.89",
              "23.129.64.130", "171.25.193.20", "162.247.74.27"]
ATTACK_USERS = ["root", "admin", "test", "guest", "ubuntu", "oracle", "postgres", "mysql",
                "ftp", "nagios", "jenkins", "backup"]

ANOMALY_TEMPLATES = [
    # Brute force SSH
    ("sshd", "Failed password for {user} from {ip} port {port} ssh2", "brute_force"),
    ("sshd", "Failed password for invalid user {user} from {ip} port {port} ssh2", "brute_force"),
    ("sshd", "Invalid user {user} from {ip} port {port}", "brute_force"),
    ("sshd", "Connection closed by authenticating user {user} {ip} port {port} [preauth]", "brute_force"),
    ("sshd", "maximum authentication attempts exceeded for {user} from {ip} port {port} ssh2 [preauth]", "brute_force"),
    # Privilege escalation
    ("sudo", "{user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash", "privilege_escalation"),
    ("sudo", "{user} : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/{user} ; USER=root ; COMMAND=/bin/su -", "privilege_escalation"),
    ("su", "FAILED SU (to root) {user} on pts/0", "privilege_escalation"),
    ("su", "pam_unix(su:auth): authentication failure; logname={user} uid=1000 euid=0 tty=pts/0 ruser={user} rhost= user=root", "privilege_escalation"),
    # Resource exhaustion
    ("kernel", "Out of memory: Killed process {pid} ({process}) total-vm:{vm}kB, anon-rss:{rss}kB, file-rss:0kB, shmem-rss:0kB, UID:{uid} pgtables:{pgt}kB oom_score_adj:0", "resource_exhaustion"),
    ("kernel", "oom-killer: constraint CONSTRAINT_NONE, cpuset=/, mems_allowed=0, oom_score_adj=0, task_size_anon={rss}, task_size_file=0", "resource_exhaustion"),
    ("kernel", "Memory cgroup out of memory: Killed process {pid} ({process}) total-vm:{vm}kB", "resource_exhaustion"),
    # Crashes
    ("kernel", "{process}[{pid}]: segfault at {addr} ip {addr2} sp {addr3} error 4 in {lib}[{addr4}+{size}]", "crash"),
    ("kernel", "traps: {process}[{pid}] trap divide error ip:{addr} sp:{addr2} error:0 in {lib}[{addr3}+{size}]", "crash"),
    ("systemd", "{service}.service: Main process exited, code=killed, status=11/SEGV", "crash"),
    ("systemd", "{service}.service: Failed with result 'signal'.", "crash"),
    # Disk full
    ("kernel", "EXT4-fs error (device sda1): ext4_journal_check_start: Detected aborted journal", "resource_exhaustion"),
    ("kernel", "EXT4-fs warning (device sda1): ext4_dx_add_entry: Directory index full!", "resource_exhaustion"),
    ("systemd", "Failed to write to /var/log/journal: No space left on device", "resource_exhaustion"),
    # Network anomalies
    ("kernel", "nf_conntrack: table full, dropping packet", "network_anomaly"),
    ("kernel", "TCP: request_sock_TCP: Possible SYN flooding on port 443. Sending cookies.", "network_anomaly"),
    # Service failures
    ("systemd", "{service}.service: start request repeated too quickly, refusing to start.", "service_failure"),
    ("systemd", "{service}.service: Failed with result 'exit-code'.", "service_failure"),
    ("nginx", "{ip} - - [{timestamp}] \"GET /api/v1/users HTTP/1.1\" 500 {size} \"-\" \"Mozilla/5.0\"", "service_failure"),
]


def _ts():
    """Current syslog-style timestamp."""
    now = datetime.datetime.now()
    return now.strftime("%b %d %H:%M:%S")  # e.g., "Mar 24 10:15:32"


def _nginx_ts():
    """Nginx-style timestamp for log format."""
    now = datetime.datetime.now()
    return now.strftime("%d/%b/%Y:%H:%M:%S +0000")


def _rand_port():
    return random.randint(1024, 65535)


def _rand_pid():
    return random.randint(100, 65535)


def _rand_hex(length=8):
    return "".join(random.choices("0123456789abcdef", k=length))


def _rand_mac():
    return ":".join(_rand_hex(2) for _ in range(6))


def _fill_template(template: str) -> str:
    """Replace placeholders in a template with random values."""
    replacements = {
        "{user}": random.choice(NORMAL_USERS),
        "{ip}": random.choice(NORMAL_IPS),
        "{port}": str(_rand_port()),
        "{pid}": str(_rand_pid()),
        "{uid}": str(random.randint(1000, 1010)),
        "{session}": str(random.randint(1, 9999)),
        "{id}": _rand_hex(6),
        "{mac}": _rand_mac(),
        "{octet}": str(random.randint(1, 254)),
        "{size}": str(random.randint(50, 50000)),
        "{timestamp}": _nginx_ts(),
    }
    result = template
    for key, val in replacements.items():
        result = result.replace(key, val, 1)
    return result


def _fill_anomaly_template(template: str) -> str:
    """Replace placeholders in anomaly templates with attack-appropriate values."""
    replacements = {
        "{user}": random.choice(ATTACK_USERS),
        "{ip}": random.choice(ATTACK_IPS),
        "{port}": str(_rand_port()),
        "{pid}": str(_rand_pid()),
        "{uid}": str(random.randint(0, 65534)),
        "{process}": random.choice(["java", "python3", "node", "mysqld", "nginx", "apache2"]),
        "{vm}": str(random.randint(500000, 8000000)),
        "{rss}": str(random.randint(100000, 4000000)),
        "{pgt}": str(random.randint(100, 10000)),
        "{addr}": _rand_hex(12),
        "{addr2}": _rand_hex(12),
        "{addr3}": _rand_hex(12),
        "{addr4}": _rand_hex(12),
        "{lib}": random.choice(["libc-2.31.so", "libpthread-2.31.so", "ld-2.31.so", "libssl.so.1.1"]),
        "{size}": _rand_hex(5),
        "{service}": random.choice(["myapp", "backend-api", "worker", "scheduler", "cache-proxy"]),
        "{timestamp}": _nginx_ts(),
    }
    result = template
    for key, val in replacements.items():
        # Replace only first occurrence of each placeholder per iteration
        result = result.replace(key, val, 1)
    # Second pass for remaining placeholders (templates may have the same placeholder multiple times)
    for key, val in replacements.items():
        while key in result:
            replacements[key] = _rand_hex(12) if "addr" in key else val
            result = result.replace(key, replacements[key], 1)
    return result


def generate_normal_line() -> str:
    """Generate a single normal syslog line."""
    process, template = random.choice(NORMAL_TEMPLATES)
    msg = _fill_template(template)
    host = random.choice(HOSTNAMES)
    pid = _rand_pid()
    return f"{_ts()} {host} {process}[{pid}]: {msg}"


def generate_anomaly_line() -> tuple[str, str]:
    """Generate a single anomalous syslog line. Returns (line, category)."""
    process, template, category = random.choice(ANOMALY_TEMPLATES)
    msg = _fill_anomaly_template(template)
    host = random.choice(HOSTNAMES)
    pid = _rand_pid()
    return f"{_ts()} {host} {process}[{pid}]: {msg}", category


def generate_brute_force_burst(count: int = None) -> list[str]:
    """Generate a burst of brute force attempts (realistic attack pattern)."""
    if count is None:
        count = random.randint(5, 30)
    lines = []
    attacker_ip = random.choice(ATTACK_IPS)
    target_host = random.choice(HOSTNAMES)
    pid = _rand_pid()
    for _ in range(count):
        user = random.choice(ATTACK_USERS)
        port = _rand_port()
        templates = [
            f"Failed password for {user} from {attacker_ip} port {port} ssh2",
            f"Failed password for invalid user {user} from {attacker_ip} port {port} ssh2",
            f"Invalid user {user} from {attacker_ip} port {port}",
        ]
        msg = random.choice(templates)
        lines.append(f"{_ts()} {target_host} sshd[{pid}]: {msg}")
    return lines


def main():
    log.info("Synthetic syslog generator starting")
    log.info("Output: %s, Rate: %.1f events/sec, Anomaly ratio: %.1f%%",
             OUTPUT_FILE, EVENTS_PER_SEC, ANOMALY_RATIO * 100)

    # Ensure output directory exists
    os.makedirs(os.path.dirname(OUTPUT_FILE), exist_ok=True)

    delay = 1.0 / EVENTS_PER_SEC
    total = 0
    anomalies = 0
    burst_counter = 0
    next_burst_at = random.randint(100, 300)  # first burst after 100-300 events

    with open(OUTPUT_FILE, "a", buffering=1) as f:  # line-buffered
        while not shutdown:
            # Check if it's time for a brute force burst
            if burst_counter >= next_burst_at:
                log.info("Injecting brute force burst at event %d", total)
                burst_lines = generate_brute_force_burst()
                for line in burst_lines:
                    f.write(line + "\n")
                    total += 1
                    anomalies += 1
                burst_counter = 0
                next_burst_at = random.randint(200, 500)
                continue

            # Normal or anomaly?
            if random.random() < ANOMALY_RATIO:
                line, category = generate_anomaly_line()
                anomalies += 1
            else:
                line = generate_normal_line()

            f.write(line + "\n")
            total += 1
            burst_counter += 1

            if total % 100 == 0:
                pct = (anomalies / total * 100) if total > 0 else 0
                log.info("Generated %d events (%d anomalies, %.1f%%)", total, anomalies, pct)

            time.sleep(delay)

    log.info("Generator stopped. Total: %d events, %d anomalies.", total, anomalies)


if __name__ == "__main__":
    main()

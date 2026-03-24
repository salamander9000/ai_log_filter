#!/usr/bin/env bash
# ==========================================================================
# Anomaly injection script for AI Log Filter PoC
# ==========================================================================
#
# Injects realistic anomalous events into /var/log/messages via the
# `logger` command (goes through syslog properly).
#
# Filebeat picks these up -> Redis -> AI service -> should be flagged.
#
# Usage:
#   ./inject-anomalies.sh <scenario> [count]
#   ./inject-anomalies.sh all              # random mix of all scenarios
#   ./inject-anomalies.sh brute_force 20   # 20 brute force attempts
#   ./inject-anomalies.sh oom 3            # 3 OOM kills
#   ./inject-anomalies.sh list             # show available scenarios
#
# ==========================================================================

set -euo pipefail

SCENARIO="${1:-all}"
COUNT="${2:-10}"
DELAY="${3:-0.5}"  # seconds between events

# Randomization helpers
rand_ip() {
    echo "$((RANDOM % 223 + 1)).$((RANDOM % 254 + 1)).$((RANDOM % 254 + 1)).$((RANDOM % 254 + 1))"
}

rand_port() {
    echo "$((RANDOM % 64000 + 1024))"
}

rand_pid() {
    echo "$((RANDOM % 60000 + 1000))"
}

rand_choice() {
    local arr=("$@")
    echo "${arr[$((RANDOM % ${#arr[@]}))]}"
}

# Attack source IPs (known Tor exit nodes / scanner ranges)
ATTACK_IPS=("185.220.101.42" "45.155.205.233" "103.143.8.71" "194.26.135.89" "23.129.64.130" "171.25.193.20")

# Usernames attackers try
ATTACK_USERS=("root" "admin" "test" "guest" "ubuntu" "oracle" "postgres" "mysql" "ftp" "jenkins" "deploy" "backup" "nagios" "www-data")

# Services that might crash
SERVICES=("java" "python3" "node" "mysqld" "nginx" "apache2" "redis-server" "mongod" "elasticsearch")

# -------------------------------------------------------------------------
# Scenario: SSH brute force attack
# -------------------------------------------------------------------------
inject_brute_force() {
    local n="${1:-10}"
    local attacker_ip
    attacker_ip=$(rand_choice "${ATTACK_IPS[@]}")
    echo "Injecting SSH brute force from ${attacker_ip} (${n} attempts)..."

    for ((i = 1; i <= n; i++)); do
        local user
        user=$(rand_choice "${ATTACK_USERS[@]}")
        local port
        port=$(rand_port)

        # Vary the message type
        case $((RANDOM % 4)) in
            0) logger -t sshd -p auth.warning "Failed password for ${user} from ${attacker_ip} port ${port} ssh2" ;;
            1) logger -t sshd -p auth.warning "Failed password for invalid user ${user} from ${attacker_ip} port ${port} ssh2" ;;
            2) logger -t sshd -p auth.info "Invalid user ${user} from ${attacker_ip} port ${port}" ;;
            3) logger -t sshd -p auth.warning "Connection closed by authenticating user ${user} ${attacker_ip} port ${port} [preauth]" ;;
        esac

        # Burst: some fast, some with delay
        if ((RANDOM % 3 == 0)); then
            sleep "${DELAY}"
        else
            sleep 0.1
        fi
    done

    # Final lockout message
    logger -t sshd -p auth.warning "maximum authentication attempts exceeded for root from ${attacker_ip} port $(rand_port) ssh2 [preauth]"
    echo "  Done: ${n} brute force events injected."
}

# -------------------------------------------------------------------------
# Scenario: Out of Memory kills
# -------------------------------------------------------------------------
inject_oom() {
    local n="${1:-3}"
    echo "Injecting OOM kills (${n} events)..."

    for ((i = 1; i <= n; i++)); do
        local proc
        proc=$(rand_choice "${SERVICES[@]}")
        local pid
        pid=$(rand_pid)
        local vm=$((RANDOM * 100 + 500000))
        local rss=$((RANDOM * 50 + 100000))

        logger -t kernel -p kern.crit "Out of memory: Killed process ${pid} (${proc}) total-vm:${vm}kB, anon-rss:${rss}kB, file-rss:0kB, shmem-rss:0kB, UID:0 pgtables:$((RANDOM % 5000 + 500))kB oom_score_adj:0"
        sleep 0.2
        logger -t kernel -p kern.crit "oom-killer: constraint CONSTRAINT_NONE, cpuset=/, mems_allowed=0, oom_score_adj=0, task_size_anon=${rss}, task_size_file=0"
        sleep "${DELAY}"
    done
    echo "  Done: ${n} OOM events injected."
}

# -------------------------------------------------------------------------
# Scenario: Segfaults / crashes
# -------------------------------------------------------------------------
inject_segfault() {
    local n="${1:-5}"
    echo "Injecting segfaults/crashes (${n} events)..."

    for ((i = 1; i <= n; i++)); do
        local proc
        proc=$(rand_choice "${SERVICES[@]}")
        local pid
        pid=$(rand_pid)

        case $((RANDOM % 3)) in
            0) logger -t kernel -p kern.err "${proc}[${pid}]: segfault at 00000000 ip 00007f$(printf '%06x' $((RANDOM * RANDOM))) sp 00007ff$(printf '%06x' $((RANDOM * RANDOM))) error 4 in libc-2.31.so[7f000000+1000]" ;;
            1) logger -t systemd -p daemon.err "${proc}.service: Main process exited, code=killed, status=11/SEGV" ;;
            2) logger -t systemd -p daemon.err "${proc}.service: Failed with result 'signal'." ;;
        esac
        sleep "${DELAY}"
    done
    echo "  Done: ${n} crash events injected."
}

# -------------------------------------------------------------------------
# Scenario: Privilege escalation attempts
# -------------------------------------------------------------------------
inject_privesc() {
    local n="${1:-5}"
    echo "Injecting privilege escalation attempts (${n} events)..."

    for ((i = 1; i <= n; i++)); do
        local user
        user=$(rand_choice "${ATTACK_USERS[@]}")

        case $((RANDOM % 4)) in
            0) logger -t sudo -p auth.warning "${user} : TTY=pts/0 ; PWD=/root ; USER=root ; COMMAND=/bin/bash" ;;
            1) logger -t sudo -p auth.alert "${user} : 3 incorrect password attempts ; TTY=pts/0 ; PWD=/home/${user} ; USER=root ; COMMAND=/bin/su -" ;;
            2) logger -t su -p auth.warning "FAILED SU (to root) ${user} on pts/0" ;;
            3) logger -t su -p auth.warning "pam_unix(su:auth): authentication failure; logname=${user} uid=1000 euid=0 tty=pts/0 ruser=${user} rhost= user=root" ;;
        esac
        sleep "${DELAY}"
    done
    echo "  Done: ${n} privilege escalation events injected."
}

# -------------------------------------------------------------------------
# Scenario: Disk full / filesystem errors
# -------------------------------------------------------------------------
inject_disk_full() {
    local n="${1:-3}"
    echo "Injecting disk full / filesystem errors (${n} events)..."

    for ((i = 1; i <= n; i++)); do
        case $((RANDOM % 3)) in
            0) logger -t kernel -p kern.err "EXT4-fs error (device sda1): ext4_journal_check_start: Detected aborted journal" ;;
            1) logger -t kernel -p kern.warning "EXT4-fs warning (device sda1): ext4_dx_add_entry: Directory index full!" ;;
            2) logger -t systemd -p daemon.err "Failed to write to /var/log/journal: No space left on device" ;;
        esac
        sleep "${DELAY}"
    done
    echo "  Done: ${n} disk full events injected."
}

# -------------------------------------------------------------------------
# Scenario: Network anomalies (SYN flood, conntrack full)
# -------------------------------------------------------------------------
inject_network() {
    local n="${1:-5}"
    echo "Injecting network anomalies (${n} events)..."

    for ((i = 1; i <= n; i++)); do
        case $((RANDOM % 3)) in
            0) logger -t kernel -p kern.warning "nf_conntrack: table full, dropping packet" ;;
            1) logger -t kernel -p kern.warning "TCP: request_sock_TCP: Possible SYN flooding on port 443. Sending cookies." ;;
            2) logger -t kernel -p kern.warning "TCP: request_sock_TCP: Possible SYN flooding on port 80. Sending cookies." ;;
        esac
        sleep "${DELAY}"
    done
    echo "  Done: ${n} network anomaly events injected."
}

# -------------------------------------------------------------------------
# Scenario: Service failures (restarts, exit codes)
# -------------------------------------------------------------------------
inject_service_failure() {
    local n="${1:-5}"
    echo "Injecting service failures (${n} events)..."

    for ((i = 1; i <= n; i++)); do
        local svc
        svc=$(rand_choice "myapp" "backend-api" "worker" "scheduler" "cache-proxy" "payment-service")

        case $((RANDOM % 3)) in
            0) logger -t systemd -p daemon.err "${svc}.service: start request repeated too quickly, refusing to start." ;;
            1) logger -t systemd -p daemon.err "${svc}.service: Failed with result 'exit-code'." ;;
            2) logger -t systemd -p daemon.warning "${svc}.service: Scheduled restart job, restart counter is at $((RANDOM % 50 + 5))." ;;
        esac
        sleep "${DELAY}"
    done
    echo "  Done: ${n} service failure events injected."
}

# -------------------------------------------------------------------------
# Scenario: Suspicious access / permission denied
# -------------------------------------------------------------------------
inject_access_denied() {
    local n="${1:-5}"
    echo "Injecting suspicious access events (${n} events)..."

    for ((i = 1; i <= n; i++)); do
        local user
        user=$(rand_choice "${ATTACK_USERS[@]}")
        local path
        path=$(rand_choice "/etc/shadow" "/etc/passwd" "/root/.ssh/authorized_keys" "/var/lib/mysql" "/etc/sudoers")

        case $((RANDOM % 2)) in
            0) logger -t kernel -p kern.warning "audit: type=1400 audit($(date +%s).000:$((RANDOM))): apparmor=\"DENIED\" operation=\"open\" profile=\"/usr/sbin/${user}\" name=\"${path}\" pid=$(rand_pid) comm=\"${user}\"" ;;
            1) logger -t sshd -p auth.warning "error: Received disconnect from $(rand_choice "${ATTACK_IPS[@]}") port $(rand_port):3: com.jcraft.jsch.JSchException: Auth fail [preauth]" ;;
        esac
        sleep "${DELAY}"
    done
    echo "  Done: ${n} access denied events injected."
}

# -------------------------------------------------------------------------
# Run all scenarios with random mix
# -------------------------------------------------------------------------
inject_all() {
    local n="${1:-10}"
    echo ""
    echo "=== Injecting random mix of all anomaly types (${n} total events) ==="
    echo ""

    local scenarios=("brute_force" "oom" "segfault" "privesc" "disk_full" "network" "service_failure" "access_denied")

    for ((i = 1; i <= n; i++)); do
        local scenario
        scenario=$(rand_choice "${scenarios[@]}")
        case "${scenario}" in
            brute_force)     inject_brute_force 1 ;;
            oom)             inject_oom 1 ;;
            segfault)        inject_segfault 1 ;;
            privesc)         inject_privesc 1 ;;
            disk_full)       inject_disk_full 1 ;;
            network)         inject_network 1 ;;
            service_failure) inject_service_failure 1 ;;
            access_denied)   inject_access_denied 1 ;;
        esac
    done

    echo ""
    echo "=== All done: ${n} mixed anomaly events injected ==="
}

# -------------------------------------------------------------------------
# Help / list scenarios
# -------------------------------------------------------------------------
show_help() {
    echo "AI Log Filter - Anomaly Injection Script"
    echo ""
    echo "Usage: $0 <scenario> [count] [delay_seconds]"
    echo ""
    echo "Scenarios:"
    echo "  brute_force     SSH brute force attack from a single IP"
    echo "  oom             Out of Memory kills"
    echo "  segfault        Segfaults and service crashes"
    echo "  privesc         Privilege escalation attempts (sudo/su failures)"
    echo "  disk_full       Disk full / filesystem errors"
    echo "  network         Network anomalies (SYN flood, conntrack full)"
    echo "  service_failure Service start failures and restart loops"
    echo "  access_denied   Permission denied / unauthorized access"
    echo "  all             Random mix of all scenarios"
    echo "  list            Show this help"
    echo ""
    echo "Examples:"
    echo "  $0 brute_force 20     # 20 SSH brute force attempts"
    echo "  $0 oom 5              # 5 OOM kills"
    echo "  $0 all 30             # 30 random mixed anomalies"
    echo "  $0 all 10 0.1         # 10 random, 0.1s delay between events"
}

# -------------------------------------------------------------------------
# Main dispatch
# -------------------------------------------------------------------------
case "${SCENARIO}" in
    brute_force)     inject_brute_force "${COUNT}" ;;
    oom)             inject_oom "${COUNT}" ;;
    segfault)        inject_segfault "${COUNT}" ;;
    privesc)         inject_privesc "${COUNT}" ;;
    disk_full)       inject_disk_full "${COUNT}" ;;
    network)         inject_network "${COUNT}" ;;
    service_failure) inject_service_failure "${COUNT}" ;;
    access_denied)   inject_access_denied "${COUNT}" ;;
    all)             inject_all "${COUNT}" ;;
    list|help|-h|--help)
        show_help ;;
    *)
        echo "Unknown scenario: ${SCENARIO}"
        echo ""
        show_help
        exit 1 ;;
esac

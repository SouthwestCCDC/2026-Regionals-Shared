#!/bin/bash
# =============================================================================
# Linux Asset Inventory Script
# Author: Matthew
# Version: 2.1
# Description: Comprehensive system asset inventory for Linux machines.
#              Supports Debian, Red Hat, Alpine, and FreeBSD-based systems.
# Usage: sudo ./asset_inventory.sh [-e] [-o output_file] [-h]
#
# Note: set -e is intentionally omitted. Section functions use '|| true' and
#       fallback patterns to handle command failures gracefully without aborting
#       the entire inventory run.
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Variables & Config
# ---------------------------------------------------------------------------
# FIX #1: Remove pre-set from $1 — getopts handles all flag parsing below.
FLAG=""
OUTPUT_FILE=""
DISTRIBUTION=""
SCRIPT_VERSION="2.1"

# Text Colors
GREEN='\033[1;32m'
CYAN='\033[1;36m'
YELLOW='\033[1;33m'
RED='\033[1;31m'
BOLD='\033[1m'
END='\033[0m'

# ---------------------------------------------------------------------------
# Utility Functions
# ---------------------------------------------------------------------------
command_exists() {
    command -v "$1" > /dev/null 2>&1
}

header() {
    local msg="$1"
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════${END}"
    echo -e "${GREEN}  $msg${END}"
    echo -e "${GREEN}══════════════════════════════════════════${END}"
}

subheader() {
    echo -e "${CYAN}  ▶ $1${END}"
}

info() {
    echo -e "    ${BOLD}$1:${END} $2"
}

warn() {
    echo -e "    ${YELLOW}⚠ $1${END}"
}

usage() {
    local programname="$0"
    echo ""
    echo -e "${BOLD}Usage:${END} $programname [option] [-o output_file]"
    echo ""
    echo "  -e                  Execute full asset inventory"
    echo "  -o <file>           Save output to a file (use with -e)"
    echo "  -h                  Display this help message"
    echo ""
    echo "  Example: sudo $programname -e"
    echo "  Example: sudo $programname -e -o /tmp/inventory.txt"
    echo ""
    exit 0
}

# ---------------------------------------------------------------------------
# Detect Distribution
# ---------------------------------------------------------------------------
detect_distro() {
    if command_exists apt-get; then
        DISTRIBUTION="debian"
    elif command_exists yum || command_exists dnf; then
        DISTRIBUTION="redhat"
    elif command_exists apk; then
        DISTRIBUTION="alpine"
    elif command_exists pkg; then
        DISTRIBUTION="freebsd"
    else
        DISTRIBUTION="unsupported"
    fi
}

# ---------------------------------------------------------------------------
# 1. System Overview
# ---------------------------------------------------------------------------
system_overview() {
    header "System Overview"

    local hostname
    hostname=$(hostname 2>/dev/null || echo "Unknown")
    info "Hostname" "$hostname"

    if [[ -f /etc/os-release ]]; then
        local os
        os=$(awk -F= '/PRETTY_NAME/ {gsub(/"/, "", $2); print $2}' /etc/os-release)
        info "OS" "${os:-Unknown}"
    else
        info "OS" "Unknown (no /etc/os-release)"
    fi

    info "Kernel" "$(uname -r 2>/dev/null || echo 'Unknown')"
    info "Architecture" "$(uname -m 2>/dev/null || echo 'Unknown')"

    if command_exists uptime; then
        local uptime_str
        uptime_str=$(uptime -p 2>/dev/null || uptime 2>/dev/null || echo "Unknown")
        info "Uptime" "$uptime_str"
    else
        info "Uptime" "Not available"
    fi

    if command_exists who; then
        local last_boot
        last_boot=$(who -b 2>/dev/null | awk '{print $3, $4}' || echo "Unknown")
        info "Last Boot" "${last_boot:-Unknown}"
    fi

    info "Report Time" "$(date '+%Y-%m-%d %H:%M:%S %Z')"

    if command_exists timedatectl; then
        local tz
        tz=$(timedatectl 2>/dev/null | awk '/Time zone/ {print $3}' || echo "Unknown")
        info "Timezone" "${tz:-Unknown}"
    elif [[ -f /etc/timezone ]]; then
        info "Timezone" "$(cat /etc/timezone)"
    fi
}

# ---------------------------------------------------------------------------
# 2. Hardware / Resources
# ---------------------------------------------------------------------------
hardware() {
    header "Hardware & Resources"

    subheader "CPU"
    if [[ -f /proc/cpuinfo ]]; then
        local cpu_model cpu_cores
        cpu_model=$(awk -F: '/model name/ {print $2; exit}' /proc/cpuinfo | sed 's/^ //')
        cpu_cores=$(grep -c "^processor" /proc/cpuinfo 2>/dev/null || echo "Unknown")
        info "Model" "${cpu_model:-Unknown}"
        info "Logical CPUs" "$cpu_cores"
    else
        warn "CPU info not available (/proc/cpuinfo missing)"
    fi

    if [[ -f /proc/loadavg ]]; then
        local loadavg
        loadavg=$(awk '{print "1m: "$1"  5m: "$2"  15m: "$3}' /proc/loadavg)
        info "Load Average" "$loadavg"
    fi

    subheader "Memory"
    if command_exists free; then
        local mem_total mem_used mem_avail swap_total swap_used
        mem_total=$(free -h 2>/dev/null | awk '/^Mem:/ {print $2}')
        mem_used=$(free -h 2>/dev/null | awk '/^Mem:/ {print $3}')
        mem_avail=$(free -h 2>/dev/null | awk '/^Mem:/ {print $7}')
        swap_total=$(free -h 2>/dev/null | awk '/^Swap:/ {print $2}')
        swap_used=$(free -h 2>/dev/null | awk '/^Swap:/ {print $3}')
        info "Total RAM" "${mem_total:-Unknown}"
        info "Used RAM" "${mem_used:-Unknown}"
        info "Available RAM" "${mem_avail:-Unknown}"
        info "Swap Total" "${swap_total:-None}"
        info "Swap Used" "${swap_used:-None}"
    elif [[ -f /proc/meminfo ]]; then
        local mem_total mem_avail
        mem_total=$(awk '/MemTotal/ {printf "%.1f GB", $2/1024/1024}' /proc/meminfo)
        mem_avail=$(awk '/MemAvailable/ {printf "%.1f GB", $2/1024/1024}' /proc/meminfo)
        info "Total RAM" "$mem_total"
        info "Available RAM" "$mem_avail"
    else
        warn "Memory info not available"
    fi

    subheader "Disk Usage"
    if command_exists df; then
        echo ""
        if df -h --output=source,size,used,avail,pcent,target / > /dev/null 2>&1; then
            df -h --output=source,size,used,avail,pcent,target 2>/dev/null \
                | grep -v "^tmpfs\|^devtmpfs\|^udev\|^overlay\|^Filesystem" \
                | awk 'NR==1{printf "    %-30s %8s %8s %8s %6s  %s\n","Filesystem","Size","Used","Avail","Use%","Mounted On"} NR>0{printf "    %-30s %8s %8s %8s %6s  %s\n",$1,$2,$3,$4,$5,$6}'
        else
            df -h 2>/dev/null \
                | grep -v "^tmpfs\|^devtmpfs\|^udev\|^overlay" \
                | awk '{print "    " $0}'
        fi
    else
        warn "df command not available"
    fi
}

# ---------------------------------------------------------------------------
# 3. Network Configuration
# ---------------------------------------------------------------------------
network() {
    header "Network Configuration"

    subheader "Interfaces"
    if command_exists ip; then
        ip -br addr 2>/dev/null || ip addr 2>/dev/null || warn "Could not retrieve interface info"
    elif command_exists ifconfig; then
        ifconfig 2>/dev/null || warn "Could not retrieve interface info"
    else
        warn "Neither 'ip' nor 'ifconfig' found"
    fi

    subheader "Default Gateway"
    if command_exists ip; then
        local gw
        gw=$(ip route 2>/dev/null | awk '/default/ {print $3; exit}')
        echo "    ${gw:-Not set}"
    elif command_exists route; then
        route -n 2>/dev/null | awk '/^0.0.0.0/ {print "    " $2}' || warn "Cannot determine gateway"
    else
        warn "Cannot determine default gateway"
    fi

    subheader "DNS Resolvers"
    if [[ -f /etc/resolv.conf ]]; then
        grep "^nameserver" /etc/resolv.conf 2>/dev/null | awk '{print "    " $2}' || warn "No nameservers found"
    else
        warn "/etc/resolv.conf not found"
    fi

    subheader "Open Listening Ports"
    if command_exists ss; then
        echo ""
        echo "    Proto  Port   Process"
        echo "    ─────  ─────  ───────────────────────"
        # FIX #7: Use regex match on the address field to correctly handle both
        # IPv4 (0.0.0.0:22) and IPv6 ([::]:22) address formats.
        ss -tlnpu 2>/dev/null \
            | awk 'NR>1 {
                if (match($5, /:([0-9]+)$/, m)) {
                    port = m[1];
                    proto = $1;
                    proc = ($7 != "" ? $7 : "-");
                    if (port+0 > 0)
                        printf "    %-6s %-6s %s\n", proto, port, proc
                }
              }' \
            | sort -k2 -n | uniq \
            || warn "Could not retrieve port info"
    elif command_exists netstat; then
        netstat -tlnpu 2>/dev/null | grep LISTEN \
            | awk '{printf "    %-6s %-22s %s\n", $1, $4, $7}' \
            || warn "Could not retrieve port info"
    else
        warn "Neither 'ss' nor 'netstat' found — cannot list open ports"
    fi

    subheader "Firewall Status"
    if command_exists ufw; then
        local ufw_status
        ufw_status=$(ufw status 2>/dev/null | head -1)
        info "UFW" "${ufw_status:-Unknown}"
    fi
    if command_exists firewall-cmd; then
        local fwd_status
        fwd_status=$(firewall-cmd --state 2>/dev/null || echo "not running")
        info "firewalld" "$fwd_status"
    fi
    if command_exists iptables; then
        local ipt_rules
        ipt_rules=$(iptables -L 2>/dev/null | grep -c "^ACCEPT\|^DROP\|^REJECT" 2>/dev/null || echo "0")
        info "iptables rules" "$ipt_rules active rules (use 'iptables -L' for details)"
    fi
    if ! command_exists ufw && ! command_exists firewall-cmd && ! command_exists iptables; then
        warn "No firewall management tool detected"
    fi
}

# ---------------------------------------------------------------------------
# 4. Users & Authentication
# ---------------------------------------------------------------------------
users() {
    header "Users & Authentication"

    subheader "Local Users (UID >= 1000)"
    local user_found=false
    while IFS=: read -r username _ uid _ _ homedir shell; do
        if [[ "$uid" -ge 1000 && "$username" != "nobody" ]]; then
            printf "    %-20s UID:%-6s  Home: %-25s  Shell: %s\n" \
                "$username" "$uid" "$homedir" "$shell"
            user_found=true
        fi
    done < /etc/passwd
    if ! $user_found; then
        warn "No standard users found (UID >= 1000)"
    fi

    subheader "Users with sudo Access"
    if [[ -f /etc/sudoers ]]; then
        grep -v "^#\|^Defaults\|^$" /etc/sudoers 2>/dev/null \
            | awk '{print "    " $0}' \
            || warn "Could not read /etc/sudoers"
    fi
    if [[ -d /etc/sudoers.d ]]; then
        local sudoers_files
        sudoers_files=$(ls /etc/sudoers.d/ 2>/dev/null | wc -l)
        if [[ "$sudoers_files" -gt 0 ]]; then
            echo "    Sudoers drop-in files: $(ls /etc/sudoers.d/ 2>/dev/null | tr '\n' ' ')"
        fi
    fi

    subheader "Currently Logged-in Users"
    if command_exists who; then
        who 2>/dev/null | awk '{print "    " $0}' || warn "Could not determine logged-in users"
    else
        warn "'who' command not available"
    fi

    subheader "Recent Logins (last 10)"
    if command_exists last; then
        last -n 10 2>/dev/null | awk '{print "    " $0}' || warn "Could not retrieve login history"
    else
        warn "'last' command not available"
    fi

    subheader "Failed Login Attempts"
    if command_exists lastb; then
        # FIX #3: Strip the trailing "btmp begins..." footer line and blank lines
        # rather than blindly subtracting 2, which was unreliable across distros.
        local failed_count
        failed_count=$(lastb 2>/dev/null | grep -vc "^$\|begins" || echo "0")
        info "Failed logins in btmp" "$failed_count attempts"
    elif [[ -f /var/log/auth.log ]]; then
        local failed_count
        failed_count=$(grep -c "Failed password" /var/log/auth.log 2>/dev/null || echo "0")
        info "Failed SSH logins (auth.log)" "$failed_count"
    elif [[ -f /var/log/secure ]]; then
        local failed_count
        failed_count=$(grep -c "Failed password" /var/log/secure 2>/dev/null || echo "0")
        info "Failed SSH logins (secure)" "$failed_count"
    else
        warn "Cannot determine failed login count"
    fi
}

# ---------------------------------------------------------------------------
# 5. Installed Software Summary
# ---------------------------------------------------------------------------
software() {
    header "Installed Software"

    # FIX #6: Guard against DISTRIBUTION being unset if this function is ever
    # called outside the standard runall() flow.
    if [[ -z "$DISTRIBUTION" ]]; then
        detect_distro
    fi

    local pkg_count=0

    if [[ "$DISTRIBUTION" == "debian" ]]; then
        if command_exists dpkg; then
            pkg_count=$(dpkg --get-selections 2>/dev/null | grep -c "install$" || echo 0)
            info "Package Manager" "APT/dpkg"
            info "Packages Installed" "$pkg_count"
        else
            warn "dpkg not found on Debian-based system"
        fi
    elif [[ "$DISTRIBUTION" == "redhat" ]]; then
        if command_exists rpm; then
            pkg_count=$(rpm -qa 2>/dev/null | wc -l || echo 0)
            info "Package Manager" "RPM/YUM/DNF"
            info "Packages Installed" "$pkg_count"
        else
            warn "rpm not found on Red Hat-based system"
        fi
    elif [[ "$DISTRIBUTION" == "alpine" ]]; then
        if command_exists apk; then
            pkg_count=$(apk info 2>/dev/null | wc -l || echo 0)
            info "Package Manager" "APK"
            info "Packages Installed" "$pkg_count"
        else
            warn "apk not found on Alpine system"
        fi
    elif [[ "$DISTRIBUTION" == "freebsd" ]]; then
        if command_exists pkg; then
            pkg_count=$(pkg info 2>/dev/null | wc -l || echo 0)
            info "Package Manager" "pkg"
            info "Packages Installed" "$pkg_count"
        else
            warn "pkg not found on FreeBSD system"
        fi
    else
        warn "Unsupported distribution — cannot list packages"
    fi

    subheader "Notable Tools Detected"
    local tools=(git curl wget python3 python perl ruby java node docker kubectl terraform ansible vim nano gcc make)
    local found_tools=()
    for tool in "${tools[@]}"; do
        if command_exists "$tool"; then
            local version
            # FIX #9: java writes version info to stderr; redirect 2>&1 to capture it.
            # For all other tools, stdout is sufficient.
            if [[ "$tool" == "java" ]]; then
                version=$("$tool" -version 2>&1 | head -1 | grep -oP '\d[\d._]+' | head -1 || echo "installed")
            else
                version=$("$tool" --version 2>/dev/null | head -1 | sed 's/^[^0-9]*//' | cut -c1-30 || echo "installed")
            fi
            found_tools+=("$(printf '    %-15s %s' "$tool" "$version")")
        fi
    done

    if [[ ${#found_tools[@]} -gt 0 ]]; then
        for t in "${found_tools[@]}"; do
            echo "$t"
        done
    else
        warn "No notable tools detected"
    fi
}

# ---------------------------------------------------------------------------
# 6. Running Services & Processes
# ---------------------------------------------------------------------------
check_process() {
    local proc_name="$1"
    if command_exists pgrep; then
        pgrep -f "$proc_name" > /dev/null 2>&1
    else
        ps aux 2>/dev/null | grep -v grep | grep -q "$proc_name"
    fi
}

detect_services() {
    header "Running Services & Processes"

    subheader "System Service Manager"
    if command_exists systemctl; then
        local svc_count
        svc_count=$(systemctl list-units --type=service --state=running 2>/dev/null | grep -c "\.service" || echo "Unknown")
        info "Init System" "systemd"
        info "Running Services" "$svc_count"

        subheader "All Running systemd Services"
        systemctl list-units --type=service --state=running --no-pager 2>/dev/null \
            | awk 'NR>1 && /\.service/ {printf "    %s\n", $0}' \
            | head -40
        if [[ $(systemctl list-units --type=service --state=running 2>/dev/null | grep -c "\.service") -gt 40 ]]; then
            warn "Output truncated — more than 40 services running"
        fi

        subheader "Failed Services"
        local failed
        failed=$(systemctl list-units --type=service --state=failed --no-pager 2>/dev/null | grep "\.service" || true)
        if [[ -n "$failed" ]]; then
            echo -e "${RED}$failed${END}" | awk '{print "    " $0}'
        else
            echo "    None ✓"
        fi
    elif command_exists rc-status; then
        info "Init System" "OpenRC"
        rc-status 2>/dev/null | awk '{print "    " $0}' || warn "Could not retrieve OpenRC status"
    elif command_exists service; then
        info "Init System" "SysV-style"
        service --status-all 2>/dev/null | awk '{print "    " $0}' || warn "Could not retrieve service status"
    else
        warn "No recognized init system found"
    fi

    subheader "Key Service Detection"
    check_process "named"        && echo "  ✔  DNS: BIND (named)"
    check_process "unbound"      && echo "  ✔  DNS: Unbound"
    check_process "dnsmasq"      && echo "  ✔  DNS: Dnsmasq"
    { check_process "apache2" || check_process "httpd"; } && echo "  ✔  Web: Apache"
    check_process "nginx"        && echo "  ✔  Web: Nginx"
    check_process "caddy"        && echo "  ✔  Web: Caddy"
    check_process "mysqld"       && echo "  ✔  DB: MySQL"
    check_process "mariadbd"     && echo "  ✔  DB: MariaDB"
    check_process "postgres"     && echo "  ✔  DB: PostgreSQL"
    check_process "mongod"       && echo "  ✔  DB: MongoDB"
    check_process "redis-server" && echo "  ✔  Cache: Redis"
    check_process "postfix"      && echo "  ✔  Mail: Postfix"
    check_process "exim"         && echo "  ✔  Mail: Exim"
    check_process "sendmail"     && echo "  ✔  Mail: Sendmail"
    check_process "dovecot"      && echo "  ✔  Mail: Dovecot (IMAP/POP3)"
    check_process "slapd"        && echo "  ✔  LDAP: OpenLDAP"
    if check_process "dockerd"; then
        if command_exists docker; then
            local count
            count=$(docker ps -q 2>/dev/null | wc -l)
            echo "  ✔  Container: Docker ($count containers running)"
        else
            echo "  ✔  Container: Docker (daemon running, CLI unavailable)"
        fi
    fi
    check_process "containerd"   && echo "  ✔  Container: containerd"
    check_process "kubelet"      && echo "  ✔  Orchestration: Kubernetes (kubelet)"
    check_process "sshd"         && echo "  ✔  Remote: OpenSSH"
    check_process "smbd"         && echo "  ✔  File Share: Samba (SMB)"
    check_process "vsftpd"       && echo "  ✔  File Transfer: vsftpd"
    check_process "proftpd"      && echo "  ✔  File Transfer: ProFTPD"
    check_process "prometheus"   && echo "  ✔  Monitoring: Prometheus"
    check_process "grafana"      && echo "  ✔  Monitoring: Grafana"
    check_process "zabbix"       && echo "  ✔  Monitoring: Zabbix"
    check_process "node_exporter" && echo "  ✔  Monitoring: Node Exporter"

    subheader "Top 10 Processes by CPU"
    if command_exists ps; then
        echo ""
        printf "    %-8s %-8s %-8s %-8s %s\n" "PID" "USER" "%CPU" "%MEM" "COMMAND"
        ps aux --sort=-%cpu 2>/dev/null \
            | awk 'NR>1 && NR<=11 {printf "    %-8s %-8s %-8s %-8s %s\n", $2, $1, $3, $4, $11}' \
            || warn "Could not retrieve process list"
    else
        warn "ps not available"
    fi
}

# ---------------------------------------------------------------------------
# 7. Security Snapshot
# ---------------------------------------------------------------------------
security() {
    header "Security Snapshot"

    subheader "SSH Configuration"
    local sshd_config="/etc/ssh/sshd_config"
    if [[ -f "$sshd_config" ]]; then
        local root_login permit_empty pw_auth
        root_login=$(grep -i "^PermitRootLogin" "$sshd_config" 2>/dev/null | awk '{print $2}' || echo "not set (default: prohibit-password)")
        permit_empty=$(grep -i "^PermitEmptyPasswords" "$sshd_config" 2>/dev/null | awk '{print $2}' || echo "not set (default: no)")
        pw_auth=$(grep -i "^PasswordAuthentication" "$sshd_config" 2>/dev/null | awk '{print $2}' || echo "not set (default: yes)")
        info "PermitRootLogin" "$root_login"
        info "PermitEmptyPasswords" "$permit_empty"
        info "PasswordAuthentication" "$pw_auth"
    else
        warn "sshd_config not found"
    fi

    subheader "SELinux / AppArmor"
    if command_exists getenforce; then
        info "SELinux" "$(getenforce 2>/dev/null || echo 'Unknown')"
    elif command_exists sestatus; then
        info "SELinux" "$(sestatus 2>/dev/null | awk '/SELinux status/ {print $3}')"
    else
        info "SELinux" "Not present"
    fi

    if command_exists aa-status; then
        local aa_status
        aa_status=$(aa-status 2>/dev/null | head -1 || echo "Unknown")
        info "AppArmor" "$aa_status"
    else
        info "AppArmor" "Not present"
    fi

    subheader "World-Writable Files in /etc (potential risk)"
    local ww_files
    ww_files=$(find /etc -maxdepth 2 -perm -o+w -type f 2>/dev/null | head -10)
    if [[ -n "$ww_files" ]]; then
        echo -e "${RED}    WARNING: World-writable files found:${END}"
        echo "$ww_files" | awk '{print "    " $0}'
    else
        echo "    None found ✓"
    fi

    subheader "SUID/SGID Binaries (non-standard paths)"
    # FIX #8: Capture output and print "None found" when empty.
    # FIX #11: Added -xdev to avoid crossing filesystem boundaries (NFS, bind mounts, etc.)
    local suid_files
    suid_files=$(find /usr/local /opt /home -maxdepth 4 -xdev \( -perm -4000 -o -perm -2000 \) -type f 2>/dev/null)
    if [[ -n "$suid_files" ]]; then
        echo "$suid_files" | awk '{print "    " $0}'
    else
        echo "    None found ✓"
    fi
    echo "    (Standard system paths excluded)"
}

# ---------------------------------------------------------------------------
# 8. Cron Jobs
# ---------------------------------------------------------------------------
cron_jobs() {
    header "Scheduled Tasks (Cron)"

    subheader "System Crontabs"
    # FIX #5: Use nullglob-safe pattern — check file existence before iterating.
    local cron_files=(/etc/crontab)
    if [[ -d /etc/cron.d ]]; then
        while IFS= read -r -d '' f; do
            cron_files+=("$f")
        done < <(find /etc/cron.d -maxdepth 1 -type f -print0 2>/dev/null)
    fi

    for cron_file in "${cron_files[@]}"; do
        if [[ -f "$cron_file" ]]; then
            echo "    [$cron_file]"
            grep -v "^#\|^$" "$cron_file" 2>/dev/null | awk '{print "      " $0}' || true
        fi
    done

    subheader "User Crontabs"
    if command_exists crontab; then
        while IFS=: read -r username _ uid _; do
            if [[ "$uid" -ge 1000 && "$username" != "nobody" ]]; then
                local user_cron
                user_cron=$(crontab -l -u "$username" 2>/dev/null | grep -v "^#\|^$")
                if [[ -n "$user_cron" ]]; then
                    echo "    [User: $username]"
                    echo "$user_cron" | awk '{print "      " $0}'
                fi
            fi
        done < /etc/passwd
    else
        warn "crontab not available"
    fi

    subheader "Systemd Timers"
    if command_exists systemctl; then
        systemctl list-timers --no-pager 2>/dev/null | awk '{print "    " $0}' | head -20 \
            || warn "Could not list systemd timers"
    fi
}

# ---------------------------------------------------------------------------
# Main Run
# ---------------------------------------------------------------------------
runall() {
    system_overview
    hardware
    network
    users
    software
    detect_services
    security
    cron_jobs
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════${END}"
    echo -e "${GREEN}  Inventory Complete${END}"
    echo -e "${GREEN}══════════════════════════════════════════${END}"
    echo ""
}

# ---------------------------------------------------------------------------
# Argument Parsing
# ---------------------------------------------------------------------------
if [[ $# -eq 0 ]]; then
    usage
fi

# FIX #1: All flag handling now goes through getopts exclusively.
while getopts ":eo:h" opt; do
    case $opt in
        e) FLAG="-e" ;;
        o) OUTPUT_FILE="$OPTARG" ;;
        h) usage ;;
        \?) echo -e "${RED}Error: Unknown option -$OPTARG${END}" >&2; usage ;;
        :)  echo -e "${RED}Error: Option -$OPTARG requires an argument${END}" >&2; usage ;;
    esac
done

if [[ "$FLAG" == "-e" ]]; then
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${RED}Error: Please run as root (sudo)!${END}" >&2
        exit 1
    fi

    # FIX #10: Warn the operator that the output file may contain sensitive data.
    if [[ -n "$OUTPUT_FILE" ]]; then
        if ! touch "$OUTPUT_FILE" 2>/dev/null; then
            echo -e "${RED}Error: Cannot write to output file: $OUTPUT_FILE${END}" >&2
            exit 1
        fi
        echo -e "${YELLOW}WARNING: Output file may contain sensitive system data (credentials, ports, users). Secure or encrypt it accordingly.${END}"
        echo "" > "$OUTPUT_FILE"
        echo "Saving output to: $OUTPUT_FILE"
        exec > >(tee -a "$OUTPUT_FILE") 2>&1
    fi

    detect_distro

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${END}"
    echo -e "${GREEN}║     Linux Asset Inventory Script         ║${END}"
    echo -e "${GREEN}║     Author: Matthew  |  Version: $SCRIPT_VERSION   ║${END}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${END}"
    echo -e "  Running as: $(whoami)  |  Distribution: $DISTRIBUTION"

    runall
else
    usage
fi
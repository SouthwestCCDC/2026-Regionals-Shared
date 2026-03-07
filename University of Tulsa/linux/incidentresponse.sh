#!/bin/bash
# =============================================================================
# Linux Incident Response Script
# For use in CCDC / Hivestorm competitions
# Original authors: TNAR5, colonket, ferdinand
# Improved by: Matthew
# Version: 2.1 (bug-fix pass)
#
# Usage: sudo ./ir.sh [flag] [arg]
# =============================================================================

set -uo pipefail

# ---------------------------------------------------------------------------
# Variables
# ---------------------------------------------------------------------------
FLAG=""
ARG2=""
SCRIPT_VERSION="2.1"
LOG_FILE="/var/log/ir_script_$(date '+%Y%m%d_%H%M%S').log"

# Text Colors
GREEN='\033[1;32m'
RED='\033[1;31m'
YELLOW='\033[1;33m'
CYAN='\033[1;36m'
BOLD='\033[1m'
END='\033[0m'

# ---------------------------------------------------------------------------
# Utility Functions
# (defined first — before any function that calls them)
# ---------------------------------------------------------------------------
command_exists() {
    command -v "$1" > /dev/null 2>&1
}

header() {
    echo ""
    echo -e "${GREEN}══════════════════════════════════════════${END}"
    echo -e "${GREEN}  $1${END}"
    echo -e "${GREEN}══════════════════════════════════════════${END}"
}

warn()  { echo -e "  ${YELLOW}⚠ $1${END}"; }
alert() { echo -e "  ${RED}✖ $1${END}"; }
good()  { echo -e "  ${GREEN}✔ $1${END}"; }
info_line() { echo -e "  ${BOLD}$1:${END} $2"; }

# Log every action to the IR log file
log_action() {
    echo "[$(date '+%Y-%m-%d %H:%M:%S')] [$(whoami)] $*" >> "$LOG_FILE"
}

# Prompt yes/no — returns 0 for yes, 1 for no
confirm() {
    local prompt="${1:-Are you sure?}"
    echo -en "  ${CYAN}${prompt} (y/n): ${END}"
    read -r response
    [[ "$response" =~ ^[yY] ]]
}

# Validate an IPv4 address (basic — rejects shell injection)
validate_ip() {
    local ip="$1"
    if [[ "$ip" =~ ^([0-9]{1,3}\.){3}[0-9]{1,3}(/[0-9]{1,2})?$ ]]; then
        return 0
    else
        alert "Invalid IP address: '$ip'"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# Detect Distribution (runs at startup)
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
# 1. Basic System Info
# ---------------------------------------------------------------------------
info() {
    header "System Uptime"
    uptime

    header "Active Users"
    w 2>/dev/null || who 2>/dev/null || warn "Could not determine active users"

    header "Open Ports (Listening)"
    if command_exists ss; then
        ss -tulnp
    elif command_exists netstat; then
        netstat -tulnp
    else
        warn "Neither ss nor netstat found"
    fi

    header "Top 10 Processes by Memory"
    ps aux --sort=-%mem 2>/dev/null | head -n 11 || warn "ps not available"

    header "Network Connections (Established)"
    if command_exists ss; then
        ss -tunap state established
    elif command_exists netstat; then
        netstat -tunap | grep ESTABLISHED
    else
        warn "Neither ss nor netstat found"
    fi

    header "Sudo Commands Today"
    _show_sudo_logs ""

    header "Current Firewall Rules"
    _show_firewall_rules

    log_action "Ran: basic info"
}

# ---------------------------------------------------------------------------
# 2. Login Activity
# ---------------------------------------------------------------------------
logins() {
    header "Successful SSH Logins Today"
    if command_exists journalctl; then
        journalctl -u ssh -u sshd --no-pager 2>/dev/null | grep "$(date '+%b %d')" | grep -i "accepted" || warn "No SSH logins found in journal"
    elif [[ -f /var/log/auth.log ]]; then
        grep "sshd.*Accepted" /var/log/auth.log | grep "$(date '+%b %d')" || warn "No accepted SSH logins today"
    elif [[ -f /var/log/secure ]]; then
        grep "sshd.*Accepted" /var/log/secure | grep "$(date '+%b %d')" || warn "No accepted SSH logins today"
    else
        warn "Could not find SSH logs"
    fi

    header "Failed SSH Login Attempts Today"
    if command_exists journalctl; then
        journalctl -u ssh -u sshd --no-pager 2>/dev/null | grep "$(date '+%b %d')" | grep -i "failed\|invalid" || warn "No failed logins found"
    elif [[ -f /var/log/auth.log ]]; then
        grep "Failed password" /var/log/auth.log | grep "$(date '+%b %d')" || warn "None found"
    elif [[ -f /var/log/secure ]]; then
        grep "Failed password" /var/log/secure | grep "$(date '+%b %d')" || warn "None found"
    fi

    header "Failed Login Summary (lastb)"
    if command_exists lastb; then
        # BUG FIX 4: grep -vc exits 1 when count is 0, triggering the false ||
        # branch. Capture count separately with || true to handle zero matches.
        local failed_count
        failed_count=$(lastb 2>/dev/null | grep -vc "^$\|^btmp begins" || true)
        failed_count="${failed_count:-0}"
        info_line "Total failed login attempts on record" "$failed_count"
        lastb 2>/dev/null | head -n 15 || true
    else
        warn "lastb not available"
    fi

    header "Recent Successful Logins (last 20)"
    if command_exists last; then
        last -n 20 2>/dev/null || warn "last not available"
    fi

    log_action "Ran: login check"
}

# ---------------------------------------------------------------------------
# 3. Software Info
# ---------------------------------------------------------------------------
software() {
    header "Installed Packages"
    if [[ "$DISTRIBUTION" == "debian" ]]; then
        dpkg --get-selections 2>/dev/null | awk '{print $1}'
    elif [[ "$DISTRIBUTION" == "redhat" ]]; then
        rpm -qa 2>/dev/null
    elif [[ "$DISTRIBUTION" == "alpine" ]]; then
        apk info 2>/dev/null
    elif [[ "$DISTRIBUTION" == "freebsd" ]]; then
        pkg info 2>/dev/null
    else
        warn "Unsupported distribution"
    fi

    header "Outdated / Upgradable Packages"
    if [[ "$DISTRIBUTION" == "debian" ]]; then
        apt list --upgradable 2>/dev/null
    elif [[ "$DISTRIBUTION" == "redhat" ]]; then
        yum check-update 2>/dev/null || dnf check-update 2>/dev/null || true
    elif [[ "$DISTRIBUTION" == "alpine" ]]; then
        apk version -l '<' 2>/dev/null
    elif [[ "$DISTRIBUTION" == "freebsd" ]]; then
        pkg version -l '<' 2>/dev/null
    fi

    log_action "Ran: software check"
}

# ---------------------------------------------------------------------------
# 4. Block an IP
# ---------------------------------------------------------------------------
block_ip() {
    local ip="${1:-}"
    if [[ -z "$ip" ]]; then
        echo -n "  Enter IP address to block: "
        read -r ip
    fi

    # Validate before passing to firewall commands to prevent injection
    validate_ip "$ip" || return 1

    header "Blocking IP: $ip"
    log_action "Blocking IP: $ip"

    if command_exists ufw; then
        ufw deny from "$ip" && good "Blocked $ip with UFW"
    elif command_exists firewall-cmd; then
        firewall-cmd --permanent --add-rich-rule="rule family='ipv4' source address='$ip' drop" && \
        firewall-cmd --reload && good "Blocked $ip with firewalld"
    elif command_exists iptables; then
        iptables -I INPUT 1 -s "$ip" -j DROP && good "Blocked $ip with iptables (-I inserts at top)"
    else
        alert "No firewall tool found (ufw, firewall-cmd, iptables)"
        log_action "FAILED to block $ip — no firewall tool found"
        return 1
    fi
}

# ---------------------------------------------------------------------------
# 5. Kick a User
# ---------------------------------------------------------------------------
kick_user() {
    local target_user="${1:-}"
    if [[ -z "$target_user" ]]; then
        echo -n "  Enter username to kick: "
        read -r target_user
    fi

    if [[ "$target_user" == "$(whoami)" ]]; then
        alert "You cannot kick yourself!"
        return 1
    fi

    # Verify user exists
    if ! id "$target_user" > /dev/null 2>&1; then
        alert "User '$target_user' does not exist"
        return 1
    fi

    header "Kicking user: $target_user"
    log_action "Kicking user: $target_user"

    # Kill all user processes
    if command_exists pkill; then
        pkill -KILL -u "$target_user" 2>/dev/null && good "Killed all processes for $target_user" || warn "No processes found for $target_user"
    elif command_exists killall; then
        killall -KILL -u "$target_user" 2>/dev/null && good "Killed all processes for $target_user" || warn "No processes found"
    else
        # Fallback: use kill with PIDs from ps
        local pids
        pids=$(ps -u "$target_user" -o pid= 2>/dev/null | tr '\n' ' ')
        if [[ -n "$pids" ]]; then
            # shellcheck disable=SC2086
            kill -9 $pids 2>/dev/null && good "Killed PIDs: $pids"
        else
            warn "No processes found for $target_user"
        fi
    fi

    if confirm "Lock account '$target_user'?"; then
        if [[ "$DISTRIBUTION" == "freebsd" ]]; then
            pw lock "$target_user" && good "Account $target_user locked"
        else
            passwd -l "$target_user" && good "Account $target_user locked"
        fi
        log_action "Locked account: $target_user"
    fi
}

# ---------------------------------------------------------------------------
# 6. Suspicious Activity Check
# ---------------------------------------------------------------------------
suspicious() {
    header "Checking for Suspicious Activity"

    echo ""
    echo -e "  ${BOLD}1. World-Writable Files in /etc:${END}"
    local ww
    ww=$(find /etc -maxdepth 3 -perm -o+w -type f 2>/dev/null | head -n 10)
    if [[ -n "$ww" ]]; then
        echo -e "${RED}$ww${END}" | awk '{print "    " $0}'
    else
        good "None found"
    fi

    echo ""
    echo -e "  ${BOLD}2. SUID Binaries in non-standard paths:${END}"
    local suid
    suid=$(find /home /tmp /var/tmp /opt /usr/local -maxdepth 5 -xdev -perm -4000 -type f 2>/dev/null)
    if [[ -n "$suid" ]]; then
        echo -e "${RED}$suid${END}" | awk '{print "    " $0}'
    else
        good "None found"
    fi

    echo ""
    echo -e "  ${BOLD}3. Users with UID 0 (root-level access):${END}"
    local uid0
    uid0=$(awk -F: '($3 == 0) {print "    " $0}' /etc/passwd)
    echo "$uid0"

    echo ""
    # BUG FIX 3: -newer /proc/1 compares against PID 1's mtime (epoch on most
    # systems), so every file always matched. Use -mmin -1440 for a true 24h window.
    echo -e "  ${BOLD}4. Recently Modified /etc/passwd or /etc/shadow (last 24h):${END}"
    local modified
    modified=$(find /etc/passwd /etc/shadow /etc/sudoers -mmin -1440 -type f 2>/dev/null)
    if [[ -n "$modified" ]]; then
        echo "$modified" | awk '{print "    MODIFIED: " $0}'
    else
        good "No recent modifications detected"
    fi

    echo ""
    echo -e "  ${BOLD}5. Unlinked (deleted) files held open by running processes:${END}"
    if command_exists lsof; then
        local deleted
        deleted=$(lsof +L1 2>/dev/null | head -n 10)
        if [[ -n "$deleted" ]]; then
            echo -e "${YELLOW}$deleted${END}" | awk '{print "    " $0}'
        else
            good "None found"
        fi
    else
        local del_procs
        del_procs=$(ls -l /proc/*/exe 2>/dev/null | grep "deleted" | head -n 10)
        if [[ -n "$del_procs" ]]; then
            echo "$del_procs"
        else
            good "None found"
        fi
    fi

    echo ""
    echo -e "  ${BOLD}6. Large Files in /tmp or /var/tmp (>10MB):${END}"
    local bigfiles
    bigfiles=$(find /tmp /var/tmp -type f -size +10M 2>/dev/null)
    if [[ -n "$bigfiles" ]]; then
        echo -e "${YELLOW}$bigfiles${END}" | awk '{print "    " $0}'
    else
        good "None found"
    fi

    echo ""
    echo -e "  ${BOLD}7. Listening on unusual high ports (>1024, non-ephemeral):${END}"
    if command_exists ss; then
        ss -tlnp 2>/dev/null | awk 'NR>1 {
            if (match($4, /:([0-9]+)$/, m)) {
                port = m[1]+0
                if (port > 1024 && port < 32768)
                    print "    " $0
            }
        }' || true
    fi

    echo ""
    echo -e "  ${BOLD}8. Authorized Keys Files:${END}"
    local found_keys=0
    while IFS= read -r keyfile; do
        found_keys=1
        echo "    [$keyfile]"
        awk '{print "      " $0}' "$keyfile" 2>/dev/null
    done < <(find /root /home -name "authorized_keys" -type f 2>/dev/null)
    if [[ "$found_keys" -eq 0 ]]; then
        good "No authorized_keys files found"
    fi

    echo ""
    echo -e "  ${BOLD}9. Crontabs (system + users):${END}"
    for f in /etc/crontab /etc/cron.d/*; do
        [[ -f "$f" ]] && echo "    [$f]" && grep -v "^#\|^$" "$f" 2>/dev/null | awk '{print "      " $0}'
    done
    # BUG FIX 5: /etc/passwd has 7 colon-separated fields:
    #   user:password:uid:gid:gecos:home:shell
    # The original read pattern "user _ uid _" assigned GID to $uid.
    # Fixed to explicitly name all 7 fields so $uid is correct.
    while IFS=: read -r user _pass uid _gid _gecos _home _shell; do
        if [[ "$uid" -ge 1000 && "$user" != "nobody" ]]; then
            local usercron
            usercron=$(crontab -l -u "$user" 2>/dev/null | grep -v "^#\|^$")
            if [[ -n "$usercron" ]]; then
                echo "    [User crontab: $user]"
                echo "$usercron" | awk '{print "      " $0}'
            fi
        fi
    done < /etc/passwd

    log_action "Ran: suspicious activity check"
}

# ---------------------------------------------------------------------------
# 7. Change Passwords
# ---------------------------------------------------------------------------
change_passwords() {
    header "Change Passwords"

    echo ""
    echo -e "  ${BOLD}Local users (UID >= 1000):${END}"
    local users=()
    # BUG FIX 5 (same as above): use all 7 fields so $uid maps correctly.
    while IFS=: read -r username _pass uid _gid _gecos _home _shell; do
        if [[ "$uid" -ge 1000 && "$username" != "nobody" ]]; then
            users+=("$username")
            echo "    - $username"
        fi
    done < /etc/passwd

    echo ""
    echo "  Options:"
    echo "    1) Change password for a specific user"
    echo "    2) Change passwords for ALL listed users"
    echo "    3) Cancel"
    echo -n "  Choice: "
    read -r choice

    case "$choice" in
        1)
            echo -n "  Enter username: "
            read -r target_user
            if id "$target_user" > /dev/null 2>&1; then
                passwd "$target_user"
                log_action "Changed password for user: $target_user"
            else
                alert "User '$target_user' not found"
            fi
            ;;
        2)
            if confirm "Change passwords for ALL ${#users[@]} users?"; then
                for u in "${users[@]}"; do
                    echo ""
                    echo -e "  ${CYAN}Setting password for: $u${END}"
                    passwd "$u"
                    log_action "Changed password for user: $u"
                done
            fi
            ;;
        3)
            warn "Cancelled"
            ;;
        *)
            warn "Invalid choice"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# 8. Firewall Management
# ---------------------------------------------------------------------------
_show_firewall_rules() {
    if command_exists ufw; then
        ufw status verbose 2>/dev/null || warn "UFW not active"
    fi
    if command_exists firewall-cmd; then
        firewall-cmd --list-all 2>/dev/null || warn "firewalld not active"
    fi
    if command_exists iptables; then
        echo "--- iptables INPUT chain ---"
        iptables -L INPUT -n -v 2>/dev/null || warn "Could not read iptables rules"
    fi
}

firewall() {
    header "Firewall Rules"
    _show_firewall_rules

    echo ""
    echo "  Options:"
    echo "    1) Backup iptables rules to file"
    echo "    2) Restore iptables rules from file"
    echo "    3) Flush ALL iptables rules (dangerous!)"
    echo "    4) Cancel"
    echo -n "  Choice: "
    read -r choice

    case "$choice" in
        1)
            local backup_file="/root/iptables_backup_$(date '+%Y%m%d_%H%M%S').rules"
            if command_exists iptables-save; then
                iptables-save > "$backup_file" && good "Rules backed up to $backup_file"
                log_action "Backed up iptables rules to $backup_file"
            else
                warn "iptables-save not found"
            fi
            ;;
        2)
            echo -n "  Enter path to rules file: "
            read -r restore_file
            if [[ -f "$restore_file" ]] && command_exists iptables-restore; then
                iptables-restore < "$restore_file" && good "Rules restored from $restore_file"
                log_action "Restored iptables rules from $restore_file"
            else
                alert "File not found or iptables-restore unavailable"
            fi
            ;;
        3)
            if confirm "FLUSH ALL iptables rules? This opens the firewall!"; then
                iptables -F && iptables -X && iptables -P INPUT ACCEPT && iptables -P FORWARD ACCEPT && iptables -P OUTPUT ACCEPT
                alert "All iptables rules flushed — system is unfiltered!"
                log_action "FLUSHED all iptables rules"
            fi
            ;;
        4)
            warn "Cancelled"
            ;;
        *)
            warn "Invalid choice"
            ;;
    esac
}

# ---------------------------------------------------------------------------
# 9. sudo Commands (shared helper + standalone mode)
# ---------------------------------------------------------------------------
_show_sudo_logs() {
    local username="${1:-}"
    local today
    today=$(date '+%b %d')

    # BUG FIX 1: The original used inline `{ [[ -n "$username" ]] && grep ... || cat; }`
    # inside a pipe. This is fragile — `||` fires when grep finds zero matches (exit 1),
    # causing cat to dump everything even when a username was specified.
    # Fixed by branching before the pipe so each path is unambiguous.
    if command_exists journalctl; then
        local log_lines
        log_lines=$(journalctl _COMM=sudo --no-pager 2>/dev/null | grep "$today" | grep -v "session opened\|session closed")
        if [[ -z "$log_lines" ]]; then
            warn "No sudo commands today"
            return
        fi
        if [[ -n "$username" ]]; then
            echo "$log_lines" | grep "$username" || warn "No sudo commands found for $username today"
        else
            echo "$log_lines"
        fi
    elif [[ -f /var/log/auth.log ]]; then
        local log_lines
        log_lines=$(grep "sudo" /var/log/auth.log | grep "$today")
        if [[ -z "$log_lines" ]]; then
            warn "No sudo logs found"
            return
        fi
        if [[ -n "$username" ]]; then
            echo "$log_lines" | grep "$username" || warn "No sudo commands found for $username today"
        else
            echo "$log_lines"
        fi
    elif [[ -f /var/log/secure ]]; then
        local log_lines
        log_lines=$(grep "sudo" /var/log/secure | grep "$today")
        if [[ -z "$log_lines" ]]; then
            warn "No sudo logs found"
            return
        fi
        if [[ -n "$username" ]]; then
            echo "$log_lines" | grep "$username" || warn "No sudo commands found for $username today"
        else
            echo "$log_lines"
        fi
    else
        warn "No sudo log source found"
    fi
}

sudocommands() {
    local username="${1:-}"
    if [[ -z "$username" ]]; then
        echo -n "  Enter username: "
        read -r username
    fi
    header "Sudo Commands Today for: $username"
    _show_sudo_logs "$username"
    log_action "Ran: sudo command lookup for $username"
}

# ---------------------------------------------------------------------------
# 10. Setup — install dependencies
# ---------------------------------------------------------------------------
setup() {
    header "Installing Required Packages"
    log_action "Ran: setup"

    local packages="net-tools lsof"

    if [[ "$DISTRIBUTION" == "debian" ]]; then
        apt-get update -q && apt-get install -y $packages
    elif [[ "$DISTRIBUTION" == "redhat" ]]; then
        yum install -y $packages 2>/dev/null || dnf install -y $packages
    elif [[ "$DISTRIBUTION" == "alpine" ]]; then
        apk update && apk add $packages
    elif [[ "$DISTRIBUTION" == "freebsd" ]]; then
        pkg update && pkg install -y $packages
    else
        warn "Unsupported distribution — install net-tools and lsof manually"
    fi
}

# ---------------------------------------------------------------------------
# Usage
# ---------------------------------------------------------------------------
usage() {
    echo ""
    echo -e "${BOLD}Usage:${END} $0 [option] [arg]"
    echo ""
    echo "  -b              Basic system info (ports, users, connections, firewall)"
    echo "  -l              Login activity (successful, failed, lastb)"
    echo "  -s              Installed & outdated software"
    echo "  -k  [user]      Kick a user off the system and optionally lock account"
    echo "  -bi [ip]        Block an IP address (validates input before firing)"
    echo "  -c              Check for suspicious indicators (SUID, crons, keys, etc.)"
    echo "  -p              Change user passwords interactively"
    echo "  -f              View and manage firewall rules"
    echo "  -su [user]      Show sudo commands run today by a given user"
    echo "  -setup          Install required packages (lsof, net-tools)"
    echo "  -h              Show this help message"
    echo ""
    echo -e "  Logs are written to: ${CYAN}$LOG_FILE${END}"
    echo ""
    exit 0
}

# ---------------------------------------------------------------------------
# Argument Parsing
# ---------------------------------------------------------------------------
if [[ $# -ge 1 ]]; then
    FLAG="$1"
fi
if [[ $# -ge 2 ]]; then
    ARG2="$2"
fi

if [[ -z "$FLAG" ]]; then
    usage
fi

# Detect distro early so all functions can use $DISTRIBUTION
detect_distro

# Show header and enforce root for all non-help flags
if [[ "$FLAG" != "-h" ]]; then
    if [[ "$EUID" -ne 0 ]]; then
        echo -e "${RED}Error: Please run as root (sudo)!${END}" >&2
        exit 1
    fi

    # Initialise log file
    touch "$LOG_FILE" 2>/dev/null || LOG_FILE="/tmp/ir_script_$(date '+%Y%m%d_%H%M%S').log"
    log_action "Script started — flag: $FLAG ${ARG2:-}"

    echo ""
    echo -e "${GREEN}╔══════════════════════════════════════════╗${END}"
    echo -e "${GREEN}║    Linux Incident Response Script        ║${END}"
    echo -e "${GREEN}║    Author: Matthew  |  Version: $SCRIPT_VERSION      ║${END}"
    echo -e "${GREEN}╚══════════════════════════════════════════╝${END}"
    echo ""
    if [[ -f /etc/os-release ]]; then
        echo -e "  OS: $(awk -F= '/PRETTY_NAME/{gsub(/"/, "", $2); print $2}' /etc/os-release)"
    fi
    echo -e "  Distro family : $DISTRIBUTION"
    echo -e "  Running as    : $(whoami)"
    echo -e "  Log file      : ${CYAN}$LOG_FILE${END}"
fi

case "$FLAG" in
    -b)      info ;;
    -l)      logins ;;
    -s)      software ;;
    -k)      kick_user "$ARG2" ;;
    -bi)     block_ip "$ARG2" ;;
    -c)      suspicious ;;
    -p)      change_passwords ;;
    -f)      firewall ;;
    -su)     sudocommands "$ARG2" ;;
    -setup)  setup ;;
    -h)      usage ;;
    *)       alert "Unknown flag: $FLAG"; usage ;;
esac
#!/usr/bin/env bash
# =============================================================
# CCDC - configure-linux-syslog.sh
# Run on EACH Linux client machine to forward logs to Graylog
# Works with rsyslog (Ubuntu, Debian, Rocky, CentOS)
# =============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }

[[ $EUID -eq 0 ]] || { echo "Run as root: sudo bash configure-linux-syslog.sh <GRAYLOG_IP>"; exit 1; }

GRAYLOG_IP="${1:-}"
[[ -n "$GRAYLOG_IP" ]] || { echo "Usage: sudo bash $0 <GRAYLOG_IP>"; exit 1; }
GRAYLOG_PORT=5140

# ---- Install rsyslog if missing ----
if ! command -v rsyslogd &>/dev/null; then
    info "Installing rsyslog..."

    if command -v dnf &>/dev/null; then
        dnf install -y rsyslog

    elif command -v yum &>/dev/null; then
        yum install -y rsyslog

    elif command -v apt-get &>/dev/null; then
        apt-get update -y
        apt-get install -y rsyslog

    elif command -v zypper &>/dev/null; then
        zypper install -y rsyslog

    else
        echo "Unsupported distro: no known package manager found."
        exit 1
    fi
fi

# ---- Write rsyslog forwarding config ----
info "Writing /etc/rsyslog.d/90-graylog.conf..."
cat > /etc/rsyslog.d/90-graylog.conf <<EOF
# CCDC - Forward all logs to Graylog via Syslog TCP
# Uses RFC5424 format for better parsing in Graylog

# Load TCP module
\$ModLoad imtcp

# Use RFC5424 (structured syslog) format
template(name="CCDC_GraylogFwd" type="string"
    string="<%pri%>1 %timestamp:::date-rfc3339% %hostname% %app-name% %procid% %msgid% %structured-data% %msg%\n")

# Forward everything to Graylog via TCP (more reliable than UDP)
*.* action(
    type="omfwd"
    target="${GRAYLOG_IP}"
    port="${GRAYLOG_PORT}"
    protocol="tcp"
    template="CCDC_GraylogFwd"
    action.resumeRetryCount="-1"
    queue.type="LinkedList"
    queue.size="10000"
    queue.filename="graylog_fwd"
    queue.saveonshutdown="on"
)
EOF

# ---- Also enable auditd -> syslog bridging if auditd is present ----
if command -v auditd &>/dev/null || systemctl is-active auditd &>/dev/null 2>&1; then
    info "auditd detected - enabling syslog plugin for audit logs..."
    if [[ -f /etc/audit/plugins.d/syslog.conf ]]; then
        sed -i 's/^active = no/active = yes/' /etc/audit/plugins.d/syslog.conf
        systemctl restart auditd || true
    fi
fi

# ---- Restart rsyslog ----
info "Restarting rsyslog..."
systemctl restart rsyslog
systemctl enable rsyslog

# ---- Test connectivity ----
info "Testing connection to Graylog ${GRAYLOG_IP}:${GRAYLOG_PORT}..."
if timeout 3 bash -c "echo > /dev/tcp/${GRAYLOG_IP}/${GRAYLOG_PORT}" 2>/dev/null; then
    info "Connection OK!"
else
    warn "Could not connect to ${GRAYLOG_IP}:${GRAYLOG_PORT} - check firewall."
fi

info "Done! This host is now forwarding logs to Graylog at ${GRAYLOG_IP}."
logger -t ccdc_test "Syslog forwarding to Graylog configured successfully"

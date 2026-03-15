#!/usr/bin/env bash
# =============================================================
# CCDC - create-alert-definitions.sh
# Run AFTER importing the content pack and creating a pipeline.
# Creates Graylog Event Definitions (alerts) for high-priority
# security events.
#
# Usage:
#   bash create-alert-definitions.sh <GRAYLOG_IP> <ADMIN_PASSWORD>
# Example:
#   bash create-alert-definitions.sh 10.0.0.10 mysecretpass
# =============================================================

set -euo pipefail

GRAYLOG_IP="${1:-127.0.0.1}"
ADMIN_PASS="${2:-admin}"
API="http://${GRAYLOG_IP}:9000/api"
AUTH_HEADER="Authorization: Basic $(echo -n "admin:${ADMIN_PASS}" | base64)"
CONTENT="Content-Type: application/json"
XRB="X-Requested-By: cli"

GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
ok()   { echo -e "${GREEN}[OK]${NC} $*"; }
warn() { echo -e "${YELLOW}[!!]${NC} $*"; }

# Helper: create event definition
# $1 = title, $2 = description, $3 = search query, $4 = threshold count,
# $5 = time window minutes, $6 = severity (low/medium/high/critical)
create_event() {
    local TITLE="$1"
    local DESC="$2"
    local QUERY="$3"
    local THRESHOLD="${4:-1}"
    local WINDOW="${5:-5}"
    local SEVERITY="${6:-medium}"

    local PAYLOAD=$(cat <<EOF
{
  "title": "${TITLE}",
  "description": "${DESC}",
  "priority": 2,
  "alert": true,
  "config": {
    "type": "aggregation-v1",
    "query": "${QUERY}",
    "query_parameters": [],
    "streams": [],
    "group_by": [],
    "series": [
      {
        "id": "count-1",
        "type": "count",
        "field": null
      }
    ],
    "conditions": {
      "expression": {
        "expr": ">=",
        "ref": "count-1",
        "value": ${THRESHOLD}
      }
    },
    "search_within_ms": $((WINDOW * 60000)),
    "execute_every_ms": $((WINDOW * 60000))
  },
  "field_spec": {},
  "key_spec": [],
  "notification_settings": {
    "grace_period_ms": $((WINDOW * 60000)),
    "backlog_size": 25
  },
  "notifications": [],
  "alert": true
}
EOF
)

    local RESULT
    RESULT=$(curl -sf -X POST "${API}/events/definitions" \
        -H "$AUTH_HEADER" \
        -H "$CONTENT" \
        -H "$XRB" \
        -d "$PAYLOAD" 2>&1)

    if [[ $? -eq 0 ]]; then
        ok "Created: ${TITLE}"
    else
        warn "Failed (may already exist): ${TITLE}"
    fi
}

echo "Creating CCDC alert event definitions on ${GRAYLOG_IP}..."
echo ""

# ---- CRITICAL ----
create_event \
    "CCDC CRITICAL: New User Created" \
    "A new user account was created on Windows or Linux. Verify immediately." \
    "ccdc_event_type:user_created AND ccdc_severity:critical" \
    1 5 "high"

create_event \
    "CCDC CRITICAL: Log Cleared" \
    "Windows event log was cleared - attacker covering tracks." \
    "ccdc_event_type:log_cleared" \
    1 1 "high"

create_event \
    "CCDC CRITICAL: New Service/Driver Installed" \
    "A new service or driver was installed - persistence mechanism." \
    "ccdc_event_type:service_installed" \
    1 5 "high"

create_event \
    "CCDC CRITICAL: Credential Dumping Tool Detected" \
    "Mimikatz or similar detected in process name or PowerShell script." \
    "ccdc_alert_reason:*credential*dump*" \
    1 1 "high"

create_event \
    "CCDC CRITICAL: Group Membership Changed" \
    "User added/removed from a Windows group - watch for Domain Admins." \
    "ccdc_event_type:group_change" \
    1 5 "high"

create_event \
    "CCDC CRITICAL: New Linux User/Group Created" \
    "useradd/adduser/groupadd on a Linux host." \
    "ccdc_event_type:user_created AND log_source_os:linux" \
    1 5 "high"

create_event \
    "CCDC CRITICAL: Possible Reverse Shell (Linux)" \
    "Reverse shell command pattern detected in Linux logs." \
    "ccdc_event_type:reverse_shell" \
    1 1 "high"

# ---- HIGH ----
create_event \
    "CCDC HIGH: Windows Account Lockout Spike" \
    "Multiple account lockouts in short window - brute force likely." \
    "ccdc_event_type:account_lockout" \
    3 5 "medium"

create_event \
    "CCDC HIGH: Scheduled Task Created" \
    "A new scheduled task was created - common persistence method." \
    "ccdc_event_type:scheduled_task_created" \
    1 5 "medium"

create_event \
    "CCDC HIGH: Windows Firewall Rule Modified" \
    "Firewall rule added/changed - attacker may be opening backdoor." \
    "ccdc_event_type:firewall_change" \
    1 5 "medium"

create_event \
    "CCDC HIGH: User Account Enabled or Password Changed" \
    "Account enabled or password reset - verify authorisation." \
    "ccdc_event_type:account_modified" \
    1 5 "medium"

create_event \
    "CCDC HIGH: Suspicious PowerShell (Download/AMSI Bypass)" \
    "PowerShell with download cradle, IEX, or AMSI bypass detected." \
    "ccdc_event_type:powershell_scriptblock AND ccdc_severity:high" \
    1 5 "medium"

create_event \
    "CCDC HIGH: Linux Service Enabled at Boot" \
    "A systemd service was enabled to start at boot - possible persistence." \
    "ccdc_event_type:service_change AND ccdc_severity:high" \
    1 5 "medium"

create_event \
    "CCDC HIGH: Linux Cron Job Modified" \
    "A crontab was modified on a Linux host." \
    "ccdc_event_type:cron_activity AND ccdc_severity:high" \
    1 5 "medium"

create_event \
    "CCDC HIGH: Linux Password Changed" \
    "Password changed on a Linux host - verify authorisation." \
    "ccdc_event_type:password_change" \
    1 5 "medium"

create_event \
    "CCDC HIGH: Possible Kerberoasting (RC4 TGS Request)" \
    "Kerberos TGS requested with RC4 encryption - Kerberoasting indicator." \
    "ccdc_alert_reason:*kerberoasting*" \
    3 5 "medium"

# ---- WARNING ----
create_event \
    "CCDC WARNING: Windows Failed Logon Storm (Brute Force)" \
    "More than 10 failed logons in 5 minutes from same source." \
    "ccdc_event_type:logon_failure" \
    10 5 "low"

create_event \
    "CCDC WARNING: Linux SSH Brute Force" \
    "More than 10 SSH failures in 5 minutes." \
    "ccdc_event_type:ssh_failure" \
    10 5 "low"

create_event \
    "CCDC WARNING: Suspicious Linux Download (wget/curl to bash)" \
    "wget or curl piped to bash/sh detected." \
    "ccdc_event_type:suspicious_download" \
    1 5 "low"

echo ""
echo "=============================="
echo "Alert definitions created!"
echo "Review them in Graylog:"
echo "  http://${GRAYLOG_IP}:9000 -> Alerts -> Event Definitions"
echo ""
echo "IMPORTANT: Go through each alert and add a notification"
echo "(email, Slack webhook, or HTTP) so you actually get paged."
echo "=============================="

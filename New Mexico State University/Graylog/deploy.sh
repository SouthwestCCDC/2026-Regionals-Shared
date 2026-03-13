#!/usr/bin/env bash
# =============================================================
# CCDC Graylog - deploy.sh
# Run on the Linux infrastructure machine as root (or sudo)
# Sets up Docker, configures OS prereqs, generates passwords,
# and launches the Graylog stack.
# =============================================================

set -euo pipefail

RED='\033[0;31m'; GREEN='\033[0;32m'; YELLOW='\033[1;33m'; NC='\033[0m'
info()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()    { echo -e "${YELLOW}[!]${NC} $*"; }
err()     { echo -e "${RED}[ERROR]${NC} $*"; exit 1; }

# ---- Require root ----
[[ $EUID -eq 0 ]] || err "Run as root: sudo bash deploy.sh"

SCRIPT_DIR="$(cd "$(dirname "${BASH_SOURCE[0]}")" && pwd)"
cd "$SCRIPT_DIR"

# ---- 1. Install Docker if missing ----
if ! command -v docker &>/dev/null; then
    info "Installing Docker..."
    apt-get update -qq
    apt-get install -y ca-certificates curl gnupg lsb-release
    install -m 0755 -d /etc/apt/keyrings
    curl -fsSL https://download.docker.com/linux/ubuntu/gpg \
        | gpg --dearmor -o /etc/apt/keyrings/docker.gpg
    chmod a+r /etc/apt/keyrings/docker.gpg
    echo "deb [arch=$(dpkg --print-architecture) signed-by=/etc/apt/keyrings/docker.gpg] \
        https://download.docker.com/linux/ubuntu $(lsb_release -cs) stable" \
        | tee /etc/apt/sources.list.d/docker.list > /dev/null
    apt-get update -qq
    apt-get install -y docker-ce docker-ce-cli containerd.io docker-compose-plugin
    systemctl enable --now docker
    info "Docker installed."
else
    info "Docker already installed."
fi

# ---- 2. OS tuning for OpenSearch ----
info "Setting vm.max_map_count for OpenSearch..."
sysctl -w vm.max_map_count=262144
grep -q "vm.max_map_count" /etc/sysctl.conf \
    && sed -i 's/vm.max_map_count=.*/vm.max_map_count=262144/' /etc/sysctl.conf \
    || echo "vm.max_map_count=262144" >> /etc/sysctl.conf

# ---- 3. Generate .env if it doesn't exist ----
if [[ ! -f .env ]]; then
    info "Generating .env with random secrets..."
    
    # Detect password generation method
    if command -v pwgen &>/dev/null; then
        SECRET=$(pwgen -N 1 -s 96)
    else
        SECRET=$(openssl rand -hex 48)
    fi

    # Prompt for admin password
    echo ""
    read -rsp "Enter Graylog admin password: " GRAYLOG_PASS
    echo ""
    read -rsp "Confirm password: " GRAYLOG_PASS2
    echo ""
    [[ "$GRAYLOG_PASS" == "$GRAYLOG_PASS2" ]] || err "Passwords do not match."
    PASS_HASH=$(echo -n "$GRAYLOG_PASS" | sha256sum | cut -d" " -f1)

    # Detect this machine's primary non-loopback IP
    HOST_IP=$(ip route get 1 2>/dev/null | awk '{for(i=1;i<=NF;i++) if($i=="src") print $(i+1); exit}')
    warn "Detected host IP: $HOST_IP"
    read -rp "Use this IP for GRAYLOG_HOST? [Y/n]: " USE_IP
    if [[ "${USE_IP,,}" == "n" ]]; then
        read -rp "Enter the correct IP/hostname: " HOST_IP
    fi

    cat > .env <<EOF
GRAYLOG_HOST=${HOST_IP}
GRAYLOG_PASSWORD_SECRET=${SECRET}
GRAYLOG_ROOT_PASSWORD_SHA2=${PASS_HASH}
EOF
    info ".env created."
else
    warn ".env already exists, skipping generation."
fi

# ---- 4. Pull images (pre-cache, handy if internet is available now) ----
info "Pulling Docker images..."
docker compose pull || warn "Pull failed - will try on compose up anyway."

# ---- 5. Start the stack ----
info "Starting Graylog stack..."
docker compose up -d

# ---- 6. Wait for Graylog to be ready ----
info "Waiting for Graylog to become available (this can take 60-90s)..."
GRAYLOG_HOST_IP=$(grep GRAYLOG_HOST .env | cut -d= -f2)
for i in $(seq 1 30); do
    if curl -sf "http://${GRAYLOG_HOST_IP}:9000/api/system/lbstatus" &>/dev/null; then
        info "Graylog is up!"
        break
    fi
    sleep 5
    echo -n "."
done
echo ""

# ---- 7. Auto-configure Inputs via API ----
info "Configuring Graylog inputs via API..."
PASS_HASH=$(grep GRAYLOG_ROOT_PASSWORD_SHA2 .env | cut -d= -f2)
# We need the plaintext pass for API - read it again
read -rsp "Enter your Graylog admin password (for API setup): " API_PASS
echo ""

API_BASE="http://${GRAYLOG_HOST_IP}:9000/api"
AUTH_HEADER="Authorization: Basic $(echo -n "admin:${API_PASS}" | base64)"

# Helper function to create an input
create_input() {
    local TITLE="$1"
    local TYPE="$2"
    local PORT="$3"
    local EXTRA="$4"
    
    curl -sf -X POST "${API_BASE}/system/inputs" \
        -H "$AUTH_HEADER" \
        -H "Content-Type: application/json" \
        -H "X-Requested-By: cli" \
        -d "{
            \"title\": \"${TITLE}\",
            \"type\": \"${TYPE}\",
            \"global\": true,
            \"configuration\": {
                \"bind_address\": \"0.0.0.0\",
                \"port\": ${PORT},
                \"recv_buffer_size\": 262144
                ${EXTRA}
            }
        }" > /dev/null && echo "  [OK] ${TITLE}" || echo "  [SKIP/EXISTS] ${TITLE}"
}

# Syslog UDP (Linux machines, rsyslog)
create_input \
    "Syslog UDP" \
    "org.graylog2.inputs.syslog.udp.SyslogUDPInput" \
    5140 \
    ', "store_full_message": true, "expand_structured_data": true'

# Syslog TCP (more reliable, Windows NXLog/rsyslog)
create_input \
    "Syslog TCP" \
    "org.graylog2.inputs.syslog.tcp.SyslogTCPInput" \
    5140 \
    ', "store_full_message": true, "expand_structured_data": true, "use_null_delimiter": true'

# GELF UDP (Docker containers, structured apps)
create_input \
    "GELF UDP" \
    "org.graylog2.inputs.gelf.udp.GELFUDPInput" \
    12201 \
    ''

# GELF TCP
create_input \
    "GELF TCP" \
    "org.graylog2.inputs.gelf.tcp.GELFTCPInput" \
    12201 \
    ', "use_null_delimiter": true'

# Beats (Winlogbeat / Filebeat)
create_input \
    "Beats" \
    "org.graylog.plugins.beats.BeatsInput" \
    5044 \
    ''

info "Done! Inputs configured."

# ---- Summary ----
echo ""
echo "======================================================"
echo " GRAYLOG DEPLOYMENT COMPLETE"
echo "======================================================"
echo " Web UI:    http://${GRAYLOG_HOST_IP}:9000"
echo " Username:  admin"
echo " Password:  (what you set)"
echo ""
echo " Log Inputs:"
echo "   Syslog UDP/TCP  -> ${GRAYLOG_HOST_IP}:5140"
echo "   GELF UDP/TCP    -> ${GRAYLOG_HOST_IP}:12201"
echo "   Beats           -> ${GRAYLOG_HOST_IP}:5044"
echo ""
echo " Next steps:"
echo "   1. Point Linux boxes at Syslog (see configure-linux-syslog.sh)"
echo "   2. Install Winlogbeat on Windows (see winlogbeat.yml)"
echo "   3. Firewall: allow ports 5140, 12201, 5044 inbound"
echo "======================================================"

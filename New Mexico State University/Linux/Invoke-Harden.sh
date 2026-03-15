#!/usr/bin/env bash
# Interactive Linux hardening helper.
# Start with high-signal checks and expand over time.

set -euo pipefail

if [[ "$(uname -s)" != "Linux" ]]; then
    echo "[!] This script only supports Linux."
    exit 1
fi

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[1;33m'
BLUE='\033[0;34m'
NC='\033[0m'

info() { echo -e "${GREEN}[+]${NC} $*"; }
warn() { echo -e "${YELLOW}[!]${NC} $*"; }
fail() { echo -e "${RED}[-]${NC} $*"; }
section() { echo -e "\n${BLUE}==${NC} $*"; }

PASSWORDLESS_SUDO_FOUND=0
REMEDIATE=0

usage() {
    cat <<'EOF'
Usage: bash Linux/Invoke-Harden.sh [--remediate]

Options:
  --remediate    Prompt to comment out unsafe NOPASSWD sudoers entries.
EOF
}

parse_args() {
    while [[ $# -gt 0 ]]; do
        case "$1" in
            --remediate)
                REMEDIATE=1
                ;;
            -h|--help)
                usage
                exit 0
                ;;
            *)
                echo "[!] Unknown argument: $1"
                usage
                exit 1
                ;;
        esac
        shift
    done
}

backup_file() {
    local file="$1"
    local backup="${file}.bak.$(date +%Y%m%d_%H%M%S)"
    cp -p "$file" "$backup"
    info "Backup created: $backup"
}

validate_sudoers_file() {
    local file="$1"

    if command -v visudo >/dev/null 2>&1; then
        visudo -c -f "$file" >/dev/null
        return 0
    fi

    warn "'visudo' is not installed; skipping syntax validation for $file."
    return 0
}

remediate_nopasswd_file() {
    local file="$1"
    local tmp

    if [[ ! -w "$file" ]]; then
        warn "Cannot modify $file. Re-run as root to remediate."
        return 1
    fi

    backup_file "$file"
    tmp="$(mktemp)"

    awk '
        /^[[:space:]]*#/ { print; next }
        /NOPASSWD/ { print "# Disabled by Invoke-Harden.sh: " $0; next }
        { print }
    ' "$file" > "$tmp"

    if validate_sudoers_file "$tmp"; then
        cat "$tmp" > "$file"
        info "Commented out NOPASSWD entries in $file"
        rm -f "$tmp"
        return 0
    fi

    fail "Validation failed for updated $file. Original file preserved."
    rm -f "$tmp"
    return 1
}

prompt_remediation() {
    local file="$1"
    local answer

    if [[ $REMEDIATE -ne 1 ]]; then
        return 0
    fi

    if [[ ! -t 0 ]]; then
        warn "Remediation requested, but no interactive terminal is available."
        return 1
    fi

    printf "Comment out NOPASSWD entries in %s? [y/N] " "$file"
    read -r answer

    case "${answer,,}" in
        y|yes)
            remediate_nopasswd_file "$file"
            ;;
        *)
            warn "Skipped remediation for $file"
            ;;
    esac
}

check_passwordless_sudo_runtime() {
    section "Checking passwordless sudo for current user"

    if ! command -v sudo >/dev/null 2>&1; then
        warn "'sudo' is not installed on this host."
        return 0
    fi

    if sudo -n true >/dev/null 2>&1; then
        fail "Current user '$(id -un)' can run sudo without a password."
        PASSWORDLESS_SUDO_FOUND=1
    else
        info "Current user '$(id -un)' does not have passwordless sudo."
    fi
}

check_passwordless_sudo_config() {
    section "Scanning sudoers configuration for NOPASSWD"

    local -a sudoers_files=()
    local file
    local found=0

    if [[ -r /etc/sudoers ]]; then
        sudoers_files+=("/etc/sudoers")
    else
        warn "Cannot read /etc/sudoers without elevated privileges."
    fi

    if [[ -d /etc/sudoers.d ]]; then
        while IFS= read -r file; do
            sudoers_files+=("$file")
        done < <(find /etc/sudoers.d -maxdepth 1 -type f 2>/dev/null | sort)
    fi

    if [[ ${#sudoers_files[@]} -eq 0 ]]; then
        warn "No readable sudoers files were found."
        return 0
    fi

    for file in "${sudoers_files[@]}"; do
        if grep -Eq '^[[:space:]]*[^#].*\bNOPASSWD\b' "$file"; then
            fail "NOPASSWD entry detected in $file"
            grep -En '^[[:space:]]*[^#].*\bNOPASSWD\b' "$file" || true
            prompt_remediation "$file"

            if grep -Eq '^[[:space:]]*[^#].*\bNOPASSWD\b' "$file"; then
                found=1
            fi
        fi
    done

    if [[ $found -eq 0 ]]; then
        info "No readable sudoers entries containing NOPASSWD were found."
    else
        PASSWORDLESS_SUDO_FOUND=1
    fi
}

main() {
    parse_args "$@"

    echo "Linux hardening helper"
    echo "Host: $(hostname)"
    echo "User: $(id -un)"

    check_passwordless_sudo_runtime
    check_passwordless_sudo_config

    section "Summary"
    if [[ $PASSWORDLESS_SUDO_FOUND -eq 1 ]]; then
        fail "Passwordless sudo is enabled or configured. Remove NOPASSWD entries unless explicitly required."
        exit 1
    fi

    info "No passwordless sudo exposure was detected."
}

main "$@"

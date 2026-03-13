#!/usr/bin/env bash
# Interactive SSH hardening helper.

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

SSH_FINDINGS_FOUND=0
REMEDIATE=0

usage() {
    cat <<'EOF'
Usage: bash Linux/Invoke-SSH-Harden.sh [--remediate]

Options:
  --remediate    Prompt to update low-risk SSH directives only.
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

normalize_value() {
    local value="$1"

    value="${value%%#*}"
    value="${value//[$'\t\r\n ']/}"
    value="${value%\"}"
    value="${value#\"}"
    value="${value%\'}"
    value="${value#\'}"

    printf '%s' "${value,,}"
}

discover_ssh_configs() {
    local -a files=()
    local file

    [[ -f /etc/ssh/sshd_config ]] && files+=("/etc/ssh/sshd_config")

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        if [[ " ${files[*]} " != *" $file "* ]]; then
            files+=("$file")
        fi
    done < <(find /etc/ssh/sshd_config.d -type f -name '*.conf' 2>/dev/null | sort)

    printf '%s\n' "${files[@]}"
}

get_last_directive_value() {
    local file="$1"
    local key="$2"

    awk -v key="$key" '
        BEGIN { IGNORECASE=1 }
        /^[[:space:]]*#/ { next }
        tolower($1) == tolower(key) {
            value = $2
            for (i = 3; i <= NF; i++) {
                value = value " " $i
            }
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            found = 1
        }
        END {
            if (!found) {
                exit 1
            }
            print value
        }
    ' "$file"
}

value_matches() {
    local current="$1"
    local expected="$2"
    local normalized

    normalized="$(normalize_value "$current")"

    case "$expected" in
        yes) [[ "$normalized" == "yes" ]] ;;
        no) [[ "$normalized" == "no" ]] ;;
        *) [[ "$normalized" == "$(normalize_value "$expected")" ]] ;;
    esac
}

ensure_directive() {
    local file="$1"
    local key="$2"
    local value="$3"
    local tmp

    tmp="$(mktemp)"
    awk -v key="$key" -v value="$value" '
        BEGIN { updated=0; IGNORECASE=1 }
        /^[[:space:]]*#/ { print; next }
        tolower($1) == tolower(key) {
            if (!updated) {
                print key " " value
                updated=1
            }
            next
        }
        { print }
        END {
            if (!updated) {
                print key " " value
            }
        }
    ' "$file" > "$tmp"

    cat "$tmp" > "$file"
    rm -f "$tmp"
}

remediate_ssh_directive() {
    local file="$1"
    local key="$2"
    local expected="$3"

    if [[ ! -w "$file" ]]; then
        warn "Cannot modify $file. Re-run as root to remediate."
        return 1
    fi

    backup_file "$file"
    ensure_directive "$file" "$key" "$expected"
    info "Updated $key in $file to $expected"
}

prompt_remediation() {
    local file="$1"
    local key="$2"
    local current="$3"
    local expected="$4"
    local answer

    if [[ $REMEDIATE -ne 1 ]]; then
        return 0
    fi

    if [[ ! -t 0 ]]; then
        warn "Remediation requested, but no interactive terminal is available."
        return 1
    fi

    printf "Update %s in %s from '%s' to '%s'? [y/N] " "$key" "$file" "$current" "$expected"
    read -r answer

    case "${answer,,}" in
        y|yes)
            remediate_ssh_directive "$file" "$key" "$expected"
            ;;
        *)
            warn "Skipped remediation for $key in $file"
            ;;
    esac
}

check_ssh_directives() {
    section "Scanning SSH configuration for conservative hardening settings"

    local -a config_files=()
    local file
    local found=0
    local current

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        config_files+=("$file")
    done < <(discover_ssh_configs)

    if [[ ${#config_files[@]} -eq 0 ]]; then
        warn "No SSH config files were discovered."
        return 0
    fi

    for file in "${config_files[@]}"; do
        info "Inspecting $file"

        if current="$(get_last_directive_value "$file" "PermitEmptyPasswords" 2>/dev/null)"; then
            if value_matches "$current" "no"; then
                info "PermitEmptyPasswords is set to a hardened value in $file"
            else
                fail "PermitEmptyPasswords in $file is '$current' but should be 'no'"
                found=1
                prompt_remediation "$file" "PermitEmptyPasswords" "$current" "no"
            fi
        else
            fail "PermitEmptyPasswords is not set in $file"
            found=1
            prompt_remediation "$file" "PermitEmptyPasswords" "<unset>" "no"
        fi

        if current="$(get_last_directive_value "$file" "X11Forwarding" 2>/dev/null)"; then
            if value_matches "$current" "no"; then
                info "X11Forwarding is set to a hardened value in $file"
            else
                fail "X11Forwarding in $file is '$current' but should be 'no'"
                found=1
                prompt_remediation "$file" "X11Forwarding" "$current" "no"
            fi
        fi

        if current="$(get_last_directive_value "$file" "PermitRootLogin" 2>/dev/null)"; then
            if [[ "$(normalize_value "$current")" == "yes" ]]; then
                fail "PermitRootLogin in $file is 'yes'"
                found=1
            else
                info "PermitRootLogin is restricted in $file to '$current'"
            fi
        fi

        if current="$(get_last_directive_value "$file" "PasswordAuthentication" 2>/dev/null)"; then
            if [[ "$(normalize_value "$current")" == "yes" ]]; then
                warn "PasswordAuthentication is enabled in $file; review carefully before disabling"
            else
                info "PasswordAuthentication is not enabled in $file"
            fi
        fi
    done

    if [[ $found -eq 0 ]]; then
        info "No conservative SSH hardening issues were detected."
        return 0
    fi

    SSH_FINDINGS_FOUND=1
    return 1
}

main() {
    parse_args "$@"

    echo "SSH hardening helper"
    echo "Host: $(hostname)"
    echo "User: $(id -un)"

    check_ssh_directives || true

    section "Summary"
    if [[ $SSH_FINDINGS_FOUND -eq 1 ]]; then
        fail "SSH hardening findings were detected. Review and remediate unsafe configuration."
        exit 1
    fi

    info "No SSH hardening issues were detected."
}

main "$@"

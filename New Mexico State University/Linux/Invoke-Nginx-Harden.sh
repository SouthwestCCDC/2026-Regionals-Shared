#!/usr/bin/env bash
# Interactive Nginx hardening helper.

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

NGINX_FINDINGS_FOUND=0
REMEDIATE=0

usage() {
    cat <<'EOF'
Usage: bash Linux/Invoke-Nginx-Harden.sh [--remediate]

Options:
  --remediate    Prompt to update insecure Nginx directives.
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
    value="${value%%;*}"
    value="${value//[$'\t\r\n ']/}"
    value="${value%\"}"
    value="${value#\"}"
    value="${value%\'}"
    value="${value#\'}"

    printf '%s' "${value,,}"
}

discover_nginx_configs() {
    local -a files=()
    local file
    local main="/etc/nginx/nginx.conf"

    [[ -f "$main" ]] && files+=("$main")

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        if [[ " ${files[*]} " != *" $file "* ]]; then
            files+=("$file")
        fi
    done < <(find /etc/nginx -type f \( -name '*.conf' -o -name 'nginx.conf' \) 2>/dev/null | sort)

    printf '%s\n' "${files[@]}"
}

get_last_nginx_directive_value() {
    local file="$1"
    local key="$2"

    awk -v key="$key" '
        /^[[:space:]]*#/ { next }
        $1 == key {
            value = $2
            gsub(/;$/, "", value)
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

nginx_value_matches() {
    local current="$1"
    local expected="$2"

    [[ "$(normalize_value "$current")" == "$(normalize_value "$expected")" ]]
}

ensure_nginx_directive() {
    local file="$1"
    local key="$2"
    local value="$3"
    local tmp

    tmp="$(mktemp)"
    awk -v key="$key" -v value="$value" '
        BEGIN { updated=0 }
        /^[[:space:]]*#/ { print; next }
        $1 == key {
            if (!updated) {
                print key " " value ";"
                updated=1
            }
            next
        }
        { print }
        END {
            if (!updated) {
                print key " " value ";"
            }
        }
    ' "$file" > "$tmp"

    cat "$tmp" > "$file"
    rm -f "$tmp"
}

remediate_nginx_directive() {
    local file="$1"
    local key="$2"
    local expected="$3"

    if [[ ! -w "$file" ]]; then
        warn "Cannot modify $file. Re-run as root to remediate."
        return 1
    fi

    backup_file "$file"
    ensure_nginx_directive "$file" "$key" "$expected"
    info "Updated $key in $file to $expected"
}

prompt_nginx_remediation() {
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
            remediate_nginx_directive "$file" "$key" "$expected"
            ;;
        *)
            warn "Skipped remediation for $key in $file"
            ;;
    esac
}

check_nginx_directives() {
    section "Scanning Nginx configuration for conservative hardening settings"

    local -a config_files=()
    local file
    local found=0
    local current

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        config_files+=("$file")
    done < <(discover_nginx_configs)

    if [[ ${#config_files[@]} -eq 0 ]]; then
        warn "No Nginx config files were discovered."
        return 0
    fi

    for file in "${config_files[@]}"; do
        info "Inspecting $file"

        if current="$(get_last_nginx_directive_value "$file" "server_tokens" 2>/dev/null)"; then
            if nginx_value_matches "$current" "off"; then
                info "server_tokens is set to a hardened value in $file"
            else
                fail "server_tokens in $file is '$current' but should be 'off' (reduce version disclosure)"
                found=1
                prompt_nginx_remediation "$file" "server_tokens" "$current" "off"
            fi
        else
            fail "server_tokens is not set in $file (expected 'off' - reduce version disclosure)"
            found=1
            prompt_nginx_remediation "$file" "server_tokens" "<unset>" "off"
        fi

        if grep -Ein '^[[:space:]]*autoindex[[:space:]]+on;' "$file" >/dev/null 2>&1; then
            fail "Directory listing is enabled via autoindex on in $file"
            grep -Ein '^[[:space:]]*autoindex[[:space:]]+on;' "$file" || true
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        info "No conservative Nginx hardening issues were detected."
        return 0
    fi

    NGINX_FINDINGS_FOUND=1
    return 1
}

main() {
    parse_args "$@"

    echo "Nginx hardening helper"
    echo "Host: $(hostname)"
    echo "User: $(id -un)"

    check_nginx_directives || true

    section "Summary"
    if [[ $NGINX_FINDINGS_FOUND -eq 1 ]]; then
        fail "Nginx hardening findings were detected. Review and remediate unsafe configuration."
        exit 1
    fi

    info "No Nginx hardening issues were detected."
}

main "$@"

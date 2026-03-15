#!/usr/bin/env bash
# Interactive PHP-FPM hardening helper.

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

PHP_FPM_FINDINGS_FOUND=0
REMEDIATE=0

usage() {
    cat <<'EOF'
Usage: bash Linux/Invoke-PHP-FPM-Harden.sh [--remediate]

Options:
  --remediate    Prompt to update low-risk PHP-FPM directives.
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

    value="${value%%;*}"
    value="${value%%#*}"
    value="${value//[$'\t\r\n ']/}"
    value="${value%\"}"
    value="${value#\"}"
    value="${value%\'}"
    value="${value#\'}"

    printf '%s' "${value,,}"
}

discover_php_fpm_configs() {
    local -a files=()
    local file

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        files+=("$file")
    done < <(find /etc/php -type f \( -name 'php-fpm.conf' -o -name '*.conf' \) 2>/dev/null | sort)

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        if [[ " ${files[*]} " != *" $file "* ]]; then
            files+=("$file")
        fi
    done < <(find /etc/php-fpm.d /etc/php-fpm.conf /etc/php-fpm.d /etc/php*/fpm/pool.d -type f 2>/dev/null | sort)

    printf '%s\n' "${files[@]}"
}

get_last_directive_value() {
    local file="$1"
    local key="$2"

    awk -F'=' -v key="$key" '
        BEGIN { IGNORECASE=1 }
        /^[[:space:]]*[;#]/ { next }
        $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
            value=$0
            sub(/^[^=]*=/, "", value)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            found=1
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
        yes) [[ "$normalized" == "yes" || "$normalized" == "1" || "$normalized" == "on" ]] ;;
        no) [[ "$normalized" == "no" || "$normalized" == "0" || "$normalized" == "off" ]] ;;
        *) [[ "$normalized" == "$(normalize_value "$expected")" ]] ;;
    esac
}

ensure_ini_directive() {
    local file="$1"
    local key="$2"
    local value="$3"
    local tmp

    tmp="$(mktemp)"
    awk -v key="$key" -v value="$value" '
        BEGIN { updated=0 }
        /^[[:space:]]*[;#]/ { print; next }
        $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            if (!updated) {
                print key " = " value
                updated=1
            }
            next
        }
        { print }
        END {
            if (!updated) {
                print key " = " value
            }
        }
    ' "$file" > "$tmp"

    cat "$tmp" > "$file"
    rm -f "$tmp"
}

remediate_php_fpm_directive() {
    local file="$1"
    local key="$2"
    local expected="$3"

    if [[ ! -w "$file" ]]; then
        warn "Cannot modify $file. Re-run as root to remediate."
        return 1
    fi

    backup_file "$file"
    ensure_ini_directive "$file" "$key" "$expected"
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
            remediate_php_fpm_directive "$file" "$key" "$expected"
            ;;
        *)
            warn "Skipped remediation for $key in $file"
            ;;
    esac
}

check_php_fpm_directives() {
    section "Scanning PHP-FPM configuration for conservative hardening settings"

    local -a config_files=()
    local file
    local found=0
    local current

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        config_files+=("$file")
    done < <(discover_php_fpm_configs)

    if [[ ${#config_files[@]} -eq 0 ]]; then
        warn "No PHP-FPM config files were discovered."
        return 0
    fi

    for file in "${config_files[@]}"; do
        info "Inspecting $file"

        if current="$(get_last_directive_value "$file" "clear_env" 2>/dev/null)"; then
            if value_matches "$current" "yes"; then
                info "clear_env is set to a hardened value in $file"
            else
                fail "clear_env in $file is '$current' but should be 'yes' (avoid leaking environment variables)"
                found=1
                prompt_remediation "$file" "clear_env" "$current" "yes"
            fi
        fi

        if current="$(get_last_directive_value "$file" "security.limit_extensions" 2>/dev/null)"; then
            if value_matches "$current" ".php"; then
                info "security.limit_extensions is set to a hardened value in $file"
            else
                fail "security.limit_extensions in $file is '$current' but should be '.php' (restrict executable extensions)"
                found=1
                prompt_remediation "$file" "security.limit_extensions" "$current" ".php"
            fi
        fi

        if current="$(get_last_directive_value "$file" "listen" 2>/dev/null)"; then
            if [[ "$current" == *:* ]]; then
                if get_last_directive_value "$file" "listen.allowed_clients" >/dev/null 2>&1; then
                    info "listen.allowed_clients is present for TCP listener in $file"
                else
                    fail "TCP listener '$current' in $file has no listen.allowed_clients restriction"
                    found=1
                fi
            fi
        fi
    done

    if [[ $found -eq 0 ]]; then
        info "No conservative PHP-FPM hardening issues were detected."
        return 0
    fi

    PHP_FPM_FINDINGS_FOUND=1
    return 1
}

main() {
    parse_args "$@"

    echo "PHP-FPM hardening helper"
    echo "Host: $(hostname)"
    echo "User: $(id -un)"

    check_php_fpm_directives || true

    section "Summary"
    if [[ $PHP_FPM_FINDINGS_FOUND -eq 1 ]]; then
        fail "PHP-FPM hardening findings were detected. Review and remediate unsafe configuration."
        exit 1
    fi

    info "No PHP-FPM hardening issues were detected."
}

main "$@"

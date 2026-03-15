#!/usr/bin/env bash
# Interactive PHP application hardening helper.

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

PHP_INI_ISSUES_FOUND=0
REMEDIATE=0

usage() {
    cat <<'EOF'
Usage: bash Linux/Invoke-PHP-Harden.sh [--remediate]

Options:
  --remediate    Prompt to update insecure or missing php.ini directives.
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

normalize_ini_value() {
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

discover_php_ini_files() {
    local php_ini=""
    local -a files=()
    local file

    if command -v php >/dev/null 2>&1; then
        php_ini="$(php --ini 2>/dev/null | awk -F': ' '/Loaded Configuration File/ { print $2 }' | head -n1)"
        if [[ -n "$php_ini" && "$php_ini" != "(none)" && -f "$php_ini" ]]; then
            files+=("$php_ini")
        fi
    fi

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue

        if [[ " ${files[*]} " != *" $file "* ]]; then
            files+=("$file")
        fi
    done < <(find /etc/php /etc -type f -name php.ini 2>/dev/null | sort)

    printf '%s\n' "${files[@]}"
}

get_ini_value() {
    local file="$1"
    local key="$2"

    awk -F'=' -v key="$key" '
        /^[[:space:]]*[;#]/ { next }
        $1 ~ "^[[:space:]]*" key "[[:space:]]*$" {
            value=$0
            sub(/^[^=]*=/, "", value)
            gsub(/^[[:space:]]+|[[:space:]]+$/, "", value)
            print value
            found=1
        }
        END {
            if (!found) {
                exit 1
            }
        }
    ' "$file"
}

ini_value_matches() {
    local current="$1"
    local expected="$2"
    local normalized

    normalized="$(normalize_ini_value "$current")"

    case "$expected" in
        off) [[ "$normalized" == "off" || "$normalized" == "0" ]] ;;
        on) [[ "$normalized" == "on" || "$normalized" == "1" ]] ;;
        1) [[ "$normalized" == "1" || "$normalized" == "on" ]] ;;
        0) [[ "$normalized" == "0" || "$normalized" == "off" ]] ;;
        *) [[ "$normalized" == "$(normalize_ini_value "$expected")" ]] ;;
    esac
}

set_ini_value() {
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

remediate_php_ini_file() {
    local file="$1"
    local key="$2"
    local expected="$3"

    if [[ ! -w "$file" ]]; then
        warn "Cannot modify $file. Re-run as root to remediate."
        return 1
    fi

    backup_file "$file"
    set_ini_value "$file" "$key" "$expected"
    info "Updated $key in $file to $expected"
}

prompt_php_ini_remediation() {
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
            remediate_php_ini_file "$file" "$key" "$expected"
            ;;
        *)
            warn "Skipped remediation for $key in $file"
            ;;
    esac
}

check_php_ini_hardening() {
    section "Scanning PHP configuration for insecure php.ini settings"

    local -a php_ini_files=()
    local file
    local found=0
    local key
    local expected
    local current
    local label

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        php_ini_files+=("$file")
    done < <(discover_php_ini_files)

    if [[ ${#php_ini_files[@]} -eq 0 ]]; then
        warn "No php.ini files were discovered."
        return 0
    fi

    for file in "${php_ini_files[@]}"; do
        info "Inspecting $file"

        while IFS='|' read -r key expected label; do
            if current="$(get_ini_value "$file" "$key" 2>/dev/null)"; then
                if ini_value_matches "$current" "$expected"; then
                    info "$key is set to a hardened value in $file"
                else
                    fail "$key in $file is '$current' but should be '$expected' ($label)"
                    found=1
                    prompt_php_ini_remediation "$file" "$key" "$current" "$expected"
                fi
            else
                fail "$key is not set in $file (expected '$expected' - $label)"
                found=1
                prompt_php_ini_remediation "$file" "$key" "<unset>" "$expected"
            fi
        done <<'EOF'
expose_php|Off|hide PHP version disclosure headers
display_errors|Off|avoid leaking stack traces to clients
display_startup_errors|Off|avoid leaking startup errors to clients
log_errors|On|preserve server-side error visibility
session.cookie_httponly|1|block JavaScript access to session cookies
session.use_strict_mode|1|reject uninitialized session IDs
session.cookie_samesite|Lax|tighten cross-site cookie behavior
allow_url_include|Off|disable remote file inclusion in include/require
cgi.fix_pathinfo|0|reduce path traversal risk on CGI/FPM setups
EOF
    done

    if [[ $found -eq 0 ]]; then
        info "No insecure php.ini settings were detected in discovered files."
        return 0
    fi

    PHP_INI_ISSUES_FOUND=1
    return 1
}

main() {
    parse_args "$@"

    echo "PHP hardening helper"
    echo "Host: $(hostname)"
    echo "User: $(id -un)"

    check_php_ini_hardening || true

    section "Summary"
    if [[ $PHP_INI_ISSUES_FOUND -eq 1 ]]; then
        fail "PHP configuration findings were detected. Review and remediate unsafe php.ini settings."
        exit 1
    fi

    info "No php.ini hardening issues were detected."
}

main "$@"

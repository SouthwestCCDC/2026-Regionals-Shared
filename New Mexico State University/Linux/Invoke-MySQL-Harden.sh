#!/usr/bin/env bash
# Interactive MySQL/MariaDB hardening helper.

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

MYSQL_FINDINGS_FOUND=0
REMEDIATE=0

usage() {
    cat <<'EOF'
Usage: bash Linux/Invoke-MySQL-Harden.sh [--remediate]

Options:
  --remediate    Prompt to update low-risk MySQL/MariaDB directives.
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

discover_mysql_configs() {
    local -a files=()
    local file

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        if [[ " ${files[*]} " != *" $file "* ]]; then
            files+=("$file")
        fi
    done < <(find /etc/mysql /etc/my.cnf /etc/my.cnf.d /etc/mysql.conf.d -type f 2>/dev/null | sort)

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
        1|on) [[ "$normalized" == "1" || "$normalized" == "on" ]] ;;
        0|off) [[ "$normalized" == "0" || "$normalized" == "off" ]] ;;
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

remediate_mysql_directive() {
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
            remediate_mysql_directive "$file" "$key" "$expected"
            ;;
        *)
            warn "Skipped remediation for $key in $file"
            ;;
    esac
}

check_mysql_directives() {
    section "Scanning MySQL/MariaDB configuration for conservative hardening settings"

    local -a config_files=()
    local file
    local found=0
    local current

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        config_files+=("$file")
    done < <(discover_mysql_configs)

    if [[ ${#config_files[@]} -eq 0 ]]; then
        warn "No MySQL/MariaDB config files were discovered."
        return 0
    fi

    for file in "${config_files[@]}"; do
        info "Inspecting $file"

        if current="$(get_last_directive_value "$file" "local_infile" 2>/dev/null)"; then
            if value_matches "$current" "0"; then
                info "local_infile is set to a hardened value in $file"
            else
                fail "local_infile in $file is '$current' but should be '0' (reduce file import abuse)"
                found=1
                prompt_remediation "$file" "local_infile" "$current" "0"
            fi
        fi

        if current="$(get_last_directive_value "$file" "symbolic-links" 2>/dev/null)"; then
            if value_matches "$current" "0"; then
                info "symbolic-links is set to a hardened value in $file"
            else
                fail "symbolic-links in $file is '$current' but should be '0' (avoid symlink abuse)"
                found=1
                prompt_remediation "$file" "symbolic-links" "$current" "0"
            fi
        fi

        if current="$(get_last_directive_value "$file" "secure_file_priv" 2>/dev/null)"; then
            info "secure_file_priv is set in $file to '$current'"
        else
            fail "secure_file_priv is not set in $file"
            found=1
        fi

        if current="$(get_last_directive_value "$file" "skip_networking" 2>/dev/null)"; then
            info "skip_networking is set in $file to '$current'"
        fi

        if current="$(get_last_directive_value "$file" "bind-address" 2>/dev/null)"; then
            if [[ "$(normalize_value "$current")" == "0.0.0.0" ]]; then
                fail "bind-address in $file is '$current' (exposed on all interfaces)"
                found=1
            else
                info "bind-address is restricted in $file to '$current'"
            fi
        fi
    done

    if [[ $found -eq 0 ]]; then
        info "No conservative MySQL/MariaDB hardening issues were detected."
        return 0
    fi

    MYSQL_FINDINGS_FOUND=1
    return 1
}

main() {
    parse_args "$@"

    echo "MySQL/MariaDB hardening helper"
    echo "Host: $(hostname)"
    echo "User: $(id -un)"

    check_mysql_directives || true

    section "Summary"
    if [[ $MYSQL_FINDINGS_FOUND -eq 1 ]]; then
        fail "MySQL/MariaDB hardening findings were detected. Review and remediate unsafe configuration."
        exit 1
    fi

    info "No MySQL/MariaDB hardening issues were detected."
}

main "$@"

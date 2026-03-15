#!/usr/bin/env bash
# Interactive Apache hardening helper.

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

APACHE_FINDINGS_FOUND=0
REMEDIATE=0

usage() {
    cat <<'EOF'
Usage: bash Linux/Invoke-Apache-Harden.sh [--remediate]

Options:
  --remediate    Prompt to update insecure Apache directives.
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

apache_ctl() {
    if command -v apache2ctl >/dev/null 2>&1; then
        printf '%s\n' "apache2ctl"
        return 0
    fi

    if command -v apachectl >/dev/null 2>&1; then
        printf '%s\n' "apachectl"
        return 0
    fi

    return 1
}

discover_apache_configs() {
    local ctl=""
    local -a files=()
    local file

    if ctl="$(apache_ctl)"; then
        file="$("$ctl" -V 2>/dev/null | awk -F'"' '/SERVER_CONFIG_FILE/ { print $2 }' | head -n1)"
        if [[ -n "$file" ]]; then
            if [[ "$file" != /* ]]; then
                local root
                root="$("$ctl" -V 2>/dev/null | awk -F'"' '/HTTPD_ROOT/ { print $2 }' | head -n1)"
                if [[ -n "$root" ]]; then
                    file="$root/$file"
                fi
            fi
            [[ -f "$file" ]] && files+=("$file")
        fi
    fi

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        if [[ " ${files[*]} " != *" $file "* ]]; then
            files+=("$file")
        fi
    done < <(find /etc/apache2 /etc/httpd -type f \( -name '*.conf' -o -name 'httpd.conf' -o -name 'apache2.conf' \) 2>/dev/null | sort)

    printf '%s\n' "${files[@]}"
}

get_last_directive_value() {
    local file="$1"
    local key="$2"

    awk -v key="$key" '
        BEGIN { IGNORECASE=1 }
        /^[[:space:]]*#/ { next }
        tolower($1) == tolower(key) {
            value=""
            for (i = 2; i <= NF; i++) {
                value = value (i == 2 ? "" : " ") $i
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

apache_value_matches() {
    local current="$1"
    local expected="$2"

    [[ "$(normalize_value "$current")" == "$(normalize_value "$expected")" ]]
}

ensure_apache_directive() {
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

remediate_apache_directive() {
    local file="$1"
    local key="$2"
    local expected="$3"

    if [[ ! -w "$file" ]]; then
        warn "Cannot modify $file. Re-run as root to remediate."
        return 1
    fi

    backup_file "$file"
    ensure_apache_directive "$file" "$key" "$expected"
    info "Updated $key in $file to $expected"
}

prompt_apache_remediation() {
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
            remediate_apache_directive "$file" "$key" "$expected"
            ;;
        *)
            warn "Skipped remediation for $key in $file"
            ;;
    esac
}

check_apache_directives() {
    section "Scanning Apache configuration for conservative hardening settings"

    local -a config_files=()
    local file
    local found=0
    local key
    local expected
    local label
    local current

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue
        config_files+=("$file")
    done < <(discover_apache_configs)

    if [[ ${#config_files[@]} -eq 0 ]]; then
        warn "No Apache config files were discovered."
        return 0
    fi

    for file in "${config_files[@]}"; do
        info "Inspecting $file"

        while IFS='|' read -r key expected label; do
            if current="$(get_last_directive_value "$file" "$key" 2>/dev/null)"; then
                if apache_value_matches "$current" "$expected"; then
                    info "$key is set to a hardened value in $file"
                else
                    fail "$key in $file is '$current' but should be '$expected' ($label)"
                    found=1
                    prompt_apache_remediation "$file" "$key" "$current" "$expected"
                fi
            else
                fail "$key is not set in $file (expected '$expected' - $label)"
                found=1
                prompt_apache_remediation "$file" "$key" "<unset>" "$expected"
            fi
        done <<'EOF'
ServerTokens|Prod|reduce version disclosure
ServerSignature|Off|hide Apache version on generated pages
TraceEnable|Off|disable TRACE requests
EOF
    done

    local autoindex_files=()
    while IFS= read -r file; do
        autoindex_files+=("$file")
    done < <(find /etc/apache2 /etc/httpd -type f \( -name '*.conf' -o -name 'httpd.conf' -o -name 'apache2.conf' \) 2>/dev/null | sort)

    for file in "${autoindex_files[@]}"; do
        if grep -Ein '^[[:space:]]*Options\b.*\bIndexes\b' "$file" >/dev/null 2>&1; then
            fail "Directory listing is enabled via Options Indexes in $file"
            grep -Ein '^[[:space:]]*Options\b.*\bIndexes\b' "$file" || true
            found=1
        fi
    done

    if [[ $found -eq 0 ]]; then
        info "No conservative Apache hardening issues were detected."
        return 0
    fi

    APACHE_FINDINGS_FOUND=1
    return 1
}

main() {
    parse_args "$@"

    echo "Apache hardening helper"
    echo "Host: $(hostname)"
    echo "User: $(id -un)"

    check_apache_directives || true

    section "Summary"
    if [[ $APACHE_FINDINGS_FOUND -eq 1 ]]; then
        fail "Apache hardening findings were detected. Review and remediate unsafe configuration."
        exit 1
    fi

    info "No Apache hardening issues were detected."
}

main "$@"

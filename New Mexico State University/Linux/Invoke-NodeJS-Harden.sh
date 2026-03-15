#!/usr/bin/env bash
# Interactive Node.js hardening helper.

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

NODE_FINDINGS_FOUND=0
REMEDIATE=0

usage() {
    cat <<'EOF'
Usage: bash Linux/Invoke-NodeJS-Harden.sh [--remediate]

Options:
  --remediate    Prompt to update low-risk Node.js findings.
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

discover_node_projects() {
    local root

    while IFS= read -r root; do
        [[ "$root" == *"/node_modules/"* ]] && continue
        printf '%s\n' "$root"
    done < <(find /opt /srv /var/www /home -type f -name package.json 2>/dev/null | sort | xargs -I{} dirname "{}")
}

discover_env_files() {
    local project_dir="$1"
    local file

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        printf '%s\n' "$file"
    done < <(find "$project_dir" -maxdepth 2 -type f \( -name '.env' -o -name '.env.production' -o -name '.env.local' \) 2>/dev/null | sort)
}

discover_runtime_configs() {
    local project_dir="$1"
    local file

    while IFS= read -r file; do
        [[ -f "$file" ]] || continue
        printf '%s\n' "$file"
    done < <(find "$project_dir" -maxdepth 2 -type f \( -name 'package.json' -o -name 'ecosystem*.config.js' -o -name 'ecosystem*.config.cjs' -o -name 'ecosystem*.config.json' \) 2>/dev/null | sort)
}

get_env_value() {
    local file="$1"
    local key="$2"

    awk -F'=' -v key="$key" '
        /^[[:space:]]*#/ { next }
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

set_env_value() {
    local file="$1"
    local key="$2"
    local value="$3"
    local tmp

    tmp="$(mktemp)"
    awk -v key="$key" -v value="$value" '
        BEGIN { updated=0 }
        /^[[:space:]]*#/ { print; next }
        $0 ~ "^[[:space:]]*" key "[[:space:]]*=" {
            if (!updated) {
                print key "=" value
                updated=1
            }
            next
        }
        { print }
        END {
            if (!updated) {
                print key "=" value
            }
        }
    ' "$file" > "$tmp"

    cat "$tmp" > "$file"
    rm -f "$tmp"
}

remediate_env_value() {
    local file="$1"
    local key="$2"
    local expected="$3"

    if [[ ! -w "$file" ]]; then
        warn "Cannot modify $file. Re-run as root to remediate."
        return 1
    fi

    backup_file "$file"
    set_env_value "$file" "$key" "$expected"
    info "Updated $key in $file to $expected"
}

prompt_env_remediation() {
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
            remediate_env_value "$file" "$key" "$expected"
            ;;
        *)
            warn "Skipped remediation for $key in $file"
            ;;
    esac
}

file_mode_octal() {
    local file="$1"
    stat -f '%Lp' "$file" 2>/dev/null || stat -c '%a' "$file" 2>/dev/null
}

is_permissions_hardened() {
    local mode="$1"
    [[ -n "$mode" ]] || return 1

    local group=$(( (10#$mode / 10) % 10 ))
    local other=$(( 10#$mode % 10 ))

    (( group <= 4 && other == 0 ))
}

remediate_permissions() {
    local file="$1"
    local mode="$2"

    if [[ ! -w "$file" ]]; then
        warn "Cannot modify permissions on $file. Re-run as root to remediate."
        return 1
    fi

    chmod "$mode" "$file"
    info "Updated permissions on $file to $mode"
}

prompt_permission_remediation() {
    local file="$1"
    local current="$2"
    local expected="$3"
    local answer

    if [[ $REMEDIATE -ne 1 ]]; then
        return 0
    fi

    if [[ ! -t 0 ]]; then
        warn "Remediation requested, but no interactive terminal is available."
        return 1
    fi

    printf "Update permissions on %s from '%s' to '%s'? [y/N] " "$file" "$current" "$expected"
    read -r answer

    case "${answer,,}" in
        y|yes)
            remediate_permissions "$file" "$expected"
            ;;
        *)
            warn "Skipped permission remediation for $file"
            ;;
    esac
}

check_node_project() {
    local project_dir="$1"
    local package_json="$project_dir/package.json"
    local file
    local current
    local mode
    local project_found=0

    section "Scanning Node.js project: $project_dir"

    if [[ ! -f "$package_json" ]]; then
        warn "No package.json found in $project_dir"
        return 0
    fi

    project_found=1

    if grep -Ein '"start"[[:space:]]*:[[:space:]]*"[^"]*nodemon' "$package_json" >/dev/null 2>&1; then
        fail "package.json uses nodemon in the start script"
        NODE_FINDINGS_FOUND=1
    else
        info "No nodemon usage detected in the start script"
    fi

    if grep -Ein '"(start|serve|prod|pm2:start)"[[:space:]]*:[[:space:]]*"[^"]*--inspect(-brk)?' "$package_json" >/dev/null 2>&1; then
        fail "package.json includes Node inspector flags in runtime scripts"
        NODE_FINDINGS_FOUND=1
    else
        info "No Node inspector flags detected in runtime scripts"
    fi

    if grep -Ein '"express"[[:space:]]*:' "$package_json" >/dev/null 2>&1; then
        if grep -Ein '"helmet"[[:space:]]*:' "$package_json" >/dev/null 2>&1; then
            info "Express app appears to include helmet"
        else
            warn "Express dependency found without helmet. Review application-layer headers manually."
        fi
    fi

    while IFS= read -r file; do
        info "Inspecting environment file $file"

        if current="$(get_env_value "$file" "NODE_ENV" 2>/dev/null)"; then
            if [[ "$(normalize_value "$current")" == "production" ]]; then
                info "NODE_ENV is set to production in $file"
            else
                fail "NODE_ENV in $file is '$current' but should be 'production'"
                NODE_FINDINGS_FOUND=1
                prompt_env_remediation "$file" "NODE_ENV" "$current" "production"
            fi
        else
            fail "NODE_ENV is not set in $file"
            NODE_FINDINGS_FOUND=1
            prompt_env_remediation "$file" "NODE_ENV" "<unset>" "production"
        fi

        mode="$(file_mode_octal "$file" || true)"
        if is_permissions_hardened "$mode"; then
            info "Permissions on $file are adequately restricted ($mode)"
        else
            fail "Permissions on $file are too broad ($mode). Expected 640 or stricter."
            NODE_FINDINGS_FOUND=1
            prompt_permission_remediation "$file" "${mode:-unknown}" "640"
        fi
    done < <(discover_env_files "$project_dir")

    while IFS= read -r file; do
        [[ "$file" == "$package_json" ]] && continue
        info "Inspecting runtime config $file"

        if grep -Ein -- '--inspect(-brk)?' "$file" >/dev/null 2>&1; then
            fail "Inspector flags detected in $file"
            NODE_FINDINGS_FOUND=1
        fi

        if grep -Ein '\bnodemon\b' "$file" >/dev/null 2>&1; then
            fail "nodemon detected in runtime config $file"
            NODE_FINDINGS_FOUND=1
        fi
    done < <(discover_runtime_configs "$project_dir")

    mode="$(file_mode_octal "$package_json" || true)"
    if is_permissions_hardened "$mode"; then
        info "Permissions on package.json are adequately restricted ($mode)"
    else
        fail "Permissions on package.json are too broad ($mode). Expected 644 or stricter."
        NODE_FINDINGS_FOUND=1
        prompt_permission_remediation "$package_json" "${mode:-unknown}" "644"
    fi

    [[ $project_found -eq 1 ]] || return 0
}

main() {
    parse_args "$@"

    echo "Node.js hardening helper"
    echo "Host: $(hostname)"
    echo "User: $(id -un)"

    local found_any=0
    local project_dir

    while IFS= read -r project_dir; do
        [[ -n "$project_dir" ]] || continue
        found_any=1
        check_node_project "$project_dir"
    done < <(discover_node_projects)

    if [[ $found_any -eq 0 ]]; then
        section "Summary"
        warn "No Node.js projects were discovered under /opt, /srv, /var/www, or /home."
        exit 0
    fi

    section "Summary"
    if [[ $NODE_FINDINGS_FOUND -eq 1 ]]; then
        fail "Node.js hardening findings were detected. Review and remediate unsafe configuration."
        exit 1
    fi

    info "No Node.js hardening issues were detected."
}

main "$@"

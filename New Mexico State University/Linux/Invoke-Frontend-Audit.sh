#!/usr/bin/env bash
# Front-end web application audit helper.

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

FRONTEND_FINDINGS_FOUND=0

usage() {
    cat <<'EOF'
Usage: bash Linux/Invoke-Frontend-Audit.sh [path ...]

Arguments:
  path           Optional one or more application roots to scan.

Behavior:
  If no paths are provided, scans /var/www, /srv, /opt, and /home for front-end assets.
EOF
}

parse_args() {
    if [[ $# -gt 0 ]]; then
        case "$1" in
            -h|--help)
                usage
                exit 0
                ;;
        esac
    fi
}

discover_roots() {
    if [[ $# -gt 0 ]]; then
        printf '%s\n' "$@"
        return 0
    fi

    local path
    for path in /var/www /srv /opt /home; do
        [[ -d "$path" ]] && printf '%s\n' "$path"
    done
}

find_frontend_files() {
    local root="$1"

    find "$root" \
        -type d \( -name node_modules -o -name dist -o -name build -o -name coverage -o -name .git \) -prune -o \
        -type f \( \
            -name '*.html' -o -name '*.htm' -o -name '*.js' -o -name '*.jsx' -o \
            -name '*.ts' -o -name '*.tsx' -o -name '*.vue' -o -name '*.svelte' -o \
            -name '*.php' -o -name '*.ejs' -o -name '*.hbs' -o -name '*.mustache' \
        \) -print 2>/dev/null
}

run_pattern_check() {
    local root="$1"
    local title="$2"
    local pattern="$3"
    local message="$4"
    local type="${5:-fail}"
    local output=""

    output="$(find_frontend_files "$root" | xargs -r rg -n -H -e "$pattern" 2>/dev/null || true)"
    if [[ -n "$output" ]]; then
        section "$title"
        if [[ "$type" == "warn" ]]; then
            warn "$message"
        else
            fail "$message"
            FRONTEND_FINDINGS_FOUND=1
        fi
        printf '%s\n' "$output"
    fi
}

check_target_blank_links() {
    local root="$1"
    local output=""

    output="$(find_frontend_files "$root" | xargs -r rg -n -H 'target=["'"'"']_blank["'"'"']' 2>/dev/null | rg -v 'rel=["'"'"'][^"'"'"']*(noopener|noreferrer)' || true)"
    if [[ -n "$output" ]]; then
        section "Unsafe External Links"
        fail "Links opening in a new tab without rel=noopener/noreferrer were found."
        printf '%s\n' "$output"
        FRONTEND_FINDINGS_FOUND=1
    fi
}

check_http_resources() {
    local root="$1"
    local output=""

    output="$(find_frontend_files "$root" | xargs -r rg -n -H 'https?://[^"'"'"' )]+' 2>/dev/null | rg 'http://' || true)"
    if [[ -n "$output" ]]; then
        section "Insecure External Resources"
        fail "HTTP resources were found in front-end code or templates."
        printf '%s\n' "$output"
        FRONTEND_FINDINGS_FOUND=1
    fi
}

check_post_forms_for_csrf() {
    local root="$1"
    local files=""
    local file
    local found=0

    files="$(find_frontend_files "$root" | rg '\.(html|htm|php|ejs|hbs|mustache|vue)$' || true)"
    [[ -n "$files" ]] || return 0

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue

        if rg -n '<form[^>]*method=["'"'"']?post["'"'"']?' "$file" >/dev/null 2>&1; then
            if ! rg -n 'csrf|_token|csrf_token|authenticity_token|@csrf|name=["'"'"']_csrf["'"'"']|name=["'"'"']csrf' "$file" >/dev/null 2>&1; then
                if [[ $found -eq 0 ]]; then
                    section "Potential CSRF Gaps"
                    fail "POST forms without an obvious CSRF token marker were found."
                fi
                rg -n '<form[^>]*method=["'"'"']?post["'"'"']?' "$file" || true
                found=1
                FRONTEND_FINDINGS_FOUND=1
            fi
        fi
    done <<< "$files"
}

check_missing_csp_meta() {
    local root="$1"
    local files=""
    local file
    local found=0

    files="$(find_frontend_files "$root" | rg '\.(html|htm)$' || true)"
    [[ -n "$files" ]] || return 0

    while IFS= read -r file; do
        [[ -n "$file" ]] || continue

        if rg -n '<head' "$file" >/dev/null 2>&1; then
            if ! rg -n 'Content-Security-Policy' "$file" >/dev/null 2>&1; then
                if [[ $found -eq 0 ]]; then
                    section "CSP Review"
                    warn "HTML entrypoints without an inline CSP meta tag were found. Header-based CSP may still be present server-side."
                fi
                printf '%s\n' "$file"
                found=1
            fi
        fi
    done <<< "$files"
}

check_sourcemaps() {
    local root="$1"
    local output=""

    output="$(find "$root" -type f -name '*.map' 2>/dev/null || true)"
    if [[ -n "$output" ]]; then
        section "Exposed Sourcemaps"
        warn "Sourcemap files were found. Verify they are not exposed in production."
        printf '%s\n' "$output"
    fi
}

check_frontend_secrets() {
    local root="$1"
    local output=""

    output="$(find_frontend_files "$root" | xargs -r rg -n -H -i '(api[_-]?key|secret|token|aws_access_key_id|aws_secret_access_key|private_key|BEGIN (RSA|EC|OPENSSH) PRIVATE KEY)' 2>/dev/null | rg -v 'csrf|csrf_token|_token|authenticity_token' || true)"
    if [[ -n "$output" ]]; then
        section "Potential Front-End Secrets"
        fail "Potential secrets or sensitive tokens were found in front-end files."
        printf '%s\n' "$output"
        FRONTEND_FINDINGS_FOUND=1
    fi
}

scan_root() {
    local root="$1"
    local first_file=""

    if [[ ! -d "$root" ]]; then
        warn "Skipping non-directory path: $root"
        return 0
    fi

    section "Scanning Root: $root"

    first_file="$(find_frontend_files "$root" | head -n 1 || true)"
    if [[ -z "$first_file" ]]; then
        warn "No front-end files were discovered under $root."
        return 0
    fi

    run_pattern_check "$root" "DOM XSS Sinks" '(\.innerHTML\s*=|\.outerHTML\s*=|insertAdjacentHTML\s*\(|document\.write\s*\()' \
        "Potential DOM XSS sinks were found in front-end code."
    run_pattern_check "$root" "Dangerous Dynamic Code" '(eval\s*\(|new Function\s*\(|setTimeout\s*\(\s*["'"'"'])' \
        "Dynamic code execution patterns were found."
    run_pattern_check "$root" "Framework HTML Injection" '(dangerouslySetInnerHTML|v-html|{@html}|bypassSecurityTrust(Html|Script|Style|Url|ResourceUrl))' \
        "Framework-specific raw HTML or trust-bypass patterns were found."
    run_pattern_check "$root" "Client Storage of Sensitive Data" '(localStorage|sessionStorage).*(token|jwt|auth|secret)' \
        "Potential sensitive client-side storage patterns were found."
    run_pattern_check "$root" "Insecure PostMessage Usage" 'postMessage\s*\([^,]+,\s*["'"'"']\*["'"'"']' \
        "postMessage calls using a wildcard target origin were found."

    check_target_blank_links "$root"
    check_http_resources "$root"
    check_post_forms_for_csrf "$root"
    check_missing_csp_meta "$root"
    check_sourcemaps "$root"
    check_frontend_secrets "$root"
}

main() {
    parse_args "$@"

    echo "Front-end audit helper"
    echo "Host: $(hostname)"
    echo "User: $(id -un)"

    local found_root=0
    local root

    while IFS= read -r root; do
        [[ -n "$root" ]] || continue
        found_root=1
        scan_root "$root"
    done < <(discover_roots "$@")

    section "Summary"
    if [[ $found_root -eq 0 ]]; then
        warn "No scan roots were available."
        exit 0
    fi

    if [[ $FRONTEND_FINDINGS_FOUND -eq 1 ]]; then
        fail "Front-end audit findings were detected. Review flagged code paths and templates."
        exit 1
    fi

    info "No high-signal front-end findings were detected by this audit."
}

main "$@"

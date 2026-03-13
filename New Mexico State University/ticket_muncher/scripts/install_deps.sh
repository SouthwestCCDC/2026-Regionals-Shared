#!/usr/bin/env bash
# install_deps.sh -- Install all dependencies for recon.py and cred_spray.py
#
# Usage:
#   sudo bash scripts/install_deps.sh          # install everything
#   sudo bash scripts/install_deps.sh --check  # just check what's missing
#
# Supports: Debian/Ubuntu, RHEL/Alma/Rocky/Fedora/CentOS, Arch
# Installs to .local/bin/ for tools without packages (nuclei, httpx)
# Builds from source for masscan/hydra when no package is available.
set -euo pipefail

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
LOCAL_BIN="$PROJECT_DIR/.local/bin"
BUILD_DIR="/tmp/ccdc_build_$$"
CHECK_ONLY=false

RED='\033[0;31m'
GREEN='\033[0;32m'
YELLOW='\033[0;33m'
CYAN='\033[0;36m'
NC='\033[0m'

# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

info()  { echo -e "${CYAN}[*]${NC} $*"; }
ok()    { echo -e "${GREEN}[+]${NC} $*"; }
warn()  { echo -e "${YELLOW}[!]${NC} $*"; }
fail()  { echo -e "${RED}[-]${NC} $*"; }

find_bin() {
    local name="$1"
    local local_path="$LOCAL_BIN/$name"
    if [[ -x "$local_path" ]]; then
        echo "$local_path"
        return 0
    fi
    command -v "$name" 2>/dev/null && return 0
    return 1
}

need_root() {
    if [[ $EUID -ne 0 ]]; then
        fail "This script needs root for package installation."
        fail "Run: sudo bash $0"
        exit 1
    fi
}

cleanup() {
    rm -rf "$BUILD_DIR" 2>/dev/null || true
}
trap cleanup EXIT

# ---------------------------------------------------------------------------
# Distro detection
# ---------------------------------------------------------------------------

detect_distro() {
    if [[ -f /etc/os-release ]]; then
        # shellcheck disable=SC1091
        . /etc/os-release
        DISTRO_ID="${ID,,}"
        DISTRO_LIKE="${ID_LIKE,,:-}"
        DISTRO_NAME="${PRETTY_NAME:-$ID}"
    elif command -v lsb_release &>/dev/null; then
        DISTRO_ID="$(lsb_release -si | tr '[:upper:]' '[:lower:]')"
        DISTRO_LIKE=""
        DISTRO_NAME="$(lsb_release -sd)"
    else
        DISTRO_ID="unknown"
        DISTRO_LIKE=""
        DISTRO_NAME="Unknown"
    fi

    # Normalize to package manager family
    case "$DISTRO_ID" in
        ubuntu|debian|kali|linuxmint|pop|raspbian)
            PKG_FAMILY="apt" ;;
        rhel|centos|rocky|almalinux|fedora|ol|amzn)
            PKG_FAMILY="dnf" ;;
        arch|manjaro|endeavouros)
            PKG_FAMILY="pacman" ;;
        *)
            # Check ID_LIKE for derivatives
            if [[ "$DISTRO_LIKE" == *debian* ]] || [[ "$DISTRO_LIKE" == *ubuntu* ]]; then
                PKG_FAMILY="apt"
            elif [[ "$DISTRO_LIKE" == *rhel* ]] || [[ "$DISTRO_LIKE" == *fedora* ]] \
              || [[ "$DISTRO_LIKE" == *centos* ]]; then
                PKG_FAMILY="dnf"
            elif [[ "$DISTRO_LIKE" == *arch* ]]; then
                PKG_FAMILY="pacman"
            else
                PKG_FAMILY="unknown"
            fi
            ;;
    esac

    info "Detected: $DISTRO_NAME  (pkg family: $PKG_FAMILY)"
}

# ---------------------------------------------------------------------------
# Architecture
# ---------------------------------------------------------------------------

detect_arch() {
    local machine
    machine="$(uname -m)"
    case "$machine" in
        x86_64|amd64)    ARCH="amd64" ;;
        aarch64|arm64)   ARCH="arm64" ;;
        armv7l|armv6l)   ARCH="armv6" ;;
        *)               ARCH="amd64"; warn "Unknown arch '$machine', assuming amd64" ;;
    esac
}

# ---------------------------------------------------------------------------
# Package manager wrappers
# ---------------------------------------------------------------------------

pkg_install() {
    case "$PKG_FAMILY" in
        apt)
            apt-get update -qq
            apt-get install -y -qq "$@"
            ;;
        dnf)
            # Use dnf if available, fall back to yum
            if command -v dnf &>/dev/null; then
                dnf install -y -q "$@"
            else
                yum install -y -q "$@"
            fi
            ;;
        pacman)
            pacman -Sy --noconfirm --needed "$@"
            ;;
        *)
            fail "No supported package manager. Install manually: $*"
            return 1
            ;;
    esac
}

# Install EPEL on RHEL-family if not already present
ensure_epel() {
    if [[ "$PKG_FAMILY" != "dnf" ]]; then
        return
    fi
    if rpm -q epel-release &>/dev/null; then
        return
    fi
    info "Installing EPEL repository..."
    if command -v dnf &>/dev/null; then
        dnf install -y -q epel-release 2>/dev/null || true
        # On RHEL proper, EPEL might need enabling differently
        dnf install -y -q \
            "https://dl.fedoraproject.org/pub/epel/epel-release-latest-$(rpm -E %rhel).noarch.rpm" \
            2>/dev/null || true
    else
        yum install -y -q epel-release 2>/dev/null || true
    fi
}

# Install build essentials for compiling from source
ensure_build_tools() {
    info "Installing build tools..."
    case "$PKG_FAMILY" in
        apt)    pkg_install build-essential git ;;
        dnf)    pkg_install gcc make git ;;
        pacman) pkg_install base-devel git ;;
    esac
}

# ---------------------------------------------------------------------------
# GitHub binary installers (nuclei, httpx)
# ---------------------------------------------------------------------------

github_latest_url() {
    # $1 = owner/repo, $2 = asset name pattern (e.g. "httpx_*_linux_amd64.zip")
    local repo="$1" pattern="$2"
    local api_url="https://api.github.com/repos/$repo/releases/latest"
    local url
    url=$(curl -fsSL "$api_url" \
        -H "Accept: application/vnd.github+json" \
        -H "User-Agent: ccdc-deps" \
        | python3 -c "
import json, sys, fnmatch
data = json.load(sys.stdin)
for a in data.get('assets', []):
    if fnmatch.fnmatch(a['name'], '$pattern'):
        print(a['browser_download_url'])
        break
" 2>/dev/null)
    echo "$url"
}

ensure_unzip() {
    command -v unzip &>/dev/null && return 0
    info "Installing unzip..."
    case "$PKG_FAMILY" in
        apt)    pkg_install unzip ;;
        dnf)    pkg_install unzip ;;
        pacman) pkg_install unzip ;;
        *)      fail "Cannot install unzip automatically"; return 1 ;;
    esac
}

install_go_binary() {
    # $1 = owner/repo, $2 = binary name, $3 = asset glob pattern
    local repo="$1" name="$2" pattern="$3"
    info "Fetching latest $name from GitHub ($repo)..."
    local url
    url=$(github_latest_url "$repo" "$pattern")
    if [[ -z "$url" ]]; then
        fail "Could not find $name release asset matching '$pattern'"
        return 1
    fi
    mkdir -p "$LOCAL_BIN"
    local tmp_zip="/tmp/${name}_$$.zip"
    info "Downloading $url ..."
    curl -fsSL -o "$tmp_zip" "$url"
    ensure_unzip || { fail "unzip required to extract $name"; rm -f "$tmp_zip"; return 1; }
    unzip -o -q "$tmp_zip" "$name" -d "$LOCAL_BIN" 2>/dev/null \
        || unzip -o -q "$tmp_zip" -d "$LOCAL_BIN"  # some zips have flat structure
    rm -f "$tmp_zip"
    chmod 755 "$LOCAL_BIN/$name"
    ok "$name installed to $LOCAL_BIN/$name"
}

# ---------------------------------------------------------------------------
# Individual tool installers
# ---------------------------------------------------------------------------

install_nmap() {
    if find_bin nmap &>/dev/null; then
        ok "nmap: $(find_bin nmap)"
        return 0
    fi
    if $CHECK_ONLY; then fail "nmap: MISSING"; return 1; fi

    info "Installing nmap..."
    case "$PKG_FAMILY" in
        apt)    pkg_install nmap ;;
        dnf)    pkg_install nmap ;;
        pacman) pkg_install nmap ;;
        *)
            # Fallback: install from nmap.org RPM
            info "Trying nmap RPM from nmap.org..."
            local rpm_url="https://nmap.org/dist/nmap-7.98-1.x86_64.rpm"
            if [[ "$ARCH" == "amd64" ]]; then
                rpm -ivh "$rpm_url" 2>/dev/null && return 0
            fi
            fail "Could not install nmap. Install manually."
            return 1
            ;;
    esac
    ok "nmap: $(find_bin nmap)"
}

install_masscan() {
    if find_bin masscan &>/dev/null; then
        ok "masscan: $(find_bin masscan)"
        return 0
    fi
    if $CHECK_ONLY; then fail "masscan: MISSING"; return 1; fi

    info "Installing masscan..."
    # Try package manager first
    case "$PKG_FAMILY" in
        apt)
            if pkg_install masscan 2>/dev/null; then
                ok "masscan: $(find_bin masscan)"
                return 0
            fi
            ;;
        pacman)
            if pkg_install masscan 2>/dev/null; then
                ok "masscan: $(find_bin masscan)"
                return 0
            fi
            ;;
    esac

    # Build from source (RHEL/Alma don't package masscan)
    info "Building masscan from source..."
    case "$PKG_FAMILY" in
        apt)    pkg_install libpcap-dev ;;
        dnf)    pkg_install libpcap-devel ;;
        pacman) pkg_install libpcap ;;
    esac
    ensure_build_tools

    mkdir -p "$BUILD_DIR"
    git clone --depth 1 https://github.com/robertdavidgraham/masscan.git \
        "$BUILD_DIR/masscan" 2>/dev/null
    make -C "$BUILD_DIR/masscan" -j"$(nproc)" 2>/dev/null
    mkdir -p "$LOCAL_BIN"
    cp "$BUILD_DIR/masscan/bin/masscan" "$LOCAL_BIN/masscan"
    chmod 755 "$LOCAL_BIN/masscan"
    ok "masscan: $LOCAL_BIN/masscan (built from source)"
}

install_hydra() {
    if find_bin hydra &>/dev/null; then
        ok "hydra: $(find_bin hydra)"
        return 0
    fi
    if $CHECK_ONLY; then fail "hydra: MISSING"; return 1; fi

    info "Installing hydra (thc-hydra)..."
    # Try package manager first
    case "$PKG_FAMILY" in
        apt)
            if pkg_install hydra 2>/dev/null; then
                ok "hydra: $(find_bin hydra)"
                return 0
            fi
            ;;
        pacman)
            if pkg_install hydra 2>/dev/null; then
                ok "hydra: $(find_bin hydra)"
                return 0
            fi
            ;;
    esac

    # Build from source (RHEL/Alma don't package hydra)
    info "Building hydra from source..."
    # Install build dependencies
    case "$PKG_FAMILY" in
        apt)
            pkg_install libssl-dev libssh-dev libidn11-dev \
                libpcre3-dev libgtk2.0-dev libmysqlclient-dev \
                libpq-dev libsvn-dev firebird-dev libmemcached-dev \
                libgpg-error-dev libgcrypt20-dev 2>/dev/null || true
            # Minimal fallback -- at least get ssh+ssl
            pkg_install libssl-dev libssh-dev 2>/dev/null || true
            ;;
        dnf)
            ensure_epel
            # Install what's available; some may not exist on minimal installs
            for dep in openssl-devel libssh-devel libidn-devel \
                       pcre-devel mariadb-devel postgresql-devel \
                       libgcrypt-devel; do
                pkg_install "$dep" 2>/dev/null || true
            done
            ;;
        pacman)
            pkg_install openssl libssh libidn pcre ;;
    esac
    ensure_build_tools

    mkdir -p "$BUILD_DIR"
    git clone --depth 1 https://github.com/vanhauser-thc/thc-hydra.git \
        "$BUILD_DIR/hydra" 2>/dev/null
    (
        cd "$BUILD_DIR/hydra"
        ./configure --prefix="$BUILD_DIR/hydra/install" 2>/dev/null
        make -j"$(nproc)" 2>/dev/null
    )
    mkdir -p "$LOCAL_BIN"
    cp "$BUILD_DIR/hydra/hydra" "$LOCAL_BIN/hydra"
    chmod 755 "$LOCAL_BIN/hydra"
    # Also copy xhydra if it exists (unlikely without GTK)
    [[ -f "$BUILD_DIR/hydra/xhydra" ]] && cp "$BUILD_DIR/hydra/xhydra" "$LOCAL_BIN/"
    ok "hydra: $LOCAL_BIN/hydra (built from source)"
}

install_nuclei() {
    if find_bin nuclei &>/dev/null; then
        ok "nuclei: $(find_bin nuclei)"
        return 0
    fi
    if $CHECK_ONLY; then fail "nuclei: MISSING"; return 1; fi

    install_go_binary "projectdiscovery/nuclei" "nuclei" "nuclei_*_linux_${ARCH}.zip"
}

install_httpx() {
    if find_bin httpx &>/dev/null; then
        ok "httpx: $(find_bin httpx)"
        return 0
    fi
    if $CHECK_ONLY; then fail "httpx: MISSING"; return 1; fi

    install_go_binary "projectdiscovery/httpx" "httpx" "httpx_*_linux_${ARCH}.zip"
}

install_nmblookup() {
    if find_bin nmblookup &>/dev/null; then
        ok "nmblookup: $(find_bin nmblookup)"
        return 0
    fi
    if $CHECK_ONLY; then warn "nmblookup: MISSING (optional)"; return 0; fi

    info "Installing nmblookup (samba-client)..."
    case "$PKG_FAMILY" in
        apt)    pkg_install samba-common-bin 2>/dev/null || true ;;
        dnf)    pkg_install samba-client 2>/dev/null || true ;;
        pacman) pkg_install samba 2>/dev/null || true ;;
    esac
    if find_bin nmblookup &>/dev/null; then
        ok "nmblookup: $(find_bin nmblookup)"
    else
        warn "nmblookup: could not install (optional, NBNS hostname resolution)"
    fi
}

install_netexec() {
    # Check for any of the known names
    for name in nxc netexec crackmapexec cme; do
        if find_bin "$name" &>/dev/null; then
            ok "netexec: $(find_bin "$name")"
            return 0
        fi
    done
    if $CHECK_ONLY; then warn "netexec: MISSING (optional)"; return 0; fi

    info "Installing netexec..."
    # Try pipx first (preferred), then pip
    if command -v pipx &>/dev/null; then
        pipx install netexec 2>/dev/null && { ok "netexec: installed via pipx"; return 0; }
    fi
    # Ensure pipx is available
    case "$PKG_FAMILY" in
        apt)    pkg_install pipx 2>/dev/null || pkg_install python3-pip ;;
        dnf)    pkg_install pipx 2>/dev/null || pkg_install python3-pip ;;
        pacman) pkg_install python-pipx 2>/dev/null || pkg_install python-pip ;;
    esac
    if command -v pipx &>/dev/null; then
        pipx install netexec 2>/dev/null && { ok "netexec: installed via pipx"; return 0; }
    fi
    # Last resort: pip
    python3 -m pip install --break-system-packages netexec 2>/dev/null \
        || python3 -m pip install netexec 2>/dev/null \
        || true
    for name in nxc netexec; do
        if find_bin "$name" &>/dev/null; then
            ok "netexec: $(find_bin "$name")"
            return 0
        fi
    done
    warn "netexec: could not install (optional, SMB admin check)"
}

install_uv() {
    if command -v uv &>/dev/null; then
        ok "uv: $(command -v uv)"
        return 0
    fi
    if $CHECK_ONLY; then fail "uv: MISSING"; return 1; fi

    info "Installing uv..."
    curl -fsSL https://astral.sh/uv/install.sh | sh 2>/dev/null
    # The installer puts uv in ~/.local/bin (or ~/.cargo/bin).  Source the env.
    export PATH="$HOME/.local/bin:$HOME/.cargo/bin:$PATH"
    if command -v uv &>/dev/null; then
        ok "uv: $(command -v uv)"
    else
        fail "uv: install failed"
        return 1
    fi
}

run_uv_sync() {
    if ! command -v uv &>/dev/null; then
        warn "uv not available, skipping uv sync"
        return 1
    fi
    if [[ ! -f "$PROJECT_DIR/pyproject.toml" ]]; then
        warn "No pyproject.toml found, skipping uv sync"
        return 1
    fi
    info "Running uv sync in $PROJECT_DIR ..."
    # Run as the invoking user if running under sudo, so the venv is owned correctly
    if [[ -n "${SUDO_USER:-}" ]]; then
        su - "$SUDO_USER" -c "cd '$PROJECT_DIR' && uv sync" 2>&1
    else
        (cd "$PROJECT_DIR" && uv sync) 2>&1
    fi
    if [[ $? -eq 0 ]]; then
        ok "uv sync: complete"
    else
        warn "uv sync: may have failed (check output above)"
    fi
}

ensure_nuclei_templates() {
    local nuclei_bin
    nuclei_bin=$(find_bin nuclei 2>/dev/null) || return 0
    local tpl_dir
    # Templates live in the invoking user's home, not root's
    if [[ -n "${SUDO_USER:-}" ]]; then
        tpl_dir=$(eval echo "~$SUDO_USER")/nuclei-templates
    else
        tpl_dir="$HOME/nuclei-templates"
    fi
    if [[ -d "$tpl_dir" ]]; then
        ok "nuclei templates: $tpl_dir"
        return 0
    fi
    if $CHECK_ONLY; then warn "nuclei templates: MISSING"; return 0; fi

    info "Downloading nuclei templates (first run)..."
    if [[ -n "${SUDO_USER:-}" ]]; then
        su - "$SUDO_USER" -c "'$nuclei_bin' -update-templates" 2>&1
    else
        "$nuclei_bin" -update-templates 2>&1
    fi
    if [[ -d "$tpl_dir" ]]; then
        ok "nuclei templates: $tpl_dir"
    else
        warn "nuclei templates: download may have failed"
    fi
}

# ---------------------------------------------------------------------------
# Chown .local/bin to invoking user
# ---------------------------------------------------------------------------

fix_ownership() {
    if [[ -n "${SUDO_UID:-}" ]] && [[ -n "${SUDO_GID:-}" ]]; then
        if [[ -d "$LOCAL_BIN" ]]; then
            chown -R "$SUDO_UID:$SUDO_GID" "$PROJECT_DIR/.local"
        fi
    fi
}

# ---------------------------------------------------------------------------
# Summary
# ---------------------------------------------------------------------------

print_summary() {
    echo ""
    echo "================================================================"
    echo "  Dependency status"
    echo "================================================================"
    local all_ok=true

    for tool in nmap masscan hydra nuclei httpx; do
        if find_bin "$tool" &>/dev/null; then
            ok "$tool: $(find_bin "$tool")"
        else
            fail "$tool: NOT FOUND"
            all_ok=false
        fi
    done

    if command -v uv &>/dev/null; then
        ok "uv: $(command -v uv)"
    else
        fail "uv: NOT FOUND"
        all_ok=false
    fi

    for tool in nmblookup; do
        if find_bin "$tool" &>/dev/null; then
            ok "$tool: $(find_bin "$tool") (optional)"
        else
            warn "$tool: not found (optional)"
        fi
    done

    for name in nxc netexec crackmapexec cme; do
        if find_bin "$name" &>/dev/null; then
            ok "netexec: $(find_bin "$name") (optional)"
            break
        fi
    done

    # Check Python packages via the project venv
    local venv_python="$PROJECT_DIR/.venv/bin/python"
    if [[ -x "$venv_python" ]]; then
        local py_ok=true
        "$venv_python" -c "import paramiko" 2>/dev/null \
            || { warn "paramiko: not installed (optional)"; py_ok=false; }
        "$venv_python" -c "import winrm" 2>/dev/null \
            || { warn "pywinrm: not installed (optional)"; py_ok=false; }
        $py_ok && ok "Python packages: paramiko, pywinrm (via venv)"
    else
        warn "venv not found at $PROJECT_DIR/.venv — run uv sync"
    fi

    echo "================================================================"
    if $all_ok; then
        ok "All required tools are installed."
    else
        fail "Some required tools are missing."
    fi
    echo ""
}

# ---------------------------------------------------------------------------
# Main
# ---------------------------------------------------------------------------

main() {
    if [[ "${1:-}" == "--check" ]]; then
        CHECK_ONLY=true
    fi

    echo ""
    echo "================================================================"
    echo "  CCDC Dependency Installer"
    echo "  Installs: uv, nmap, masscan, hydra, nuclei, httpx"
    echo "  Optional: nmblookup, netexec"
    echo "  Python:   paramiko, pywinrm (via uv sync)"
    echo "================================================================"
    echo ""

    detect_distro
    detect_arch

    if $CHECK_ONLY; then
        info "Check-only mode (no installs)"
        echo ""
        print_summary
        return 0
    fi

    need_root
    mkdir -p "$LOCAL_BIN"

    # Python toolchain first (uv + venv)
    install_uv
    run_uv_sync

    # Required tools
    install_nmap
    install_masscan
    install_hydra
    install_nuclei
    install_httpx

    # Nuclei templates (must happen after nuclei install)
    ensure_nuclei_templates

    # Optional tools
    install_nmblookup
    install_netexec

    fix_ownership
    print_summary
}

main "$@"

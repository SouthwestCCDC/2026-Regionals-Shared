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
import re
import shutil
import ssl
import socket
import struct
import subprocess
import sys
import tempfile
import time
import xml.etree.ElementTree as ET
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


# -- Dependency installer fallback -------------------------------------------

INSTALL_SCRIPT = Path(__file__).parent / "install_deps.sh"


def _run_install_deps():
    """Run install_deps.sh to install missing dependencies."""
    if not INSTALL_SCRIPT.is_file():
        return False
    print(f"\n[*] Running {INSTALL_SCRIPT} to install missing tools...")
    try:
        subprocess.run(
            ["bash", str(INSTALL_SCRIPT)],
            timeout=600,
        )
        return True
    except subprocess.TimeoutExpired:
        print("    [ERROR] install_deps.sh timed out")
        return False
    except Exception as e:
        print(f"    [ERROR] install_deps.sh failed: {e}")
        return False


def check_dependencies(need_nuclei: bool) -> dict[str, str]:
    required = ["masscan", "nmap"]
    optional = ["nmblookup"]
    if need_nuclei:
        required += ["nuclei"]
        optional += ["httpx"]

    # First pass: check what's available
    tools: dict[str, str] = {}
    missing: list[str] = []
    for name in required:
        path = _find_bin(name)
        if path:
            tools[name] = path
        else:
            missing.append(name)
    for name in optional:
        path = _find_bin(name)
        if path:
            tools[name] = path

    # If anything required is missing, try the installer script
    if missing:
        print(f"\n[!] Missing tools: {', '.join(missing)}")
        if _run_install_deps():
            # Re-check after install
            for name in missing.copy():
                path = _find_bin(name)
                if path:
                    tools[name] = path
                    missing.remove(name)
            # Also pick up optional tools that may have been installed
            for name in optional:
                if name not in tools:
                    path = _find_bin(name)
                    if path:
                        tools[name] = path

    # Die on still-missing required tools
    for name in missing:
        if name == "nuclei":
            die("nuclei not found. Install manually or use --no-nuclei.")
        die(f"Required tool '{name}' not found. Run: sudo bash scripts/install_deps.sh")

    # Warn on missing optional tools
    if need_nuclei and "httpx" not in tools:
        print("    [WARN] httpx not available; nuclei will scan without pre-filter")

    # Ensure nuclei templates exist
    if "nuclei" in tools:
        tpl_dir = Path.home() / "nuclei-templates"
        if not tpl_dir.is_dir():
            print("[*] Downloading nuclei templates (first run)...")
            subprocess.run(
                [tools["nuclei"], "-update-templates"],
                capture_output=True,
                timeout=120,
            )
            if tpl_dir.is_dir():
                print(f"    templates installed to {tpl_dir}")
            else:
                print("    [WARN] template download may have failed")

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


def _tls_grab_names(target: tuple[str, int]) -> tuple[str, str]:
    """Connect to ip:port and extract CN/SAN hostnames from the TLS certificate."""
    ip, port = target
    ctx = ssl.create_default_context()
    ctx.check_hostname = False
    ctx.verify_mode = ssl.CERT_NONE
    try:
        with socket.create_connection((ip, port), timeout=5) as sock:
            with ctx.wrap_socket(sock, server_hostname=ip) as tls:
                der = tls.getpeercert(binary_form=True)
                if not der:
                    return ip, ""
                # getpeercert(binary_form=False) returns {} with CERT_NONE,
                # so write DER->PEM to a temp file and use the internal decoder.
                pem = ssl.DER_cert_to_PEM_cert(der)
                fd, pem_path = tempfile.mkstemp(suffix=".pem")
                try:
                    os.write(fd, pem.encode())
                    os.close(fd)
                    decoded = ssl._ssl._test_decode_cert(pem_path)
                finally:
                    os.unlink(pem_path)
                names: list[str] = []
                if decoded:
                    # CN from subject
                    for rdn in decoded.get("subject", ()):
                        for attr, val in rdn:
                            if attr == "commonName" and val:
                                names.append(val)
                    # SAN dNSName entries
                    for typ, val in decoded.get("subjectAltName", ()):
                        if typ == "DNS" and val:
                            names.append(val)
                # pick first non-IP, non-wildcard name
                for n in names:
                    n = n.strip()
                    if n and not n.startswith("*") and not _is_ip(n):
                        return ip, n
    except (OSError, ssl.SSLError, ValueError, TimeoutError):
        pass
    return ip, ""


def _is_ip(s: str) -> bool:
    try:
        ipaddress.ip_address(s)
        return True
    except ValueError:
        return False


def run_tls_hostnames(
    masscan_hits: list[dict], existing: dict[str, str]
) -> dict[str, str]:
    """Grab hostnames from TLS certificates on HTTPS-likely ports."""
    tls_ports = {443, 636, 993, 995, 8443, 9443}
    targets = [
        (h["ip"], h["port"])
        for h in masscan_hits
        if h["port"] in tls_ports and h["ip"] not in existing
    ]
    if not targets:
        return {}
    print(f"[*] TLS cert grab  {len(targets)} targets")
    start = time.time()
    results: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(20, len(targets))) as pool:
        for ip, name in pool.map(_tls_grab_names, targets):
            if name:
                results[ip] = name
    print(f"    resolved {len(results)}/{len(targets)}  ({_elapsed(start)})")
    return results


def _mdns_query(ip: str) -> tuple[str, str]:
    """Send a unicast mDNS PTR query for an IP and parse the response."""
    octets = ip.split(".")
    # build reverse pointer name: 4.3.2.1.in-addr.arpa
    rev = ".".join(reversed(octets)) + ".in-addr.arpa"
    # encode DNS query for PTR record
    labels = rev.split(".")
    qname = b""
    for label in labels:
        qname += bytes([len(label)]) + label.encode("ascii")
    qname += b"\x00"
    # DNS header: ID=0x1234, QR=0, OPCODE=0, RD=1, QDCOUNT=1
    header = struct.pack(">HHHHHH", 0x1234, 0x0100, 1, 0, 0, 0)
    # QTYPE=PTR(12), QCLASS=IN(1) with unicast-response bit
    question = qname + struct.pack(">HH", 12, 0x8001)
    packet = header + question
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(2)
        # send unicast to the host's mDNS port
        sock.sendto(packet, (ip, 5353))
        data, _ = sock.recvfrom(1024)
        sock.close()
        # parse answer: skip header (12 bytes) + question section
        offset = 12
        # skip question name
        while offset < len(data) and data[offset] != 0:
            if data[offset] & 0xC0 == 0xC0:
                offset += 2
                break
            offset += data[offset] + 1
        else:
            offset += 1
        offset += 4  # skip QTYPE + QCLASS
        # parse answer RR
        if offset >= len(data):
            return ip, ""
        # read answer name (may be compressed)
        name = _decode_dns_name(data, offset)
        if not name:
            return ip, ""
        # skip name, type(2), class(2), ttl(4), rdlength(2)
        ans_offset = _skip_dns_name(data, offset)
        ans_offset += 10  # type + class + ttl + rdlength
        # read PTR rdata (a domain name)
        hostname = _decode_dns_name(data, ans_offset)
        if hostname and hostname.endswith("."):
            hostname = hostname[:-1]
        if hostname and hostname.endswith(".local"):
            return ip, hostname
        if hostname:
            return ip, hostname
    except (OSError, struct.error, IndexError, TimeoutError):
        pass
    return ip, ""


def _decode_dns_name(data: bytes, offset: int) -> str:
    """Decode a DNS name from a packet, handling compression pointers."""
    parts: list[str] = []
    seen: set[int] = set()
    while offset < len(data):
        if offset in seen:
            break
        seen.add(offset)
        length = data[offset]
        if length == 0:
            break
        if length & 0xC0 == 0xC0:
            pointer = struct.unpack(">H", data[offset : offset + 2])[0] & 0x3FFF
            offset = pointer
            continue
        offset += 1
        parts.append(data[offset : offset + length].decode("ascii", errors="replace"))
        offset += length
    return ".".join(parts)


def _skip_dns_name(data: bytes, offset: int) -> int:
    """Skip past a DNS name in a packet, return new offset."""
    while offset < len(data):
        length = data[offset]
        if length == 0:
            return offset + 1
        if length & 0xC0 == 0xC0:
            return offset + 2
        offset += length + 1
    return offset


def run_mdns_lookup(ips: set[str]) -> dict[str, str]:
    """Query each IP via unicast mDNS to discover .local hostnames."""
    return _parallel_lookup(ips, _mdns_query, 20, "mDNS lookup")


# -- DNS forward lookup (query network DNS servers for PTR) ------------------


def _dns_fwd_lookup(args: tuple[str, list[str]]) -> tuple[str, str]:
    """Query DNS servers for a PTR record for *ip*."""
    ip, servers = args
    octets = ip.split(".")
    ptr = ".".join(reversed(octets)) + ".in-addr.arpa"
    dig = shutil.which("dig")
    for server in servers:
        # Try dig first (more reliable), fall back to nslookup
        if dig:
            try:
                out = subprocess.check_output(
                    [dig, f"@{server}", ptr, "PTR", "+short", "+time=3", "+tries=1"],
                    stderr=subprocess.DEVNULL,
                    timeout=5,
                    text=True,
                )
                for line in out.strip().splitlines():
                    line = line.strip().rstrip(".")
                    if line and not line.startswith(";"):
                        return ip, line
            except (
                subprocess.CalledProcessError,
                subprocess.TimeoutExpired,
                FileNotFoundError,
            ):
                pass
        # nslookup fallback
        try:
            out = subprocess.check_output(
                ["nslookup", ip, server],
                stderr=subprocess.DEVNULL,
                timeout=5,
                text=True,
            )
            for line in out.splitlines():
                if "name =" in line.lower():
                    parts = line.split("=")
                    if len(parts) >= 2:
                        name = parts[-1].strip().rstrip(".")
                        if name:
                            return ip, name
        except (
            subprocess.CalledProcessError,
            subprocess.TimeoutExpired,
            FileNotFoundError,
        ):
            pass
    return ip, ""


def run_dns_forward_lookup(ips: set[str], dns_servers: list[str]) -> dict[str, str]:
    """Query network DNS servers for PTR records of each IP."""
    if not dns_servers:
        return {}
    targets = [(ip, dns_servers) for ip in ips]
    if not targets:
        return {}
    print(f"[*] DNS forward lookup  {len(targets)} IPs via {', '.join(dns_servers)}")
    start = time.time()
    results: dict[str, str] = {}
    with ThreadPoolExecutor(max_workers=min(20, len(targets))) as pool:
        for ip, name in pool.map(_dns_fwd_lookup, targets):
            if name:
                results[ip] = name
    print(f"    resolved {len(results)}/{len(targets)}  ({_elapsed(start)})")
    return results


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

NMAP_SVC_ARGS = [
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
NMAP_VULN_ARGS = [
    "-sV",
    "--version-intensity",
    "5",
    "-O",
    "--osscan-guess",
    "--script",
    "vuln",
    "--script-timeout",
    "30s",
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
    "--max-scan-delay",
    "0",
    "--min-hostgroup",
    "64",
    "--stats-every",
    "30s",
]
NMAP_LIVE_KW = ["Stats:", "Timing:", "% done", "Service scan", "Completed", "NSE"]


def _run_nmap_batches(
    masscan_hits: list[dict],
    xml_dir: Path,
    nmap_bin: str,
    nmap_args: list[str],
    prefix: str,
    nmap_workers: int = 4,
) -> list[Path]:
    """Run nmap in parallel batches, return list of XML output paths."""
    ports = sorted({h["port"] for h in masscan_hits})
    targets = sorted({h["ip"] for h in masscan_hits})
    port_str = ",".join(str(p) for p in ports)
    chunks = _chunk_list(targets, nmap_workers)
    print(
        f"[*] nmap ({prefix})  {len(targets)} hosts  "
        f"{len(ports)} ports  workers={len(chunks)}"
    )
    start = time.time()

    def _run_batch(idx, batch):
        xml_out = xml_dir / f"nmap_{prefix}_{idx}.xml"
        cmd = [nmap_bin] + nmap_args + ["-p", port_str, "-oX", str(xml_out)] + batch
        proc = subprocess.Popen(
            cmd, stdout=subprocess.PIPE, stderr=subprocess.STDOUT, text=True
        )
        for line in proc.stdout:
            if any(k in line for k in NMAP_LIVE_KW):
                print(f"    {line.rstrip()}")
        proc.wait()
        if proc.returncode != 0:
            print(f"    [WARN] nmap {prefix} batch {idx} exited {proc.returncode}")
        return xml_out

    xml_parts: list[Path] = []
    with ThreadPoolExecutor(max_workers=len(chunks)) as pool:
        futs = {pool.submit(_run_batch, i, b): i for i, b in enumerate(chunks)}
        for fut in as_completed(futs):
            xml_parts.append(fut.result())

    print(f"    nmap ({prefix}) finished  ({_elapsed(start)})")
    return xml_parts


def run_nmap(
    masscan_hits: list[dict], xml_dir: Path, nmap_bin: str, nmap_workers: int = 4
) -> list[dict]:
    """Phase 3a: service + OS detection."""
    if not masscan_hits:
        die("No open ports -- nothing for nmap to scan.")
    xml_parts = _run_nmap_batches(
        masscan_hits,
        xml_dir,
        nmap_bin,
        NMAP_SVC_ARGS,
        "svc",
        nmap_workers,
    )
    hosts: list[dict] = []
    for xp in xml_parts:
        if xp.exists():
            hosts.extend(_parse_nmap_xml(xp))
    print(f"    {len(hosts)} hosts identified")
    return hosts


def run_nmap_vuln(
    masscan_hits: list[dict], xml_dir: Path, nmap_bin: str, nmap_workers: int = 4
) -> dict[str, list[dict]]:
    """Phase 3b: vuln script scan.  Returns {ip: [{port, script_id, output, cvss, cves}, ...]}."""
    if not masscan_hits:
        return {}
    xml_parts = _run_nmap_batches(
        masscan_hits,
        xml_dir,
        nmap_bin,
        NMAP_VULN_ARGS,
        "vuln",
        nmap_workers,
    )
    all_vulns: dict[str, list[dict]] = defaultdict(list)
    for xp in xml_parts:
        if xp.exists():
            for ip, findings in _parse_vuln_xml(xp).items():
                all_vulns[ip].extend(findings)
    total = sum(len(v) for v in all_vulns.values())
    print(f"    vuln scan: {total} findings on {len(all_vulns)} host(s)")
    return dict(all_vulns)


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
            if best is not None:
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


def _parse_vuln_xml(xml_path: Path) -> dict[str, list[dict]]:
    """Parse nmap --script=vuln XML output.  Returns {ip: [finding, ...]}."""
    try:
        root = ET.parse(xml_path).getroot()
    except ET.ParseError as e:
        print(f"    [WARN] XML parse error {xml_path}: {e}")
        return {}
    vulns: dict[str, list[dict]] = defaultdict(list)
    cve_re = re.compile(r"CVE-\d{4}-\d+", re.IGNORECASE)
    cvss_re = re.compile(r"(\d+\.?\d*)\s*https?://vulners", re.IGNORECASE)
    for host_el in root.findall("host"):
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
        for port_el in host_el.findall(".//port"):
            st = port_el.find("state")
            if st is None or st.get("state") != "open":
                continue
            port_id = int(port_el.get("portid", 0))
            for script_el in port_el.findall("script"):
                sid = script_el.get("id", "")
                output = script_el.get("output", "")
                if not output.strip():
                    continue
                # skip noise scripts that aren't real vuln findings
                if sid in ("fingerprint-strings", "http-fileupload-exploiter"):
                    continue
                # skip noise: "Couldn't find any ...", "ERROR:", "NOT VULNERABLE"
                low = output.lower()
                if "not vulnerable" in low and "vulnerable" not in low.replace(
                    "not vulnerable", ""
                ):
                    continue
                if low.startswith("couldn't find any"):
                    continue
                if low.startswith("error:"):
                    continue
                # extract CVEs and best CVSS score
                cves = list(dict.fromkeys(cve_re.findall(output)))
                cvss_matches = cvss_re.findall(output)
                best_cvss = 0.0
                for m in cvss_matches:
                    try:
                        best_cvss = max(best_cvss, float(m))
                    except ValueError:
                        pass
                # also check for CVSS in table elements
                for tbl in script_el.findall(".//table"):
                    for elem in tbl.findall(".//elem"):
                        txt = elem.text or ""
                        for c in cve_re.findall(txt):
                            if c not in cves:
                                cves.append(c)
                        for m in cvss_re.findall(txt):
                            try:
                                best_cvss = max(best_cvss, float(m))
                            except ValueError:
                                pass
                # truncate output for readability (keep first ~300 chars)
                short_output = output.strip().expandtabs(4)
                if len(short_output) > 300:
                    short_output = short_output[:297] + "..."
                vulns[ip].append(
                    {
                        "port": port_id,
                        "script_id": sid,
                        "output": short_output,
                        "cvss": best_cvss,
                        "cves": cves,
                        "has_exploit": "*exploit*" in low or "*EXPLOIT*" in output,
                    }
                )
    return dict(vulns)


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
                patched += 1
            if not host["hostname"]:
                host["hostname"] = dns_map.get(ip, "")
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


def _build_nuclei_targets(hosts, masscan_hits, raw_dir: Path) -> tuple[Path, Path]:
    """Split targets into HTTP URLs and raw ip:port.  Returns (http_file, raw_file)."""
    http_targets: set[str] = set()
    raw_targets: set[str] = set()
    nmap_ports_by_ip: dict[str, set[int]] = defaultdict(set)
    for h in hosts:
        for s in h.get("services", []):
            port, name = s["port"], s.get("name", "")
            nmap_ports_by_ip[h["ip"]].add(port)
            if "http" in name:
                scheme = "https" if ("ssl" in name or "https" in name) else "http"
                http_targets.add(f"{scheme}://{h['ip']}:{port}")
            else:
                raw_targets.add(f"{h['ip']}:{port}")
    # masscan hits not in nmap results -> raw only
    for hit in masscan_hits:
        ip, port = hit["ip"], hit["port"]
        if port not in nmap_ports_by_ip.get(ip, set()):
            raw_targets.add(f"{ip}:{port}")
    http_path = raw_dir / "nuclei_targets_http.txt"
    raw_path = raw_dir / "nuclei_targets_raw.txt"
    http_path.write_text("\n".join(sorted(http_targets)) + "\n")
    raw_path.write_text("\n".join(sorted(raw_targets)) + "\n")
    print(f"    nuclei targets: {len(http_targets)} HTTP, {len(raw_targets)} raw")
    return http_path, raw_path


def _probe_http_targets(
    targets_file: Path, raw_dir: Path, httpx_bin: str | None = None
) -> Path:
    """Use httpx to pre-filter live HTTP targets before nuclei."""
    if not httpx_bin:
        print("    [SKIP] httpx not found, skipping HTTP pre-filter")
        return targets_file
    live_file = raw_dir / "nuclei_targets_http_live.txt"
    cmd = [
        httpx_bin,
        "-l",
        str(targets_file),
        "-silent",
        "-nc",
        "-o",
        str(live_file),
        "-timeout",
        "5",
        "-threads",
        "100",
        "-retries",
        "0",
    ]
    print(f"[*] httpx pre-filter  targets={targets_file}")
    start = time.time()
    subprocess.run(cmd, capture_output=True, text=True)
    if live_file.exists():
        total = sum(1 for l in targets_file.read_text().splitlines() if l.strip())
        live = sum(1 for l in live_file.read_text().splitlines() if l.strip())
        print(f"    httpx: {live}/{total} targets live  ({_elapsed(start)})")
        return live_file
    return targets_file


def run_nuclei(
    targets_file: Path,
    raw_dir: Path,
    nuclei_bin: str,
    tags: str = "cve,misconfig",
    label: str = "",
    auto_scan: bool = False,
    no_mhe: bool = False,
) -> dict[str, list[str]]:
    suffix = f"_{label}" if label else ""
    out_file = raw_dir / f"nuclei_output{suffix}.jsonl"
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
        "-ss",
        "host-spray",
        "-rate-limit",
        "500",
        "-bulk-size",
        "100",
        "-concurrency",
        "50",
        "-timeout",
        "5",
        "-retries",
        "0",
        "-response-size-read",
        "1048576",
        "-ot",
        "-severity",
        "high,critical",
        "-tags",
        tags,
        "-exclude-tags",
        "dos,fuzz",
    ]
    if no_mhe:
        cmd.append("-nmhe")
    else:
        cmd += ["-mhe", "60"]
    if auto_scan:
        cmd.append("-as")
    print(f"[*] nuclei  targets={targets_file}  label={label or 'default'}")
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
    print(f"    nuclei ({label or 'default'}) finished  ({_elapsed(start)})")

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


def write_summary(hosts, meta, nmap_vulns, nuclei_results, path):
    div = "\u2550" * 72
    lines = [
        div,
        f"  CCDC RECON  \u2014  {meta['scan_time']}",
        f"  Subnets : {', '.join(meta['cidrs'])}",
        f"  Hosts   : {meta['total']}  Linux={meta['linux']}  "
        f"Windows={meta['windows']}  Unknown={meta['unknown']}",
    ]
    if meta["skipped"]:
        lines.append(f"  Skipped : {meta['skipped']} host(s) alive but no open ports")
    lines += [div, ""]
    for family, label in (
        ("linux", "LINUX"),
        ("windows", "WINDOWS"),
        ("unknown", "UNKNOWN"),
    ):
        group = [h for h in hosts if h["os_family"] == family]
        if not group:
            continue
        lines += [f"  {label} ({len(group)})", "\u2500" * 72]
        for h in _sort_hosts(group):
            hn = f"  ({h['hostname']})" if h["hostname"] else ""
            lines += [
                f"  \u25ba {h['ip']}{hn}",
                f"    OS    : {h['os']}",
                f"    Ports : {', '.join(str(p) for p in h['ports'])}",
            ]
            for s in h["services"]:
                name = s["name"] or _port_name(s["port"])
                ver = f"{s['product']} {s['version']}".strip()
                lines.append(f"    {s['port']}/{s['proto']:<4}  {name:<15}  {ver}")
            # nmap vuln script findings
            for v in nmap_vulns.get(h["ip"], []):
                cvss_str = f"CVSS: {v['cvss']:.1f}" if v["cvss"] else "CVSS: N/A"
                lines.append(f"    VULN: [{v['port']}] {v['script_id']} ({cvss_str}):")
                for ol in v["output"].splitlines():
                    lines.append(f"      {ol.strip()}")
            # nuclei findings
            for finding in nuclei_results.get(h["ip"], []):
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
        lines.append(f"\n\u250c\u2500 {subnet} ({len(ips)} hosts) \u2500\u2500\u2500")
        for ip in ips:
            hn = f"  ({dns_map[ip]})" if ip in dns_map else ""
            if ip in by_ip:
                ports = ",".join(str(p) for p in sorted(by_ip[ip]))
                lines.append(f"\u2502  {ip:<15}  ports: {ports}{hn}")
            else:
                lines.append(f"\u2502  {ip:<15}  (skipped \u2014 no open ports){hn}")
        lines.append("\u2514\u2500\u2500\u2500")
    path.write_text("\n".join(lines) + "\n")
    print(f"    [READY] {path}")


def write_nmap_vulns(nmap_vulns: dict[str, list[dict]], path: Path):
    """Write all nmap vuln script findings to a human-readable file."""
    lines: list[str] = []
    for ip in _sort_ips(nmap_vulns):
        lines.append(f"{ip}:")
        for v in nmap_vulns[ip]:
            cvss_str = f"CVSS: {v['cvss']:.1f}" if v["cvss"] else "CVSS: N/A"
            cve_str = ", ".join(v["cves"]) if v["cves"] else ""
            lines.append(f"  [{v['port']}] {v['script_id']} ({cvss_str}): {cve_str}")
            for ol in v["output"].splitlines():
                lines.append(f"    {ol.strip()}")
            lines.append("")
    if lines:
        path.write_text("\n".join(lines) + "\n")
        print(
            f"    [READY] {path}  ({sum(len(v) for v in nmap_vulns.values())} findings)"
        )


def write_nmap_vulns_critical(nmap_vulns: dict[str, list[dict]], path: Path):
    """Write only high/critical nmap vuln findings (CVSS >= 7.0 with known exploit)."""
    lines: list[str] = []
    count = 0
    for ip in _sort_ips(nmap_vulns):
        ip_lines: list[str] = []
        for v in nmap_vulns[ip]:
            if v["cvss"] >= 7.0 and v["has_exploit"]:
                cvss_str = f"CVSS: {v['cvss']:.1f}" if v["cvss"] else "CVSS: N/A"
                cve_str = ", ".join(v["cves"]) if v["cves"] else ""
                exploit_tag = " *EXPLOIT*" if v["has_exploit"] else ""
                ip_lines.append(
                    f"  [{v['port']}] {v['script_id']} ({cvss_str}){exploit_tag}: "
                    f"{cve_str}"
                )
                for ol in v["output"].splitlines():
                    ip_lines.append(f"    {ol.strip()}")
                ip_lines.append("")
                count += 1
        if ip_lines:
            lines.append(f"{ip}:")
            lines.extend(ip_lines)
    if lines:
        path.write_text("\n".join(lines) + "\n")
        print(f"    [READY] {path}  ({count} high/critical findings)")
    else:
        print("    no high/critical nmap vuln findings")


def main():
    parser = argparse.ArgumentParser(
        description="CCDC recon: ping -> ports -> services -> vulns + nuclei"
    )
    parser.add_argument(
        "--cidrs",
        required=True,
        help="Comma-separated CIDR ranges (e.g. 10.0.0.0/24,192.168.1.0/24)",
    )
    parser.add_argument(
        "--top-ports",
        type=int,
        default=1000,
        dest="top_ports",
        help="masscan --top-ports (default: 1000)",
    )
    parser.add_argument(
        "--rate",
        type=int,
        default=10000,
        help="masscan packet rate in pps (default: 10000)",
    )
    parser.add_argument(
        "--iface", default="", help="Network interface for masscan (e.g. eth0)"
    )
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
    raw_dir = run_dir / "raw"
    run_dir.mkdir(parents=True, exist_ok=True)
    raw_dir.mkdir(parents=True, exist_ok=True)
    _chown_to_invoker(OUTPUT_DIR)
    _chown_to_invoker(run_dir)
    _chown_to_invoker(raw_dir)

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

    # -- Hostname resolution (priority: rDNS > DNS fwd > mDNS > NBNS > TLS) --
    # Higher-priority sources are never overwritten by lower ones.
    dns_map: dict[str, str] = {}

    def _merge_no_overwrite(new: dict[str, str]):
        for ip, name in new.items():
            if ip not in dns_map:
                dns_map[ip] = name

    # 1. rDNS (highest priority)
    _merge_no_overwrite(run_reverse_dns(all_ips))

    # 2-5: DNS fwd, mDNS, NBNS, TLS (concurrent, merged in priority order)
    dns_servers = [h["ip"] for h in all_hits if h["port"] == 53]
    smb_ips = {h["ip"] for h in all_hits if h["port"] in (139, 445)}
    with ThreadPoolExecutor(max_workers=4) as hn_pool:
        dns_fwd_fut = hn_pool.submit(
            run_dns_forward_lookup, all_ips - set(dns_map), dns_servers
        )
        mdns_fut = hn_pool.submit(run_mdns_lookup, all_ips - set(dns_map))
        nbns_fut = hn_pool.submit(
            run_nbns_lookup,
            smb_ips - set(dns_map),
            nmblookup_bin=tools.get("nmblookup"),
        )
        tls_fut = hn_pool.submit(run_tls_hostnames, all_hits, dns_map)
        # Merge in priority order (2 > 3 > 4 > 5)
        _merge_no_overwrite(dns_fwd_fut.result())
        _merge_no_overwrite(mdns_fut.result())
        _merge_no_overwrite(nbns_fut.result())
        _merge_no_overwrite(tls_fut.result())

    write_network_map(all_ips, all_hits, dns_map, path=run_dir / "network_map.txt")

    # Phase 3a: Service + OS detection
    print(f"\n-- Phase 3a: Service scan \u2014 {len(masscan_ips)} hosts {'-' * 23}")
    if not all_hits:
        print("    no open ports -- skipping nmap")
        hosts: list[dict] = []
    else:
        hosts = run_nmap(
            all_hits,
            raw_dir,
            nmap_bin=tools["nmap"],
            nmap_workers=args.nmap_workers,
        )
    hosts = _merge_masscan_into_hosts(hosts, all_hits, dns_map)

    for h in hosts:
        if h.get("hostname") and h["ip"] not in dns_map:
            dns_map[h["ip"]] = h["hostname"]
    write_network_map(all_ips, all_hits, dns_map, path=run_dir / "network_map.txt")

    # Phase 3b + 4: Vuln scan + Nuclei (concurrent)
    nmap_vulns: dict[str, list[dict]] = {}
    nuclei_results: dict[str, list[str]] = {}
    run_nuclei_scan = not args.no_nuclei and all_hits and "nuclei" in tools

    # Prepare nuclei targets before launching concurrent work (fast, sync)
    http_targets: Path | None = None
    raw_targets: Path | None = None
    if run_nuclei_scan:
        print(f"\n-- Phase 3b+4: Vuln scan + Nuclei (concurrent) {'-' * 21}")
        http_targets, raw_targets = _build_nuclei_targets(hosts, all_hits, raw_dir)
        http_targets = _probe_http_targets(
            http_targets, raw_dir, httpx_bin=tools.get("httpx")
        )
    elif all_hits:
        print(f"\n-- Phase 3b: Vuln scan \u2014 {len(masscan_ips)} hosts {'-' * 25}")

    def _vuln_scan_work() -> dict[str, list[dict]]:
        if not all_hits:
            return {}
        result = run_nmap_vuln(
            all_hits,
            raw_dir,
            nmap_bin=tools["nmap"],
            nmap_workers=args.nmap_workers,
        )
        if result:
            write_nmap_vulns(result, run_dir / "nmap_vulns.txt")
            write_nmap_vulns_critical(result, run_dir / "nmap_vulns_critical.txt")
        return result

    http_count = 0
    raw_count = 0
    if run_nuclei_scan and http_targets is not None and raw_targets is not None:
        http_count = sum(1 for l in http_targets.read_text().splitlines() if l.strip())
        raw_count = sum(1 for l in raw_targets.read_text().splitlines() if l.strip())

    if all_hits:
        with ThreadPoolExecutor(max_workers=3) as pool:
            vuln_fut = pool.submit(_vuln_scan_work)
            nuclei_http_fut = (
                pool.submit(
                    run_nuclei,
                    http_targets,
                    raw_dir,
                    tools["nuclei"],
                    "cve,misconfig,default",
                    "http",
                    True,
                )
                if http_count > 0
                else None
            )
            nuclei_raw_fut = (
                pool.submit(
                    run_nuclei,
                    raw_targets,
                    raw_dir,
                    tools["nuclei"],
                    "network,misconfig",
                    "raw",
                    False,
                    True,
                )
                if raw_count > 0
                else None
            )
            nmap_vulns = vuln_fut.result()
            http_results = nuclei_http_fut.result() if nuclei_http_fut else {}
            raw_results = nuclei_raw_fut.result() if nuclei_raw_fut else {}

        nuclei_results: dict[str, list[str]] = defaultdict(list)
        for src in (http_results, raw_results):
            for ip, findings in src.items():
                nuclei_results[ip].extend(findings)
        nuclei_results = dict(nuclei_results)

        if nuclei_results:
            total_findings = sum(len(v) for v in nuclei_results.values())
            print(
                f"    nuclei combined: {total_findings} finding(s) "
                f"on {len(nuclei_results)} host(s)"
            )

    # -- Write final reports
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
    write_summary(hosts, meta, nmap_vulns, nuclei_results, recon_path)
    print(f"    [READY] {recon_path}")

    if nuclei_results:
        vuln_txt = run_dir / "vulns.txt"
        vuln_txt.write_text(
            "\n".join(
                f"{ip}:\n" + "\n".join(findings)
                for ip, findings in sorted(nuclei_results.items())
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

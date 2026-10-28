"""Discovery: find live hosts on one private subnet.

Safety rules, enforced here and in the CLI:
- Only RFC1918 private subnets (10/8, 172.16/12, 192.168/16).
- Refuse anything larger than MAX_SCAN_HOSTS addresses (a /22).
  The normal case is a /24. A run that names several scopes uses
  that same cap on the unique addresses across the whole run.
- No scanning of public IPs, ever.
- Discovery is ping + ARP + a TCP connect to a few common ports.
  No exploits, no password guessing, no packet crafting.
"""

from __future__ import annotations

import ipaddress
import platform
import re
import socket
import subprocess
import threading
from pathlib import Path

MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")
IPV4_RE = re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d{1,3}){3})(?![\d.])")

# Hard cap on addresses per scan. A /22 is 1024 addresses; a /24 is 256.
MAX_SCAN_HOSTS = 1024
MIN_PREFIXLEN = 32 - (MAX_SCAN_HOSTS.bit_length() - 1)  # 22

_EMPTY_MAC = "00:00:00:00:00:00"
# Resolving this machine's hostname can wait on DNS for a long time on macOS.
# Auto-detect must not stall a scan or the dashboard on that lookup.
_HOSTNAME_LOOKUP_TIMEOUT = 0.5
_hostname_lock = threading.Lock()


def validate_subnet(text: str) -> ipaddress.IPv4Network:
    """Parse and validate a subnet string. Raise ValueError if unsafe.

    Accepts a network ("192.168.1.0/24") or a host inside one
    ("192.168.1.5/24"); the host bits are dropped. Returns the network.
    """
    text = str(text).strip()
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValueError(f"Not a valid subnet: {text!r}. Example: 192.168.1.0/24") from exc
    if network.version != 4:
        raise ValueError("Lantern scans IPv4 subnets only.")
    if not network.is_private or network.is_loopback or network.is_link_local:
        raise ValueError("Lantern only scans private home networks, not public IPs.")
    if network.prefixlen < MIN_PREFIXLEN:
        raise ValueError(
            f"Subnet is too large: {text} has {network.num_addresses} addresses. "
            f"Lantern scans at most {MAX_SCAN_HOSTS} (a /{MIN_PREFIXLEN}), normally a /24."
        )
    return network


def merged_address_count(networks) -> int:
    """Unique addresses covered by these networks, including network and broadcast.

    Overlapping and adjacent ranges are collapsed. An empty list is 0.
    """
    intervals = sorted(
        (int(network.network_address), int(network.broadcast_address))
        for network in networks
    )
    if not intervals:
        return 0
    total = 0
    start, end = intervals[0]
    for left, right in intervals[1:]:
        if left <= end + 1:
            end = max(end, right)
            continue
        total += end - start + 1
        start, end = left, right
    return total + (end - start + 1)


def _hostname_ipv4() -> str | None:
    """This machine's hostname as an IPv4 address, or None if it is slow or fails.

    The lookup runs in a daemon thread and is abandoned after
    `_HOSTNAME_LOOKUP_TIMEOUT` seconds. A second call while one is still
    in flight returns None instead of starting another, so a stuck DNS
    lookup cannot pile up threads when the dashboard polls status.
    """
    if not _hostname_lock.acquire(blocking=False):
        return None
    found: list[str] = []

    def lookup() -> None:
        try:
            found.append(socket.gethostbyname(socket.gethostname()))
        except Exception:
            pass
        finally:
            _hostname_lock.release()

    worker = threading.Thread(target=lookup, name="lantern-hostname", daemon=True)
    try:
        worker.start()
    except Exception:
        _hostname_lock.release()
        return None
    worker.join(_HOSTNAME_LOOKUP_TIMEOUT)
    return found[0] if found else None


def _local_ipv4_candidates() -> list[str]:
    """Best-effort list of this machine's IPv4 addresses, outbound first.

    Many Linux hosts resolve their hostname to 127.0.0.1, so hostname lookup
    alone is not enough. Connecting a UDP socket does not send packets; it
    only asks the OS which source address it would use.
    """
    candidates = []
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect(("8.8.8.8", 80))
            candidates.append(sock.getsockname()[0])
    except Exception:
        pass
    host_ip = _hostname_ipv4()
    if host_ip:
        candidates.append(host_ip)
    return list(dict.fromkeys(candidates))


def guess_subnet() -> str | None:
    """Guess the local /24 from the machine's own IP. Returns a string or None."""
    for local_ip in _local_ipv4_candidates():
        try:
            addr = ipaddress.ip_address(local_ip)
        except ValueError:
            continue
        if addr.is_private and not addr.is_loopback and not addr.is_link_local:
            return str(ipaddress.ip_network(f"{local_ip}/24", strict=False))
    return None


def ping_command(ip: str, timeout_ms: int = 1000, system: str | None = None) -> list[str]:
    """Build the one-shot ping command for this OS.

    The wait flag differs per platform: Windows -w is milliseconds, Linux -W
    is seconds, macOS/BSD -W is milliseconds (and -t is the overall timeout
    in seconds). Getting this wrong makes every host look offline.
    """
    system = (system or platform.system()).lower()
    seconds = str(max(1, round(timeout_ms / 1000)))
    if system == "windows":
        return ["ping", "-n", "1", "-w", str(timeout_ms), str(ip)]
    if system == "darwin":
        return ["ping", "-c", "1", "-t", seconds, str(ip)]
    return ["ping", "-c", "1", "-W", seconds, str(ip)]


def ping_host(ip: str, timeout_ms: int = 1000) -> bool:
    """True if the host answers one ping. Best effort, never fatal."""
    try:
        result = subprocess.run(
            ping_command(ip, timeout_ms), capture_output=True,
            timeout=timeout_ms / 1000 + 2,
        )
        return result.returncode == 0
    except Exception:
        return False


def parse_neighbors(text: str) -> dict[str, str]:
    """Parse ARP-style output (one entry per line) into {ip: mac}.

    Works for /proc/net/arp, `arp -a` (Linux, macOS, Windows), and
    `ip neigh`. Incomplete entries (no MAC, or an all-zero MAC) are skipped.
    """
    table = {}
    for line in text.splitlines():
        ip_match = IPV4_RE.search(line)
        mac_match = MAC_RE.search(line)
        if not ip_match or not mac_match:
            continue
        ip = ip_match.group(1)
        try:
            ipaddress.IPv4Address(ip)
        except ValueError:
            continue
        mac = mac_match.group(0).lower().replace("-", ":")
        if mac != _EMPTY_MAC:
            table[ip] = mac
    return table


def _run_text(cmd: list[str], timeout: float = 5) -> str:
    try:
        return subprocess.run(cmd, capture_output=True, text=True, timeout=timeout).stdout
    except Exception:
        return ""


def arp_table() -> dict[str, str]:
    """Read the OS neighbor (ARP) cache into {ip: mac}. Best effort.

    Tries /proc/net/arp (Linux, no subprocess), then `arp -a`, then
    `ip neigh`, and merges whatever answers. Never raises.
    """
    table = {}
    proc_arp = Path("/proc/net/arp")
    try:
        if proc_arp.is_file():
            table.update(parse_neighbors(proc_arp.read_text(errors="ignore")))
    except Exception:
        pass
    if not table:
        table.update(parse_neighbors(_run_text(["arp", "-a"])))
    if not table:
        table.update(parse_neighbors(_run_text(["ip", "neigh"])))
    return table


def reverse_hostname(ip: str) -> str | None:
    """Best-effort reverse DNS. Returns None on failure."""
    try:
        name, _, _ = socket.gethostbyaddr(str(ip))
        return name or None
    except Exception:
        return None

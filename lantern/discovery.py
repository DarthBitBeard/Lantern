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

# A scope must sit entirely inside one of these. Python's is_private is
# wider (0/8, 240/4, TEST-NET, 198.18/15, 192.0.0.0/24) and is not used.
_RFC1918 = (
    ipaddress.ip_network("10.0.0.0/8"),
    ipaddress.ip_network("172.16.0.0/12"),
    ipaddress.ip_network("192.168.0.0/16"),
)

_EMPTY_MAC = "00:00:00:00:00:00"
# Resolving this machine's hostname can wait on DNS for a long time on macOS.
# Auto-detect must not stall a scan or the dashboard on that lookup.
_HOSTNAME_LOOKUP_TIMEOUT = 0.5
_hostname_lock = threading.Lock()
# A reverse lookup that is not answered by now is not worth holding a scan
# worker for. The slot count bounds lookups still stuck in the resolver.
_REVERSE_LOOKUP_TIMEOUT = 1.0
_REVERSE_LOOKUP_SLOTS = 32
_reverse_slots = threading.BoundedSemaphore(_REVERSE_LOOKUP_SLOTS)
# Marks a real echo reply in Windows `ping` output. "TTL expired in transit"
# has no equals sign, so it does not match.
_TTL_MARK = b"ttl="


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
    if not any(network.subnet_of(block) for block in _RFC1918):
        raise ValueError(
            "Lantern only scans private home networks "
            "(10.0.0.0/8, 172.16.0.0/12, or 192.168.0.0/16)."
        )
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
            host = ipaddress.ip_network(f"{local_ip}/32", strict=False)
        except ValueError:
            continue
        if any(host.subnet_of(block) for block in _RFC1918):
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
    """True if the host answers one ping. Best effort, never fatal.

    Windows `ping` can exit 0 on "Reply from <this machine>: Destination host
    unreachable", which would make every empty address on the local subnet
    look alive. A real echo reply carries `TTL=`; an unreachable or
    TTL-expired reply does not. Windows therefore also needs that marker.
    """
    system = platform.system().lower()
    try:
        result = subprocess.run(
            ping_command(ip, timeout_ms, system), capture_output=True,
            timeout=timeout_ms / 1000 + 2,
        )
        if result.returncode != 0:
            return False
        if system == "windows":
            return _TTL_MARK in (result.stdout or b"").lower()
        return True
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
    """Best-effort reverse DNS. Returns None on failure or after a short wait.

    Home networks often have no PTR records, and the system resolver can take
    several seconds per address to give up (longer on Windows, which also
    tries NetBIOS). The lookup runs in a daemon thread that is abandoned
    after `_REVERSE_LOOKUP_TIMEOUT` seconds. At most `_REVERSE_LOOKUP_SLOTS`
    abandoned or running lookups exist at once; a caller that cannot get a
    slot within the timeout also returns None, so stuck lookups cannot pile
    up threads across a large scan.
    """
    slots = _reverse_slots
    if not slots.acquire(timeout=_REVERSE_LOOKUP_TIMEOUT):
        return None
    found: list[str] = []

    def lookup() -> None:
        try:
            name, _, _ = socket.gethostbyaddr(str(ip))
            if name:
                found.append(name)
        except Exception:
            pass
        finally:
            slots.release()

    worker = threading.Thread(target=lookup, name="lantern-reverse-dns", daemon=True)
    try:
        worker.start()
    except Exception:
        slots.release()
        return None
    worker.join(_REVERSE_LOOKUP_TIMEOUT)
    return found[0] if found else None

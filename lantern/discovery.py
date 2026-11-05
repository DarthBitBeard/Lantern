"""Discovery: find live hosts on one private subnet.

Safety rules, enforced here and in the CLI:
- Only RFC1918 private subnets (10/8, 172.16/12, 192.168/16).
- Refuse anything larger than MAX_SCAN_HOSTS addresses (a /22).
  The normal case is a /24. A run that names several scopes uses
  that same cap on the unique addresses across the whole run.
- No scanning of public IPs, ever.
- Discovery is ping + ARP + a TCP connect to a few common ports for
  addresses that did not answer the first two.
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


# Sizes of the network a /24 guess may be replaced by. A /31 or /32 has no
# neighbours to scan, and anything over the scan cap is refused anyway.
_MIN_GUESS_PREFIX = MIN_PREFIXLEN
_MAX_GUESS_PREFIX = 30

_INET_SLASH_RE = re.compile(r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})/(\d{1,2})\b")
_INET_NETMASK_RE = re.compile(
    r"\binet\s+(\d{1,3}(?:\.\d{1,3}){3})\s+.*?\bnetmask\s+(0x[0-9a-fA-F]+|\d{1,3}(?:\.\d{1,3}){3})"
)
_WIN_ADDRESS_RE = re.compile(r"IPv4 Address[ .]*:\s*(\d{1,3}(?:\.\d{1,3}){3})")
_WIN_MASK_RE = re.compile(r"Subnet Mask[ .]*:\s*(\d{1,3}(?:\.\d{1,3}){3})")


def _mask_prefixlen(mask: str) -> int | None:
    """Prefix length of a netmask written as 0xffffff00 or 255.255.255.0."""
    try:
        if mask.lower().startswith("0x"):
            value = int(mask, 16)
        else:
            value = int(ipaddress.IPv4Address(mask))
    except ValueError:
        return None
    if value < 0 or value > 0xFFFFFFFF:
        return None
    bits = f"{value:032b}"
    # A real mask is a run of ones then a run of zeros.
    if "01" in bits:
        return None
    return bits.count("1")


def parse_interface_prefixes(text: str) -> dict[str, int]:
    """Parse interface listings into {ipv4_address: prefix_length}.

    Understands `ip -4 -o addr`, `ifconfig` on Linux and macOS, and the
    English `ipconfig` on Windows. Text in another language, or anything
    unrecognised, simply yields fewer entries.
    """
    prefixes: dict[str, int] = {}
    pending_windows_ip = None
    for line in text.splitlines():
        match = _INET_SLASH_RE.search(line)
        if match:
            ip, length = match.group(1), int(match.group(2))
            if 0 <= length <= 32:
                prefixes[ip] = length
            continue
        match = _INET_NETMASK_RE.search(line)
        if match:
            length = _mask_prefixlen(match.group(2))
            if length is not None:
                prefixes[match.group(1)] = length
            continue
        match = _WIN_ADDRESS_RE.search(line)
        if match:
            pending_windows_ip = match.group(1)
            continue
        match = _WIN_MASK_RE.search(line)
        if match and pending_windows_ip:
            length = _mask_prefixlen(match.group(1))
            if length is not None:
                prefixes[pending_windows_ip] = length
            pending_windows_ip = None
    return prefixes


def interface_prefixes(system: str | None = None) -> dict[str, int]:
    """This machine's {ipv4: prefix length}. Best effort, never raises."""
    system = (system or platform.system()).lower()
    commands = [["ipconfig"]] if system == "windows" else [["ip", "-4", "-o", "addr", "show"], ["ifconfig"]]
    for command in commands:
        found = parse_interface_prefixes(_run_text(command))
        if found:
            return found
    return {}


def _guess_prefix(local_ip: str, prefixes: dict[str, int]) -> int:
    """The prefix to scan around this address: the real one when it is sensible, else /24."""
    length = prefixes.get(local_ip)
    if length is None or length < _MIN_GUESS_PREFIX or length > _MAX_GUESS_PREFIX:
        return 24
    return length


def guess_subnet() -> str | None:
    """Guess the local subnet from the machine's own IP. Returns a string or None.

    Uses the interface's real prefix length when the OS reports one that fits
    inside the scan cap (so a /23 is scanned whole, and a /26 is not widened).
    Otherwise it falls back to the /24 around the address.
    """
    prefixes = None
    for local_ip in _local_ipv4_candidates():
        try:
            host = ipaddress.ip_network(f"{local_ip}/32", strict=False)
        except ValueError:
            continue
        if any(host.subnet_of(block) for block in _RFC1918):
            if prefixes is None:
                prefixes = interface_prefixes()
            length = _guess_prefix(local_ip, prefixes)
            return str(ipaddress.ip_network(f"{local_ip}/{length}", strict=False))
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


# Ports tried to tell that an address is alive when it ignores ping and is
# not in the ARP cache. A refused connection counts: it proves a host answered.
DISCOVERY_PORTS = (80, 443, 22, 445)
DISCOVERY_TIMEOUT = 0.3


def tcp_alive(ip: str, ports=DISCOVERY_PORTS, timeout: float = DISCOVERY_TIMEOUT) -> bool:
    """True if a host answers a TCP connect on any of these ports, even with a refusal.

    Catches hosts that block ping, and machines (such as a Docker container
    without a `ping` binary) where the ping sweep cannot run at all. Silence,
    a timeout, or "no route" mean nobody answered. Never raises.
    """
    for port in ports:
        try:
            with socket.create_connection((str(ip), port), timeout=timeout):
                return True
        except ConnectionRefusedError:
            return True
        except OSError:
            continue
        except Exception:
            return False
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


_ROUTE_TOKEN_RE = re.compile(r"\S+")


def _ipv4_or_none(text: str) -> str | None:
    try:
        return str(ipaddress.IPv4Address(text))
    except ValueError:
        return None


def parse_default_gateways(text: str) -> list[str]:
    """Default-route gateways from routing-table output, in the order listed.

    Understands `route print -4` (Windows, any display language: the
    columns are numbers), `ip -4 route show default` and `/proc/net/route`
    (Linux), and `netstat -rn` (macOS and BSD). "On-link" and other
    non-address gateways are skipped, as is 0.0.0.0.
    """
    found: list[str] = []

    def add(candidate: str | None) -> None:
        if candidate and candidate != "0.0.0.0" and candidate not in found:
            found.append(candidate)

    for line in text.splitlines():
        tokens = _ROUTE_TOKEN_RE.findall(line)
        if not tokens:
            continue
        # Linux `ip route`: default via 192.168.1.1 dev eth0 ...
        if tokens[0] == "default" and "via" in tokens:
            index = tokens.index("via")
            if index + 1 < len(tokens):
                add(_ipv4_or_none(tokens[index + 1]))
            continue
        # macOS/BSD `netstat -rn`: default 192.168.1.1 UGScg en0
        if tokens[0] == "default" and len(tokens) >= 2:
            add(_ipv4_or_none(tokens[1]))
            continue
        # Windows `route print -4`: 0.0.0.0 0.0.0.0 <gateway> <interface> <metric>
        if len(tokens) >= 3 and tokens[0] == "0.0.0.0" and tokens[1] == "0.0.0.0":
            add(_ipv4_or_none(tokens[2]))
            continue
        # /proc/net/route: Iface Destination Gateway Flags ... in little-endian hex.
        if len(tokens) >= 3 and tokens[1] == "00000000" and re.fullmatch(r"[0-9A-Fa-f]{8}", tokens[2]):
            raw = int(tokens[2], 16)
            add(_ipv4_or_none(socket.inet_ntoa(raw.to_bytes(4, "little"))))
    return found


def default_gateways(system: str | None = None) -> list[str]:
    """This machine's IPv4 default gateways. Best effort; never raises."""
    system = (system or platform.system()).lower()
    if system == "windows":
        return parse_default_gateways(_run_text(["route", "print", "-4"]))
    if system == "linux":
        proc_route = Path("/proc/net/route")
        try:
            if proc_route.is_file():
                found = parse_default_gateways(proc_route.read_text(errors="ignore"))
                if found:
                    return found
        except Exception:
            pass
        return parse_default_gateways(_run_text(["ip", "-4", "route", "show", "default"]))
    return parse_default_gateways(_run_text(["netstat", "-rn", "-f", "inet"]))


def local_ipv4_in(network: ipaddress.IPv4Network) -> str | None:
    """This machine's own address inside `network`, if it has one."""
    for candidate in _local_ipv4_candidates():
        try:
            if ipaddress.IPv4Address(candidate) in network:
                return candidate
        except ValueError:
            continue
    return None


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

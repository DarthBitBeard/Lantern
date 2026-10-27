"""Discovery: find live hosts on one private subnet.

Safety rules, enforced here and in the CLI:
- Only RFC1918 private subnets (10/8, 172.16/12, 192.168/16).
- Refuse anything larger than a /16. The normal case is a /24.
- No scanning of public IPs, ever.
- Discovery is ping + ARP + a TCP connect to a few common ports.
  No exploits, no password guessing, no packet crafting.
"""

import ipaddress
import platform
import re
import socket
import subprocess

MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}")


def validate_subnet(text):
    """Parse and validate a subnet string. Raise ValueError if unsafe."""
    try:
        network = ipaddress.ip_network(text, strict=False)
    except ValueError as exc:
        raise ValueError(f"Not a valid subnet: {text}") from exc
    if not network.is_private:
        raise ValueError("Lantern only scans private home networks, not public IPs.")
    if network.prefixlen < 16:
        raise ValueError("Subnet is too large. Use a /16 or smaller, normally a /24.")
    if network.version != 4:
        raise ValueError("IPv4 only in v0.1.")
    return network


def guess_subnet():
    """Guess the local /24 from the machine's own IP. Returns a string or None."""
    try:
        hostname = socket.gethostname()
        local_ip = socket.gethostbyname(hostname)
        addr = ipaddress.ip_address(local_ip)
        if addr.is_private and not addr.is_loopback:
            network = ipaddress.ip_network(f"{local_ip}/24", strict=False)
            return str(network)
    except Exception:
        return None
    return None


def ping_host(ip, timeout_ms=500):
    """True if the host answers one ping. Best effort, never fatal."""
    system = platform.system().lower()
    if system == "windows":
        cmd = ["ping", "-n", "1", "-w", str(timeout_ms), str(ip)]
    else:
        cmd = ["ping", "-c", "1", "-W", "1", str(ip)]
    try:
        result = subprocess.run(cmd, capture_output=True, timeout=3)
        return result.returncode == 0
    except Exception:
        return False


def arp_table():
    """Parse the OS ARP cache into {ip: mac}. Best effort."""
    table = {}
    try:
        result = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=5)
        for line in result.stdout.splitlines():
            ip_match = re.search(r"(\d+\.\d+\.\d+\.\d+)", line)
            mac_match = MAC_RE.search(line)
            if ip_match and mac_match:
                table[ip_match.group(1)] = mac_match.group(1).lower().replace("-", ":")
    except Exception:
        pass
    return table


def reverse_hostname(ip):
    """Best-effort reverse DNS. Returns None on failure."""
    try:
        name, _, _ = socket.gethostbyaddr(str(ip))
        return name
    except Exception:
        return None

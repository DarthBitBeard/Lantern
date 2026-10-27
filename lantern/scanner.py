"""Port scanning: plain TCP connect scans, stdlib only.

No Nmap, no Scapy, no root needed. A connect scan only asks "is
something listening?" and reads an optional banner. It never sends
exploit payloads or login attempts.
"""

from __future__ import annotations

import socket
from concurrent.futures import ThreadPoolExecutor

# Ports that usually speak HTTP and stay silent until asked. A HEAD
# request is the only thing Lantern ever sends, and only to these.
BANNER_PORTS = {80, 8080, 8888, 9000, 9090, 32400, 8096, 8123}
BANNER_BYTES = 256
BANNER_MAX_CHARS = 120
DEFAULT_TIMEOUT = 0.6
MAX_PORT_WORKERS = 50


def clean_banner(data: bytes) -> str:
    """First printable line of a service banner, trimmed. Never raises."""
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = "".join(ch for ch in line if ch.isprintable()).strip()
        if line:
            return line[:BANNER_MAX_CHARS]
    return ""


def _recv_banner(sock: socket.socket) -> str:
    try:
        return clean_banner(sock.recv(BANNER_BYTES))
    except Exception:
        return ""


def probe_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """TCP connect to one port. Returns {port, open, banner}."""
    result = {"port": port, "open": False, "banner": ""}
    try:
        with socket.create_connection((str(ip), port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            result["open"] = True
            banner = _recv_banner(sock)
            if not banner and port in BANNER_PORTS:
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    banner = _recv_banner(sock)
                except Exception:
                    banner = ""
            result["banner"] = banner
    except Exception:
        pass
    return result


def scan_host(ip: str, ports, timeout: float = DEFAULT_TIMEOUT, workers: int = MAX_PORT_WORKERS) -> list[dict]:
    """Return a sorted list of open ports with banners for one host."""
    ports = sorted({int(p) for p in ports})
    if not ports:
        return []
    workers = max(1, min(workers, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: probe_port(ip, p, timeout), ports)
    return [r for r in results if r["open"]]

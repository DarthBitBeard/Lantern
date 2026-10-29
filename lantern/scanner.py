"""Port scanning: plain TCP connect scans, stdlib only.

No Nmap, no Scapy, no root needed. A connect scan only asks "is
something listening?" and reads an optional banner. It never sends
exploit payloads or login attempts.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor

from .fingerprint import fingerprint_for_storage

# Ports that usually speak HTTP and stay silent until asked. A HEAD
# request is the only thing Lantern ever sends, and only to these.
BANNER_PORTS = {80, 8080, 8888, 9000, 9090, 32400, 8096, 8123}
BANNER_BYTES = 256
BANNER_MAX_CHARS = 120
DEFAULT_TIMEOUT = 0.6
MAX_PORT_WORKERS = 50
# Header block on the existing HEAD request. Server is not on the first line.
# The 0.6 s greeting read runs first. This second wait is 1.0 s, about 1.6 s total.
HTTP_READ_BYTES = 2048
HTTP_READ_SECONDS = 1.0

# Ports already in a normal scan. Fingerprinting does not add ports or probes.
_PROTOCOL_BY_PORT = {21: "ftp", 22: "ssh", 25: "smtp"}
for _http_port in BANNER_PORTS:
    _PROTOCOL_BY_PORT[_http_port] = "http"


def clean_banner(data: bytes) -> str:
    """First printable line of a service banner, trimmed. Never raises."""
    text = data.decode("utf-8", errors="replace")
    for line in text.splitlines():
        line = "".join(ch for ch in line if ch.isprintable()).strip()
        if line:
            return line[:BANNER_MAX_CHARS]
    return ""


def protocol_for_port(port: int) -> str | None:
    """ssh, ftp, smtp, or http for a port we already connect to. Otherwise None."""
    try:
        return _PROTOCOL_BY_PORT.get(int(port))
    except (TypeError, ValueError):
        return None


def _recv_some(sock: socket.socket, limit: int) -> bytes:
    """One read, capped. A short greeting must not wait out the timeout."""
    try:
        return sock.recv(limit) or b""
    except Exception:
        return b""


def read_http_headers(sock: socket.socket) -> bytes:
    """Read the HEAD response until the header break, 2048 bytes, or 1.0 s.

    This clock starts after HEAD is sent. The 0.6 s greeting read already
    ran, so a silent HTTP port takes about 1.6 s total. Nothing is sent
    here. The caller already sent the single HEAD line.
    """
    data = bytearray()
    deadline = time.monotonic() + HTTP_READ_SECONDS
    while len(data) < HTTP_READ_BYTES and b"\r\n\r\n" not in data:
        remaining = deadline - time.monotonic()
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        try:
            chunk = sock.recv(min(1024, HTTP_READ_BYTES - len(data)))
        except Exception:
            break
        if not chunk:
            break
        data += chunk
    return bytes(data[:HTTP_READ_BYTES])


def probe_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT) -> dict:
    """TCP connect to one port. Returns {port, open, banner} and maybe fingerprint."""
    result = {"port": port, "open": False, "banner": ""}
    try:
        with socket.create_connection((str(ip), port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            result["open"] = True
            raw = _recv_some(sock, BANNER_BYTES)
            banner = clean_banner(raw)
            if not banner and port in BANNER_PORTS:
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    raw = read_http_headers(sock)
                    banner = clean_banner(raw)
                except Exception:
                    banner = ""
                    raw = b""
            result["banner"] = banner
            fingerprint = fingerprint_for_storage(protocol_for_port(port), raw)
            if fingerprint is not None:
                result["fingerprint"] = fingerprint
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

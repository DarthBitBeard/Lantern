"""Port scanning: plain TCP connect scans, stdlib only.

No Nmap, no Scapy, no root needed. A connect scan only asks "is
something listening?" and reads an optional banner. It never sends
exploit payloads or login attempts.
"""

import socket
from concurrent.futures import ThreadPoolExecutor

BANNER_PORTS = {80, 8080, 8888, 9000, 9090, 32400, 8096, 8123}


def _probe(ip, port, timeout=0.6):
    try:
        with socket.create_connection((str(ip), port), timeout=timeout) as sock:
            sock.settimeout(0.6)
            banner = ""
            try:
                data = sock.recv(256)
                if data:
                    banner = data.decode(errors="ignore").strip().splitlines()[0][:120]
            except Exception:
                banner = ""
            if not banner and port in BANNER_PORTS:
                try:
                    sock.sendall(b"HEAD / HTTP/1.0\r\n\r\n")
                    data = sock.recv(256)
                    if data:
                        banner = data.decode(errors="ignore").strip().splitlines()[0][:120]
                except Exception:
                    pass
            return {"port": port, "open": True, "banner": banner}
    except Exception:
        return {"port": port, "open": False, "banner": ""}


def scan_host(ip, ports, timeout=0.6, workers=50):
    """Return a sorted list of open ports with banners for one host."""
    open_ports = []
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = list(pool.map(lambda p: _probe(ip, p, timeout), ports))
    for result in results:
        if result["open"]:
            open_ports.append(result)
    open_ports.sort(key=lambda r: r["port"])
    return open_ports

"""Port scanning: plain TCP connect scans, stdlib only.

No Nmap, no Scapy, no root needed. A connect scan only asks "is
something listening?" and reads an optional banner. It never sends
exploit payloads or login attempts.
"""

from __future__ import annotations

import socket
import time
from concurrent.futures import ThreadPoolExecutor

from . import fingerprint

# Ports that usually speak HTTP and stay silent until asked. A HEAD
# request is the only thing Lantern ever sends, and only to these.
BANNER_PORTS = {80, 8080, 8888, 9000, 9090, 32400, 8096, 8123}
BANNER_BYTES = 256
BANNER_MAX_CHARS = 120
DEFAULT_TIMEOUT = 0.6
HTTP_HEADER_BYTES = 2048
HTTP_HEADER_SECONDS = 1.0
MAX_PORT_WORKERS = 24  # with HOST_WORKERS = 8 this stays under 256 open sockets (the macOS default limit)
_HEAD_REQUEST = b"HEAD / HTTP/1.0\r\n\r\n"
_SMTP_PORTS = {25, 465, 587}


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


def _recv_some(sock: socket.socket, size: int) -> bytes:
    """One ``recv``. A timeout or a reset is empty, the same as no banner."""
    try:
        return sock.recv(size) or b""
    except Exception:
        return b""


def _headers_complete(data: bytes) -> bool:
    return b"\r\n\r\n" in data or b"\n\n" in data


def _line_complete(data: bytes) -> bool:
    return b"\n" in data


def _read_until(sock: socket.socket, data: bytes, *, started: float, limit: int, deadline: float, done) -> bytes:
    """Read more of what the peer already sends. Never sends.

    ``deadline`` is seconds from ``started`` (the moment the connection
    was up). The first ``recv`` has already happened; this only continues
    it for parsing.
    """
    while len(data) < limit and not done(data):
        remaining = deadline - (time.monotonic() - started)
        if remaining <= 0:
            break
        sock.settimeout(remaining)
        chunk = _recv_some(sock, min(BANNER_BYTES, limit - len(data)))
        if not chunk:
            break
        data += chunk
    return data[:limit]


def _service_hint(port: int, raw: bytes) -> str | None:
    """Which parser applies. HTTP is only the ports that may receive HEAD.

    SSH, FTP, and SMTP are recognised from the well-known port or from the
    banner the peer already sent, so a test listener on a free port can
    still be parsed. A ``220`` that names neither family is not guessed.
    """
    if port in BANNER_PORTS:
        return "http"
    stripped = raw.lstrip(b"\r\n\t ")
    if port == 22 or stripped.startswith(b"SSH-"):
        return "ssh"
    lowered = stripped.lower()
    if port == 21 or b"vsftpd" in lowered or b"proftpd" in lowered or b"pure-ftpd" in lowered:
        return "ftp"
    if port in _SMTP_PORTS or b"postfix" in lowered or b"exim" in lowered or b"sendmail" in lowered:
        return "smtp"
    return None


def _fingerprint_value(port: int, raw: bytes) -> dict | None:
    hint = _service_hint(port, raw)
    if hint is None:
        return None
    parsed = fingerprint.parse(hint, raw)
    if parsed is None:
        return None
    return {
        "service": parsed.service,
        "product": parsed.product,
        "version": parsed.version,
        "parse_status": parsed.parse_status,
        "raw": parsed.raw,
    }


def _probe_once(sock: socket.socket, port: int) -> str:
    """Today's single read, then HEAD only when that read cleans to empty."""
    banner = _recv_banner(sock)
    if not banner and port in BANNER_PORTS:
        try:
            sock.sendall(_HEAD_REQUEST)
            banner = _recv_banner(sock)
        except Exception:
            banner = ""
    return banner


def _probe_fingerprint(sock: socket.socket, port: int, timeout: float, started: float) -> tuple[str, dict | None]:
    """Read a bounded banner. HEAD uses only the first recv, as main does.

    Extra recv calls happen after that decision and only to finish the
    line or the HTTP headers. They never cause another HEAD.
    """
    # The same timeout and the same one recv as main. The cleaned result
    # is the whole HEAD decision.
    sock.settimeout(timeout)
    first = _recv_some(sock, BANNER_BYTES)
    banner = clean_banner(first)
    if not banner and port in BANNER_PORTS:
        try:
            sock.sendall(_HEAD_REQUEST)
        except Exception:
            return "", _fingerprint_value(port, b"")
        # One recv, capped by the time still left from connect, is the
        # banner. Further bytes are for the parser only.
        remaining = HTTP_HEADER_SECONDS - (time.monotonic() - started)
        sock.settimeout(max(0.0, remaining))
        second = _recv_some(sock, BANNER_BYTES)
        banner = clean_banner(second)
        raw = _read_until(
            sock, second, started=started, limit=HTTP_HEADER_BYTES,
            deadline=HTTP_HEADER_SECONDS, done=_headers_complete,
        )
        return banner, _fingerprint_value(port, raw)
    if port in BANNER_PORTS:
        raw = _read_until(
            sock, first, started=started, limit=HTTP_HEADER_BYTES,
            deadline=HTTP_HEADER_SECONDS, done=_headers_complete,
        )
    else:
        raw = _read_until(
            sock, first, started=started, limit=BANNER_BYTES,
            deadline=timeout, done=_line_complete,
        )
    return banner, _fingerprint_value(port, raw)


def probe_port(ip: str, port: int, timeout: float = DEFAULT_TIMEOUT, *, fingerprint: bool = True) -> dict:
    """TCP connect to one port. Returns {port, open, banner} and, when on, fingerprint.

    ``fingerprint=False`` is the single-recv probe: one read, and ``HEAD``
    only when that read cleans to empty on an HTTP banner port. The parser
    is not called.
    """
    result = {"port": port, "open": False, "banner": ""}
    try:
        with socket.create_connection((str(ip), port), timeout=timeout) as sock:
            sock.settimeout(timeout)
            result["open"] = True
            if not fingerprint:
                result["banner"] = _probe_once(sock, port)
                return result
            started = time.monotonic()
            banner, parsed = _probe_fingerprint(sock, port, timeout, started)
            result["banner"] = banner
            if parsed is not None:
                result["fingerprint"] = parsed
    except Exception:
        pass
    return result


def scan_host(
    ip: str,
    ports,
    timeout: float = DEFAULT_TIMEOUT,
    workers: int = MAX_PORT_WORKERS,
    *,
    fingerprint: bool = True,
) -> list[dict]:
    """Return a sorted list of open ports with banners for one host."""
    ports = sorted({int(p) for p in ports})
    if not ports:
        return []
    workers = max(1, min(workers, len(ports)))
    with ThreadPoolExecutor(max_workers=workers) as pool:
        results = pool.map(lambda p: probe_port(ip, p, timeout, fingerprint=fingerprint), ports)
    return [r for r in results if r["open"]]

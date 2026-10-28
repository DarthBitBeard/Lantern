"""Web dashboard: stdlib only, no pip install needed.

Plain HTML/CSS/JS, a JSON API, and static files served by the app,
without a web framework, so Lantern stays a zero-dependency tool:
python3 -m lantern web, open the URL.

Binds to 127.0.0.1 by default. A non-loopback bind needs the CLI's
--allow-lan flag and one startup API token. Never expose this to the
internet.

Local-tool hygiene, enforced here:
- Every request must send a Host header on the allowlist. On loopback
  that is 127.0.0.1, localhost, or [::1] on the bound port, plus hosts
  named with --allow-host. When LAN-bound, the allowlist is only the
  explicit bind address and --allow-host values. A public name that
  rebinds to 127.0.0.1 is still refused.
- Loopback: POST /api/* requires X-Lantern-Token. The process generates
  it, embeds it in the dashboard page, and compares it with
  hmac.compare_digest. GET does not need it. The token is not logged.
- LAN-bound: the same token, supplied by the CLI, is required on every
  API route including GET inventory and reports. It is not embedded in
  the page. Static files other than that rule stay unauthenticated.
- A POST that includes Origin must use http or https, and that origin's
  host:port must be on the same allowlist. A missing Origin is accepted
  only together with a valid token.
- Request targets must be origin-form (a path). An absolute-form URL is
  rejected with 400.
- POST bodies must be JSON (Content-Type application/json) and at most
  64 KiB. Each connection has a socket timeout and the process caps how
  many connections it handles at once.
- Unexpected errors return a generic 500. The exception text is written
  only when --debug is on, and only to stderr.
- Responses carry nosniff, a strict CSP on HTML, and no-store caching.
"""

from __future__ import annotations

import hmac
import html
import ipaddress
import json
import re
import secrets
import socket
import sys
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse, urlsplit

from . import __version__, demo
from .discovery import MAC_RE, guess_subnet, validate_subnet
from .ports import DEFAULT_PORTS
from .report import to_html, to_json
from .store import connect, list_scans, load_scan_with_diff, save_scan, set_trusted

WEB_DIR = Path(__file__).resolve().parent / "web"
STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".svg": "image/svg+xml",
}
MAX_BODY_BYTES = 64 * 1024
MAX_LABEL_CHARS = 80
# Signed 64-bit SQLite INTEGER. Larger values used to raise OverflowError
# and leak the exception text to the client.
MAX_SCAN_ID = 2**63 - 1
REQUEST_TIMEOUT_SECONDS = 10
MAX_CONNECTIONS = 32
CSP = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"
TOKEN_HEADER = "X-Lantern-Token"
TOKEN_PLACEHOLDER = "__LANTERN_TOKEN__"
AUTH_PLACEHOLDER = "__LANTERN_AUTH__"
FORBIDDEN_MESSAGE = "Forbidden."
SERVER_ERROR_MESSAGE = "Server error."
BAD_REQUEST_MESSAGE = "Bad request."
# 32 bytes is 256 bits. The LAN gate accepts anything of at least 128 bits,
# which is 22 characters of urlsafe text (token_urlsafe(16) with no padding).
_TOKEN_BYTES = 32
MIN_API_TOKEN_CHARS = 22
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]+")
_BUSY_BODY = b'{"error": "Server is busy."}'
_HOSTNAME_RE = re.compile(
    r"(?=.{1,253}$)"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
)
_scan_lock = threading.Lock()


def _canonical_host(host: str) -> str:
    """Return a bracketed IPv6 address, an IPv4 address, or a lowercase DNS name.

    IPv6 must already be in brackets. Bare IPv6 is rejected so a port cannot
    be confused with the address. DNS names are compared in punycode.
    """
    text = host.strip().lower().rstrip(".")
    if not text:
        raise ValueError("not a host")
    if text.startswith("["):
        if not text.endswith("]"):
            raise ValueError("not a host")
        try:
            ip = ipaddress.IPv6Address(text[1:-1])
        except ValueError as exc:
            raise ValueError("not a host") from exc
        return f"[{ip.compressed}]"
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        parsed = None
    if isinstance(parsed, ipaddress.IPv6Address):
        raise ValueError("IPv6 hosts must be written in brackets")
    if isinstance(parsed, ipaddress.IPv4Address):
        return str(parsed)
    try:
        ascii_host = text.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("not a host") from exc
    if not _HOSTNAME_RE.fullmatch(ascii_host):
        raise ValueError("not a host")
    return ascii_host


def parse_host_port(value: str) -> tuple[str, int | None]:
    """Split a host or host:port into (canonical host, port or None).

    Raises ValueError when the text is not a hostname, an IPv4 address,
    or a bracketed IPv6 address, with an optional numeric port.
    """
    if not isinstance(value, str):
        raise ValueError("not a host")
    raw = value.strip()
    if not raw or any(ch in raw for ch in " \t\r\n\x00@\\/#?"):
        raise ValueError("not a host")
    if raw.startswith("["):
        end = raw.find("]")
        if end < 2 or raw.count("]") != 1:
            raise ValueError("not a host")
        host_text = raw[: end + 1]
        rest = raw[end + 1 :]
        if rest == "":
            port = None
        elif rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
        else:
            raise ValueError("not a host")
    else:
        if raw.count(":") > 1:
            raise ValueError("not a host")
        if ":" in raw:
            host_text, port_text = raw.rsplit(":", 1)
            if not port_text.isdigit():
                raise ValueError("not a host")
            port = int(port_text)
        else:
            host_text, port = raw, None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("port out of range")
    return _canonical_host(host_text), port


def api_token_error(token) -> str | None:
    """Return an error when `token` is not at least 128 bits of urlsafe text.

    The message never includes the token. None means the token is acceptable.
    """
    if (
        isinstance(token, str)
        and len(token) >= MIN_API_TOKEN_CHARS
        and _TOKEN_RE.fullmatch(token)
    ):
        return None
    return (
        "refusing to start without a valid API token "
        "(at least 128 bits, 22 urlsafe characters)"
    )


def _ip_from_canonical_host(canonical: str):
    text = canonical[1:-1] if canonical.startswith("[") and canonical.endswith("]") else canonical
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _is_unspecified_bind(host: str) -> bool:
    if not isinstance(host, str):
        return False
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return bool(ipaddress.ip_address(text).is_unspecified)
    except ValueError:
        return False


def _is_specific_ip_text(host: str) -> bool:
    """True for a unicast IP with no zone id. Hostnames are not specific IPs."""
    if not isinstance(host, str) or "%" in host:
        return False
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if getattr(ip, "scope_id", None):
        return False
    return not ip.is_unspecified


def _canonical_is_specific_ip(canonical: str) -> bool:
    ip = _ip_from_canonical_host(canonical)
    if ip is None or getattr(ip, "scope_id", None):
        return False
    return not ip.is_unspecified


def _bind_host_key(host: str, port: int) -> str:
    """Allowlist key for a configured bind address, which may be bare IPv6."""
    text = host.strip()
    if text.startswith("["):
        canonical, _parsed_port = parse_host_port(text)
        return f"{canonical}:{port}"
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        canonical, _parsed_port = parse_host_port(text)
        return f"{canonical}:{port}"
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id:
            raise ValueError(
                f"bind address {host!r} must not include a zone id."
            )
        return f"[{ip.compressed}]:{port}"
    return f"{ip}:{port}"


def parse_allow_host(value: str) -> tuple[str, int | None]:
    """Parse one --allow-host value. Raises ValueError with a CLI-facing message.

    Unspecified addresses (0.0.0.0, ::) and zone-scoped IPv6
    ([fe80::1%eth0]) are rejected. Wildcards and CIDR are not hosts.
    """
    if isinstance(value, str) and "%" in value:
        raise ValueError(
            f"--allow-host value {value!r} must not include a zone id."
        )
    try:
        host, port = parse_host_port(value)
    except ValueError as exc:
        raise ValueError(
            f"--allow-host value {value!r} is not a hostname or IP address with an optional port."
        ) from exc
    ip = _ip_from_canonical_host(host)
    if ip is not None and getattr(ip, "scope_id", None):
        raise ValueError(
            f"--allow-host value {value!r} must not include a zone id."
        )
    if ip is not None and ip.is_unspecified:
        raise ValueError(
            f"--allow-host value {value!r} must be a specific host, not an unspecified address."
        )
    return host, port


def allowlist_for(bound_port: int, parsed: list[tuple[str, int | None]]) -> frozenset[str]:
    """Host:port values that may call this process. Loopback is always included."""
    if isinstance(bound_port, bool) or not isinstance(bound_port, int) or not 1 <= bound_port <= 65535:
        raise ValueError("port must be between 1 and 65535.")
    allowed = set()
    for spec in ("127.0.0.1", "localhost", "[::1]"):
        host, _port = parse_host_port(spec)
        allowed.add(f"{host}:{bound_port}")
    for host, port in parsed:
        allowed.add(f"{host}:{bound_port if port is None else port}")
    return frozenset(allowed)


def build_allowed_hosts(bound_port: int, extra_hosts: list[str] | None = None) -> frozenset[str]:
    """Loopback allowlist for a bound port. Extra names without a port use that port."""
    parsed = [parse_allow_host(item) for item in (extra_hosts or [])]
    return allowlist_for(bound_port, parsed)


def build_lan_allowlist(
    bind_host: str,
    bound_port: int,
    extra_hosts: list[str] | None = None,
) -> frozenset[str]:
    """Host:port values for a LAN bind. No automatic loopback and no wildcard.

    The explicit bind address is included when it is a specific address.
    0.0.0.0 and :: are not added. That bind is refused unless one
    --allow-host value is a specific IP (the address clients will send).
    """
    if isinstance(bound_port, bool) or not isinstance(bound_port, int) or not 1 <= bound_port <= 65535:
        raise ValueError("port must be between 1 and 65535.")
    parsed = [parse_allow_host(item) for item in (extra_hosts or [])]
    allowed: set[str] = set()
    unspecified = _is_unspecified_bind(bind_host)
    specific_ip = False
    if not unspecified:
        if "%" in bind_host:
            raise ValueError(f"bind address {bind_host!r} must not include a zone id.")
        allowed.add(_bind_host_key(bind_host, bound_port))
        specific_ip = _is_specific_ip_text(bind_host)
    for host, port in parsed:
        allowed.add(f"{host}:{bound_port if port is None else port}")
        if _canonical_is_specific_ip(host):
            specific_ip = True
    if unspecified and not specific_ip:
        raise ValueError(
            f"refusing to bind {bind_host}: pass --allow-host with the LAN address "
            "clients will use. An unspecified address is not added to the Host allowlist."
        )
    if not allowed:
        raise ValueError(f"refusing to bind {bind_host}: the Host allowlist is empty.")
    return frozenset(allowed)


def is_origin_form(target: str) -> bool:
    """True for an origin-form request target: a path, optional query.

    Absolute-form (http://host/path), authority-form, and asterisk-form
    are rejected. A scheme-relative target that starts with // is too.
    """
    if not isinstance(target, str) or not target.startswith("/") or target.startswith("//"):
        return False
    parts = urlsplit(target)
    return not parts.scheme and not parts.netloc


def _is_ipv6_literal(host: str) -> bool:
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return isinstance(ipaddress.ip_address(text), ipaddress.IPv6Address)
    except ValueError:
        return False


def _format_url_host(host: str) -> str:
    text = str(host)
    if ":" in text and not text.startswith("["):
        return f"[{text}]"
    return text


def startup_lines(
    bound_host: str,
    bound_port: int,
    *,
    lan_bound: bool,
    allowed_hosts: frozenset[str],
) -> list[str]:
    """Banner lines for one mode. Never includes the API token."""
    shown = _format_url_host(bound_host)
    if lan_bound:
        allowed = ", ".join(sorted(allowed_hosts))
        return [
            f"Lantern dashboard: LAN bind on {shown}:{bound_port}/  "
            "(every API call requires the startup token)",
            f"Allowed Host values: {allowed}",
        ]
    return [
        f"Lantern dashboard: http://{shown}:{bound_port}/  "
        "(loopback only; the page holds the API token)",
    ]


def request_host_key(value: str, bound_port: int) -> str | None:
    """Canonical Host key, or None if the header is not a host we can compare.

    Browsers omit the port only for 80 and 443. On any other port a missing
    port does not match, so `127.0.0.1` is not treated as `127.0.0.1:8068`.
    """
    try:
        host, port = parse_host_port(value)
    except ValueError:
        return None
    if port is None:
        if bound_port in (80, 443):
            port = bound_port
        else:
            return None
    return f"{host}:{port}"


def origin_allowlist_key(origin: str) -> str | None:
    """host:port from an Origin, or None when it is not an http(s) origin.

    An omitted port means 80 for http and 443 for https, which is what the
    header means. It is not filled in with the dashboard's port.
    """
    if not isinstance(origin, str):
        return None
    text = origin.strip()
    if not text or text.lower() == "null":
        return None
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if parts.path not in ("", "/"):
        return None
    if parts.query or parts.fragment:
        return None
    hostname = parts.hostname
    if not hostname:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    rendered = f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"
    try:
        host, parsed_port = parse_host_port(rendered)
    except ValueError:
        return None
    if parsed_port is None:
        return None
    return f"{host}:{parsed_port}"


def _extra_allowed_hosts(allowed: frozenset[str], bound_port: int) -> list[str]:
    defaults = {
        f"127.0.0.1:{bound_port}",
        f"localhost:{bound_port}",
        f"[::1]:{bound_port}",
    }
    return sorted(allowed - defaults)


class LanternHandler(BaseHTTPRequestHandler):
    db_path = None
    debug = False
    # Fail closed until make_server fills these in for this process.
    api_token = ""
    allowed_hosts = frozenset()
    bound_port = 0
    # Loopback embeds the token and checks it on POST only. LAN mode
    # (set by the CLI) checks it on every API route and does not embed it.
    lan_bound = False
    # Per-request socket timeout. Slow clients cannot hold a thread forever.
    timeout = REQUEST_TIMEOUT_SECONDS
    protocol_version = "HTTP/1.1"

    def version_string(self):
        return "Lantern"

    def log_message(self, format, *args):
        # Request line, status, and size only. Never log headers: POST calls
        # carry X-Lantern-Token, and that value must not be written here.
        if self.debug:
            super().log_message(format, *args)

    # -- helpers ------------------------------------------------------

    def _send_bytes(self, status: int, data: bytes, content_type: str, cache: str = "no-store") -> None:
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if content_type.startswith("text/html"):
            self.send_header("Content-Security-Policy", CSP)
        if self.close_connection:
            self.send_header("Connection", "close")
        self.end_headers()
        if self.command != "HEAD":
            self.wfile.write(data)

    def _send_json(self, status: int, payload) -> None:
        self._send_bytes(status, json.dumps(payload).encode(), "application/json")

    def _send_text(self, status: int, body: str, content_type: str) -> None:
        self._send_bytes(status, body.encode(), content_type)

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError as exc:
            raise ValueError("Content-Length must be a number.") from exc
        if length < 0:
            raise ValueError("Content-Length must not be negative.")
        if length > MAX_BODY_BYTES:
            raise RequestTooLarge(f"Request body is too large (max {MAX_BODY_BYTES} bytes).")
        if not length:
            return {}
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise UnsupportedMediaType("Send JSON with Content-Type: application/json.")
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Request body is not valid JSON.") from exc
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object.")
        return value

    def _host_allowed(self) -> bool:
        values = self.headers.get_all("Host")
        if not values or len(values) != 1:
            return False
        key = request_host_key(values[0], self.bound_port)
        return key is not None and key in self.allowed_hosts

    def _token_ok(self) -> bool:
        values = self.headers.get_all(TOKEN_HEADER)
        if not values or len(values) != 1:
            return False
        provided = values[0]
        expected = self.api_token
        if not isinstance(provided, str) or not isinstance(expected, str) or not expected:
            return False
        try:
            return hmac.compare_digest(provided, expected)
        except (TypeError, ValueError):
            # Non-ASCII or mixed types. Reject without echoing the header.
            return False

    def _origin_ok(self) -> bool:
        """True when Origin is absent or its host:port is on the allowlist.

        Absent is only safe because POST /api/* has already required the token.
        """
        values = self.headers.get_all("Origin")
        if not values:
            return True
        if len(values) != 1:
            return False
        key = origin_allowlist_key(values[0])
        return key is not None and key in self.allowed_hosts

    def _forbid(self, *, unread_body: bool) -> None:
        if unread_body:
            self.close_connection = True
        self._send_json(403, {"error": FORBIDDEN_MESSAGE})

    def _server_error(self, exc: BaseException) -> None:
        """Generic 500. The exception text stays on stderr, and only with --debug."""
        if self.debug:
            try:
                print(
                    f"Lantern server error: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
            except OSError:
                pass
        self._send_json(500, {"error": SERVER_ERROR_MESSAGE})

    def _reject_bad_target(self, *, unread_body: bool) -> None:
        if unread_body:
            self.close_connection = True
        self._send_json(400, {"error": BAD_REQUEST_MESSAGE})

    def _api_get_allowed(self) -> bool:
        """Loopback GET is open to an allowed Host. LAN GET needs the token."""
        if not self.lan_bound:
            return True
        return self._token_ok()

    def _db(self):
        return connect(self.db_path)

    # -- static --------------------------------------------------------

    def _serve_static(self, name: str) -> None:
        if name in ("", "/"):
            name = "index.html"
        path = (WEB_DIR / name.lstrip("/")).resolve()
        if WEB_DIR not in path.parents or not path.is_file() or path.suffix not in STATIC_TYPES:
            self._send_json(404, {"error": "Not found."})
            return
        if path.name == "index.html":
            # no-store: the page contains this process's token.
            self._send_bytes(200, self._index_bytes(path), STATIC_TYPES[".html"], cache="no-store")
            return
        self._send_bytes(200, path.read_bytes(), STATIC_TYPES[path.suffix], cache="no-cache")

    def _index_bytes(self, path: Path) -> bytes:
        text = path.read_text(encoding="utf-8")
        if text.count(TOKEN_PLACEHOLDER) != 1 or text.count(AUTH_PLACEHOLDER) != 1:
            raise RuntimeError("Dashboard index is missing its token placeholder.")
        if self.lan_bound:
            # The page must not contain the token. A Host-forging LAN client
            # can still GET /, and that response is how the old gate leaked.
            page = (
                text.replace(TOKEN_PLACEHOLDER, "", 1)
                .replace(AUTH_PLACEHOLDER, "token", 1)
            )
            if self.api_token and self.api_token in page:
                raise RuntimeError("Refusing to embed the API token in a LAN-bound page.")
            return page.encode("utf-8")
        # token_urlsafe is already [A-Za-z0-9_-]. Escape anyway so a future
        # generator cannot break out of the attribute. Do not log the token.
        escaped = html.escape(self.api_token, quote=True)
        page = (
            text.replace(TOKEN_PLACEHOLDER, escaped, 1)
            .replace(AUTH_PLACEHOLDER, "page", 1)
        )
        return page.encode("utf-8")

    # -- GET -----------------------------------------------------------

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self._host_allowed():
            self._forbid(unread_body=False)
            return
        if not is_origin_form(self.path):
            self._reject_bad_target(unread_body=False)
            return
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if parsed.path.startswith("/api/") and not self._api_get_allowed():
            self._forbid(unread_body=False)
            return
        try:
            if parsed.path.startswith("/api/"):
                self._handle_api_get(parsed.path, query)
            elif parsed.path == "/favicon.ico":
                self._send_bytes(204, b"", "image/x-icon", cache="max-age=86400")
            else:
                self._serve_static(parsed.path)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:
            self._server_error(exc)

    @staticmethod
    def _int_param(value, name: str) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be a number.") from exc
        if number < 1 or number > MAX_SCAN_ID:
            raise ValueError(f"{name} must be a positive number.")
        return number

    def _handle_api_get(self, path: str, query: dict) -> None:
        conn = self._db()
        try:
            if path == "/api/status":
                scans = list_scans(conn)
                self._send_json(200, {
                    "version": __version__,
                    "guessed_subnet": guess_subnet(),
                    "scan_count": len(scans),
                    "latest_scan_id": scans[0]["id"] if scans else None,
                    "scan_running": _scan_lock.locked(),
                })
                return
            if path == "/api/scans":
                self._send_json(200, {"scans": list_scans(conn)})
                return
            if path in ("/api/scans/latest", "/api/diff"):
                scan, diff = load_scan_with_diff(conn)
                self._send_json(200, {"scan": scan, "diff": diff})
                return
            if path.startswith("/api/scans/"):
                scan_id = self._int_param(path[len("/api/scans/"):], "Scan id")
                scan, diff = load_scan_with_diff(conn, scan_id)
                if scan is None:
                    self._send_json(404, {"error": "Scan not found."})
                else:
                    self._send_json(200, {"scan": scan, "diff": diff})
                return
            if path == "/api/report":
                scan_id = query.get("scan_id", [None])[0]
                fmt = query.get("format", ["json"])[0]
                if fmt not in ("json", "html"):
                    raise ValueError("format must be json or html.")
                if scan_id:
                    scan_id = self._int_param(scan_id, "scan_id")
                scan, diff = load_scan_with_diff(conn, scan_id)
                if scan is None:
                    self._send_json(404, {"error": "Scan not found." if scan_id else "No scans yet."})
                    return
                if fmt == "html":
                    self._send_text(200, to_html(scan, diff), "text/html; charset=utf-8")
                else:
                    self._send_text(200, to_json(scan, diff), "application/json")
                return
            self._send_json(404, {"error": "Unknown API route."})
        finally:
            conn.close()

    # -- POST ----------------------------------------------------------

    def do_POST(self):
        parsed = urlparse(self.path)
        if not self._host_allowed():
            self._forbid(unread_body=True)
            return
        if not is_origin_form(self.path):
            self._reject_bad_target(unread_body=True)
            return
        if not parsed.path.startswith("/api/"):
            self.close_connection = True  # body left unread
            self._send_json(404, {"error": "Not found."})
            return
        # Token first, then Origin. A missing Origin is allowed only because
        # the token matched. A present Origin must itself be on the allowlist.
        if not self._token_ok() or not self._origin_ok():
            self._forbid(unread_body=True)
            return
        try:
            body = self._read_json()
        except RequestTooLarge as exc:
            self._send_json(413, {"error": str(exc)})
            self.close_connection = True
            return
        except UnsupportedMediaType as exc:
            self._send_json(415, {"error": str(exc)})
            self.close_connection = True
            return
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            self.close_connection = True
            return
        try:
            if parsed.path == "/api/demo":
                self._handle_demo()
            elif parsed.path == "/api/scan":
                self._handle_scan(body)
            elif parsed.path == "/api/trust":
                self._handle_trust(body)
            else:
                self._send_json(404, {"error": "Unknown API route."})
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:
            self._server_error(exc)

    def _handle_demo(self) -> None:
        conn = self._db()
        try:
            save_scan(conn, demo.DEMO_SUBNET, demo.demo_scan_1(), demo=True)
            save_scan(conn, demo.DEMO_SUBNET, demo.demo_scan_2(), demo=True)
            scan, diff = load_scan_with_diff(conn)
            self._send_json(200, {"scan_id": scan["id"], "scan": scan, "diff": diff})
        finally:
            conn.close()

    def _handle_scan(self, body: dict) -> None:
        # Validate before taking the lock, so a typo never blocks a real scan.
        subnet = body.get("subnet")
        if subnet is not None and not isinstance(subnet, str):
            raise ValueError("subnet must be a string like 192.168.1.0/24.")
        subnet = (subnet or "").strip() or guess_subnet()
        if not subnet:
            raise ValueError(
                "Could not auto-detect your subnet. Send {\"subnet\": \"192.168.1.0/24\"}."
            )
        subnet = str(validate_subnet(subnet))

        if not _scan_lock.acquire(blocking=False):
            self._send_json(409, {"error": "A scan is already running. Wait for it to finish."})
            return
        try:
            # Import here to avoid a module cycle with cli.py.
            from .cli import run_scan

            devices = run_scan(subnet, DEFAULT_PORTS)
            conn = self._db()
            try:
                scan_id = save_scan(conn, subnet, devices, demo=False)
                scan, diff = load_scan_with_diff(conn, scan_id)
            finally:
                conn.close()
        finally:
            _scan_lock.release()
        self._send_json(200, {"scan_id": scan_id, "scan": scan, "diff": diff})

    def _handle_trust(self, body: dict) -> None:
        mac = str(body.get("mac") or "").strip().lower()
        if not MAC_RE.fullmatch(mac):
            raise ValueError("mac must look like aa:bb:cc:dd:ee:ff.")
        mac = mac.replace("-", ":")
        label = body.get("label")
        if label is not None and not isinstance(label, str):
            raise ValueError("label must be text.")
        label = (label or "").strip()[:MAX_LABEL_CHARS]
        trusted = body.get("trusted", True)
        if not isinstance(trusted, bool):
            raise ValueError("trusted must be true or false.")
        conn = self._db()
        try:
            set_trusted(conn, mac, label, trusted)
        finally:
            conn.close()
        self._send_json(200, {"mac": mac, "label": label or None, "trusted": trusted})


class RequestTooLarge(ValueError):
    pass


class UnsupportedMediaType(ValueError):
    pass


def _reject_busy(request) -> None:
    body = _BUSY_BODY
    raw = (
        b"HTTP/1.1 503 Service Unavailable\r\n"
        b"Content-Type: application/json\r\n"
        b"Cache-Control: no-store\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        + body
    )
    try:
        # Drop anything already buffered so close() is a FIN, not a RST
        # that would discard the 503.
        request.settimeout(0.05)
        try:
            request.recv(65536)
        except OSError:
            pass
        request.sendall(raw)
    except OSError:
        pass
    finally:
        try:
            request.close()
        except OSError:
            pass


class _LanternServer(ThreadingHTTPServer):
    """Threading server with an IPv6 option, a connection cap, and quiet errors.

    ``address_family`` and ``max_connections`` are set on a subclass before
    the socket is created. ``daemon_threads`` keeps a request thread from
    blocking process exit. ``handle_error`` stays silent unless --debug is
    on, so a traceback cannot land in ``docker logs`` by default.
    """

    daemon_threads = True
    max_connections = MAX_CONNECTIONS

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except OSError:
                pass
        super().server_bind()

    def server_activate(self):
        self._slots = threading.BoundedSemaphore(self.max_connections)
        super().server_activate()

    def handle_error(self, request, client_address):
        if getattr(self.RequestHandlerClass, "debug", False):
            super().handle_error(request, client_address)

    def process_request(self, request, client_address):
        if not self._slots.acquire(blocking=False):
            _reject_busy(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            self._slots.release()


def _server_class(family: int, connection_limit: int):
    if family not in (socket.AF_INET, socket.AF_INET6):
        raise ValueError("unsupported address family")
    if isinstance(connection_limit, bool) or not isinstance(connection_limit, int) or connection_limit < 1:
        raise ValueError("max_connections must be a positive number.")

    class BoundServer(_LanternServer):
        address_family = family
        max_connections = connection_limit

    return BoundServer


def _loopback_host(host: str) -> bool:
    # cli.is_loopback_host is the one list. serve() used to keep a second,
    # shorter one, and the banner disagreed with it.
    from .cli import is_loopback_host

    return is_loopback_host(host)


def make_server(
    db_path,
    host: str = "127.0.0.1",
    port: int = 8068,
    debug: bool = False,
    allow_hosts: list[str] | None = None,
    api_token: str | None = None,
    lan_bound: bool = False,
    listen_host: str | None = None,
    max_connections: int = MAX_CONNECTIONS,
    request_timeout: float = REQUEST_TIMEOUT_SECONDS,
) -> ThreadingHTTPServer:
    """Build the dashboard server without starting it. Used by serve() and tests.

    ``api_token``, when passed, is the only token for this process. Loopback
    generates one when it is omitted and embeds it in the page. LAN mode
    requires the CLI token and does not embed it.

    ``listen_host`` is the socket address. Tests simulate a LAN allowlist
    while binding ``127.0.0.1`` by setting ``host`` to the LAN address and
    ``listen_host`` to loopback. The CLI does not pass ``listen_host``.

    Validation runs before the listening socket is opened.
    """
    index_path = WEB_DIR / "index.html"
    if not index_path.is_file():
        raise FileNotFoundError(
            f"Dashboard files missing under {WEB_DIR}. "
            "Reinstall Lantern from the repo so lantern/web is included."
        )
    index_text = index_path.read_text(encoding="utf-8")
    if index_text.count(TOKEN_PLACEHOLDER) != 1 or index_text.count(AUTH_PLACEHOLDER) != 1:
        raise ValueError(
            "Dashboard index is missing its token placeholder. "
            "Reinstall Lantern from the repo so lantern/web is intact."
        )
    if isinstance(request_timeout, bool) or not isinstance(request_timeout, (int, float)) or request_timeout <= 0:
        raise ValueError("request timeout must be a positive number of seconds.")

    socket_host = host if listen_host is None else listen_host
    # Reject a bad --allow-host before opening a socket.
    parsed_hosts = [parse_allow_host(item) for item in (allow_hosts or [])]
    if lan_bound or api_token is not None:
        token_problem = api_token_error(api_token)
        if token_problem:
            raise ValueError(token_problem)
        token = api_token
    else:
        token = secrets.token_urlsafe(_TOKEN_BYTES)
    if lan_bound:
        # Port 0 is assigned at bind. The host rules do not depend on it.
        build_lan_allowlist(host, port or 1, allow_hosts)
    elif not _loopback_host(socket_host):
        raise ValueError(
            f"refusing to bind {socket_host}. The dashboard listens on loopback "
            "unless it is started with a LAN token."
        )

    handler = type(
        "BoundHandler",
        (LanternHandler,),
        {
            "db_path": str(db_path),
            "debug": bool(debug),
            "lan_bound": bool(lan_bound),
            "timeout": float(request_timeout),
        },
    )
    family = socket.AF_INET6 if _is_ipv6_literal(socket_host) else socket.AF_INET
    server = _server_class(family, max_connections)((socket_host, port), handler)
    bound_port = int(server.server_address[1])
    handler.bound_port = bound_port
    if lan_bound:
        handler.allowed_hosts = build_lan_allowlist(host, bound_port, allow_hosts)
    else:
        handler.allowed_hosts = allowlist_for(bound_port, parsed_hosts)
    handler.api_token = token
    return server


def serve(
    db_path,
    host: str = "127.0.0.1",
    port: int = 8068,
    debug: bool = False,
    allow_hosts: list[str] | None = None,
    api_token: str | None = None,
    lan_bound: bool = False,
) -> None:
    server = make_server(
        db_path,
        host=host,
        port=port,
        debug=debug,
        allow_hosts=allow_hosts,
        api_token=api_token,
        lan_bound=lan_bound,
    )
    bound_host, bound_port = server.server_address[:2]
    handler = server.RequestHandlerClass
    for line in startup_lines(
        str(bound_host),
        int(bound_port),
        lan_bound=bool(handler.lan_bound),
        allowed_hosts=handler.allowed_hosts,
    ):
        print(line, flush=True)
    print(f"Database: {db_path}", flush=True)
    if not handler.lan_bound:
        extras = _extra_allowed_hosts(handler.allowed_hosts, int(bound_port))
        if extras:
            print("Additional allowed Host headers: " + ", ".join(extras), flush=True)
    if debug:
        print("Debug request logging on.", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

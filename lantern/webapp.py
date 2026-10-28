"""Web dashboard: stdlib only, no pip install needed.

Plain HTML/CSS/JS, a JSON API, and static files served by the app,
without a web framework, so Lantern stays a zero-dependency tool:
python3 -m lantern web, open the URL.

Binds to 127.0.0.1 by default. Only bind another address if you
understand the network: on a home LAN, prefer Tailscale-only access.
Never expose this to the internet. It has no login, by design, for
local use only.

Local-tool hygiene, enforced here:
- Every GET and POST, including the index and /api/*, must send a Host
  header on the allowlist: 127.0.0.1, localhost, or [::1] on the bound
  port, plus hosts named with --allow-host. A public name that rebinds
  to 127.0.0.1 is still refused. That is the DNS-rebinding check.
- POST /api/* requires X-Lantern-Token. The process generates it at
  startup, embeds it in the dashboard page, and compares it with
  hmac.compare_digest. The token is not written to the log.
- A POST that includes Origin must use http or https, and that origin's
  host:port must be on the same allowlist. A missing Origin is accepted
  only together with a valid token, which is how the CLI and curl call in.
- POST bodies must be JSON (Content-Type application/json) and at most
  64 KiB. A plain HTML form cannot trigger a scan.
- Responses carry nosniff, a strict CSP on HTML, and no-store caching.
"""

from __future__ import annotations

import hmac
import html
import ipaddress
import json
import re
import secrets
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
CSP = "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; frame-ancestors 'none'"
TOKEN_HEADER = "X-Lantern-Token"
TOKEN_PLACEHOLDER = "__LANTERN_TOKEN__"
FORBIDDEN_MESSAGE = "Forbidden."
# 32 bytes, URL-safe, no padding. Long enough that guessing it is not practical,
# and short enough to embed in the page. Generated once per process.
_TOKEN_BYTES = 32
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


def parse_allow_host(value: str) -> tuple[str, int | None]:
    """Parse one --allow-host value. Raises ValueError with a CLI-facing message."""
    try:
        return parse_host_port(value)
    except ValueError as exc:
        raise ValueError(
            f"--allow-host value {value!r} is not a hostname or IP address with an optional port."
        ) from exc


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
    """Allowlist for a bound port. Extra names without a port use that port."""
    parsed = [parse_allow_host(item) for item in (extra_hosts or [])]
    return allowlist_for(bound_port, parsed)


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
        if text.count(TOKEN_PLACEHOLDER) != 1:
            raise RuntimeError("Dashboard index is missing its token placeholder.")
        # token_urlsafe is already [A-Za-z0-9_-]. Escape anyway so a future
        # generator cannot break out of the attribute. Do not log the token.
        escaped = html.escape(self.api_token, quote=True)
        return text.replace(TOKEN_PLACEHOLDER, escaped, 1).encode("utf-8")

    # -- GET -----------------------------------------------------------

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
        if not self._host_allowed():
            self._forbid(unread_body=False)
            return
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
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
            self._send_json(500, {"error": f"Server error: {exc}"})

    @staticmethod
    def _int_param(value, name: str) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be a number.") from exc
        if number < 1:
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
            self._send_json(500, {"error": f"Server error: {exc}"})

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


def make_server(
    db_path,
    host: str = "127.0.0.1",
    port: int = 8068,
    debug: bool = False,
    allow_hosts: list[str] | None = None,
) -> ThreadingHTTPServer:
    """Build the dashboard server without starting it. Used by serve() and tests.

    The API token is created here and kept on the handler class. Callers must
    not log it. It is handed to the browser only inside index.html.
    """
    index_path = WEB_DIR / "index.html"
    if not index_path.is_file():
        raise FileNotFoundError(
            f"Dashboard files missing under {WEB_DIR}. "
            "Reinstall Lantern from the repo so lantern/web is included."
        )
    if index_path.read_text(encoding="utf-8").count(TOKEN_PLACEHOLDER) != 1:
        raise ValueError(
            "Dashboard index is missing its token placeholder. "
            "Reinstall Lantern from the repo so lantern/web is intact."
        )
    # Reject a bad --allow-host before opening a socket.
    parsed_hosts = [parse_allow_host(item) for item in (allow_hosts or [])]
    handler = type(
        "BoundHandler",
        (LanternHandler,),
        {"db_path": str(db_path), "debug": bool(debug)},
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    bound_port = int(server.server_address[1])
    handler.bound_port = bound_port
    handler.allowed_hosts = allowlist_for(bound_port, parsed_hosts)
    handler.api_token = secrets.token_urlsafe(_TOKEN_BYTES)
    return server


def serve(
    db_path,
    host: str = "127.0.0.1",
    port: int = 8068,
    debug: bool = False,
    allow_hosts: list[str] | None = None,
) -> None:
    server = make_server(db_path, host=host, port=port, debug=debug, allow_hosts=allow_hosts)
    bound_host, bound_port = server.server_address[:2]
    url_host = "127.0.0.1" if bound_host in ("0.0.0.0", "") else bound_host
    print(f"Lantern dashboard: http://{url_host}:{bound_port}/  (local only, no login)", flush=True)
    print(f"Database: {db_path}", flush=True)
    extras = _extra_allowed_hosts(server.RequestHandlerClass.allowed_hosts, int(bound_port))
    if extras:
        print("Additional allowed Host headers: " + ", ".join(extras), flush=True)
    if debug:
        print("Debug request logging on.", flush=True)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: bound to a non-localhost address. Keep this behind Tailscale, never the internet.", flush=True)
    print("Press Ctrl+C to stop.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        server.server_close()

"""Web dashboard: stdlib only, no pip install needed.

Plain HTML/CSS/JS, a JSON API, and static files served by the app,
without a web framework, so Lantern stays a zero-dependency tool:
python3 -m lantern web, open the URL.

Binds to 127.0.0.1 by default. Only bind another address if you
understand the network: on a home LAN, prefer Tailscale-only access.
Never expose this to the internet. It has no login, by design, for
local use only.

Local-tool hygiene, enforced here:
- POST bodies must be JSON (Content-Type application/json) and small.
  A plain HTML form or a text/plain cross-site fetch cannot trigger a scan.
- A POST with an Origin header must come from this dashboard's own
  origin. That blocks cross-site requests from other pages in the browser.
- Responses carry nosniff, a strict CSP, and no-store caching.
"""

from __future__ import annotations

import json
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

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
_scan_lock = threading.Lock()


class LanternHandler(BaseHTTPRequestHandler):
    db_path = None
    debug = False
    protocol_version = "HTTP/1.1"
    server_version = "Lantern"
    sys_version = ""

    def log_message(self, format, *args):
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

    def _same_origin(self) -> bool:
        """False only when a browser says the POST came from another site."""
        origin = self.headers.get("Origin")
        if origin and origin != "null":
            host = self.headers.get("Host") or ""
            return urlparse(origin).netloc.lower() == host.lower()
        fetch_site = (self.headers.get("Sec-Fetch-Site") or "").lower()
        return fetch_site not in ("cross-site",)

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
        self._send_bytes(200, path.read_bytes(), STATIC_TYPES[path.suffix], cache="no-cache")

    # -- GET -----------------------------------------------------------

    def do_HEAD(self):
        self.do_GET()

    def do_GET(self):
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
        if not parsed.path.startswith("/api/"):
            self.close_connection = True  # body left unread
            self._send_json(404, {"error": "Not found."})
            return
        if not self._same_origin():
            self.close_connection = True
            self._send_json(403, {"error": "Cross-site requests are not allowed."})
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


def make_server(db_path, host: str = "127.0.0.1", port: int = 8068, debug: bool = False) -> ThreadingHTTPServer:
    """Build the dashboard server without starting it. Used by serve() and tests."""
    if not (WEB_DIR / "index.html").is_file():
        raise FileNotFoundError(
            f"Dashboard files missing under {WEB_DIR}. "
            "Reinstall Lantern from the repo so lantern/web is included."
        )
    handler = type(
        "BoundHandler",
        (LanternHandler,),
        {"db_path": str(db_path), "debug": bool(debug)},
    )
    server = ThreadingHTTPServer((host, port), handler)
    server.daemon_threads = True
    return server


def serve(db_path, host: str = "127.0.0.1", port: int = 8068, debug: bool = False) -> None:
    server = make_server(db_path, host=host, port=port, debug=debug)
    bound_host, bound_port = server.server_address[:2]
    url_host = "127.0.0.1" if bound_host in ("0.0.0.0", "") else bound_host
    print(f"Lantern dashboard: http://{url_host}:{bound_port}/  (local only, no login)", flush=True)
    print(f"Database: {db_path}", flush=True)
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

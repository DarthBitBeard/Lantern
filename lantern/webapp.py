"""Web dashboard: stdlib only, no pip install needed.

Same pattern as SecondLook (plain HTML/CSS/JS, JSON API, static
files served by the app), but without FastAPI, so Lantern stays a
zero-dependency tool: python3 -m lantern web, open the URL.

Binds to 127.0.0.1 by default. Only bind another address if you
understand the network: on a home LAN, prefer Tailscale-only access.
Never expose this to the internet. It has no login, by design, for
local use only.
"""

import json
import re
import threading
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, urlparse

from . import __version__, demo
from .discovery import guess_subnet
from .ports import DEFAULT_PORTS
from .report import to_html, to_json
from .store import (
    apply_trust,
    connect,
    diff_scans,
    get_trusted,
    latest_two_scan_ids,
    list_scans,
    load_scan,
    save_scan,
    set_trusted,
)

WEB_DIR = Path(__file__).resolve().parent / "web"
MAC_RE = re.compile(r"^([0-9a-fA-F]{2}[:-]){5}[0-9a-fA-F]{2}$")
STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".svg": "image/svg+xml",
}
_scan_lock = threading.Lock()


class LanternHandler(BaseHTTPRequestHandler):
    db_path = None
    protocol_version = "HTTP/1.1"

    def log_message(self, *args):
        pass

    # -- helpers ------------------------------------------------------

    def _send_json(self, status, payload):
        body = json.dumps(payload).encode()
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_text(self, status, body, content_type):
        data = body.encode()
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    def _read_json(self):
        length = int(self.headers.get("Content-Length") or 0)
        if not length:
            return {}
        raw = self.rfile.read(length)
        try:
            value = json.loads(raw.decode())
        except Exception as exc:
            raise ValueError("Request body is not valid JSON.") from exc
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object.")
        return value

    def _db(self):
        return connect(self.db_path)

    def _latest_with_diff(self, conn):
        ids = latest_two_scan_ids(conn)
        if not ids:
            return None, None
        trusted = get_trusted(conn)
        scan = apply_trust(load_scan(conn, ids[0]), trusted)
        diff = None
        if len(ids) == 2:
            old = apply_trust(load_scan(conn, ids[1]), trusted)
            diff = diff_scans(old, scan)
        return scan, diff

    # -- static --------------------------------------------------------

    def _serve_static(self, name):
        if name in ("", "/"):
            name = "index.html"
        name = name.lstrip("/")
        path = (WEB_DIR / name).resolve()
        if WEB_DIR not in path.parents and path != WEB_DIR:
            self._send_json(404, {"error": "Not found."})
            return
        if not path.is_file() or path.suffix not in STATIC_TYPES:
            self._send_json(404, {"error": "Not found."})
            return
        data = path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", STATIC_TYPES[path.suffix])
        self.send_header("Content-Length", str(len(data)))
        self.end_headers()
        self.wfile.write(data)

    # -- GET -----------------------------------------------------------

    def do_GET(self):
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        try:
            if parsed.path.startswith("/api/"):
                self._handle_api_get(parsed.path, query)
            elif parsed.path == "/favicon.ico":
                self.send_response(204)
                self.send_header("Content-Length", "0")
                self.end_headers()
            else:
                self._serve_static(parsed.path)
        except Exception as exc:
            self._send_json(500, {"error": str(exc)})

    def _handle_api_get(self, path, query):
        conn = self._db()
        try:
            if path == "/api/status":
                scans = list_scans(conn)
                self._send_json(200, {
                    "version": __version__,
                    "demo": False,
                    "guessed_subnet": guess_subnet(),
                    "scan_count": len(scans),
                    "latest_scan_id": scans[0]["id"] if scans else None,
                })
                return
            if path == "/api/scans":
                self._send_json(200, {"scans": list_scans(conn)})
                return
            if path == "/api/scans/latest":
                scan, diff = self._latest_with_diff(conn)
                if scan is None:
                    self._send_json(200, {"scan": None, "diff": None})
                else:
                    self._send_json(200, {"scan": scan, "diff": diff})
                return
            if path.startswith("/api/scans/"):
                try:
                    scan_id = int(path.rsplit("/", 1)[-1])
                except ValueError:
                    self._send_json(400, {"error": "Scan id must be a number."})
                    return
                scan = apply_trust(load_scan(conn, scan_id), get_trusted(conn))
                if scan is None:
                    self._send_json(404, {"error": "Scan not found."})
                else:
                    self._send_json(200, {"scan": scan})
                return
            if path == "/api/diff":
                scan, diff = self._latest_with_diff(conn)
                self._send_json(200, {"scan": scan, "diff": diff})
                return
            if path == "/api/report":
                scan_id = query.get("scan_id", [None])[0]
                fmt = query.get("format", ["json"])[0]
                if scan_id:
                    try:
                        scan_id = int(scan_id)
                    except ValueError:
                        self._send_json(400, {"error": "scan_id must be a number."})
                        return
                    scan = apply_trust(load_scan(conn, scan_id), get_trusted(conn))
                else:
                    scan, _ = self._latest_with_diff(conn)
                if scan is None:
                    self._send_json(404, {"error": "No scans yet."})
                    return
                if fmt == "html":
                    self._send_text(200, to_html(scan), "text/html; charset=utf-8")
                else:
                    self._send_text(200, to_json(scan), "application/json")
                return
            self._send_json(404, {"error": "Unknown API route."})
        finally:
            conn.close()

    # -- POST ----------------------------------------------------------

    def do_POST(self):
        parsed = urlparse(self.path)
        try:
            body = self._read_json()
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
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
            self._send_json(500, {"error": str(exc)})

    def _handle_demo(self):
        conn = self._db()
        try:
            subnet = "192.168.1.0/24"
            save_scan(conn, subnet, demo.demo_scan_1(), demo=True)
            save_scan(conn, subnet, demo.demo_scan_2(), demo=True)
            scan, diff = self._latest_with_diff(conn)
            self._send_json(200, {"scan": scan, "diff": diff})
        finally:
            conn.close()

    def _handle_scan(self, body):
        if not _scan_lock.acquire(blocking=False):
            self._send_json(409, {"error": "A scan is already running."})
            return
        try:
            # Import here to avoid a module cycle with cli.py.
            from .cli import run_scan

            subnet = body.get("subnet") or guess_subnet()
            if not subnet:
                raise ValueError(
                    "Could not auto-detect your subnet. Send {\"subnet\": \"192.168.1.0/24\"}."
                )
            devices = run_scan(subnet, DEFAULT_PORTS, self.db_path, demo_mode=False)
            conn = self._db()
            try:
                scan_id = save_scan(conn, subnet, devices, demo=False)
                scan, diff = self._latest_with_diff(conn)
                self._send_json(200, {"scan_id": scan_id, "scan": scan, "diff": diff})
            finally:
                conn.close()
        finally:
            _scan_lock.release()

    def _handle_trust(self, body):
        mac = str(body.get("mac") or "").strip()
        if not MAC_RE.match(mac):
            raise ValueError("mac must look like aa:bb:cc:dd:ee:ff.")
        label = str(body.get("label") or "")[:80]
        trusted = bool(body.get("trusted", True))
        conn = self._db()
        try:
            set_trusted(conn, mac, label, trusted)
            self._send_json(200, {"mac": mac.lower(), "label": label, "trusted": trusted})
        finally:
            conn.close()


def serve(db_path, host="127.0.0.1", port=8068):
    handler = type("BoundHandler", (LanternHandler,), {"db_path": str(db_path)})
    server = ThreadingHTTPServer((host, port), handler)
    print(f"Lantern dashboard: http://{host}:{port}/  (local only, no login)", flush=True)
    print(f"Database: {db_path}", flush=True)
    if host not in ("127.0.0.1", "localhost", "::1"):
        print("WARNING: bound to a non-localhost address. Keep this behind Tailscale, never the internet.", flush=True)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        pass

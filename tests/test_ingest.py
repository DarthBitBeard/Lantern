"""Hostname cleaning, text output, report CSP, corrupt shapes, and UPnP deadline.

Localhost and fake data only. No DNS and no device scans.
"""

import io
import json
import socket
import threading
import time
import unittest
import urllib.error
import urllib.request
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from unittest import mock

from lantern import cli, discovery, identify, report
from lantern.store import connect, load_scan, save_scan
from lantern.webapp import CSP, make_server


def _device(ip="10.1.0.5", hostname="printer.lan"):
    return {
        "ip": ip,
        "mac": "aa:bb:cc:dd:ee:05",
        "hostname": hostname,
        "label": None,
        "open_ports": [{"port": 80}],
        "findings": [],
    }


class HostnameTests(unittest.TestCase):
    def _stored(self, name):
        conn = connect(":memory:")
        try:
            with mock.patch("lantern.discovery.socket.gethostbyaddr", return_value=(name, [], [])):
                cleaned = discovery.reverse_hostname("10.1.0.5")
            save_scan(conn, "10.1.0.0/24", [_device(hostname=name)])
            loaded = load_scan(conn, 1)["devices"][0]["hostname"]
        finally:
            conn.close()
        return cleaned, loaded

    def test_a_long_or_hostile_ptr_is_capped_and_cleaned(self):
        cleaned, stored = self._stored("x" * 5000)
        self.assertLessEqual(len(cleaned), 253)
        self.assertLessEqual(len(stored), 253)
        cleaned, stored = self._stored("host\x1b[31m.lan")
        self.assertNotIn("\x1b", cleaned)
        self.assertNotIn("\x1b", stored)
        self.assertNotIn("\u202e", self._stored("a\u202eb")[1])
        self.assertIsNone(self._stored("\x00\x1b")[1])

    def test_ordinary_names_are_unchanged(self):
        for name in ("printer.lan", "xn--bcher-kva.example"):
            cleaned, stored = self._stored(name)
            self.assertEqual(cleaned, name)
            self.assertEqual(stored, name)


class TextOutputTests(unittest.TestCase):
    def test_text_printers_drop_controls(self):
        scan = {
            "id": 1, "subnet": "10.1.0.0/24", "demo": False,
            "devices": [{
                "ip": "10.1.0.5",
                "mac": "aa:bb:cc:dd:ee:05",
                "hostname": "h\x1bost",
                "label": "lab\x07el",
                "vendor": "ven\rdor",
                "open_ports": [{"port": 22, "service": "ssh"}],
                "findings": [],
            }],
        }
        topo = {
            "switches": [{"ip": "10.1.0.2", "name": "sw\x1b", "parent": None, "error": None,
                          "port_to_parent": None}],
            "locations": {},
        }
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            cli._print_text_scan(scan, None)
            cli._print_topology(scan, topo)
        text = out.getvalue()
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        self.assertNotIn("\r", text)
        self.assertIn("label", text)
        self.assertIn("sw", text)
        self.assertTrue(all(ord(ch) >= 32 or ch in "\n\t" for ch in text))


class ReportCspTests(unittest.TestCase):
    def test_the_meta_policy_is_the_first_head_element(self):
        scan = {
            "id": 3, "started_at": "t", "subnet": "10.0.0.0/24", "demo": True,
            "scope_name": None, "devices": [],
        }
        html = report.to_html(scan, None)
        head = html.split("<head>", 1)[1].split("</head>", 1)[0]
        self.assertTrue(head.lstrip().startswith('<meta http-equiv="Content-Security-Policy"'))
        self.assertIn("default-src 'none'", head)
        self.assertNotIn("<script", html.lower())
        self.assertIsNone(__import__("re").search(r"\son[a-z]+=", html.lower()))


class CorruptShapeTests(unittest.TestCase):
    def _seed(self, sql, value):
        tmp = __import__("tempfile").TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = str(Path(tmp.name) / "t.db")
        conn = connect(db)
        save_scan(conn, "10.1.0.0/24", [_device()])
        conn.execute(sql, (value,))
        conn.commit()
        conn.close()
        return db

    def test_wrong_shapes_exit_2_without_a_traceback(self):
        cases = (
            ("UPDATE devices SET open_ports = ?", '{"x":1}'),
            ("UPDATE devices SET open_ports = ?", '"str"'),
            ("UPDATE devices SET open_ports = ?", '[1, "a"]'),
            ("UPDATE devices SET findings = ?", '{"x":1}'),
            ("UPDATE devices SET identity = ?", '"str"'),
            ("UPDATE devices SET open_ports = ?", "[22]"),
            ("UPDATE devices SET findings = ?", "[{}]"),
        )
        for sql, value in cases:
            db = self._seed(sql, value)
            for args in (["report"], ["diff"], ["export", "--what", "devices"]):
                err = io.StringIO()
                with mock.patch("sys.stderr", err):
                    code = cli.main(["--db", db, *args])
                self.assertEqual(code, 2, (sql, args, err.getvalue()))
                self.assertIn("The saved scan could not be read.", err.getvalue())
                self.assertNotIn("Traceback", err.getvalue())


class DataErrorHttpTests(unittest.TestCase):
    def _serve(self, db):
        server = make_server(db, port=0, strict_auth=False)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        return f"http://127.0.0.1:{server.server_address[1]}"

    def _get(self, base, path):
        req = urllib.request.Request(base + path)
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode(), resp.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(), exc.headers

    def test_corrupt_json_is_500_and_a_newer_schema_is_409(self):
        tmp = __import__("tempfile").TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = str(Path(tmp.name) / "t.db")
        conn = connect(db)
        save_scan(conn, "10.1.0.0/24", [_device()])
        conn.execute("UPDATE devices SET open_ports = ?", ('{"x":1}',))
        conn.commit()
        conn.close()
        status, body, headers = self._get(self._serve(db), "/api/scans/latest")
        self.assertEqual(status, 500)
        self.assertEqual(json.loads(body)["error"], "The saved scan could not be read.")
        self.assertNotIn(db, body)
        self.assertEqual(headers["Content-Security-Policy"], CSP)

        raw = __import__("sqlite3").connect(db)
        raw.execute("DELETE FROM schema_version")
        raw.execute("INSERT INTO schema_version (version, applied_at) VALUES (99, 'future')")
        raw.commit()
        raw.close()
        status, body, headers = self._get(self._serve(db), "/api/scans")
        self.assertEqual(status, 409, body)
        self.assertEqual(json.loads(body)["error"], "The database schema is newer than this Lantern.")
        self.assertNotIn("schema 99", body)
        self.assertNotIn(db, body)
        self.assertEqual(headers["Content-Security-Policy"], CSP)

        fresh = str(Path(tmp.name) / "fresh.db")
        connect(fresh).close()
        status, body, _ = self._get(self._serve(fresh), "/api/nope")
        self.assertEqual(status, 404)


class DescriptionDeadlineTests(unittest.TestCase):
    def test_a_slow_drip_is_abandoned(self):
        class Handler(BaseHTTPRequestHandler):
            def do_GET(self):
                self.send_response(200)
                self.send_header("Content-Type", "text/xml")
                self.end_headers()
                for _ in range(20):
                    try:
                        self.wfile.write(b"x")
                        self.wfile.flush()
                    except OSError:
                        return
                    time.sleep(0.5)

            def log_message(self, *args):
                return

        server = ThreadingHTTPServer(("127.0.0.1", 0), Handler)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.shutdown)
        self.addCleanup(server.server_close)
        port = server.server_address[1]
        started = time.monotonic()
        with mock.patch.object(identify, "DESCRIPTION_DEADLINE", 0.4):
            body = identify.fetch_description(f"http://127.0.0.1:{port}/desc.xml", timeout=2)
        elapsed = time.monotonic() - started
        self.assertEqual(body, b"")
        self.assertLess(elapsed, 0.4 + 1.0)

    def _drip(self, first: bytes, later: bytes, pause: float, count: int):
        """A localhost socket that writes ``first`` once, then ``later`` slowly."""
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        held = []

        def run():
            try:
                conn, _ = server.accept()
            except OSError:
                return
            held.append(conn)
            conn.settimeout(2)
            try:
                conn.recv(4096)
            except OSError:
                pass
            try:
                conn.sendall(first)
                for _ in range(count):
                    conn.sendall(later)
                    time.sleep(pause)
            except OSError:
                return

        thread = threading.Thread(target=run, daemon=True)
        thread.start()
        self.addCleanup(server.close)
        self.addCleanup(lambda: [item.close() for item in held])
        return port

    def test_a_header_drip_stops_at_the_deadline(self):
        port = self._drip(b"HTTP/1.0 200 OK\r\n", b"X", 1.5, 20)
        started = time.monotonic()
        body = identify.fetch_description(f"http://127.0.0.1:{port}/desc.xml")
        self.assertEqual(body, b"")
        self.assertLess(time.monotonic() - started, identify.DESCRIPTION_DEADLINE + 1.5)

    def test_a_chunk_drip_is_refused(self):
        port = self._drip(
            b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"1",
            1.5,
            20,
        )
        started = time.monotonic()
        body = identify.fetch_description(f"http://127.0.0.1:{port}/desc.xml")
        self.assertEqual(body, b"")
        self.assertLess(time.monotonic() - started, identify.DESCRIPTION_DEADLINE + 1.5)


class BlobUrlTests(unittest.TestCase):
    def test_every_object_url_is_revoked(self):
        text = (Path(__file__).resolve().parent.parent / "lantern" / "web" / "app.js").read_text(encoding="utf-8")
        self.assertEqual(text.count("createObjectURL"), text.count("revokeObjectURL"))
        self.assertIn("revokeObjectURL", text)

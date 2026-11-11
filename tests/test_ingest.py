"""Hostname cleaning, text output, report CSP, corrupt shapes, and UPnP deadline.

Localhost and fake data only. No DNS and no device scans.
"""

import io
import json
import re
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
from lantern.store import CorruptScanError, NewerSchemaError, connect, load_scan, save_scan
from lantern.webapp import CSP, TOKEN_HEADER, LanternHandler, make_server


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
            }, {
                "ip": "10.1.0.9",
                "mac": "aa:bb:cc:dd:ee:09",
                "hostname": None,
                "label": None,
                "vendor": "Ac\u202eme",
                "open_ports": [{"port": 80}],
                "findings": [],
            }],
        }
        switch_ip = "10.1.0.\x072"
        topo = {
            "switches": [
                {
                    "ip": switch_ip, "name": "sw\u202eitch", "parent": None, "error": None,
                    "port_to_parent": "Gi\u200b0/1",
                },
                {
                    "ip": "10.9.9.9", "name": "child", "parent": switch_ip, "error": None,
                    "parent_port": "Te\x071/0/1", "port_to_parent": "Up\x071",
                },
                {"ip": "10.0.0.\x013", "name": None, "parent": None, "error": "no\x07 reply"},
            ],
            "locations": {
                "aa:bb:cc:dd:ee:05": {
                    "switch": switch_ip, "port": "Gi\u202e0/3", "shared": False, "mac_count": 1,
                },
            },
        }
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            cli._print_text_scan(scan, None)
            cli._print_topology(scan, topo)
        text = out.getvalue()
        self.assertNotIn("\x1b", text)
        self.assertNotIn("\x07", text)
        self.assertNotIn("\r", text)
        self.assertNotIn("\u202e", text)
        self.assertNotIn("\u200b", text)
        self.assertIn("label", text)
        self.assertIn("switch", text)
        self.assertIn("Acme", text)
        self.assertIn("10.1.0.2", text)
        self.assertIn("Gi0/1", text)
        self.assertIn("Gi0/3", text)
        self.assertIn("Te1/0/1", text)
        self.assertIn("no reply", text)
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
        self.assertIn("base-uri 'none'", head)
        self.assertIn("form-action 'none'", head)
        self.assertIn("style-src 'unsafe-inline'", head)
        self.assertNotIn("script-src", head)
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
            ("UPDATE devices SET open_ports = ?", "[{}]"),
            ("UPDATE devices SET open_ports = ?", '[{"port": true}]'),
            ("UPDATE devices SET open_ports = ?", '[{"port": 65536}]'),
            ("UPDATE devices SET open_ports = ?", '[{"port": -1}]'),
            ("UPDATE devices SET findings = ?", "[{}]"),
            ("UPDATE devices SET findings = ?", '[{"severity": "low"}]'),
            ("UPDATE devices SET findings = ?", '[{"port": 80, "service": 1, "severity": "low", "title": "t", "fix": "f"}]'),
            ("UPDATE devices SET findings = ?", '[{"port": 80, "service": "http", "severity": "low", "title": "t", "fix": "f", "banner": 1}]'),
            ("UPDATE devices SET open_ports = ?", '[{"port": 80, "banner": 1}]'),
            ("UPDATE devices SET findings = ?", "not json"),
            ("UPDATE devices SET open_ports = ?", "not json"),
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
        db = self._seed("UPDATE scans SET topology = ?", '"str"')
        for args in (["report"], ["diff"]):
            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                code = cli.main(["--db", db, *args])
            self.assertEqual(code, 2, (args, err.getvalue()))
            self.assertIn("The saved scan could not be read.", err.getvalue())


class DataErrorHttpTests(unittest.TestCase):
    def _serve(self, db):
        server = make_server(db, port=0, strict_auth=False)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        # LIFO: shutdown runs before the listening socket is closed.
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
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
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        port = server.server_address[1]
        started = time.monotonic()
        with mock.patch.object(identify, "DESCRIPTION_DEADLINE", 0.4):
            body = identify.fetch_description(f"http://127.0.0.1:{port}/desc.xml", timeout=2)
        elapsed = time.monotonic() - started
        self.assertEqual(body, b"")
        self.assertNotIn(b"x", body)
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

    def _bounded(self, first: bytes, later: bytes):
        port = self._drip(first, later, 0.3, 15)
        started = time.monotonic()
        with mock.patch.object(identify, "DESCRIPTION_DEADLINE", 0.45):
            body = identify.fetch_description(f"http://127.0.0.1:{port}/desc.xml", timeout=2)
        self.assertEqual(body, b"")
        self.assertLess(time.monotonic() - started, 1.2)

    def test_a_status_line_drip_stops_at_the_deadline(self):
        self._bounded(b"", b"H")

    def test_a_header_drip_stops_at_the_deadline(self):
        self._bounded(b"HTTP/1.0 200 OK\r\n", b"X")

    def test_a_chunk_drip_is_refused(self):
        port = self._drip(
            b"HTTP/1.0 200 OK\r\nTransfer-Encoding: chunked\r\n\r\n",
            b"1",
            0.3,
            15,
        )
        started = time.monotonic()
        body = identify.fetch_description(f"http://127.0.0.1:{port}/desc.xml", timeout=2)
        self.assertEqual(body, b"")
        self.assertLess(time.monotonic() - started, 1.2)

    def test_each_read_stops_at_the_per_read_timeout(self):
        port = self._drip(b"", b"", 5, 1)
        started = time.monotonic()
        body = identify.fetch_description(f"http://127.0.0.1:{port}/desc.xml", timeout=0.25)
        self.assertEqual(body, b"")
        self.assertLess(time.monotonic() - started, 0.9)

    def test_a_timeout_does_not_return_a_partial_body(self):
        port = self._drip(
            b"HTTP/1.0 200 OK\r\nContent-Type: text/xml\r\n\r\nPARTIAL",
            b"Y",
            0.4,
            8,
        )
        with mock.patch.object(identify, "DESCRIPTION_DEADLINE", 0.3):
            body = identify.fetch_description(f"http://127.0.0.1:{port}/desc.xml", timeout=2)
        self.assertEqual(body, b"")
        self.assertNotIn(b"PARTIAL", body)

    def test_exactly_64_kib_is_kept_and_one_more_byte_is_refused(self):
        cap = identify.DESCRIPTION_MAX_BYTES
        exact = self._serve_body(b"Z" * cap)
        self.assertEqual(
            identify.fetch_description(f"http://127.0.0.1:{exact}/x", timeout=2),
            b"Z" * cap,
        )
        over = self._serve_body(b"Z" * (cap + 1))
        started = time.monotonic()
        self.assertEqual(identify.fetch_description(f"http://127.0.0.1:{over}/x", timeout=2), b"")
        self.assertLess(time.monotonic() - started, 1.0)
        # No Content-Length: reading only the first 64 KiB must not return them.
        streamed = self._serve_body(b"Q" * (cap + 1), length=False)
        self.assertEqual(
            identify.fetch_description(f"http://127.0.0.1:{streamed}/x", timeout=2),
            b"",
        )
        exact_close = self._serve_body(b"Q" * cap, length=False)
        self.assertEqual(
            identify.fetch_description(f"http://127.0.0.1:{exact_close}/x", timeout=2),
            b"Q" * cap,
        )

    def _serve_body(self, payload: bytes, length: bool = True) -> int:
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(1)
        port = server.getsockname()[1]
        held = []
        if length:
            head = (
                b"HTTP/1.0 200 OK\r\nContent-Length: "
                + str(len(payload)).encode("ascii") + b"\r\n\r\n"
            )
        else:
            head = b"HTTP/1.0 200 OK\r\n\r\n"

        def run():
            try:
                conn, _ = server.accept()
            except OSError:
                return
            held.append(conn)
            try:
                conn.recv(4096)
                conn.sendall(head + payload)
                conn.shutdown(socket.SHUT_WR)
            except OSError:
                return

        threading.Thread(target=run, daemon=True).start()
        self.addCleanup(server.close)
        self.addCleanup(lambda: [item.close() for item in held])
        return port

    def _silent(self) -> int:
        """Accept the request and then say nothing, so the client waits."""
        server = socket.socket()
        server.bind(("127.0.0.1", 0))
        server.listen(8)
        port = server.getsockname()[1]
        held = []
        stop = threading.Event()

        def run():
            server.settimeout(0.2)
            while not stop.is_set():
                try:
                    conn, _addr = server.accept()
                except socket.timeout:
                    continue
                except OSError:
                    return
                held.append(conn)
                try:
                    conn.recv(4096)
                except OSError:
                    return

        threading.Thread(target=run, daemon=True).start()
        self.addCleanup(stop.set)
        self.addCleanup(server.close)
        self.addCleanup(lambda: [item.close() for item in held])
        return port

    def test_the_description_phase_shares_one_deadline(self):
        self.assertEqual(identify.DESCRIPTION_PHASE_DEADLINE, 15.0)
        fast = self._serve_body(b"<root><friendlyName>TV</friendlyName></root>")
        slow = [self._silent() for _ in range(3)]
        locations = {"10.1.0.1": f"http://127.0.0.1:{fast}/d.xml"}
        for index, port in enumerate(slow, start=2):
            locations[f"10.1.0.{index}"] = f"http://127.0.0.1:{port}/d.xml"
        started = time.monotonic()
        with mock.patch.object(identify, "DESCRIPTION_WORKERS", 1), \
                mock.patch.object(identify, "DESCRIPTION_DEADLINE", 2.5), \
                mock.patch.object(identify, "DESCRIPTION_PHASE_DEADLINE", 0.45):
            bodies = identify.fetch_descriptions(locations)
        elapsed = time.monotonic() - started
        self.assertLess(elapsed, 1.6, elapsed)
        self.assertIn(b"friendlyName", bodies["10.1.0.1"])
        self.assertEqual(bodies.get("10.1.0.2", b""), b"")


class PortShapeTests(unittest.TestCase):
    def test_bool_range_and_bare_number_are_corrupt(self):
        from lantern import store

        self.assertEqual(store._require_ports([{"port": 0}]), [{"port": 0}])
        self.assertEqual(store._require_ports([{"port": 65535, "banner": ""}]), [{"port": 65535, "banner": ""}])
        for value in (
            [{"port": True}], [{"port": False}], [{"port": -1}], [{"port": 65536}],
            [22], "nope", [{"port": 80, "banner": 1}], [{"port": 80, "banner": None}],
        ):
            with self.assertRaises(CorruptScanError):
                store._require_ports(value)
        good = {
            "port": 80, "service": "http", "severity": "low", "title": "Web", "fix": "Close it.",
        }
        self.assertEqual(store._require_findings([good]), [good])
        self.assertEqual(store._require_findings([{**good, "banner": "ok"}]), [{**good, "banner": "ok"}])
        for value in (
            [{}],
            [{"severity": "low"}],
            [{**good, "port": True}],
            [{**good, "service": 1}],
            [{**good, "title": None}],
            [{**good, "fix": ["x"]}],
            [{key: good[key] for key in good if key != "title"}],
            [{**good, "banner": 1}],
            [{**good, "banner": None}],
        ):
            with self.assertRaises(CorruptScanError):
                store._require_findings(value)


class LenientTopologyTests(unittest.TestCase):
    def test_broken_topology_json_is_missing_and_a_non_object_is_corrupt(self):
        tmp = __import__("tempfile").TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = str(Path(tmp.name) / "t.db")
        conn = connect(db)
        scan_id = save_scan(conn, "10.1.0.0/24", [_device()])
        conn.execute("UPDATE scans SET topology = ?", ("not json",))
        conn.commit()
        self.assertIsNone(load_scan(conn, scan_id)["topology"])
        conn.execute("UPDATE devices SET identity = ?", ("not json",))
        conn.commit()
        self.assertIsNone(load_scan(conn, scan_id)["devices"][0]["identity"])
        conn.execute("UPDATE scans SET topology = ?", ('"str"',))
        conn.commit()
        with self.assertRaises(CorruptScanError):
            load_scan(conn, scan_id)
        conn.close()


class HistorySubnetTests(unittest.TestCase):
    def test_history_strips_controls_from_the_subnet(self):
        tmp = __import__("tempfile").TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = str(Path(tmp.name) / "t.db")
        conn = connect(db)
        save_scan(conn, "10.1.0.0/24", [_device()])
        conn.execute("UPDATE scans SET subnet = ?", ("10.1.0.0/24\x07\u202e",))
        conn.commit()
        conn.close()
        out, err = io.StringIO(), io.StringIO()
        with mock.patch("sys.stdout", out), mock.patch("sys.stderr", err):
            code = cli.main(["--db", db, "history"])
        text = out.getvalue()
        self.assertEqual(code, 0, err.getvalue())
        self.assertIn("10.1.0.0/24", text)
        self.assertNotIn("\x07", text)
        self.assertNotIn("\u202e", text)
        out = io.StringIO()
        with mock.patch("sys.stdout", out):
            cli.main(["--db", db, "history", "--format", "json"])
        self.assertNotIn("\\u0007", out.getvalue())
        self.assertNotIn("\u202e", out.getvalue())


class TagShapeTests(unittest.TestCase):
    def _db(self, tags):
        tmp = __import__("tempfile").TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = str(Path(tmp.name) / "t.db")
        conn = connect(db)
        save_scan(conn, "10.1.0.0/24", [_device()])
        conn.execute(
            "INSERT INTO assets (asset_key, key_kind, owner, location, tags, criticality, notes, updated_at)"
            " VALUES ('mac:aa:bb:cc:dd:ee:05', 'mac', NULL, NULL, ?, NULL, NULL, 't')",
            (tags,),
        )
        conn.commit()
        conn.close()
        return db

    def test_wrong_shape_tags_are_the_same_error_everywhere(self):
        for tags in ("not json", '{"a": 1}', "[1]", '"just"'):
            db = self._db(tags)
            err = io.StringIO()
            with mock.patch("sys.stderr", err):
                code = cli.main(["--db", db, "asset", "list"])
            self.assertEqual(code, 2, (tags, err.getvalue()))
            self.assertIn("The saved scan could not be read.", err.getvalue())
            self.assertNotIn(tags, err.getvalue())
            self.assertNotIn("Expecting", err.getvalue())
            for args in (["report"], ["diff"], ["export", "--what", "devices"]):
                err = io.StringIO()
                with mock.patch("sys.stderr", err):
                    code = cli.main(["--db", db, *args])
                self.assertEqual(code, 2, (tags, args, err.getvalue()))
                self.assertIn("The saved scan could not be read.", err.getvalue())
                self.assertNotIn("Traceback", err.getvalue())


class V1DataErrorTests(unittest.TestCase):
    def _serve(self, db):
        server = make_server(db, port=0, strict_auth=False)
        thread = threading.Thread(target=server.serve_forever, daemon=True)
        thread.start()
        self.addCleanup(server.server_close)
        self.addCleanup(server.shutdown)
        base = f"http://127.0.0.1:{server.server_address[1]}"
        page = urllib.request.urlopen(base + "/", timeout=5).read().decode()
        token = re.search(r'<meta name="lantern-token" content="([^"]+)"', page).group(1)
        return base, token

    def _ask(self, base, path, token, method="GET", body=None):
        data = None if body is None else json.dumps(body).encode()
        req = urllib.request.Request(
            base + path, data=data, method=method,
            headers={TOKEN_HEADER: token, "Content-Type": "application/json"},
        )
        try:
            with urllib.request.urlopen(req, timeout=5) as resp:
                return resp.status, resp.read().decode()
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode()

    def _schema99(self, db):
        raw = __import__("sqlite3").connect(db)
        try:
            raw.execute("DELETE FROM schema_version")
            raw.execute("INSERT INTO schema_version (version, applied_at) VALUES (99, 'future')")
            raw.commit()
        finally:
            raw.close()

    def test_v1_uses_its_envelope_for_a_newer_schema_and_a_corrupt_row(self):
        tmp = __import__("tempfile").TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = str(Path(tmp.name) / "t.db")
        conn = connect(db)
        save_scan(conn, "10.1.0.0/24", [_device()])
        conn.execute("UPDATE devices SET open_ports = ?", ("not json",))
        conn.commit()
        conn.close()
        base, token = self._serve(db)
        status, body = self._ask(base, "/api/v1/devices", token)
        payload = json.loads(body)
        self.assertEqual(status, 500, body)
        self.assertEqual(payload["api_version"], 1)
        self.assertEqual(payload["error"]["code"], "server_error")
        self.assertNotIn("not json", body)

        self._schema99(db)
        status, body = self._ask(base, "/api/v1/scans", token)
        payload = json.loads(body)
        self.assertEqual(status, 409, body)
        self.assertEqual(payload["api_version"], 1)
        self.assertEqual(payload["error"]["code"], "conflict")
        self.assertNotIn("schema 99", body)

    def test_post_409_and_both_post_catches_keep_a_fixed_body(self):
        tmp = __import__("tempfile").TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = str(Path(tmp.name) / "t.db")
        connect(db).close()
        self._schema99(db)
        base, token = self._serve(db)
        status, body = self._ask(base, "/api/demo", token, "POST", {})
        self.assertEqual(status, 409, body)
        self.assertEqual(json.loads(body)["error"], "The database schema is newer than this Lantern.")
        self.assertNotIn("schema 99", body)
        self.assertNotIn("api_version", body)

        fresh = str(Path(tmp.name) / "fresh.db")
        connect(fresh).close()
        base, token = self._serve(fresh)
        with mock.patch.object(LanternHandler, "_read_json", side_effect=NewerSchemaError("schema 99")):
            status, body = self._ask(base, "/api/scan", token, "POST", {"subnet": "10.1.0.0/24"})
        self.assertEqual(status, 409, body)
        self.assertNotIn("schema 99", body)
        with mock.patch.object(LanternHandler, "_read_json", side_effect=CorruptScanError("raw json")):
            status, body = self._ask(base, "/api/scan", token, "POST", {"subnet": "10.1.0.0/24"})
        self.assertEqual(status, 500, body)
        self.assertEqual(json.loads(body)["error"], "The saved scan could not be read.")
        self.assertNotIn("raw json", body)

    def test_v1_corrupt_tags_keep_the_envelope(self):
        tmp = __import__("tempfile").TemporaryDirectory()
        self.addCleanup(tmp.cleanup)
        db = str(Path(tmp.name) / "t.db")
        conn = connect(db)
        save_scan(conn, "10.1.0.0/24", [_device()])
        conn.execute(
            "INSERT INTO assets (asset_key, key_kind, owner, location, tags, criticality, notes, updated_at)"
            " VALUES ('mac:aa:bb:cc:dd:ee:05', 'mac', NULL, NULL, ?, NULL, NULL, 't')",
            ("[1]",),
        )
        conn.commit()
        conn.close()
        base, token = self._serve(db)
        status, body = self._ask(base, "/api/v1/devices", token)
        payload = json.loads(body)
        self.assertEqual(status, 500, body)
        self.assertEqual(payload["api_version"], 1)
        self.assertEqual(payload["error"]["code"], "server_error")
        self.assertNotIn("[1]", body)


class BlobUrlTests(unittest.TestCase):
    def test_every_object_url_is_revoked(self):
        text = (Path(__file__).resolve().parent.parent / "lantern" / "web" / "app.js").read_text(encoding="utf-8")
        self.assertEqual(text.count("createObjectURL"), text.count("revokeObjectURL"))
        self.assertIn("revokeObjectURL", text)

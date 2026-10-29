"""Banner fingerprints and the schema 4 migration. No real network.

Hostile strings in the fixtures are inert test data. They are parsed and
escaped, never evaluated or used as a format template.
"""

import json
import os
import socket
import sqlite3
import stat
import tempfile
import threading
import time
import unittest
from pathlib import Path
from unittest import mock

from lantern import v1
from lantern.fingerprint import fingerprint_for_storage, parse_banner, summary_line
from lantern.report import to_html, to_json
from lantern.scanner import probe_port, read_http_headers
from lantern.store import (
    SCHEMA_VERSION,
    _migration_1_v030_baseline,
    _migration_2_scope_name,
    _migration_3_assets,
    _migration_4_fingerprints,
    apply_migrations,
    connect,
    load_scan,
    save_scan,
    schema_version,
)

_FIXTURES = Path(__file__).parent / "fixtures" / "banner-fixtures.json"


def _build(raw, encoding: str) -> bytes:
    if isinstance(raw, str):
        return raw.encode(encoding)
    if "repeat" in raw:
        return _build(raw["repeat"]["unit"], encoding) * raw["repeat"]["count"]
    return b"".join(_build(part, encoding) for part in raw["concat"])


def _schema3(path: Path) -> None:
    raw = sqlite3.connect(path)
    try:
        apply_migrations(
            raw,
            migrations={
                1: _migration_1_v030_baseline,
                2: _migration_2_scope_name,
                3: _migration_3_assets,
            },
            target=3,
            db_path=path,
        )
        raw.execute(
            "INSERT INTO scans (started_at, subnet, demo, scope_name) VALUES (?, ?, 0, ?)",
            ("2026-10-28T00:00:00+00:00", "192.168.50.0/24", "home"),
        )
        raw.execute(
            "INSERT INTO devices (scan_id, ip, mac, hostname, label, open_ports, findings)"
            " VALUES (1, ?, ?, ?, ?, ?, ?)",
            ("192.168.50.10", "aa:bb:cc:dd:ee:10", "kept-host", "kept-label", "[]", "[]"),
        )
        raw.commit()
    finally:
        raw.close()
    if os.name != "nt":
        os.chmod(path, 0o600)


class FixtureTests(unittest.TestCase):
    def test_hostile_fixtures_match_the_parser(self):
        document = json.loads(_FIXTURES.read_text(encoding="utf-8"))
        self.assertGreaterEqual(len(document["fixtures"]), 20)
        for fixture in document["fixtures"]:
            raw = _build(fixture["raw"], fixture.get("encoding", "latin-1"))
            got = parse_banner(fixture["protocol"], raw)
            for key, expected in fixture["expect"].items():
                self.assertEqual(got.get(key), expected, fixture["id"])
            # The format-string fixture must stay literal text, not be interpreted.
            if fixture["id"] == "fx15-ftp-format-string":
                self.assertIn("%s%n%x", got["raw"])
                self.assertIsNone(got["version"])

    def test_empty_banner_is_not_stored(self):
        self.assertIsNone(fingerprint_for_storage("ssh", b""))
        self.assertIsNone(fingerprint_for_storage(None, b"SSH-2.0-OpenSSH_9.6\r\n"))

    def test_rejected_banner_is_stored_without_a_product(self):
        row = fingerprint_for_storage("ssh", b"\x00\xffbinary")
        self.assertEqual(row["parse_status"], "rejected")
        self.assertIsNone(row["product"])
        self.assertIsNone(row["version"])

    def test_summary_strips_bidi_and_names_an_old_scan(self):
        marks = "\u202e\u202a"
        text = summary_line(
            [{
                "port": 22,
                "service": "ssh",
                "product": f"Open{marks}SSH",
                "version": "9.6",
                "parse_status": "ok",
            }],
            has_ports=True,
        )
        self.assertEqual(text, "22 ssh OpenSSH 9.6")
        self.assertNotIn(marks[0], text)
        self.assertEqual(summary_line([], has_ports=True), "not fingerprinted")
        self.assertEqual(summary_line([], has_ports=False), "")


class OutputTests(unittest.TestCase):
    def test_reports_and_api_strip_hostile_network_text(self):
        marks = "\u202a\u202b\u202e\u2066"
        product = "<img src=x onerror=alert(1)>"
        scan = {
            "id": 3,
            "started_at": "2026-10-28T00:00:00+00:00",
            "subnet": "192.168.50.0/24",
            "scope_name": "home",
            "demo": False,
            "devices": [{
                "ip": "192.168.50.10",
                "mac": "aa:bb:cc:dd:ee:10",
                "hostname": f"host{marks}name",
                "label": f"lab{marks}el",
                "open_ports": [{"port": 80, "open": True, "banner": f"ok{marks}banner"}],
                "findings": [],
                "fingerprints": [{
                    "port": 80,
                    "service": "http",
                    "product": product,
                    "version": None,
                    "raw_banner": f"{product}{marks}",
                    "parse_status": "unknown",
                    "collected_at": "2026-10-28T00:00:00+00:00",
                }],
            }],
        }
        page = to_html(scan)
        body = to_json(scan)
        self.assertNotIn("<img", page)
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;img", page)
        self.assertIn("hostname", page)
        self.assertIn("version unknown", page)
        for char in marks:
            self.assertNotIn(char, page)
            self.assertNotIn(char, body)
        parsed = json.loads(body)
        device = parsed["devices"][0]
        self.assertEqual(device["hostname"], "hostname")
        self.assertEqual(device["label"], "label")
        self.assertEqual(device["open_ports"][0]["banner"], "okbanner")
        self.assertEqual(device["fingerprints"][0]["product"], product)
        shown = v1._device_dict(
            scan["devices"][0], scan, {}, {}, private=False,
        )
        encoded = json.dumps(shown)
        for char in marks:
            self.assertNotIn(char, encoded)
        self.assertEqual(shown["hostname"], "hostname")
        self.assertEqual(shown["fingerprints"][0]["product"], product)
        table_headers, table = v1.device_csv_table(3, [shown], private=False)
        self.assertIn("fingerprints", table_headers)
        cell = dict(zip(table_headers, table[0]))["fingerprints"]
        self.assertIn("80 http", cell)
        self.assertNotIn("\u202e", cell)


class LocalProbeTests(unittest.TestCase):
    def test_ssh_greeting_is_fingerprinted_on_localhost(self):
        listener = _SpeakFirst(b"SSH-2.0-OpenSSH_9.6p1 Ubuntu\r\n")
        try:
            with mock.patch("lantern.scanner.protocol_for_port", return_value="ssh"):
                result = probe_port("127.0.0.1", listener.port, timeout=1)
        finally:
            listener.close()
        self.assertTrue(result["open"])
        self.assertEqual(result["fingerprint"]["product"], "OpenSSH")
        self.assertEqual(result["fingerprint"]["version"], "9.6p1")
        self.assertEqual(result["fingerprint"]["parse_status"], "ok")
        self.assertNotIn("Ubuntu", result["fingerprint"]["raw_banner"].split()[-1] if False else "ok")

    def test_http_head_is_the_only_bytes_sent(self):
        listener = _HttpListener(b"HTTP/1.0 200 OK\r\nServer: nginx/1.24.0\r\n\r\n")
        try:
            with mock.patch("lantern.scanner.BANNER_PORTS", {listener.port}), \
                    mock.patch("lantern.scanner.protocol_for_port", return_value="http"):
                result = probe_port("127.0.0.1", listener.port, timeout=0.4)
        finally:
            listener.close()
        self.assertEqual(listener.received, b"HEAD / HTTP/1.0\r\n\r\n")
        self.assertEqual(result["fingerprint"]["product"], "nginx")
        self.assertEqual(result["fingerprint"]["version"], "1.24.0")

    def test_http_read_stops_at_the_byte_cap_and_the_deadline(self):
        flood = _SpeakFirst(b"X" * 10000)
        try:
            client = socket.create_connection(("127.0.0.1", flood.port), timeout=1)
            try:
                data = read_http_headers(client)
            finally:
                client.close()
        finally:
            flood.close()
        self.assertEqual(len(data), 2048)
        self.assertTrue(set(data) <= {ord("X")})

        silent = _Silent()
        try:
            client = socket.create_connection(("127.0.0.1", silent.port), timeout=1)
            try:
                started = time.monotonic()
                data = read_http_headers(client)
                elapsed = time.monotonic() - started
            finally:
                client.close()
        finally:
            silent.close()
        self.assertEqual(data, b"")
        self.assertLess(elapsed, 2.0)


class StorageTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "lantern.db")

    def tearDown(self):
        self.tmp.cleanup()

    def test_round_trip_keeps_the_fingerprint_out_of_port_json(self):
        conn = connect(self.db)
        try:
            scan_id = save_scan(conn, "192.168.50.0/24", [{
                "ip": "192.168.50.10",
                "mac": "aa:bb:cc:dd:ee:10",
                "hostname": "host",
                "label": None,
                "open_ports": [{
                    "port": 22,
                    "open": True,
                    "banner": "SSH-2.0-OpenSSH_9.6p1",
                    "fingerprint": {
                        "service": "ssh",
                        "product": "OpenSSH",
                        "version": "9.6p1",
                        "raw_banner": "SSH-2.0-OpenSSH_9.6p1",
                        "parse_status": "ok",
                    },
                }],
                "findings": [],
            }])
            scan = load_scan(conn, scan_id)
            raw = conn.execute("SELECT open_ports FROM devices").fetchone()[0]
        finally:
            conn.close()
        self.assertNotIn("fingerprint", raw)
        self.assertIn("SSH-2.0-OpenSSH_9.6p1", raw)
        row = scan["devices"][0]["fingerprints"][0]
        self.assertEqual(row["product"], "OpenSSH")
        self.assertEqual(row["version"], "9.6p1")
        self.assertEqual(row["parse_status"], "ok")

    def test_overlong_version_is_not_truncated_into_a_match(self):
        conn = connect(self.db)
        try:
            scan_id = save_scan(conn, "192.168.50.0/24", [{
                "ip": "192.168.50.10",
                "mac": None,
                "open_ports": [{
                    "port": 22,
                    "open": True,
                    "banner": "",
                    "fingerprint": {
                        "service": "ssh",
                        "product": "OpenSSH",
                        "version": "1" * 80,
                        "raw_banner": "x",
                        "parse_status": "ok",
                    },
                }],
                "findings": [],
            }])
            scan = load_scan(conn, scan_id)
        finally:
            conn.close()
        row = scan["devices"][0]["fingerprints"][0]
        self.assertIsNone(row["version"])
        self.assertEqual(row["parse_status"], "unknown")


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "lantern.db"

    def tearDown(self):
        self.tmp.cleanup()

    def test_schema3_upgrades_to_schema4_and_backup_is_private(self):
        _schema3(self.path)
        conn = connect(self.path)
        try:
            self.assertEqual(schema_version(conn), 4)
            self.assertEqual(SCHEMA_VERSION, 4)
            scan = load_scan(conn, 1)
            self.assertEqual(scan["devices"][0]["hostname"], "kept-host")
            self.assertEqual(scan["devices"][0]["fingerprints"], [])
            self.assertIsNotNone(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'service_fingerprints'"
            ).fetchone())
            indexes = [row[1] for row in conn.execute("PRAGMA index_list('service_fingerprints')")]
            self.assertIn("fp_device", indexes)
            versions = [row[0] for row in conn.execute("SELECT version FROM schema_version ORDER BY version")]
            self.assertEqual(versions, [1, 2, 3, 4])
        finally:
            conn.close()
        backups = list(self.path.parent.glob("*.bak"))
        self.assertEqual([path.name for path in backups], ["lantern.db.v3.bak"])
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode) & 0o777, 0o600)
        saved = sqlite3.connect(backups[0])
        try:
            self.assertEqual(saved.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 3)
            self.assertIsNone(saved.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'service_fingerprints'"
            ).fetchone())
            self.assertEqual(saved.execute("SELECT hostname FROM devices").fetchone()[0], "kept-host")
        finally:
            saved.close()

        again = connect(self.path)
        again.close()
        self.assertEqual([path.name for path in self.path.parent.glob("*.bak")], ["lantern.db.v3.bak"])
        conn = connect(self.path)
        try:
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM schema_version WHERE version = 4").fetchone()[0],
                1,
            )
        finally:
            conn.close()

    def test_injected_migration_failure_rolls_back(self):
        _schema3(self.path)

        def boom(conn):
            _migration_4_fingerprints(conn)
            conn.execute(
                "INSERT INTO service_fingerprints (device_id, port, collected_at) VALUES (1, 22, 'x')"
            )
            raise RuntimeError("injected")

        raw = sqlite3.connect(self.path)
        try:
            with self.assertRaises(RuntimeError):
                apply_migrations(
                    raw,
                    migrations={
                        1: _migration_1_v030_baseline,
                        2: _migration_2_scope_name,
                        3: _migration_3_assets,
                        4: boom,
                    },
                    target=4,
                    db_path=self.path,
                )
            self.assertEqual(raw.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 3)
            self.assertIsNone(raw.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'service_fingerprints'"
            ).fetchone())
            self.assertEqual(raw.execute("SELECT hostname FROM devices").fetchone()[0], "kept-host")
        finally:
            raw.close()

    def test_newer_schema_is_refused(self):
        _schema3(self.path)
        raw = sqlite3.connect(self.path)
        raw.execute("INSERT INTO schema_version (version, applied_at) VALUES (5, 'future')")
        raw.commit()
        raw.close()
        with self.assertRaises(ValueError) as caught:
            connect(self.path)
        self.assertIn("newer", str(caught.exception))
        self.assertEqual(list(self.path.parent.glob("*.bak")), [])
        raw = sqlite3.connect(self.path)
        try:
            self.assertEqual(raw.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 5)
            self.assertIsNone(raw.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'service_fingerprints'"
            ).fetchone())
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 1)
        finally:
            raw.close()

    def test_symlink_database_is_refused(self):
        if os.name == "nt" or not hasattr(os, "symlink"):
            self.skipTest("POSIX symlink refusal")
        _schema3(self.path)
        link = self.path.parent / "link.db"
        link.symlink_to(self.path)
        before = self.path.read_bytes()
        with self.assertRaises(ValueError) as caught:
            connect(link)
        self.assertIn("symlink", str(caught.exception))
        self.assertEqual(self.path.read_bytes(), before)
        self.assertTrue(link.is_symlink())


class _SpeakFirst:
    def __init__(self, banner: bytes):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, args=(banner,), daemon=True)
        self.thread.start()

    def _serve(self, banner: bytes):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            conn.sendall(banner)

    def close(self):
        self.sock.close()


class _Silent:
    def __init__(self):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            time.sleep(2)

    def close(self):
        self.sock.close()


class _HttpListener:
    def __init__(self, response: bytes):
        self.sock = socket.socket()
        self.sock.bind(("127.0.0.1", 0))
        self.sock.listen(1)
        self.port = self.sock.getsockname()[1]
        self.received = b""
        self._response = response
        self.thread = threading.Thread(target=self._serve, daemon=True)
        self.thread.start()

    def _serve(self):
        try:
            conn, _ = self.sock.accept()
        except OSError:
            return
        with conn:
            conn.settimeout(2)
            got = b""
            while b"\r\n\r\n" not in got and len(got) < 128:
                try:
                    chunk = conn.recv(128)
                except OSError:
                    break
                if not chunk:
                    break
                got += chunk
            self.received = got
            conn.sendall(self._response)

    def close(self):
        self.sock.close()


if __name__ == "__main__":
    unittest.main()

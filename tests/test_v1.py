"""Export files and the read-only /api/v1. Localhost and fake rows only."""

import csv
import io
import json
import re
import os
import stat
import tempfile
import threading
import unittest
import urllib.error
import urllib.request
from pathlib import Path
from unittest import mock

from lantern import v1
from lantern.store import connect, save_scan, set_trusted
from lantern.webapp import make_server


def _device(ip, mac=None, hostname=None, findings=None, ports=None):
    return {
        "ip": ip,
        "mac": mac,
        "hostname": hostname,
        "label": None,
        "open_ports": ports or [],
        "findings": findings or [],
    }


class HeaderTests(unittest.TestCase):
    def test_header_values_reject_line_breaks(self):
        with self.assertRaises(v1.V1Error) as caught:
            v1.header_value("attachment\r\nX-Evil: 1")
        self.assertEqual(caught.exception.code, "server_error")
        self.assertEqual(v1.export_filename("devices", 4, "json"),
                         'attachment; filename="lantern-devices-4.json"')


class CsvTests(unittest.TestCase):
    def test_formula_cells_are_quoted_and_prefixed(self):
        headers = ["hostname", "banner", "title"]
        triggers = [
            "=1+1",
            "  =1",
            '"=1',
            "+1",
            "-1",
            "@sum",
            "\t=1",
            "\r=1",
            "\n=1",
            "|pipe",
            "\uff1d1",
            "\uff0b1",
            "\uff0d1",
            "\uff201",
            "cmd|calc",
            "DDE(cmd)",
            " =1+1|cmd",
        ]
        rows = []
        for value in triggers:
            rows.append([value, "a=b", "keep\x00=1"])
        raw = v1.csv_bytes(headers, rows)
        self.assertFalse(raw.startswith(b"\xef\xbb\xbf"))
        parsed = list(csv.reader(io.StringIO(raw.decode("utf-8"), newline="")))
        self.assertEqual(parsed[0], headers)
        for index, value in enumerate(triggers, start=1):
            hostname, banner, title = parsed[index]
            self.assertTrue(hostname.startswith("'"), value)
            self.assertEqual(banner, "a=b")
            self.assertEqual(title, "keep=1")
            self.assertNotIn("\x00", title)
        text = raw.decode("utf-8")
        for line in text.split("\r\n"):
            if line:
                self.assertTrue(line.startswith('"'), line)

    def test_format_and_unicode_space_do_not_hide_a_formula(self):
        hidden = (
            "\u00a0",  # no-break space
            "\u3000",  # ideographic space
            "\v",
            "\f",
            "\u2028",  # line separator
            "\u200b",  # zero-width space
            "\ufeff",  # BOM, format
            "\u2060",  # word joiner
            "\u202e",  # right-to-left override
            "\u202a",  # left-to-right embedding
            " \u00a0\u200b",
        )
        for prefix in hidden:
            for trigger in ("=", "+", "-", "@", "\t", "\r"):
                cell = v1.defuse_cell(f"{prefix}{trigger}1")
                self.assertTrue(cell.startswith("'"), repr(prefix + trigger))
        self.assertTrue(v1.defuse_cell("\t").startswith("'"))
        self.assertTrue(v1.defuse_cell("\r").startswith("'"))
        self.assertEqual(v1.defuse_cell("a=b"), "a=b")
        self.assertEqual(v1.defuse_cell("\u00a0safe"), "\u00a0safe")


class PathTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def test_refuses_unsafe_destinations_and_writes_mode_0600(self):
        missing = self.root / "missing" / "out.json"
        with self.assertRaises(ValueError):
            v1.write_export_file(str(missing), b"{}", force=False)
        self.assertFalse((self.root / "missing").exists())

        dest = self.root / "out.json"
        written = v1.write_export_file(str(dest), b"{}", force=False)
        self.assertEqual(Path(written), dest)
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode) & 0o777, 0o600)
        with self.assertRaises(ValueError):
            v1.write_export_file(str(dest), b"new", force=False)

        if os.name != "nt" and hasattr(os, "symlink"):
            link = self.root / "link.json"
            link.symlink_to(dest)
            with self.assertRaises(ValueError):
                v1.write_export_file(str(link), b"nope", force=True)
            dangling = self.root / "dangling.json"
            dangling.symlink_to(self.root / "no-such-file")
            with self.assertRaises(ValueError):
                v1.write_export_file(str(dangling), b"nope", force=True)
            linked_dir = self.root / "linked"
            linked_dir.symlink_to(self.root, target_is_directory=True)
            with self.assertRaises(ValueError):
                v1.write_export_file(str(linked_dir / "x.json"), b"{}", force=False)
            other = self.root / "hard.json"
            os.link(dest, other)
            with self.assertRaises(ValueError):
                v1.write_export_file(str(other), b"replaced", force=True)
            self.assertEqual(dest.read_bytes(), b"{}")

        with mock.patch("lantern.v1.os.replace", side_effect=OSError("stopped")):
            with self.assertRaises(ValueError):
                v1.write_export_file(str(dest), b"next", force=True)
        self.assertEqual(dest.read_bytes(), b"{}")
        self.assertEqual(list(self.root.glob(".lantern-export-*")), [])

    def test_a_symlink_planted_after_the_check_is_not_written_through(self):
        if os.name == "nt" or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("symlink open flags")
        secret = self.root / "secret.txt"
        secret.write_text("keep", encoding="utf-8")
        dest = self.root / "late.json"
        real = os.lstat

        def lstat(path, *args, **kwargs):
            if Path(path) == dest and not dest.is_symlink():
                dest.symlink_to(secret)
                raise FileNotFoundError(path)
            return real(path, *args, **kwargs)

        with mock.patch("lantern.v1.os.lstat", lstat):
            with self.assertRaises(ValueError):
                v1.write_export_file(str(dest), b"pwned", force=False)
        self.assertEqual(secret.read_text(encoding="utf-8"), "keep")


class ApiTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = Path(self.tmp.name) / "test.db"
        self.server = make_server(self.db, port=0)
        self.port = self.server.server_address[1]
        self.base = f"http://127.0.0.1:{self.port}"
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)
        self.thread.start()
        status, body, _ = self._request("/")
        match = re.search(r'<meta name="lantern-token" content="([^"]+)"', body)
        self.assertIsNotNone(match, body)
        self.token = match.group(1)

    def tearDown(self):
        self.server.shutdown()
        self.server.server_close()
        self.tmp.cleanup()

    def _request(self, path, method="GET", token=None, host=None, base=None):
        headers = {}
        if host:
            headers["Host"] = host
        if token:
            headers["X-Lantern-Token"] = token
        req = urllib.request.Request((base or self.base) + path, method=method, headers=headers)
        try:
            with urllib.request.urlopen(req, timeout=10) as resp:
                return resp.status, resp.read().decode(), resp.headers
        except urllib.error.HTTPError as exc:
            return exc.code, exc.read().decode(), exc.headers

    def _seed(self):
        conn = connect(self.db)
        try:
            first = save_scan(
                conn,
                "192.168.50.0/24",
                [
                    _device(
                        "192.168.50.10",
                        "aa:bb:cc:dd:ee:10",
                        hostname="=cmd",
                        ports=[{"port": 80, "banner": "ok\x00banner"}],
                        findings=[{
                            "port": 23, "service": "telnet", "severity": "high",
                            "title": "old", "fix": "close",
                        }],
                    ),
                ],
                scope_name="home",
            )
            second = save_scan(
                conn,
                "192.168.50.0/24",
                [
                    _device("192.168.50.2", None, hostname="a=b"),
                    _device(
                        "192.168.50.10",
                        "aa:bb:cc:dd:ee:10",
                        hostname="host",
                        ports=[{"port": 80, "banner": "ok"}],
                        findings=[{
                            "port": 80, "service": "http", "severity": "info",
                            "title": "web", "fix": "none",
                        }, {
                            "port": 23, "service": "telnet", "severity": "critical",
                            "title": "tel", "fix": "close",
                        }],
                    ),
                ],
                scope_name="home",
            )
            from lantern.assets import set_asset
            set_asset(
                conn, "mac:aa:bb:cc:dd:ee:10", "mac",
                owner="A" * 80, location="Rack", tags=["web"], criticality="high", notes="secret note",
            )
            set_trusted(conn, "aa:bb:cc:dd:ee:10", "Named", True)
        finally:
            conn.close()
        return first, second

    def test_token_is_required_in_every_mode_and_legacy_routes_stay(self):
        routes = [
            "/api/v1/status",
            "/api/v1/scopes",
            "/api/v1/devices",
            "/api/v1/scans",
            "/api/v1/scans/1",
            "/api/v1/diffs",
            "/api/v1/findings",
            "/api/v1/export?what=history&format=json",
        ]
        self._seed()
        for path in routes:
            status, body, headers = self._request(path)
            self.assertEqual(status, 403, path)
            self.assertEqual(json.loads(body)["error"]["code"], "forbidden")
            self.assertFalse(any(name.lower().startswith("access-control-") for name in headers))
            status, body, _ = self._request(path, token=self.token)
            self.assertEqual(status, 200, (path, body[:200]))
            self.assertEqual(json.loads(body)["api_version"], 1)
        status, body, _ = self._request("/api/v1x", token=self.token)
        self.assertEqual(status, 404, body)
        self.assertNotIn("api_version", body)
        status, body, _ = self._request("/api/status")
        self.assertEqual(status, 200, body)
        self.assertNotIn("api_version", json.loads(body))
        status, body, headers = self._request("/api/v1/status", method="POST", token=self.token)
        self.assertEqual(status, 405, body)
        self.assertEqual(json.loads(body)["error"]["code"], "method_not_allowed")
        self.assertFalse(any(name.lower().startswith("access-control-") for name in headers))
        status, body, headers = self._request("/api/v1/status", method="OPTIONS")
        self.assertEqual(status, 403, body)
        self.assertFalse(any(name.lower().startswith("access-control-") for name in headers))
        for method in ("TRACE", "CONNECT"):
            status, body, _ = self._request("/api/v1/status", method=method, token=self.token)
            self.assertEqual(status, 405, body)
            self.assertNotIn("<html", body.lower())
            self.assertEqual(json.loads(body)["error"]["code"], "method_not_allowed")
            self.assertEqual(json.loads(body)["error"]["message"], v1.MESSAGES["method_not_allowed"])

    def test_documents_sort_redact_and_round_trip(self):
        _first, second = self._seed()
        status, body, _ = self._request("/api/v1/status", token=self.token)
        self.assertEqual(json.loads(body)["role"], "admin")
        status, body, _ = self._request("/api/v1/devices?scan_id=%s" % second, token=self.token)
        data = json.loads(body)
        self.assertEqual([item["ip"] for item in data["items"]], ["192.168.50.2", "192.168.50.10"])
        macless = data["items"][0]
        self.assertEqual(macless["key_type"], "ip")
        self.assertEqual(macless["tags"], [])
        self.assertTrue(macless["first_seen"].endswith("Z"))
        named = data["items"][1]
        self.assertEqual(named["key"], "aa:bb:cc:dd:ee:10")
        self.assertLess(named["first_seen"], named["last_seen"])
        self.assertEqual(named["owner"], "A" * 80)
        self.assertTrue(named["trusted"])
        self.assertEqual(named["label"], "Named")
        status, body, headers = self._request(
            "/api/v1/export?what=devices&format=json&scan_id=%s&filename=evil" % second,
            token=self.token,
        )
        exported = json.loads(body)
        self.assertNotIn("owner", exported["items"][1])
        self.assertNotIn("notes", exported["items"][1])
        self.assertNotIn("location", exported["items"][1])
        disposition = headers["Content-Disposition"]
        self.assertIn(f'filename="lantern-devices-{second}.json"', disposition)
        self.assertNotIn("evil", disposition)
        self.assertIn("sandbox", headers["Content-Security-Policy"])
        status, body, _ = self._request(
            "/api/v1/export?what=devices&format=json&scan_id=%s&include=private" % second,
            token=self.token,
        )
        self.assertEqual(json.loads(body)["items"][1]["notes"], "secret note")
        status, body, _ = self._request(
            "/api/v1/findings?scan_id=%s" % second, token=self.token,
        )
        findings = json.loads(body)["items"]
        self.assertEqual([item["severity"] for item in findings], ["critical", "info"])
        status, body, _ = self._request(f"/api/v1/diffs?scan_id={second}", token=self.token)
        diff = json.loads(body)
        added = [item for item in diff["added"] if item["ip"] == "192.168.50.2"]
        self.assertEqual(len(added), 1)
        self.assertIn("owner", added[0])
        self.assertIn("location", added[0])
        self.assertIn("notes", added[0])
        status, body, _ = self._request("/api/v1/devices?limit=1234567890", token=self.token)
        self.assertEqual(status, 400, body)
        self.assertNotIn("1234567890", json.loads(body)["error"]["message"])
        for fmt in ("csv", "json"):
            status, body, _ = self._request(
                f"/api/v1/export?what=findings&format={fmt}&scan_id={second}",
                token=self.token,
            )
            self.assertEqual(status, 200, body[:200])
            if fmt == "json":
                item = json.loads(body)["items"][0]
                self.assertEqual(item["scan_id"], second)
                self.assertIn("title", item)
            else:
                parsed = list(csv.reader(io.StringIO(body, newline="")))
                self.assertEqual(parsed[0][0], "scan_id")
                self.assertEqual(len(parsed[1]), len(parsed[0]))
                self.assertEqual(dict(zip(parsed[0], parsed[1]))["scan_id"], str(second))

    def test_findings_csv_export_defuses_titles_and_fixes(self):
        conn = connect(self.db)
        try:
            scan_id = save_scan(
                conn,
                "192.168.50.0/24",
                [_device(
                    "192.168.50.15",
                    "aa:bb:cc:dd:ee:15",
                    findings=[{
                        "port": 445,
                        "service": "smb",
                        "severity": "high",
                        "title": "=cmd|calc",
                        "fix": "\u200b-2+2",
                    }],
                )],
            )
        finally:
            conn.close()
        status, body, _ = self._request(
            f"/api/v1/export?what=findings&format=csv&scan_id={scan_id}",
            token=self.token,
        )
        self.assertEqual(status, 200, body[:300])
        parsed = list(csv.reader(io.StringIO(body, newline="")))
        row = dict(zip(parsed[0], parsed[1]))
        self.assertEqual(row["scan_id"], str(scan_id))
        self.assertEqual(row["title"], "'=cmd|calc")
        self.assertTrue(row["fix"].startswith("'"))
        self.assertIn("-2+2", row["fix"])

    def test_errors_are_fixed_and_exports_are_limited(self):
        scan_id = self._seed()[1]
        with mock.patch("lantern.v1.status_document", side_effect=ValueError("secret-marker-path")):
            status, body, _ = self._request("/api/v1/status", token=self.token)
        self.assertEqual(status, 500, body)
        self.assertNotIn("secret-marker-path", body)
        self.assertEqual(json.loads(body)["error"]["message"], v1.MESSAGES["server_error"])
        self.assertEqual(v1.MAX_V1_ROWS, 100_000)
        self.assertEqual(v1.MAX_V1_RESPONSE_BYTES, 32 * 1024 * 1024)
        with mock.patch("lantern.v1._device_dict", side_effect=AssertionError("built")):
            with mock.patch.object(v1, "MAX_V1_ROWS", 0):
                status, body, _ = self._request(
                    f"/api/v1/devices?scan_id={scan_id}", token=self.token,
                )
        self.assertEqual(status, 413, body)
        self.assertEqual(json.loads(body)["error"]["code"], "too_large")
        with mock.patch.object(v1, "MAX_V1_RESPONSE_BYTES", 20):
            status, body, _ = self._request(
                f"/api/v1/devices?scan_id={scan_id}", token=self.token,
            )
        self.assertEqual(status, 413, body)
        with mock.patch("lantern.v1._load_trusted_scan", side_effect=AssertionError("built")):
            with mock.patch.object(v1, "MAX_V1_ROWS", 0):
                status, body, _ = self._request(
                    f"/api/v1/diffs?scan_id={scan_id}", token=self.token,
                )
        self.assertEqual(status, 413, body)
        self.assertEqual(json.loads(body)["error"]["code"], "too_large")
        started = threading.Event()
        release = threading.Event()

        def hold():
            def build():
                started.set()
                release.wait(3)
                return b"{}"
            try:
                v1.export_locked(build)
            except v1.V1Error:
                pass

        worker = threading.Thread(target=hold)
        worker.start()
        self.assertTrue(started.wait(2))
        status, body, _ = self._request(
            "/api/v1/export?what=history&format=json", token=self.token,
        )
        release.set()
        worker.join(timeout=3)
        self.assertEqual(status, 429, body)
        self.assertEqual(json.loads(body)["error"]["code"], "busy")

    def test_strict_and_lan_modes_still_require_the_token(self):
        token = "strict-token-value-0123456789abcdef"
        strict = make_server(self.db, port=0, strict_auth=True, api_token=token)
        lan = make_server(
            self.db, host="192.168.1.50", listen_host="127.0.0.1", port=0,
            lan_bound=True, api_token=token,
        )
        threads = [
            threading.Thread(target=strict.serve_forever, daemon=True),
            threading.Thread(target=lan.serve_forever, daemon=True),
        ]
        for thread in threads:
            thread.start()
        try:
            strict_base = f"http://127.0.0.1:{strict.server_address[1]}"
            lan_base = f"http://127.0.0.1:{lan.server_address[1]}"
            host = f"192.168.1.50:{lan.server_address[1]}"
            for path in ("/api/v1/status", "/api/v1/devices"):
                status, body, _ = self._request(path, base=strict_base)
                self.assertEqual(status, 403, body)
                status, body, _ = self._request(path, token=token, base=strict_base)
                self.assertIn(status, (200, 404), body)
                status, body, _ = self._request(path, token="nope", host=host, base=lan_base)
                self.assertEqual(status, 403, body)
                status, body, headers = self._request(
                    path, token=token, host="evil.example", base=lan_base,
                )
                self.assertEqual(status, 403, body)
                self.assertEqual(json.loads(body)["error"]["code"], "forbidden")
                status, body, _ = self._request(path, token=token, host=host, base=lan_base)
                self.assertIn(status, (200, 404), body)
        finally:
            strict.shutdown()
            lan.shutdown()
            strict.server_close()
            lan.server_close()


class CliExportTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "lantern.db")
        self.root = Path(self.tmp.name).resolve()

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        import contextlib
        from lantern import cli
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--db", self.db, *args])
        return code, out.getvalue(), err.getvalue()

    def test_export_omits_private_fields_and_writes_a_private_file(self):
        conn = connect(self.db)
        try:
            save_scan(conn, "192.168.50.0/24", [_device("192.168.50.10", "aa:bb:cc:dd:ee:10")])
            from lantern.assets import set_asset
            set_asset(conn, "mac:aa:bb:cc:dd:ee:10", "mac", owner="Ada", notes="secret")
        finally:
            conn.close()
        code, out, err = self.run_cli("export", "--what", "devices", "--format", "json")
        self.assertEqual(code, 0, err)
        item = json.loads(out)["items"][0]
        self.assertNotIn("owner", item)
        self.assertNotIn("notes", item)
        code, out, err = self.run_cli(
            "export", "--what", "devices", "--format", "json", "--include-private-fields",
        )
        self.assertEqual(json.loads(out)["items"][0]["owner"], "Ada")
        dest = self.root / "devices.csv"
        code, _out, err = self.run_cli(
            "export", "--what", "devices", "--format", "csv", "--output", str(dest),
        )
        self.assertEqual(code, 0, err)
        self.assertIn(f"Wrote {dest}", err)
        text = dest.read_text(encoding="utf-8")
        self.assertNotIn("Ada", text)
        self.assertNotIn("owner", text.split("\r\n", 1)[0])
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(dest.stat().st_mode) & 0o777, 0o600)
        code, _out, err = self.run_cli("export", "--what", "history", "--tag", "web")
        self.assertEqual(code, 2, err)
        code, _out, err = self.run_cli("export", "--what", "devices", "--scan-id", "99")
        self.assertEqual(code, 1, err)
        code, out, err = self.run_cli("export", "--what", "devices", "--output", "")
        self.assertEqual(code, 2, err)
        self.assertEqual(out, "")
        self.assertIn("file path", err)
        self.assertNotIn("Traceback", err)
        deep = "nested/" * 50 + "out.json"
        code, out, err = self.run_cli("export", "--what", "devices", "--output", deep)
        self.assertEqual(code, 2, err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("nested/nested", err)
        self.assertNotIn(deep[:20], out)
        huge = "x" * 5000 + ".json"
        code, out, err = self.run_cli("export", "--what", "devices", "--output", huge)
        self.assertEqual(code, 2, err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("xxxx", err)

    def _finding_scan(self):
        conn = connect(self.db)
        try:
            scan_id = save_scan(
                conn,
                "192.168.50.0/24",
                [_device(
                    "192.168.50.10",
                    "aa:bb:cc:dd:ee:10",
                    findings=[{
                        "port": 23,
                        "service": "telnet",
                        "severity": "critical",
                        "title": "Open telnet",
                        "fix": "Close it",
                    }],
                )],
            )
        finally:
            conn.close()
        return scan_id

    def test_findings_export_csv_and_json_include_scan_id(self):
        scan_id = self._finding_scan()
        code, out, err = self.run_cli("export", "--what", "findings", "--format", "csv")
        self.assertEqual(code, 0, err)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("Traceback", out)
        parsed = list(csv.reader(io.StringIO(out, newline="")))
        self.assertEqual(
            parsed[0],
            ["scan_id", "ip", "mac", "port", "service", "severity", "title", "fix"],
        )
        self.assertEqual(len(parsed[1]), len(parsed[0]))
        row = dict(zip(parsed[0], parsed[1]))
        self.assertEqual(row["scan_id"], str(scan_id))
        self.assertEqual(row["ip"], "192.168.50.10")
        self.assertEqual(row["title"], "Open telnet")
        code, out, err = self.run_cli("export", "--what", "findings", "--format", "json")
        self.assertEqual(code, 0, err)
        self.assertNotIn("Traceback", err)
        document = json.loads(out)
        self.assertEqual(document["scan_id"], scan_id)
        self.assertEqual(document["items"][0]["scan_id"], scan_id)
        self.assertEqual(document["items"][0]["service"], "telnet")

    def test_findings_csv_defuses_titles_and_fixes(self):
        conn = connect(self.db)
        try:
            scan_id = save_scan(
                conn,
                "192.168.50.0/24",
                [_device(
                    "192.168.50.10",
                    "aa:bb:cc:dd:ee:10",
                    findings=[{
                        "port": 23,
                        "service": "telnet",
                        "severity": "critical",
                        "title": "=cmd|calc",
                        "fix": "\u00a0+SUM(1)",
                    }],
                )],
            )
        finally:
            conn.close()
        code, out, err = self.run_cli("export", "--what", "findings", "--format", "csv")
        self.assertEqual(code, 0, err)
        self.assertNotIn("Traceback", err + out)
        parsed = list(csv.reader(io.StringIO(out, newline="")))
        row = dict(zip(parsed[0], parsed[1]))
        self.assertEqual(row["scan_id"], str(scan_id))
        self.assertEqual(row["title"], "'=cmd|calc")
        self.assertTrue(row["fix"].startswith("'"), row["fix"])
        self.assertIn("+SUM(1)", row["fix"])
        self.assertEqual(len(parsed[1]), len(parsed[0]))

    def test_export_does_not_create_a_missing_database(self):
        import contextlib
        from lantern import cli

        missing = Path(self.tmp.name) / "absent" / "lantern.db"
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main([
                "--db", str(missing), "export", "--what", "history",
            ])
        self.assertEqual(code, 2)
        self.assertFalse(missing.exists())
        self.assertFalse(missing.parent.exists())
        self.assertNotIn("Traceback", err.getvalue())
        self.assertIn("does not create", err.getvalue())
        self.assertEqual(out.getvalue(), "")

    def test_export_stdout_writes_bytes(self):
        import contextlib
        import sys
        from lantern import cli

        conn = connect(self.db)
        try:
            save_scan(
                conn,
                "192.168.50.0/24",
                [_device("192.168.50.10", "aa:bb:cc:dd:ee:10", hostname="\uff21")],
            )
        finally:
            conn.close()

        class Out:
            def __init__(self):
                self.buffer = io.BytesIO()

            def write(self, text):
                raise AssertionError("export used the text stream")

        out = Out()
        err = io.StringIO()
        with contextlib.redirect_stderr(err):
            previous = sys.stdout
            sys.stdout = out
            try:
                code = cli.main([
                    "--db", self.db, "export", "--what", "devices", "--format", "csv",
                ])
            finally:
                sys.stdout = previous
        self.assertEqual(code, 0, err.getvalue())
        raw = out.buffer.getvalue()
        self.assertIn("\uff21".encode("utf-8"), raw)
        self.assertIn(b"\r\n", raw)
        self.assertNotIn(b"\r\r\n", raw)

    def test_export_errors_do_not_print_a_traceback(self):
        self._finding_scan()
        with mock.patch("lantern.v1.render_export", side_effect=RuntimeError("secret-boom")):
            code, out, err = self.run_cli("export", "--what", "findings", "--format", "csv")
        self.assertEqual(code, 2)
        self.assertNotIn("Traceback", err)
        self.assertNotIn("Traceback", out)
        self.assertNotIn("secret-boom", err)
        self.assertNotIn("secret-boom", out)

"""CLI commands in-process against a temporary database. No network."""

import contextlib
import io
import json
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lantern import cli


class CliTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "lantern.db")

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--db", self.db, *args])
        return code, out.getvalue(), err.getvalue()

    def test_empty_db_messages(self):
        for command in ("diff", "report", "history"):
            code, out, _ = self.run_cli(command)
            self.assertEqual(code, 0, command)
            self.assertIn("Run `lantern demo`", out)

    def test_demo_then_history_diff_report(self):
        code, out, _ = self.run_cli("demo")
        self.assertEqual(code, 0)
        self.assertIn("New devices: ['192.168.1.99']", out)
        self.assertTrue((Path(self.tmp.name) / "demo-report.html").is_file())

        code, out, _ = self.run_cli("history")
        self.assertEqual(code, 0)
        self.assertIn("192.168.1.0/24", out)
        self.assertEqual(out.count("yes"), 2)

        code, out, _ = self.run_cli("history", "--format", "json")
        self.assertEqual([s["id"] for s in json.loads(out)["scans"]], [2, 1])

        code, out, _ = self.run_cli("diff")
        self.assertEqual(code, 0)
        self.assertIn("New: ['192.168.1.99']", out)

        code, out, _ = self.run_cli("diff", "--format", "json")
        self.assertEqual(json.loads(out)["added"][0]["ip"], "192.168.1.99")

        code, out, _ = self.run_cli("report", "--scan-id", "1")
        self.assertEqual(code, 0)
        report = json.loads(out)
        self.assertEqual((report["id"], report["device_count"], report["diff"]), (1, 5, None))

        code, out, _ = self.run_cli("report", "--format", "html")
        self.assertEqual(code, 0)
        self.assertIn("Telnet", out)
        self.assertIn("Scan #2", out)

        code, _, err = self.run_cli("report", "--scan-id", "99")
        self.assertEqual(code, 2)
        self.assertIn("No scan with id 99", err)

    def test_report_applies_trusted_labels(self):
        self.run_cli("demo")
        from lantern.store import connect, set_trusted

        conn = connect(self.db)
        set_trusted(conn, "de:ad:be:ef:00:99", "Mystery box", True)
        conn.close()
        _, out, _ = self.run_cli("report", "--format", "html")
        self.assertIn("Mystery box", out)
        self.assertIn("(trusted)", out)

    def test_scan_demo_needs_no_subnet_or_network(self):
        with mock.patch.object(cli, "guess_subnet", return_value=None), \
                mock.patch.object(cli, "ping_host", side_effect=AssertionError("network touched")):
            code, out, _ = self.run_cli("scan", "--demo")
        self.assertEqual(code, 0)
        self.assertIn("192.168.1.0/24 (demo data)", out)
        self.assertIn("192.168.1.10", out)
        code, out, _ = self.run_cli("scan", "--demo", "--format", "json")
        self.assertEqual(json.loads(out)["diff"]["added"], [])

    def test_scan_refuses_bad_subnets_before_touching_network(self):
        with mock.patch.object(cli, "ping_host", side_effect=AssertionError("network touched")):
            for subnet in ("8.8.8.0/24", "10.0.0.0/8", "nope"):
                code, _, err = self.run_cli("scan", "--subnet", subnet)
                self.assertEqual(code, 2, subnet)
                self.assertTrue(err.startswith("lantern: "), err)
        with mock.patch.object(cli, "guess_subnet", return_value=None):
            code, _, err = self.run_cli("scan")
            self.assertEqual(code, 2)
            self.assertIn("--subnet", err)

    def test_scan_uses_arp_hosts_and_normalizes_subnet(self):
        macs = {"10.9.9.7": "aa:bb:cc:dd:ee:07", "10.8.0.1": "aa:bb:cc:dd:ee:08"}
        with mock.patch.object(cli, "arp_table", return_value=macs), \
                mock.patch.object(cli, "ping_host", side_effect=lambda ip: ip == "10.9.9.3"), \
                mock.patch.object(cli, "scan_host", return_value=[]), \
                mock.patch.object(cli, "reverse_hostname", return_value=None):
            code, out, _ = self.run_cli("scan", "--subnet", "10.9.9.200/24", "--format", "json")
        self.assertEqual(code, 0)
        scan = json.loads(out)
        self.assertEqual(scan["subnet"], "10.9.9.0/24")
        self.assertEqual([d["ip"] for d in scan["devices"]], ["10.9.9.3", "10.9.9.7"])
        self.assertEqual(scan["devices"][1]["mac"], "aa:bb:cc:dd:ee:07")

    def test_bad_db_path_and_port(self):
        # A plain file where the parent directory should be: mkdir fails.
        Path(self.tmp.name, "file.db").write_text("")
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--db", str(Path(self.tmp.name) / "file.db" / "x.db"), "demo"])
        self.assertEqual(code, 2)
        self.assertIn("Cannot open database", err.getvalue())

        code, _, err = self.run_cli("web", "--port", "70000")
        self.assertEqual(code, 2)
        self.assertIn("--port", err)

    def test_web_allow_host_flag(self):
        out = io.StringIO()
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stdout(out):
            cli.main(["web", "--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("--allow-host", out.getvalue())

        args = cli.build_parser().parse_args([
            "web", "--allow-host", "dash.example", "--allow-host", "[2001:db8::5]",
        ])
        self.assertEqual(args.allow_host, ["dash.example", "[2001:db8::5]"])

        code, _, err = self.run_cli("web", "--allow-host", "bad host")
        self.assertEqual(code, 2)
        self.assertIn("--allow-host", err)
        self.assertNotIn("Traceback", err)

    def test_web_bind_failure_is_a_clear_error(self):
        import socket

        with socket.socket() as taken:
            taken.bind(("127.0.0.1", 0))
            taken.listen(1)
            port = taken.getsockname()[1]
            code, _, err = self.run_cli("web", "--port", str(port))
        self.assertEqual(code, 2)
        self.assertIn("Cannot bind", err)

    def test_version_flag(self):
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stdout(io.StringIO()):
            cli.main(["--version"])
        self.assertEqual(ctx.exception.code, 0)

    def test_newer_database_is_a_clear_error(self):
        import sqlite3

        raw = sqlite3.connect(self.db)
        raw.execute(
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        raw.execute("INSERT INTO schema_version VALUES (99, 'future')")
        raw.execute(
            "CREATE TABLE scans (id INTEGER PRIMARY KEY, started_at TEXT, subnet TEXT, demo INTEGER)"
        )
        raw.execute("INSERT INTO scans VALUES (7, 't', '10.1.0.0/24', 0)")
        raw.commit()
        raw.close()

        code, _, err = self.run_cli("history")
        self.assertEqual(code, 2)
        self.assertIn("newer", err)
        raw = sqlite3.connect(self.db)
        try:
            self.assertEqual(raw.execute("SELECT id FROM scans").fetchone()[0], 7)
        finally:
            raw.close()

    def _write_scopes(self, text, name="lantern.toml"):
        path = Path(self.tmp.name) / name
        path.write_text(text, encoding="utf-8")
        return path

    def test_scopes_command_lists_without_creating_a_database_or_scanning(self):
        path = self._write_scopes(
            '[scopes.home]\nsubnet = "192.168.1.50/24"\ndescription = "House"\n'
            '[scopes.lab]\nsubnet = "10.2.0.0/24"\n'
        )
        code, out, err = self.run_cli("scopes", "--config", str(path))
        self.assertEqual(code, 0, err)
        self.assertIn("home", out)
        self.assertIn("192.168.1.0/24", out)
        self.assertIn("House", out)
        self.assertFalse(Path(self.db).exists())

        code, out, _ = self.run_cli("scopes", "--config", str(path), "--format", "json")
        payload = json.loads(out)
        self.assertEqual(payload["scopes"][0]["subnet"], "192.168.1.0/24")
        self.assertIsNone(payload["scopes"][1]["description"])

    def test_scan_scope_uses_config_and_does_not_probe(self):
        path = self._write_scopes('[scopes.lab]\nsubnet = "10.9.9.8/24"\ndescription = "bench"\n')
        with mock.patch.object(cli, "guess_subnet", side_effect=AssertionError("should not guess")), \
                mock.patch.object(cli, "run_scan", return_value=[]) as run_scan:
            code, out, err = self.run_cli("scan", "--config", str(path), "--format", "json")
        self.assertEqual(code, 0, err)
        scan = json.loads(out)
        self.assertEqual(scan["subnet"], "10.9.9.0/24")
        self.assertEqual(scan["devices"], [])
        self.assertEqual(run_scan.call_args.args[0], "10.9.9.0/24")
        self.assertFalse(run_scan.call_args.kwargs["demo_mode"])

    def test_scan_scope_refuses_unsafe_config_before_probing(self):
        path = self._write_scopes('[scopes.bad]\nsubnet = "8.8.8.0/24"\n')
        with mock.patch.object(cli, "run_scan", side_effect=AssertionError("probed")):
            code, _, err = self.run_cli("scan", "--config", str(path), "--scope", "bad")
        self.assertEqual(code, 2)
        self.assertIn("private", err)

    def test_named_scope_and_conflicts(self):
        path = self._write_scopes(
            '[scopes.home]\nsubnet = "192.168.4.0/24"\n'
            '[scopes.lab]\nsubnet = "10.4.0.0/24"\n'
        )
        with mock.patch.object(cli, "run_scan", return_value=[]) as run_scan:
            code, out, err = self.run_cli(
                "scan", "--config", str(path), "--scope", "lab", "--format", "json",
            )
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["subnet"], "10.4.0.0/24")
        self.assertEqual(run_scan.call_args.args[0], "10.4.0.0/24")

        with mock.patch.object(cli, "run_scan", side_effect=AssertionError("probed")):
            code, _, err = self.run_cli("scan", "--config", str(path))
            self.assertEqual(code, 2)
            self.assertIn("--scope", err)

            code, _, err = self.run_cli(
                "scan", "--config", str(path), "--scope", "lab", "--subnet", "10.4.0.0/24",
            )
            self.assertEqual(code, 2)
            self.assertIn("not both", err)

            code, _, err = self.run_cli("scan", "--demo", "--config", str(path))
            self.assertEqual(code, 2)
            self.assertIn("--demo", err)

    def test_scope_flag_reads_lantern_toml_from_the_working_directory(self):
        import os

        self._write_scopes('[scopes.lab]\nsubnet = "10.8.8.0/24"\n')
        previous = os.getcwd()
        os.chdir(self.tmp.name)
        try:
            with mock.patch.object(cli, "run_scan", return_value=[]) as run_scan:
                code, out, err = self.run_cli("scan", "--scope", "lab", "--format", "json")
        finally:
            os.chdir(previous)
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["subnet"], "10.8.8.0/24")
        self.assertEqual(run_scan.call_args.args[0], "10.8.8.0/24")


if __name__ == "__main__":
    unittest.main()

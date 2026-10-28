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


class WebBindTests(unittest.TestCase):
    """Bind policy only. No socket is opened and no scan is started."""

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

    def test_loopback_hosts(self):
        for host in ("127.0.0.1", "localhost", "LocalHost", "::1", "127.0.0.2",
                     "::ffff:127.0.0.1"):
            self.assertTrue(cli.is_loopback_host(host), host)
        for host in ("0.0.0.0", "::", "192.168.1.10", "10.0.0.1", "lan.example",
                     "", " 127.0.0.1", "127.0.0.1 ", "::ffff:192.168.1.1", "[::1]"):
            self.assertFalse(cli.is_loopback_host(host), host)

    def test_loopback_needs_no_token(self):
        def fail_mint():
            raise AssertionError("minted")

        for allow in (False, True):
            decision = cli.resolve_web_bind(
                "127.0.0.1", allow, token_param="api_token", token_factory=fail_mint,
            )
            self.assertIsNone(decision.error)
            self.assertIsNone(decision.warning)
            self.assertIsNone(decision.token)

    def test_non_loopback_without_flag_is_refused(self):
        decision = cli.resolve_web_bind("0.0.0.0", False, token_param="api_token")
        self.assertIn("refusing to bind 0.0.0.0", decision.error)
        self.assertIsNone(decision.token)
        self.assertIsNone(decision.warning)

    def test_allow_lan_without_token_support_is_refused(self):
        with mock.patch.object(cli.secrets, "token_urlsafe", side_effect=AssertionError("minted")):
            decision = cli.resolve_web_bind("192.168.1.9", True, token_param=None)
        self.assertIn("requires S1 token support", decision.error)
        self.assertIsNone(decision.token)
        self.assertNotIn("API token", decision.error)

    def test_allow_lan_with_token_support_mints_one_token(self):
        decision = cli.resolve_web_bind(
            "0.0.0.0", True, token_param="api_token", token_factory=lambda: "once-token",
        )
        self.assertIsNone(decision.error)
        self.assertEqual(decision.token, "once-token")
        self.assertEqual(decision.token_param, "api_token")
        self.assertEqual(decision.warning.count("once-token"), 1)
        self.assertIn("WARNING", decision.warning)
        self.assertIn("0.0.0.0", decision.warning)

    def test_new_api_token_is_urlsafe(self):
        token = cli.new_api_token()
        self.assertGreaterEqual(len(token), 32)
        self.assertRegex(token, r"^[A-Za-z0-9_-]+$")

    def test_token_param_detector(self):
        def plain(db_path, host="127.0.0.1", port=8068, debug=False):
            pass

        def with_api_token(db_path, host="127.0.0.1", api_token=None):
            pass

        def with_both(db_path, token=None, api_token=None):
            pass

        def kwargs_only(db_path, **kwargs):
            pass

        def positional_only(db_path, token, /):
            pass

        self.assertIsNone(cli.webapp_token_param(plain))
        self.assertEqual(cli.webapp_token_param(with_api_token), "api_token")
        self.assertEqual(cli.webapp_token_param(with_both), "api_token")
        self.assertIsNone(cli.webapp_token_param(kwargs_only))
        self.assertIsNone(cli.webapp_token_param(positional_only))
        self.assertIsNone(cli.webapp_token_param(object()))

    def test_shipped_dashboard_has_no_token_parameter(self):
        # S1 owns webapp.py. Until serve() accepts a token keyword, the CLI
        # must refuse --allow-lan rather than listen on the LAN.
        from lantern.webapp import serve
        self.assertIsNone(cli.webapp_token_param(serve))

    def test_cli_refuses_lan_bind_without_opening_db(self):
        for host in ("0.0.0.0", "::", "192.168.1.10", "10.0.0.1"):
            with mock.patch("lantern.webapp.serve", side_effect=AssertionError("serve called")):
                code, out, err = self.run_cli("web", "--host", host)
            self.assertEqual(code, 2, host)
            self.assertIn(f"refusing to bind {host}", err)
            self.assertNotIn("requires S1 token support", err)
            self.assertEqual(out, "")
            self.assertFalse(Path(self.db).exists(), host)

    def test_cli_allow_lan_refused_until_s1(self):
        with mock.patch("lantern.webapp.serve", side_effect=AssertionError("serve called")):
            code, out, err = self.run_cli("web", "--host", "0.0.0.0", "--allow-lan")
        self.assertEqual(code, 2)
        self.assertIn("requires S1 token support", err)
        self.assertNotIn("API token", err)
        self.assertEqual(out, "")
        self.assertFalse(Path(self.db).exists())

    def test_cli_loopback_does_not_warn(self):
        for host in ("127.0.0.1", "localhost", "::1"):
            with mock.patch("lantern.webapp.serve") as serve:
                code, _, err = self.run_cli("web", "--host", host, "--port", "9")
            self.assertEqual(code, 0, (host, err))
            self.assertNotIn("WARNING", err)
            self.assertEqual(serve.call_args.kwargs["host"], host)
            self.assertNotIn("api_token", serve.call_args.kwargs)
            self.assertNotIn("token", serve.call_args.kwargs)

    def test_cli_allow_lan_on_loopback_does_not_mint(self):
        with mock.patch.object(cli, "webapp_token_param", return_value="api_token"), \
                mock.patch.object(cli, "new_api_token", side_effect=AssertionError("minted")), \
                mock.patch("lantern.webapp.serve") as serve:
            code, _, err = self.run_cli("web", "--allow-lan", "--port", "9")
        self.assertEqual(code, 0)
        self.assertNotIn("WARNING", err)
        self.assertEqual(serve.call_args.kwargs["host"], "127.0.0.1")
        self.assertNotIn("api_token", serve.call_args.kwargs)

    def test_cli_passes_token_when_s1_present(self):
        with mock.patch.object(cli, "webapp_token_param", return_value="api_token"), \
                mock.patch.object(cli, "new_api_token", return_value="once-token"), \
                mock.patch("lantern.webapp.serve") as serve:
            code, out, err = self.run_cli("web", "--host", "0.0.0.0", "--allow-lan", "--port", "9")
        self.assertEqual(code, 0)
        self.assertNotIn("once-token", out)
        self.assertEqual(err.count("once-token"), 1)
        self.assertGreaterEqual(err.count("WARNING"), 4)
        self.assertEqual(serve.call_args.kwargs["host"], "0.0.0.0")
        self.assertEqual(serve.call_args.kwargs["api_token"], "once-token")

    def test_process_refuses_lan_bind_without_listening(self):
        import subprocess
        import sys

        proc = subprocess.run(
            [sys.executable, "-m", "lantern", "--db", self.db, "web",
             "--host", "0.0.0.0", "--port", "8068"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("refusing to bind", proc.stderr)
        self.assertNotIn("Lantern dashboard", proc.stdout)
        self.assertNotIn("API token", proc.stderr)
        self.assertFalse(Path(self.db).exists())

        proc = subprocess.run(
            [sys.executable, "-m", "lantern", "--db", self.db, "web",
             "--host", "0.0.0.0", "--allow-lan", "--port", "8068"],
            capture_output=True, text=True, timeout=5, check=False,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("requires S1 token support", proc.stderr)
        self.assertNotIn("Lantern dashboard", proc.stdout)
        self.assertNotIn("API token", proc.stderr)
        self.assertFalse(Path(self.db).exists())

    def test_web_help_mentions_allow_lan(self):
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stdout(io.StringIO()) as out:
            cli.main(["web", "--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("--allow-lan", out.getvalue())


if __name__ == "__main__":
    unittest.main()

"""CLI commands in-process against a temporary database. No network."""

import contextlib
import io
import json
import os
import stat
import tempfile
import threading
import time
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

    def test_demo_creates_private_data_dir_and_database(self):
        """Under umask 022 the CLI used to leave data/ at 0755 and the report at 0644.

        connect() has to create that directory at 0700 and the database at
        0600, and the demo HTML report has to be 0600, including when umask is 000.
        """
        if os.name == "nt":
            self.skipTest("POSIX permission bits are not checked on Windows")
        previous = os.umask(0o022)
        try:
            for mask in (0o022, 0o000):
                os.umask(mask)
                root = Path(self.tmp.name) / f"mask-{mask:03o}"
                root.mkdir()
                os.chmod(root, 0o755)
                db = root / "data" / "lantern.db"
                out, err = io.StringIO(), io.StringIO()
                with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
                    code = cli.main(["--db", str(db), "demo"])
                self.assertEqual(code, 0, err.getvalue())
                self.assertEqual(stat.S_IMODE(root.stat().st_mode), 0o755)
                self.assertEqual(stat.S_IMODE(db.parent.stat().st_mode), 0o700)
                self.assertEqual(stat.S_IMODE(db.stat().st_mode), 0o600)
                report = db.parent / "demo-report.html"
                self.assertEqual(stat.S_IMODE(report.stat().st_mode), 0o600)
                self.assertIn("HTML report:", out.getvalue())
                self.assertIn("192.168.1.99", report.read_text(encoding="utf-8"))
        finally:
            os.umask(previous)

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
        # A plain file where the parent directory should be: open fails.
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
        for bad in ("0.0.0.0", "[::]", "[fe80::1%eth0]", "*", "10.0.0.0/24", "0", "00", "2130706433"):
            code, _, err = self.run_cli("web", "--allow-host", bad)
            self.assertEqual(code, 2, bad)
            self.assertIn("--allow-host", err)
            self.assertNotIn("Traceback", err)
            self.assertFalse(Path(self.db).exists(), bad)

    def test_web_bind_failure_is_a_clear_error(self):
        import socket

        with socket.socket() as taken:
            taken.bind(("127.0.0.1", 0))
            taken.listen(1)
            port = taken.getsockname()[1]
            code, _, err = self.run_cli("web", "--no-strict-auth", "--port", str(port))
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

    def _no_token_env(self):
        env = os.environ.copy()
        env.pop(cli.TOKEN_ENV, None)
        env.pop(cli.TOKEN_FILE_ENV, None)
        env.pop(cli.STRICT_AUTH_ENV, None)
        return env

    def test_loopback_needs_no_token(self):
        def fail_mint():
            raise AssertionError("minted")

        for allow in (False, True):
            decision = cli.resolve_web_bind(
                "127.0.0.1", allow, token_factory=fail_mint, environ={}, tty=True,
            )
            self.assertIsNone(decision.error)
            self.assertIn("local-user token gap", decision.warning)
            self.assertIsNone(decision.token)
            self.assertFalse(decision.lan_bound)
            self.assertFalse(decision.strict_auth)
            self.assertFalse(decision.print_token)

    def test_opt_out_warning_names_the_env_and_lan_still_needs_the_token(self):
        decision = cli.resolve_web_bind(
            "127.0.0.1", False, strict_auth=False, strict_off_because="env",
        )
        self.assertIsNone(decision.error)
        self.assertIn("LANTERN_STRICT_AUTH set to an off value", decision.warning)
        self.assertIn("local-user token gap", decision.warning)

        decision = cli.resolve_web_bind(
            "192.168.1.10", True,
            allow_hosts=["192.168.1.10"],
            environ={cli.TOKEN_ENV: "b" * 32},
            tty=False,
            strict_auth=False,
            strict_off_because="env",
        )
        self.assertIsNone(decision.error, decision.error)
        self.assertIn("A LAN bind still requires the token", decision.warning)
        self.assertIn("LANTERN_STRICT_AUTH set to an off value", decision.warning)

        for raw in ("false", "no", "off"):
            source = cli.strict_off_source(False, False, {cli.STRICT_AUTH_ENV: raw})
            decision = cli.resolve_web_bind(
                "127.0.0.1", False, strict_auth=False, strict_off_because=source,
            )
            self.assertIn(f"LANTERN_STRICT_AUTH={raw}", decision.warning, raw)
            self.assertNotIn("LANTERN_STRICT_AUTH=0", decision.warning, raw)
        source = cli.strict_off_source(False, False, {cli.STRICT_AUTH_ENV: "0"})
        decision = cli.resolve_web_bind(
            "127.0.0.1", False, strict_auth=False, strict_off_because=source,
        )
        self.assertIn("LANTERN_STRICT_AUTH=0", decision.warning)
        source = cli.strict_off_source(False, True, {cli.STRICT_AUTH_ENV: "1"})
        self.assertEqual(source, "flag")

    def test_non_loopback_without_flag_is_refused(self):
        decision = cli.resolve_web_bind(
            "0.0.0.0", False, environ={cli.TOKEN_ENV: "a" * 32}, tty=True,
        )
        self.assertIn("refusing to bind 0.0.0.0", decision.error)
        self.assertIsNone(decision.token)
        self.assertIsNone(decision.warning)

    def test_allow_lan_without_a_token_is_refused(self):
        with mock.patch.object(cli.secrets, "token_urlsafe", side_effect=AssertionError("minted")):
            decision = cli.resolve_web_bind(
                "192.168.1.9", True, allow_hosts=["192.168.1.9"],
                environ={}, tty=False,
            )
        self.assertEqual(decision.token, None)
        self.assertIn("refusing to start without a valid API token", decision.error)
        self.assertIn(cli.TOKEN_FILE_ENV, decision.error)
        self.assertNotIn("API token (printed", decision.error)
        self.assertFalse(decision.print_token)

    def test_short_token_is_rejected(self):
        for raw in ("tiny", "a" * 21, "bad token value!!", "ñ" * 22):
            decision = cli.resolve_web_bind(
                "192.168.1.9", True, allow_hosts=["192.168.1.9"],
                environ={cli.TOKEN_ENV: raw}, tty=False,
            )
            self.assertIsNone(decision.token, raw)
            self.assertIn("128 bits", decision.error)
            self.assertNotIn(raw, decision.error)

    def test_allow_lan_tty_mints_one_token_and_keeps_it_out_of_the_warning(self):
        token = "c" * 43
        decision = cli.resolve_web_bind(
            "192.168.1.50", True, port=8068, environ={}, tty=True,
            token_factory=lambda: token,
        )
        self.assertIsNone(decision.error)
        self.assertEqual(decision.token, token)
        self.assertTrue(decision.lan_bound)
        self.assertTrue(decision.print_token)
        self.assertEqual(decision.warning.count(token), 0)
        self.assertIn("WARNING: listen address 192.168.1.50", decision.warning)
        self.assertIn("WARNING: allowed Host values: 192.168.1.50:8068", decision.warning)
        self.assertIn(
            "anyone with the token has full control; GET data is also protected",
            decision.warning,
        )
        self.assertNotIn("127.0.0.1", decision.warning)
        self.assertNotIn("localhost", decision.warning)
        self.assertNotIn("[::1]", decision.warning)

    def test_unspecified_bind_needs_an_allow_host_address(self):
        token = "d" * 32
        missing = cli.resolve_web_bind(
            "0.0.0.0", True, environ={cli.TOKEN_ENV: token}, tty=False, port=8068,
        )
        self.assertIn("pass --allow-host", missing.error)
        self.assertIsNone(missing.token)
        self.assertNotIn(token, missing.error)

        named = cli.resolve_web_bind(
            "0.0.0.0", True, allow_hosts=["dashboard.home"],
            environ={cli.TOKEN_ENV: token}, tty=False,
        )
        self.assertIn("pass --allow-host", named.error)

        decision = cli.resolve_web_bind(
            "0.0.0.0", True, allow_hosts=["192.168.1.50"],
            environ={cli.TOKEN_ENV: token}, tty=False, port=8068,
        )
        self.assertIsNone(decision.error)
        self.assertEqual(decision.token, token)
        self.assertFalse(decision.print_token)
        self.assertIn("WARNING: listen address 0.0.0.0", decision.warning)
        self.assertIn("WARNING: allowed Host values: 192.168.1.50:8068", decision.warning)
        self.assertNotIn("0.0.0.0:8068", decision.warning)
        self.assertNotIn(token, decision.warning)
        self.assertIn(f"loaded from {cli.TOKEN_ENV}", decision.warning)

    def test_token_file_beats_env_and_is_not_printed(self):
        file_token = "f" * 32
        env_token = "e" * 32
        path = Path(self.tmp.name) / "token"
        path.write_text(file_token + "\n", encoding="utf-8")
        if os.name != "nt":
            os.chmod(path, 0o400)
        decision = cli.resolve_web_bind(
            "192.168.1.50", True, port=8068,
            environ={
                cli.TOKEN_FILE_ENV: str(path),
                cli.TOKEN_ENV: env_token,
            },
            tty=True,
            token_factory=lambda: "generated-token-should-not-be-used",
        )
        self.assertIsNone(decision.error)
        self.assertEqual(decision.token, file_token)
        self.assertNotEqual(decision.token, env_token)
        self.assertFalse(decision.print_token)
        self.assertNotIn(file_token, decision.warning)
        self.assertNotIn(env_token, decision.warning)
        self.assertIn(cli.TOKEN_FILE_ENV, decision.warning)

    def test_new_api_token_is_urlsafe(self):
        token = cli.new_api_token()
        self.assertGreaterEqual(len(token), 32)
        self.assertGreaterEqual(len(token), 22)
        self.assertRegex(token, r"^[A-Za-z0-9_-]+$")

    def test_serve_takes_the_cli_token_directly(self):
        import inspect

        from lantern.webapp import serve

        params = inspect.signature(serve).parameters
        self.assertIn("api_token", params)
        self.assertIn("lan_bound", params)
        self.assertFalse(hasattr(cli, "webapp_token_param"))

    def test_cli_refuses_lan_bind_without_opening_db(self):
        for host in ("0.0.0.0", "::", "192.168.1.10", "10.0.0.1"):
            with mock.patch("lantern.webapp.serve", side_effect=AssertionError("serve called")):
                code, out, err = self.run_cli("web", "--host", host)
            self.assertEqual(code, 2, host)
            self.assertIn(f"refusing to bind {host}", err)
            self.assertNotIn("requires S1 token support", err)
            self.assertEqual(out, "")
            self.assertFalse(Path(self.db).exists(), host)

    def test_cli_allow_lan_without_token_exits_before_the_socket(self):
        env = self._no_token_env()
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch("lantern.webapp.serve", side_effect=AssertionError("serve called")), \
                mock.patch.object(cli.secrets, "token_urlsafe", side_effect=AssertionError("minted")):
            code, out, err = self.run_cli("web", "--host", "0.0.0.0", "--allow-lan")
        self.assertEqual(code, 2)
        self.assertIn("refusing to start without a valid API token", err)
        self.assertNotIn("API token (printed", err)
        self.assertNotIn("Lantern dashboard", out)
        self.assertEqual(out, "")
        self.assertFalse(Path(self.db).exists())

    def test_cli_loopback_without_a_terminal_exits_before_listen(self):
        env = self._no_token_env()
        env.pop(cli.STRICT_AUTH_ENV, None)
        for host in ("127.0.0.1", "localhost", "::1"):
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(cli, "_stderr_is_tty", return_value=False), \
                    mock.patch("lantern.webapp.serve", side_effect=AssertionError("serve")):
                code, out, err = self.run_cli("web", "--host", host, "--port", "9")
            self.assertEqual(code, 2, (host, err))
            self.assertIn("refusing to start without a valid API token", err)
            self.assertNotIn("#token=", err)
            self.assertNotIn("Lantern dashboard", out)
            self.assertEqual(out, "")
            self.assertFalse(Path(self.db).exists(), host)

    def test_cli_default_tty_prints_the_fragment_link(self):
        token = "k" * 43
        env = self._no_token_env()
        env.pop(cli.STRICT_AUTH_ENV, None)
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(cli, "_stderr_is_tty", return_value=True), \
                mock.patch.object(cli, "new_api_token", return_value=token), \
                mock.patch("lantern.webapp.serve") as serve:
            code, out, err = self.run_cli("web", "--port", "9")
        self.assertEqual(code, 0, err)
        self.assertNotIn(token, out)
        self.assertEqual(err.count(token), 1)
        self.assertIn(f"http://127.0.0.1:9/#token={token}", err)
        self.assertNotIn("API token (printed once", err)
        self.assertTrue(serve.call_args.kwargs["strict_auth"])
        self.assertEqual(serve.call_args.kwargs["api_token"], token)
        self.assertFalse(serve.call_args.kwargs["lan_bound"])

    def test_cli_no_strict_auth_restores_the_embedded_page_token(self):
        env = self._no_token_env()
        env.pop(cli.STRICT_AUTH_ENV, None)
        for host in ("127.0.0.1", "localhost", "::1"):
            with mock.patch.dict(os.environ, env, clear=True), \
                    mock.patch.object(cli, "new_api_token", side_effect=AssertionError("minted")), \
                    mock.patch("lantern.webapp.serve") as serve:
                code, _, err = self.run_cli(
                    "web", "--no-strict-auth", "--host", host, "--port", "9",
                )
            self.assertEqual(code, 0, (host, err))
            self.assertIn("local-user token gap", err)
            self.assertNotIn("binding beyond loopback", err)
            self.assertEqual(serve.call_args.kwargs["host"], host)
            self.assertFalse(serve.call_args.kwargs["strict_auth"])
            self.assertNotIn("api_token", serve.call_args.kwargs)

    def test_cli_allow_lan_on_loopback_does_not_mint(self):
        with mock.patch.object(cli, "new_api_token", side_effect=AssertionError("minted")), \
                mock.patch("lantern.webapp.serve") as serve:
            code, _, err = self.run_cli(
                "web", "--no-strict-auth", "--allow-lan", "--port", "9",
            )
        self.assertEqual(code, 0, err)
        self.assertNotIn("binding beyond loopback", err)
        self.assertEqual(serve.call_args.kwargs["host"], "127.0.0.1")
        self.assertNotIn("api_token", serve.call_args.kwargs)
        self.assertFalse(serve.call_args.kwargs["lan_bound"])
        self.assertFalse(serve.call_args.kwargs["strict_auth"])

    def test_cli_non_tty_passes_env_token_without_printing_it(self):
        token = "n" * 32
        env = self._no_token_env()
        env[cli.TOKEN_ENV] = token
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(cli, "_stderr_is_tty", return_value=False), \
                mock.patch.object(cli, "new_api_token", side_effect=AssertionError("minted")), \
                mock.patch("lantern.webapp.serve") as serve:
            code, out, err = self.run_cli(
                "web", "--host", "192.168.1.50", "--allow-lan", "--port", "9",
            )
        self.assertEqual(code, 0, err)
        self.assertNotIn(token, out)
        self.assertNotIn(token, err)
        self.assertNotIn("API token (printed", err)
        self.assertIn("anyone with the token has full control; GET data is also protected", err)
        self.assertIn("192.168.1.50:9", err)
        self.assertEqual(serve.call_args.kwargs["api_token"], token)
        self.assertTrue(serve.call_args.kwargs["lan_bound"])
        self.assertEqual(serve.call_args.kwargs["host"], "192.168.1.50")

    def test_cli_tty_prints_generated_token_once(self):
        token = "t" * 43
        env = self._no_token_env()
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(cli, "_stderr_is_tty", return_value=True), \
                mock.patch.object(cli, "new_api_token", return_value=token), \
                mock.patch("lantern.webapp.serve") as serve:
            code, out, err = self.run_cli(
                "web", "--host", "192.168.1.50", "--allow-lan", "--port", "9",
            )
        self.assertEqual(code, 0, err)
        self.assertNotIn(token, out)
        self.assertEqual(err.count(token), 1)
        self.assertIn(f"http://192.168.1.50:9/#token={token}", err)
        self.assertNotIn("API token (printed once", err)
        self.assertEqual(serve.call_args.kwargs["api_token"], token)
        self.assertFalse(serve.call_args.kwargs["debug"])
        self.assertTrue(serve.call_args.kwargs["strict_auth"])

    def test_strict_auth_link_uses_loopback_and_a_fragment(self):
        token = "u" * 32
        self.assertEqual(
            cli.one_time_open_link("127.0.0.1", 9, token),
            f"http://127.0.0.1:9/#token={token}",
        )
        self.assertEqual(
            cli.one_time_open_link("localhost", 8068, token),
            f"http://127.0.0.1:8068/#token={token}",
        )
        self.assertNotIn("?", cli.one_time_open_link("127.0.0.1", 9, token).split("#", 1)[0])

    def test_cli_strict_auth_on_a_tty_prints_one_fragment_link(self):
        token = "k" * 43
        env = self._no_token_env()
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(cli, "_stderr_is_tty", return_value=True), \
                mock.patch.object(cli, "new_api_token", return_value=token), \
                mock.patch("lantern.webapp.serve") as serve:
            code, out, err = self.run_cli("web", "--strict-auth", "--port", "9")
        self.assertEqual(code, 0, err)
        self.assertNotIn(token, out)
        self.assertEqual(err.count(token), 1)
        self.assertIn(f"http://127.0.0.1:9/#token={token}", err)
        self.assertIn(
            "Open this link (the token is valid until Lantern restarts; "
            "the #token fragment is not sent to the server):",
            err,
        )
        self.assertNotIn("Open once", err)
        self.assertNotIn("API token (printed once", err)
        self.assertEqual(serve.call_args.kwargs["api_token"], token)
        self.assertTrue(serve.call_args.kwargs["strict_auth"])
        self.assertFalse(serve.call_args.kwargs["lan_bound"])
        self.assertEqual(serve.call_args.kwargs["host"], "127.0.0.1")

    def test_cli_strict_auth_without_a_terminal_refuses_to_mint(self):
        env = self._no_token_env()
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(cli, "_stderr_is_tty", return_value=False), \
                mock.patch.object(cli, "new_api_token", side_effect=AssertionError("minted")), \
                mock.patch("lantern.webapp.serve", side_effect=AssertionError("serve")):
            code, out, err = self.run_cli("web", "--strict-auth", "--port", "9")
        self.assertEqual(code, 2)
        self.assertIn(cli.TOKEN_FILE_ENV, err)
        self.assertIn(cli.TOKEN_ENV, err)
        self.assertNotIn("#token=", err)
        self.assertEqual(out, "")
        self.assertFalse(Path(self.db).exists())

    def test_cli_strict_auth_env_enables_it_and_a_file_is_not_printed(self):
        token = "e" * 32
        path = Path(self.tmp.name) / "strict-token"
        path.write_text(token + "\n", encoding="utf-8")
        if os.name != "nt":
            os.chmod(path, 0o400)
        env = self._no_token_env()
        env[cli.STRICT_AUTH_ENV] = "1"
        env[cli.TOKEN_FILE_ENV] = str(path)
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(cli, "_stderr_is_tty", return_value=False), \
                mock.patch.object(cli, "new_api_token", side_effect=AssertionError("minted")), \
                mock.patch("lantern.webapp.serve") as serve:
            code, out, err = self.run_cli("web", "--port", "9")
        self.assertEqual(code, 0, err)
        self.assertNotIn(token, out)
        self.assertNotIn(token, err)
        self.assertNotIn("#token=", err)
        self.assertIn("Strict auth is on", err)
        self.assertTrue(serve.call_args.kwargs["strict_auth"])
        self.assertEqual(serve.call_args.kwargs["api_token"], token)
        self.assertFalse(serve.call_args.kwargs["lan_bound"])

    def test_cli_strict_auth_rejects_an_unknown_env_value(self):
        env = self._no_token_env()
        env[cli.STRICT_AUTH_ENV] = "maybe"
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch("lantern.webapp.serve", side_effect=AssertionError("serve")):
            code, _out, err = self.run_cli("web", "--port", "9")
        self.assertEqual(code, 2)
        self.assertIn(cli.STRICT_AUTH_ENV, err)
        self.assertFalse(Path(self.db).exists())

    def test_cli_debug_on_a_tty_does_not_print_a_generated_token(self):
        token = "d" * 43
        env = self._no_token_env()
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(cli, "_stderr_is_tty", return_value=True), \
                mock.patch.object(cli, "new_api_token", side_effect=AssertionError("minted")), \
                mock.patch("lantern.webapp.serve", side_effect=AssertionError("serve")):
            code, out, err = self.run_cli(
                "web", "--host", "192.168.1.50", "--allow-lan", "--port", "9", "--debug",
            )
        self.assertEqual(code, 2)
        self.assertIn("--debug does not print a generated token", err)
        self.assertNotIn(token, out)
        self.assertNotIn(token, err)
        self.assertNotIn("API token (printed", err)
        self.assertFalse(Path(self.db).exists())

        env[cli.TOKEN_ENV] = token
        with mock.patch.dict(os.environ, env, clear=True), \
                mock.patch.object(cli, "_stderr_is_tty", return_value=True), \
                mock.patch.object(cli, "new_api_token", side_effect=AssertionError("minted")), \
                mock.patch("lantern.webapp.serve") as serve:
            code, out, err = self.run_cli(
                "web", "--host", "192.168.1.50", "--allow-lan", "--port", "9", "--debug",
            )
        self.assertEqual(code, 0, err)
        self.assertNotIn(token, out)
        self.assertNotIn(token, err)
        self.assertEqual(serve.call_args.kwargs["api_token"], token)
        self.assertTrue(serve.call_args.kwargs["debug"])

    def test_process_refuses_lan_bind_without_listening(self):
        import subprocess
        import sys

        env = os.environ.copy()
        env.pop(cli.TOKEN_ENV, None)
        env.pop(cli.TOKEN_FILE_ENV, None)
        proc = subprocess.run(
            [sys.executable, "-m", "lantern", "--db", self.db, "web",
             "--host", "0.0.0.0", "--port", "8068"],
            capture_output=True, text=True, timeout=5, check=False, env=env,
        )
        self.assertNotEqual(proc.returncode, 0)
        self.assertIn("refusing to bind", proc.stderr)
        self.assertNotIn("Lantern dashboard", proc.stdout)
        self.assertNotIn("API token (printed", proc.stderr)
        self.assertFalse(Path(self.db).exists())

        proc = subprocess.run(
            [sys.executable, "-m", "lantern", "--db", self.db, "web",
             "--host", "0.0.0.0", "--allow-lan", "--port", "8068"],
            capture_output=True, text=True, timeout=5, check=False, env=env,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("refusing to start without a valid API token", proc.stderr)
        self.assertNotIn("Lantern dashboard", proc.stdout)
        self.assertNotIn("API token (printed", proc.stderr)
        self.assertFalse(Path(self.db).exists())

        short = env.copy()
        short[cli.TOKEN_ENV] = "too-short"
        proc = subprocess.run(
            [sys.executable, "-m", "lantern", "--db", self.db, "web",
             "--host", "192.168.1.50", "--allow-lan", "--port", "8068"],
            capture_output=True, text=True, timeout=5, check=False, env=short,
        )
        self.assertEqual(proc.returncode, 2)
        self.assertIn("128 bits", proc.stderr)
        self.assertNotIn("too-short", proc.stderr)
        self.assertNotIn("Lantern dashboard", proc.stdout)
        self.assertFalse(Path(self.db).exists())

    def test_web_help_mentions_allow_lan(self):
        with self.assertRaises(SystemExit) as ctx, contextlib.redirect_stdout(io.StringIO()) as out:
            cli.main(["web", "--help"])
        self.assertEqual(ctx.exception.code, 0)
        self.assertIn("--allow-lan", out.getvalue())
        help_text = " ".join(out.getvalue().split())
        self.assertIn("--strict-auth", help_text)
        self.assertIn("valid until Lantern restarts", help_text)
        self.assertNotIn("Open once", help_text)
        for word in ("1", "true", "yes", "on", "0", "false", "no", "off", "empty"):
            self.assertIn(word, help_text)
        self.assertIn("does not override this flag", help_text)
        self.assertIn("--no-strict-auth", help_text)
        self.assertIn("local-user", help_text)

    def test_strict_auth_off_values_do_not_override_the_flag(self):
        enabled, error = cli.strict_auth_requested(False, {})
        self.assertIsNone(error)
        self.assertTrue(enabled)
        for raw in ("0", "false", "no", "off", "  0  "):
            enabled, error = cli.strict_auth_requested(False, {cli.STRICT_AUTH_ENV: raw})
            self.assertIsNone(error, raw)
            self.assertFalse(enabled, raw)
            enabled, error = cli.strict_auth_requested(True, {cli.STRICT_AUTH_ENV: raw})
            self.assertIsNone(error, raw)
            self.assertTrue(enabled, raw)
            enabled, error = cli.strict_auth_requested(
                False, {cli.STRICT_AUTH_ENV: raw}, opt_out=True,
            )
            self.assertFalse(enabled, raw)
        for raw in ("", "   "):
            enabled, error = cli.strict_auth_requested(False, {cli.STRICT_AUTH_ENV: raw})
            self.assertIsNone(error, raw)
            self.assertTrue(enabled, raw)
        for raw in ("garbage", "2", "enable"):
            enabled, error = cli.strict_auth_requested(True, {cli.STRICT_AUTH_ENV: raw})
            self.assertIsNotNone(error, raw)
            self.assertFalse(enabled)
            enabled, error = cli.strict_auth_requested(
                False, {cli.STRICT_AUTH_ENV: raw}, opt_out=True,
            )
            self.assertIsNotNone(error, raw)
            self.assertFalse(enabled)
        for raw in ("1", "true", "yes", "on", " TRUE "):
            enabled, error = cli.strict_auth_requested(False, {cli.STRICT_AUTH_ENV: raw})
            self.assertIsNone(error, raw)
            self.assertTrue(enabled, raw)
        enabled, error = cli.strict_auth_requested(
            False, {cli.STRICT_AUTH_ENV: "1"}, opt_out=True,
        )
        self.assertFalse(enabled)


class TokenFileTests(unittest.TestCase):
    """Token files are regular, small, and private. No socket is opened."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)
        self.token = "f" * 32

    def test_fifo_is_refused_without_hanging(self):
        if not hasattr(os, "mkfifo"):
            self.skipTest("mkfifo is not available")
        path = Path(self.tmp.name) / "token.fifo"
        os.mkfifo(path)
        box = {}

        def read():
            try:
                cli._read_token_file(str(path))
            except ValueError as exc:
                box["error"] = exc

        worker = threading.Thread(target=read, daemon=True)
        started = time.monotonic()
        worker.start()
        worker.join(2)
        self.assertFalse(worker.is_alive(), "token file read blocked on a FIFO")
        self.assertLess(time.monotonic() - started, 2)
        self.assertIn("regular file", str(box.get("error")))
        self.assertNotIn(self.token, str(box.get("error")))

    def test_symlink_is_refused_and_the_target_is_not_read(self):
        if os.name == "nt":
            self.skipTest("symlink refusal is checked on POSIX")
        target = Path(self.tmp.name) / "secret"
        target.write_text(self.token, encoding="utf-8")
        link = Path(self.tmp.name) / "link"
        link.symlink_to(target)
        with self.assertRaises(ValueError) as ctx:
            cli._read_token_file(str(link))
        message = str(ctx.exception)
        self.assertIn("symlink", message)
        self.assertNotIn(self.token, message)
        self.assertEqual(target.read_text(encoding="utf-8"), self.token)

    def test_oversized_file_is_refused(self):
        path = Path(self.tmp.name) / "big"
        path.write_bytes(b"a" * (cli.MAX_TOKEN_FILE_BYTES + 1))
        if os.name != "nt":
            os.chmod(path, 0o400)
        started = time.monotonic()
        with self.assertRaises(ValueError) as ctx:
            cli._read_token_file(str(path))
        self.assertLess(time.monotonic() - started, 2)
        self.assertIn("4 KiB", str(ctx.exception))
        self.assertNotIn("a" * 40, str(ctx.exception))

        long_token = Path(self.tmp.name) / "long"
        long_token.write_text("b" * 600, encoding="utf-8")
        if os.name != "nt":
            os.chmod(long_token, 0o400)
        with self.assertRaises(ValueError) as ctx:
            cli._read_token_file(str(long_token))
        self.assertIn("512", str(ctx.exception))
        self.assertNotIn("b" * 40, str(ctx.exception))

    def test_group_readable_file_is_refused_and_mode_0400_is_accepted(self):
        if os.name == "nt":
            self.skipTest("POSIX token file modes are not checked on Windows")
        path = Path(self.tmp.name) / "token"
        path.write_text(self.token + "\n", encoding="utf-8")
        os.chmod(path, 0o644)
        with self.assertRaises(ValueError) as ctx:
            cli._read_token_file(str(path))
        self.assertIn("0400", str(ctx.exception))
        self.assertNotIn(self.token, str(ctx.exception))
        os.chmod(path, 0o400)
        self.assertEqual(cli._read_token_file(str(path)), self.token)


if __name__ == "__main__":
    unittest.main()

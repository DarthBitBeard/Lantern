"""The system tray mode: flag handling, server wiring and the windowed launcher.

No window is created here. The real icon needs a Windows desktop, and is
checked by the Windows package workflow and by hand.
"""

import contextlib
import importlib.util
import io
import os
import sys
import tempfile
import threading
import unittest
from pathlib import Path
from unittest import mock

from lantern import cli, tray, webapp

ROOT = Path(__file__).resolve().parents[1]


class TrayModuleTests(unittest.TestCase):
    def test_support_follows_the_platform(self):
        self.assertEqual(tray.is_supported(), os.name == "nt")

    def test_long_tooltips_are_clipped_to_what_windows_shows(self):
        self.assertEqual(len(tray.clip_tooltip("x" * 500)), 127)
        self.assertEqual(tray.clip_tooltip("short"), "short")

    def test_run_refuses_off_windows(self):
        icon = tray.TrayIcon("t", lambda: None, lambda: None)
        with mock.patch.object(tray, "_IS_WINDOWS", False):
            with self.assertRaises(RuntimeError):
                icon.run()

    def test_stop_before_run_is_harmless(self):
        tray.TrayIcon("t", lambda: None, lambda: None).stop()

    def test_notify_before_the_icon_exists_is_kept_and_clipped(self):
        icon = tray.TrayIcon("t", lambda: None, lambda: None)
        self.assertFalse(icon.notify("T" * 100, "x" * 400))
        title, text = icon._take_pending()
        self.assertEqual((len(title), len(text)), (tray.INFO_TITLE_MAX, tray.INFO_TEXT_MAX))
        self.assertIsNone(icon._take_pending())  # shown once only


class TrayFlagTests(unittest.TestCase):
    def setUp(self):
        # Never reach a real Lantern tray running on the test machine.
        patcher = mock.patch("lantern.tray.signal_running_instance", return_value=False)
        patcher.start()
        self.addCleanup(patcher.stop)

    def run_main(self, *argv):
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stderr(err):
            code = cli.main(["web", "--db", os.path.join(folder, "t.db"), *argv])
        return code, err.getvalue()

    def test_tray_is_refused_where_it_is_not_supported(self):
        with mock.patch("lantern.tray.is_supported", return_value=False):
            code, err = self.run_main("--tray")
        self.assertEqual(code, 2)
        self.assertIn("Windows only", err)

    def test_tray_hands_the_link_to_serve(self):
        calls = {}

        def fake_serve(db_path, **kwargs):
            calls.update(kwargs)

        with mock.patch("lantern.tray.is_supported", return_value=True), \
                mock.patch.object(cli, "_load_serve", return_value=fake_serve):
            code, _err = self.run_main("--tray", "--port", "18070")
        self.assertEqual(code, 0)
        self.assertTrue(calls["tray"])
        self.assertTrue(calls["tray_url"].startswith("http://127.0.0.1:18070/"))
        self.assertNotIn("open_url", calls)  # --open was not asked for

    def test_open_and_tray_together_do_both(self):
        calls = {}
        with mock.patch("lantern.tray.is_supported", return_value=True), \
                mock.patch.object(cli, "_load_serve", return_value=lambda db, **kw: calls.update(kw)):
            code, _err = self.run_main("--tray", "--open")
        self.assertEqual(code, 0)
        self.assertTrue(calls["tray"] and calls["open_url"])


class _FakeServer:
    def __init__(self):
        self.stopped = threading.Event()
        self.shutdown_calls = 0
        self.RequestHandlerClass = type("Handler", (), {"db_path": ":memory:", "scan_listeners": []})

    def serve_forever(self):
        self.stopped.wait(5)

    def shutdown(self):
        self.shutdown_calls += 1
        self.stopped.set()


class ServeInTrayTests(unittest.TestCase):
    def test_quit_shuts_the_server_down_and_returns(self):
        server = _FakeServer()
        opened = []

        class FakeIcon:
            def __init__(self, tooltip, on_open, on_quit, icon_path=None, **kwargs):
                self.tooltip, self.on_open, self.on_quit = tooltip, on_open, on_quit

            def notify(self, title, text):
                return True

            def run(self):
                self.on_open()
                self.on_open()
                self.on_quit()
                server.stopped.wait(2)

            def stop(self):
                pass

        token = "session-token-session-token-session"
        exchange = webapp.LoginExchange(token)
        server.RequestHandlerClass.strict_auth = True
        server.RequestHandlerClass.api_token = token
        server.RequestHandlerClass.login_exchange = exchange
        server.RequestHandlerClass.watcher = None
        server.RequestHandlerClass.watch_note = ""
        server.RequestHandlerClass.subnet_guess = type("G", (), {"get": lambda self: None})()
        with mock.patch("lantern.tray.TrayIcon", FakeIcon), \
                mock.patch.object(webapp, "_open_browser", side_effect=opened.append):
            webapp._serve_in_tray(server, "127.0.0.1", 18071, "http://127.0.0.1:18071/#token=abc")
        self.assertGreaterEqual(server.shutdown_calls, 1)
        self.assertEqual(len(opened), 2)
        self.assertNotIn(token, opened[0])
        self.assertNotIn(token, opened[1])
        self.assertNotIn("#token=", opened[0])
        first = opened[0].split("#login=", 1)[1]
        second = opened[1].split("#login=", 1)[1]
        self.assertNotEqual(first, second)
        self.assertEqual(exchange.redeem(first), token)
        self.assertEqual(exchange.redeem(second), token)

    def test_a_server_that_stops_on_its_own_takes_the_icon_down(self):
        server = _FakeServer()
        server.stopped.set()  # serve_forever returns at once
        stopped = threading.Event()

        class FakeIcon:
            def __init__(self, *args, **kwargs):
                pass

            def run(self):
                stopped.wait(3)

            def stop(self):
                stopped.set()

            def notify(self, title, text):
                return True

        with mock.patch("lantern.tray.TrayIcon", FakeIcon):
            webapp._serve_in_tray(server, "127.0.0.1", 18072, None)
        self.assertTrue(stopped.is_set())


class TrayMenuTests(unittest.TestCase):
    def test_menu_has_status_scan_open_and_quit(self):
        icon = tray.TrayIcon("t", lambda: None, lambda: None, on_scan=lambda: None,
                             status=lambda: "Last scan 5 min ago")
        items = icon.menu_items()
        self.assertEqual(items[0], (tray.MF_STRING | tray.MF_GRAYED, 0, "Last scan 5 min ago"))
        self.assertEqual([i[1] for i in items if i[1]], [tray.ID_OPEN, tray.ID_SCAN, tray.ID_QUIT])
        self.assertIn("Scan now (manual)", [i[2] for i in items])

    def test_manual_scan_is_refused_when_the_gateway_does_not_match(self):
        import inspect
        import ipaddress

        network = ipaddress.ip_network("192.168.1.0/24")
        handler = type("H", (), {
            "watcher": type("W", (), {"network": network, "subnet": str(network)})(),
            "watch_gateway_mac": "aa:bb:cc:dd:ee:01",
            "watch_problem": None,
        })()
        with mock.patch("lantern.discovery.local_ipv4_in", return_value="10.1.1.5"), \
                mock.patch("lantern.discovery.default_gateways", return_value=["192.168.1.1"]), \
                mock.patch("lantern.discovery.gateway_arp_table",
                           return_value={"192.168.1.1": "aa:bb:cc:dd:ee:01"}):
            allowed, message = webapp.tray_may_scan(handler)
        self.assertFalse(allowed)
        self.assertIn("not on the network", message)
        self.assertIn("tray_may_scan", inspect.getsource(webapp._serve_in_tray))
        bare = type("H", (), {"watcher": None})()
        self.assertTrue(webapp.tray_may_scan(bare)[0])

    def test_watch_menu_says_instead_when_the_saved_gateway_differs(self):
        handler = type("H", (), {
            "db_path": os.path.join(tempfile.mkdtemp(), "t.db"),
            "subnet_guess": type("G", (), {"get": lambda self: "192.168.1.0/24"})(),
        })()
        from lantern import watch

        watch.save_opt_in(handler.db_path, watch.NetworkIdentity("192.168.1.0/24", "aa:bb:cc:dd:ee:01"))
        with mock.patch("lantern.watch.current_gateway_mac", return_value="11:22:33:44:55:66"):
            self.assertEqual(webapp.watch_menu_label(handler), "Watch this network instead")
        with mock.patch("lantern.watch.current_gateway_mac", return_value="aa:bb:cc:dd:ee:01"):
            self.assertEqual(webapp.watch_menu_label(handler), "Watch this network")

    def test_menu_without_scan_or_status_and_with_a_failing_status(self):
        def broken():
            raise RuntimeError("db gone")

        icon = tray.TrayIcon("t", lambda: None, lambda: None, status=broken)
        self.assertEqual([i[1] for i in icon.menu_items() if i[1]], [tray.ID_OPEN, tray.ID_QUIT])

    def test_no_running_instance_off_windows(self):
        with mock.patch.object(tray, "_IS_WINDOWS", False):
            self.assertFalse(tray.signal_running_instance())

    def test_second_launch_hands_off_and_exits_cleanly(self):
        err = io.StringIO()
        served = []
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stderr(err), \
                mock.patch("lantern.tray.is_supported", return_value=True), \
                mock.patch("lantern.tray.classify_running_instance", return_value=tray.INSTANCE_OURS), \
                mock.patch.object(cli, "_load_serve", return_value=lambda db, **kw: served.append(kw)):
            code = cli.main(["web", "--tray", "--db", os.path.join(folder, "t.db")])
        self.assertEqual(code, 0)
        self.assertEqual(served, [])
        self.assertIn("already running", err.getvalue())

    def test_a_foreign_tray_window_does_not_count_as_ours(self):
        install = Path("/Lantern")
        self.assertFalse(tray.tray_image_is_ours(None, str(install / "lantern-tray.exe")))
        self.assertFalse(tray.tray_image_is_ours(
            str(Path("/other") / "lantern-tray.exe"), str(install / "lantern-tray.exe"),
        ))
        self.assertFalse(tray.tray_image_is_ours(
            str(install / "notepad.exe"), str(install / "lantern-tray.exe"),
        ))
        self.assertTrue(tray.tray_image_is_ours(
            str(install / "lantern-tray.exe"), str(install / "lantern.exe"),
        ))
        err = io.StringIO()
        served = []
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stderr(err), \
                mock.patch("lantern.tray.is_supported", return_value=True), \
                mock.patch("lantern.tray.classify_running_instance", return_value=tray.INSTANCE_FOREIGN), \
                mock.patch.object(cli, "_load_serve", return_value=lambda db, **kw: served.append(kw)), \
                mock.patch.dict(os.environ, {"LANTERN_API_TOKEN": "t" * 32}):
            code = cli.main(["web", "--tray", "--db", os.path.join(folder, "t.db")])
        self.assertEqual(code, 0, err.getvalue())
        self.assertEqual(len(served), 1)
        self.assertIn("not this Lantern", err.getvalue())
        self.assertNotIn("already running", err.getvalue())

    def test_stop_does_not_use_wm_close(self):
        import inspect

        self.assertNotEqual(tray.WM_CLOSE, tray.WM_TRAY_STOP)
        self.assertIn("WM_TRAY_STOP", inspect.getsource(tray.TrayIcon.stop))
        self.assertNotIn("WM_CLOSE", inspect.getsource(tray.TrayIcon.stop))

    def test_later_dashboard_opens_authenticate(self):
        from urllib.parse import unquote

        token = "session-token-session-token-session"
        exchange = webapp.LoginExchange(token)
        opener = webapp.DashboardOpen("http://127.0.0.1:9/#token=secret", exchange)
        first = opener.url()
        second = opener.url()
        self.assertNotIn(token, first)
        self.assertNotIn(token, second)
        self.assertNotIn("#token=", first)
        self.assertNotIn("#token=", second)
        self.assertNotEqual(first, second)
        nonce_1 = unquote(first.split("#login=", 1)[1])
        nonce_2 = unquote(second.split("#login=", 1)[1])
        self.assertEqual(exchange.redeem(nonce_1), token)
        self.assertEqual(exchange.redeem(nonce_2), token)
        self.assertIsNone(exchange.redeem(nonce_1))
        plain = webapp.DashboardOpen("http://127.0.0.1:9/", None)
        self.assertEqual(plain.url(), "http://127.0.0.1:9/")
        self.assertNotIn("token", plain.url())

    def test_a_foreign_stop_message_is_ignored(self):
        import inspect

        icon = tray.TrayIcon("t", lambda: None, lambda: None)
        other = tray.TrayIcon("t", lambda: None, lambda: None)
        self.assertNotEqual(icon._stop_token, other._stop_token)
        self.assertGreaterEqual(icon._stop_token.bit_length(), 1)
        self.assertTrue(tray.accepts_stop(tray.WM_TRAY_STOP, icon._stop_token, icon._stop_token))
        self.assertTrue(tray.accepts_stop(
            tray.WM_TRAY_STOP, tray.signed_stop_lparam(icon._stop_token), icon._stop_token,
        ))
        self.assertFalse(tray.accepts_stop(tray.WM_TRAY_STOP, 0, icon._stop_token))
        self.assertFalse(tray.accepts_stop(tray.WM_TRAY_STOP, other._stop_token, icon._stop_token))
        self.assertFalse(tray.accepts_stop(tray.WM_CLOSE, icon._stop_token, icon._stop_token))
        high = (1 << 63) + 7
        self.assertTrue(tray.accepts_stop(tray.WM_TRAY_STOP, tray.signed_stop_lparam(high), high))
        self.assertFalse(tray.accepts_stop(tray.WM_TRAY_STOP, high ^ 1, high))
        source = inspect.getsource(tray.TrayIcon._run_windows)
        self.assertIn("accepts_stop", source)
        self.assertIn("self._stop_token", inspect.getsource(tray.TrayIcon.stop))


class TrayStatusLineTests(unittest.TestCase):
    def setUp(self):
        from lantern import store

        self.db = os.path.join(tempfile.mkdtemp(), "s.db")
        conn = store.connect(self.db)
        conn.close()
        self.handler = type("H", (), {"db_path": self.db, "watcher": None})
        self.store = store

    def test_no_scans_yet(self):
        self.assertEqual(webapp.tray_status_line(self.handler), "No scans yet")

    def test_last_and_next_scan(self):
        from lantern.watch import parse_started_at

        conn = self.store.connect(self.db)
        try:
            self.store.save_scan(conn, "10.0.0.0/24", [])
            started = parse_started_at(self.store.list_scans(conn, limit=1)[0]["started_at"])
        finally:
            conn.close()
        self.handler.watcher = type("W", (), {
            "next_scan_at": started + 3600, "subnet": "10.0.0.0/24",
        })()
        self.handler.watch_note = "Watching 10.0.0.0/24."
        line = webapp.tray_status_line(self.handler, now=started + 12 * 60)
        self.assertEqual(line, "Last scan 12 min ago · Watching 10.0.0.0/24 · next in 48 min")


class LauncherTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        spec = importlib.util.spec_from_file_location(
            "lantern_launcher_under_test", ROOT / "packaging" / "windows" / "lantern_launcher.py",
        )
        cls.launcher = importlib.util.module_from_spec(spec)
        spec.loader.exec_module(cls.launcher)

    def test_only_the_tray_exe_is_the_tray_build(self):
        for exe, expected in (("C:/x/lantern-tray.exe", True), ("C:/x/Lantern-Tray.EXE", True),
                              ("C:/x/lantern.exe", False), ("python.exe", False)):
            with mock.patch.object(sys, "executable", exe):
                self.assertIs(self.launcher._is_tray_build(), expected, exe)

    def test_default_database_is_in_the_local_app_data_folder(self):
        with mock.patch.dict(os.environ, {"LOCALAPPDATA": r"C:\Users\me\AppData\Local"}):
            self.assertEqual(
                self.launcher._default_db(),
                os.path.join(r"C:\Users\me\AppData\Local", "Lantern", "lantern.db"),
            )

    def test_a_failed_start_is_shown_not_swallowed(self):
        shown = []

        def failing_main(argv):
            print("Cannot bind 127.0.0.1:8068 (address in use).", file=sys.stderr)
            return 2

        saved = sys.stdout, sys.stderr
        try:
            with mock.patch.object(self.launcher, "main", failing_main), \
                    mock.patch.object(self.launcher, "_show_error", shown.append), \
                    mock.patch.object(sys, "argv", ["lantern-tray.exe"]):
                code = self.launcher.run_tray()
        finally:
            sys.stdout, sys.stderr = saved
        self.assertEqual(code, 2)
        self.assertEqual(len(shown), 1)
        self.assertIn("Cannot bind", shown[0])

    def test_defaults_start_the_tray_with_the_dashboard(self):
        seen = []
        saved = sys.stdout, sys.stderr
        try:
            with mock.patch.object(self.launcher, "main", lambda argv: seen.append(argv) or 0), \
                    mock.patch.object(sys, "argv", ["lantern-tray.exe"]):
                self.launcher.run_tray()
        finally:
            sys.stdout, sys.stderr = saved
        self.assertEqual(seen[0][:3], ["web", "--tray", "--open"])


if __name__ == "__main__":
    unittest.main()

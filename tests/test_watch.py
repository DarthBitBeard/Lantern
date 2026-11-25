"""Watch mode: the schedule, its flags, retention after a scan, and scan listeners."""

import contextlib
import io
import ipaddress
import json
import os
import secrets
import tempfile
import stat
import threading
import unittest
from pathlib import Path
from unittest import mock

from lantern import cli, store, watch, webapp


class FakeClock:
    def __init__(self, now=1_000_000.0):
        self.now = now

    def __call__(self):
        return self.now


class IntervalTests(unittest.TestCase):
    def test_parse_and_describe(self):
        self.assertEqual(watch.parse_interval("30m"), 1800)
        self.assertEqual(watch.parse_interval(" 2H "), 7200)
        self.assertEqual(watch.parse_interval("1d"), 86400)
        self.assertEqual(watch.describe_interval(7200), "2h")
        self.assertEqual(watch.describe_interval(5400), "90m")

    def test_bounds_and_garbage_are_refused(self):
        for text in ("4m", "8d", "", "60", "1w", "-5m", "1.5h"):
            with self.assertRaises(ValueError, msg=text):
                watch.parse_interval(text)

    def test_started_at_parsing(self):
        self.assertEqual(watch.parse_started_at("1970-01-01T00:01:00+00:00"), 60.0)
        self.assertEqual(watch.parse_started_at("1970-01-01T00:01:00Z"), 60.0)
        self.assertIsNone(watch.parse_started_at("nonsense"))
        self.assertIsNone(watch.parse_started_at(None))


class WatcherTests(unittest.TestCase):
    def make(self, *, started=True, here=True, last=None, clock=None):
        self.calls = []
        clock = clock or FakeClock()

        def start(subnet):
            self.calls.append(subnet)
            return started

        return watch.Watcher(3600, "192.168.1.0/24", start, on_network=lambda net: here,
                             last_scan_at=last, clock=clock, first_delay=30), clock

    def test_first_scan_waits_a_little_after_start(self):
        watcher, clock = self.make()
        self.assertEqual(watcher.next_scan_at, clock.now + 30)

    def test_a_recent_scan_pushes_the_first_one_back(self):
        clock = FakeClock()
        watcher, _ = self.make(last=clock.now - 600, clock=clock)
        self.assertEqual(watcher.next_scan_at, clock.now - 600 + 3600)

    def test_started_scan_schedules_the_next_interval(self):
        watcher, clock = self.make()
        self.assertEqual(watcher.run_once(), "started")
        self.assertEqual(self.calls, ["192.168.1.0/24"])
        self.assertEqual(watcher.next_scan_at, clock.now + 3600)

    def test_busy_retries_soon(self):
        watcher, clock = self.make(started=False)
        self.assertEqual(watcher.run_once(), "busy")
        self.assertEqual(watcher.next_scan_at, clock.now + watch.BUSY_RETRY)

    def test_away_from_the_network_never_scans(self):
        watcher, clock = self.make(here=False)
        self.assertEqual(watcher.run_once(), "away")
        self.assertEqual(self.calls, [])
        self.assertEqual(watcher.next_scan_at, clock.now + 3600)

    def test_same_subnet_different_gateway_never_scans(self):
        """A lookalike address range with another gateway is not the opted-in network."""
        network = ipaddress.ip_network("192.168.1.0/24")
        expected = "aa:bb:cc:dd:ee:01"
        calls = []
        skipped = []

        def on_network(net):
            return watch.identity_matches(
                net, expected, "192.168.1.10",
                ["192.168.1.1"], {"192.168.1.1": "11:22:33:44:55:66"},
            )

        watcher = watch.Watcher(
            3600, str(network), lambda subnet: calls.append(subnet),
            on_network=on_network, on_skip=skipped.append, first_delay=30,
        )
        self.assertEqual(watcher.run_once(), "away")
        self.assertEqual(calls, [])
        self.assertEqual(skipped, ["192.168.1.0/24"])
        self.assertTrue(watch.identity_matches(
            network, expected, "192.168.1.10", ["192.168.1.1"], {"192.168.1.1": expected},
        ))
        self.assertFalse(watch.identity_matches(
            network, expected, None, ["192.168.1.1"], {"192.168.1.1": expected},
        ))
        # A gateway outside the subnet cannot stand in for the one inside it.
        self.assertIsNone(watch.gateway_mac_for(
            network, ["10.0.0.1"], {"10.0.0.1": expected},
        ))

    def test_status_is_json_friendly(self):
        watcher, _ = self.make()
        watcher.run_once()
        status = watcher.status()
        self.assertEqual(status["interval"], "1h")
        self.assertEqual(status["subnet"], "192.168.1.0/24")
        self.assertTrue(status["next_scan_at"].endswith("Z"))
        self.assertEqual(status["last_result"], "started")

    def test_loop_runs_when_due_and_stops(self):
        fired = threading.Event()
        watcher = watch.Watcher(3600, "192.168.1.0/24", lambda s: fired.set() or True,
                                on_network=lambda n: True, first_delay=0)
        watcher.start()
        try:
            self.assertTrue(fired.wait(5))
        finally:
            watcher.stop()
        self.assertFalse(watcher._thread.is_alive())


class WatchFlagTests(unittest.TestCase):
    def run_web(self, *argv):
        calls = {}
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stderr(err), \
                mock.patch.object(cli, "_load_serve", return_value=lambda db, **kw: calls.update(kw)), \
                mock.patch.object(cli, "guess_subnet", return_value="192.168.7.0/24"), \
                mock.patch.object(watch, "current_gateway_mac", return_value="aa:bb:cc:dd:ee:01"), \
                mock.patch.dict(os.environ, {"LANTERN_API_TOKEN": secrets.token_urlsafe(32)}):
            db = os.path.join(folder, "t.db")
            code = cli.main(["web", "--db", db, *argv])
            path = watch.opt_in_path(db)
            calls["_db"] = db
            calls["_opt_in"] = path.read_text(encoding="utf-8") if path.is_file() else None
            calls["_mode"] = stat.S_IMODE(path.stat().st_mode) if path.is_file() else None
        return code, calls, err.getvalue()

    def test_watch_defaults_to_detected_subnet_and_90_days(self):
        code, calls, err = self.run_web("--watch", "2h")
        self.assertEqual(code, 0, err)
        self.assertEqual(calls["watch_seconds"], 7200)
        self.assertEqual(calls["watch_subnet"], "192.168.7.0/24")
        self.assertEqual(calls["watch_gateway_mac"], "aa:bb:cc:dd:ee:01")
        self.assertEqual(calls["keep_days"], 90)
        saved = json.loads(calls["_opt_in"])
        self.assertEqual(saved["subnet"], "192.168.7.0/24")
        self.assertEqual(saved["gateway_mac"], "aa:bb:cc:dd:ee:01")
        if os.name != "nt":
            self.assertEqual(calls["_mode"], 0o600)

    def test_explicit_subnet_and_keep_forever(self):
        code, calls, err = self.run_web("--watch", "30m", "--watch-subnet", "10.0.5.0/24", "--keep-days", "0")
        self.assertEqual(code, 0, err)
        self.assertEqual(calls["watch_subnet"], "10.0.5.0/24")
        self.assertEqual(calls["watch_gateway_mac"], "aa:bb:cc:dd:ee:01")
        self.assertNotIn("keep_days", calls)

    def test_no_watch_keeps_everything_unless_asked(self):
        code, calls, _ = self.run_web()
        self.assertEqual(code, 0)
        self.assertNotIn("watch_seconds", calls)
        self.assertNotIn("keep_days", calls)
        code, calls, _ = self.run_web("--keep-days", "30")
        self.assertEqual(calls["keep_days"], 30)

    def test_bad_values_are_refused_before_serving(self):
        for argv, text in (
            (("--watch", "1m"), "between 5m and 7d"),
            (("--watch", "1h", "--watch-subnet", "8.8.8.0/24"), ""),
            (("--watch-subnet", "10.0.0.0/24"), "needs --watch"),
            (("--keep-days", "-1"), "--keep-days"),
        ):
            code, calls, err = self.run_web(*argv)
            self.assertEqual(code, 2, argv)
            self.assertNotIn("watch_seconds", calls, argv)
            self.assertIn(text, err)

    def test_installer_watch_shortcut_reuses_the_saved_network(self):
        text = (Path(__file__).resolve().parents[1] / "packaging" / "windows" / "lantern.iss").read_text(encoding="utf-8")
        self.assertIn("--watch 1h --watch-saved", text)
        self.assertNotIn("Result := '--watch 1h '", text)

    def test_watch_refuses_to_start_without_a_gateway_mac(self):
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stderr(err), \
                mock.patch.object(cli, "_load_serve", side_effect=AssertionError("serve")), \
                mock.patch.object(cli, "guess_subnet", return_value="192.168.7.0/24"), \
                mock.patch.object(watch, "current_gateway_mac", return_value=None), \
                mock.patch.dict(os.environ, {"LANTERN_API_TOKEN": secrets.token_urlsafe(32)}):
            code = cli.main(["web", "--db", os.path.join(folder, "t.db"), "--watch", "1h"])
        self.assertEqual(code, 2)
        self.assertIn("gateway", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())

    def test_saved_watch_does_not_detect_a_network(self):
        guess = mock.Mock(side_effect=AssertionError("detected a network"))
        code, calls, err = self._run_saved(guess, opt_in=None)
        self.assertEqual(code, 0, err)
        self.assertFalse(guess.called)
        self.assertNotIn("watch_seconds", calls)
        self.assertIn("not watching", err)
        self.assertIsNone(calls["_opt_in"])

    def test_saved_watch_reuses_the_opt_in_and_does_not_replace_it(self):
        guess = mock.Mock(side_effect=AssertionError("detected a network"))
        code, calls, err = self._run_saved(
            guess,
            opt_in='{"subnet":"10.1.2.0/24","gateway_mac":"aa:bb:cc:dd:ee:09"}\n',
        )
        self.assertEqual(code, 0, err)
        self.assertFalse(guess.called)
        self.assertEqual(calls["watch_subnet"], "10.1.2.0/24")
        self.assertEqual(calls["watch_gateway_mac"], "aa:bb:cc:dd:ee:09")
        self.assertIn("aa:bb:cc:dd:ee:09", calls["_opt_in"])
        self.assertNotIn("aa:bb:cc:dd:ee:01", calls["_opt_in"])

    def _run_saved(self, guess, opt_in):
        calls = {}
        err = io.StringIO()
        with tempfile.TemporaryDirectory() as folder, contextlib.redirect_stderr(err), \
                mock.patch.object(cli, "_load_serve", return_value=lambda db, **kw: calls.update(kw)), \
                mock.patch.object(cli, "guess_subnet", guess), \
                mock.patch.object(watch, "current_gateway_mac", side_effect=AssertionError("live gateway")), \
                mock.patch.dict(os.environ, {"LANTERN_API_TOKEN": secrets.token_urlsafe(32)}):
            db = os.path.join(folder, "t.db")
            if opt_in is not None:
                watch.opt_in_path(db).write_text(opt_in, encoding="utf-8")
            code = cli.main(["web", "--db", db, "--watch", "1h", "--watch-saved"])
            calls["_db"] = db
            path = watch.opt_in_path(db)
            calls["_opt_in"] = path.read_text(encoding="utf-8") if path.is_file() else None
        return code, calls, err.getvalue()


def _device(ip):
    return {"ip": ip, "mac": None, "open_ports": [], "findings": []}


class ScanJobTests(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(), "l.db")
        store.connect(self.db).close()

    def run_job(self, **kwargs):
        job = webapp._ScanJob()
        self.assertTrue(webapp._scan_lock.acquire(blocking=False))
        with mock.patch("lantern.engine.scan_subnet", return_value=([_device("192.168.1.5")], {})):
            webapp._run_scan_job(job, self.db, "192.168.1.0/24", False, **kwargs)
        self.assertFalse(webapp._scan_lock.locked())
        return job.snapshot()

    def test_retention_deletes_old_scans_but_never_the_new_one(self):
        conn = store.connect(self.db)
        old = store.save_scan(conn, "192.168.1.0/24", [_device("192.168.1.2")])
        conn.execute("UPDATE scans SET started_at = '2000-01-01T00:00:00+00:00' WHERE id = ?", (old,))
        conn.commit()
        conn.close()
        state = self.run_job(keep_days=30)
        conn = store.connect(self.db)
        try:
            ids = [row[0] for row in conn.execute("SELECT id FROM scans")]
        finally:
            conn.close()
        self.assertEqual(ids, [state["scan_id"]])

    def test_listeners_get_the_scan_id_and_cannot_break_the_job(self):
        seen = []

        def broken(_scan_id):
            raise RuntimeError("listener bug")

        state = self.run_job(listeners=(broken, seen.append))
        self.assertEqual(state["state"], "done")
        self.assertEqual(seen, [state["scan_id"]])

    def test_scheduled_scan_skips_a_different_gateway_and_logs_it(self):
        handler = type("H", (), {"db_path": self.db})
        with mock.patch("lantern.discovery.local_ipv4_in", return_value="192.168.1.10"), \
                mock.patch("lantern.discovery.default_gateways", return_value=["192.168.1.1"]), \
                mock.patch("lantern.discovery.arp_table", return_value={"192.168.1.1": "11:22:33:44:55:66"}), \
                mock.patch("lantern.webapp.start_scan_job", side_effect=AssertionError("scanned")):
            watcher = webapp._make_watcher(handler, 3600, "192.168.1.0/24", "aa:bb:cc:dd:ee:01")
            err = io.StringIO()
            with contextlib.redirect_stderr(err):
                self.assertEqual(watcher.run_once(), "away")
        self.assertIn("scheduled scan skipped", err.getvalue())
        self.assertIn("192.168.1.0/24", err.getvalue())
        watcher.stop()

    def test_start_scan_job_reports_busy(self):
        handler = type("H", (), {"scan_job": webapp._ScanJob(), "db_path": self.db, "debug": False,
                                 "switch_config": None, "fingerprint": True, "keep_days": None,
                                 "scan_listeners": []})
        self.assertTrue(webapp._scan_lock.acquire(blocking=False))
        try:
            self.assertFalse(webapp.start_scan_job(handler, "192.168.1.0/24"))
        finally:
            webapp._scan_lock.release()


if __name__ == "__main__":
    unittest.main()

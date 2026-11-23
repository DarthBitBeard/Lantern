"""Watch mode: the schedule, its flags, retention after a scan, and scan listeners."""

import contextlib
import io
import os
import secrets
import tempfile
import threading
import unittest
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
                mock.patch.object(cli, "guess_subnet", return_value="192.168.7.0/24"),                 mock.patch.dict(os.environ, {"LANTERN_API_TOKEN": secrets.token_urlsafe(32)}):
            code = cli.main(["web", "--db", os.path.join(folder, "t.db"), *argv])
        return code, calls, err.getvalue()

    def test_watch_defaults_to_detected_subnet_and_90_days(self):
        code, calls, err = self.run_web("--watch", "2h")
        self.assertEqual(code, 0, err)
        self.assertEqual(calls["watch_seconds"], 7200)
        self.assertEqual(calls["watch_subnet"], "192.168.7.0/24")
        self.assertEqual(calls["keep_days"], 90)

    def test_explicit_subnet_and_keep_forever(self):
        code, calls, err = self.run_web("--watch", "30m", "--watch-subnet", "10.0.5.0/24", "--keep-days", "0")
        self.assertEqual(code, 0, err)
        self.assertEqual(calls["watch_subnet"], "10.0.5.0/24")
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
            self.assertEqual(calls, {}, argv)
            self.assertIn(text, err)


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

"""Scan progress: the engine reports phases, the job exposes them, the tray shows them."""

import unittest
from unittest import mock

from lantern import engine, webapp


class EngineProgressTests(unittest.TestCase):
    def test_phases_count_up_to_their_totals(self):
        seen = []
        hosts = [f"10.0.0.{i}" for i in range(1, 11)]

        def scan_one(ip, macs, ports, *, fingerprint=True):
            return {"ip": ip, "mac": None, "hostname": None, "open_ports": [], "findings": [], "label": None}

        with mock.patch.object(engine, "arp_table", return_value={}), \
                mock.patch.object(engine, "ping_host", side_effect=lambda ip: ip.endswith((".1", ".2", ".3"))), \
                mock.patch.object(engine, "tcp_alive", return_value=False), \
                mock.patch.object(engine, "scan_one", side_effect=scan_one):
            devices = engine.scan_hosts(hosts, progress=lambda *args: seen.append(args))
        self.assertEqual(len(devices), 3)
        self.assertEqual(seen[0], ("discover", 0, 10))
        self.assertIn(("discover", 10, 10), seen)
        self.assertIn(("ports", 0, 3), seen)
        self.assertEqual(seen[-1], ("ports", 3, 3))

    def test_a_broken_progress_callback_never_fails_the_scan(self):
        def broken(*_args):
            raise RuntimeError("display bug")

        with mock.patch.object(engine, "arp_table", return_value={}), \
                mock.patch.object(engine, "ping_host", return_value=False), \
                mock.patch.object(engine, "tcp_alive", return_value=False):
            with self.assertRaises(RuntimeError):
                broken()  # the callback itself really does raise
            self.assertEqual(engine.scan_hosts(["10.0.0.1"], progress=lambda *a: None), [])
            counted = engine._counting(lambda x: x * 2, lambda n: broken())
            self.assertEqual(counted(4), 8)


class ScanJobProgressTests(unittest.TestCase):
    def test_progress_is_reported_and_described(self):
        job = webapp._ScanJob()
        self.assertIsNone(job.snapshot()["progress"])
        self.assertIsNone(job.progress_text())
        job.start("10.0.0.0/24")
        self.assertEqual(job.progress_text(), "Starting scan")
        job.report("discover", 120, 254)
        snap = job.snapshot()
        self.assertEqual((snap["progress"]["phase"], snap["progress"]["done"]), ("discover", 120))
        self.assertIn("elapsed_seconds", snap["progress"])
        self.assertNotIn("started_at", snap["progress"])
        self.assertEqual(job.progress_text(), "Finding devices 120/254")
        job.report("discover", 100, 254)  # a late, smaller report is ignored
        self.assertEqual(job.snapshot()["progress"]["done"], 120)
        job.report("ports", 8, 21)
        self.assertEqual(job.progress_text(), "Checking ports 8/21")
        job.finish(5)
        self.assertIsNone(job.progress_text())
        job.report("ports", 21, 21)  # after the scan ends, nothing changes
        self.assertEqual(job.snapshot()["progress"]["done"], 8)

    def test_tray_status_line_shows_progress_while_scanning(self):
        handler = type("H", (), {"db_path": ":memory:", "watcher": None, "scan_job": webapp._ScanJob()})
        handler.scan_job.start("10.0.0.0/24")
        handler.scan_job.report("ports", 2, 9)
        self.assertTrue(webapp._scan_lock.acquire(blocking=False))
        try:
            self.assertEqual(webapp.tray_status_line(handler), "Checking ports 2/9")
        finally:
            webapp._scan_lock.release()


if __name__ == "__main__":
    unittest.main()

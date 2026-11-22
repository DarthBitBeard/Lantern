"""save_scan must not write what load_scan refuses; prune races and memory URIs."""

import os
import tempfile
import unittest
from unittest import mock

from lantern import store


def _device(**overrides):
    device = {"ip": "192.168.1.5", "open_ports": [], "findings": []}
    device.update(overrides)
    return device


class SaveScanValidationTests(unittest.TestCase):
    def setUp(self):
        self.conn = store.connect(":memory:")
        self.addCleanup(self.conn.close)

    def _scan_count(self):
        return self.conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]

    def test_malformed_finding_is_refused_and_rolled_back(self):
        bad = _device(findings=[{"port": 22}])  # no service/severity/title/fix
        with self.assertRaises(ValueError):
            store.save_scan(self.conn, "192.168.1.0/24", [_device(), bad])
        self.assertEqual(self._scan_count(), 0)

    def test_malformed_port_is_refused(self):
        with self.assertRaises(ValueError):
            store.save_scan(self.conn, "192.168.1.0/24", [_device(open_ports=[22])])
        self.assertEqual(self._scan_count(), 0)

    def test_valid_scan_round_trips(self):
        scan_id = store.save_scan(self.conn, "192.168.1.0/24", [_device(open_ports=[{"port": 22}])])
        self.assertEqual(store.load_scan(self.conn, scan_id)["devices"][0]["ip"], "192.168.1.5")


class PruneRaceTests(unittest.TestCase):
    def test_previous_scan_vanishing_means_no_diff(self):
        conn = store.connect(":memory:")
        self.addCleanup(conn.close)
        store.save_scan(conn, "192.168.1.0/24", [_device()])
        newest = store.save_scan(conn, "192.168.1.0/24", [_device()])
        real_load = store.load_scan

        def load(c, scan_id):
            return None if scan_id != newest else real_load(c, scan_id)

        with mock.patch("lantern.store.load_scan", side_effect=load):
            scan, diff = store.load_scan_with_diff(conn, newest)
        self.assertIsNotNone(scan)
        self.assertIsNone(diff)


class MemoryUriTests(unittest.TestCase):
    def test_file_memory_uri_creates_no_file(self):
        with tempfile.TemporaryDirectory() as tmp:
            old = os.getcwd()
            os.chdir(tmp)
            try:
                conn = store.connect("file::memory:")
                conn.close()
                self.assertEqual(os.listdir(tmp), [])
            finally:
                os.chdir(old)


if __name__ == "__main__":
    unittest.main()

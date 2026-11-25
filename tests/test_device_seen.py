"""Schema 8: first/last seen is kept in device_seen and matches the stored history."""

import os
import sqlite3
import tempfile
import time
import unittest

from lantern import store, v1


def _device(ip, mac=None):
    return {"ip": ip, "mac": mac, "open_ports": [], "findings": []}


def _bounds_from_history(conn):
    """The pre-schema-8 aggregate, as the reference answer."""
    found = {}
    for ip, mac, first, last in conn.execute(
        "SELECT d.ip, d.mac, MIN(s.started_at), MAX(s.started_at)"
        " FROM devices d JOIN scans s ON s.id = d.scan_id GROUP BY d.ip, d.mac"
    ):
        kind_key = store._seen_key(ip, mac)
        if kind_key is None:
            continue
        key = (kind_key[1], kind_key[0])
        old = found.get(key)
        found[key] = (first, last) if old is None else (min(old[0], first), max(old[1], last))
    return found


class DeviceSeenTests(unittest.TestCase):
    def setUp(self):
        self.folder = tempfile.mkdtemp()
        self.path = os.path.join(self.folder, "l.db")
        self.conn = store.connect(self.path)
        # A test may reopen the database; close whichever connection is current.
        self.addCleanup(lambda: self.conn.close())

    def test_saving_scans_keeps_bounds_equal_to_history(self):
        store.save_scan(self.conn, "192.168.1.0/24", [_device("192.168.1.2", "AA-BB-CC-DD-EE-01"), _device("192.168.1.3")])
        time.sleep(0.01)
        store.save_scan(self.conn, "192.168.1.0/24", [_device("192.168.1.9", "aa:bb:cc:dd:ee:01"), _device("192.168.1.4")])
        self.assertEqual(v1._seen_bounds(self.conn), _bounds_from_history(self.conn))
        first, last = v1._seen_bounds(self.conn)[("aa:bb:cc:dd:ee:01", "mac")]
        self.assertLess(first, last)  # one device across both scans, by MAC

    def test_prune_moves_first_seen_forward(self):
        old = store.save_scan(self.conn, "192.168.1.0/24", [_device("192.168.1.2", "aa:bb:cc:dd:ee:02")])
        time.sleep(0.01)
        store.save_scan(self.conn, "192.168.1.0/24", [_device("192.168.1.2", "aa:bb:cc:dd:ee:02")])
        before = v1._seen_bounds(self.conn)[("aa:bb:cc:dd:ee:02", "mac")]
        store.delete_scans(self.conn, [old])
        after = v1._seen_bounds(self.conn)[("aa:bb:cc:dd:ee:02", "mac")]
        self.assertGreater(after[0], before[0])
        self.assertEqual(v1._seen_bounds(self.conn), _bounds_from_history(self.conn))

    def test_a_device_only_in_deleted_scans_is_forgotten(self):
        gone = store.save_scan(self.conn, "192.168.1.0/24", [_device("192.168.1.77")])
        store.save_scan(self.conn, "192.168.1.0/24", [_device("192.168.1.2")])
        store.delete_scans(self.conn, [gone])
        self.assertNotIn(("192.168.1.77", "ip"), v1._seen_bounds(self.conn))

    def test_schema_7_database_is_filled_on_upgrade(self):
        store.save_scan(self.conn, "192.168.1.0/24", [_device("192.168.1.2", "aa:bb:cc:dd:ee:03")])
        self.conn.close()
        raw = sqlite3.connect(self.path)
        raw.execute("DROP TABLE device_seen")
        raw.execute("DROP INDEX scans_scope_id")
        raw.execute("DELETE FROM schema_version WHERE version >= 8")
        raw.commit()
        raw.close()
        self.conn = store.connect(self.path)
        self.assertEqual(store.schema_version(self.conn), store.SCHEMA_VERSION)
        self.assertIn(("aa:bb:cc:dd:ee:03", "mac"), v1._seen_bounds(self.conn))
        self.assertTrue(any(name.endswith(".v7.bak") for name in os.listdir(self.folder)))

    def test_reading_bounds_does_not_scan_device_history(self):
        plan = " ".join(row[-1] for row in self.conn.execute(
            "EXPLAIN QUERY PLAN SELECT kind, key, first_seen, last_seen FROM device_seen"
        ))
        self.assertNotIn("devices", plan)


if __name__ == "__main__":
    unittest.main()

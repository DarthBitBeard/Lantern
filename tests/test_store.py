"""SQLite history, trust, and diff logic against an in-memory database."""

import unittest

from lantern import demo
from lantern.store import (
    apply_trust,
    connect,
    diff_scans,
    get_trusted,
    latest_scan_id,
    list_scans,
    load_scan,
    load_scan_with_diff,
    previous_scan_id,
    save_scan,
    set_trusted,
)


def _dev(ip, mac=None, ports=()):
    return {"ip": ip, "mac": mac, "hostname": None, "label": None,
            "open_ports": [{"port": p, "open": True, "banner": ""} for p in ports],
            "findings": []}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")

    def tearDown(self):
        self.conn.close()

    def test_empty_db(self):
        self.assertIsNone(latest_scan_id(self.conn))
        self.assertEqual(list_scans(self.conn), [])
        self.assertEqual(load_scan_with_diff(self.conn), (None, None))
        self.assertEqual(load_scan_with_diff(self.conn, 42), (None, None))
        self.assertIsNone(load_scan(self.conn, 1))

    def test_devices_sorted_numerically(self):
        scan_id = save_scan(self.conn, "10.0.0.0/24", [_dev("10.0.0.10"), _dev("10.0.0.2"), _dev("10.0.0.1")])
        scan = load_scan(self.conn, scan_id)
        self.assertEqual([d["ip"] for d in scan["devices"]], ["10.0.0.1", "10.0.0.2", "10.0.0.10"])

    def test_history_and_previous(self):
        id1 = save_scan(self.conn, "10.0.0.0/24", [_dev("10.0.0.1")], demo=True)
        id2 = save_scan(self.conn, "10.0.0.0/24", [])
        self.assertEqual(latest_scan_id(self.conn), id2)
        self.assertIsNone(previous_scan_id(self.conn, id1))
        self.assertEqual(previous_scan_id(self.conn, id2), id1)
        scans = list_scans(self.conn)
        self.assertEqual([s["id"] for s in scans], [id2, id1])
        self.assertEqual(scans[1]["device_count"], 1)
        self.assertTrue(scans[1]["demo"])
        self.assertFalse(scans[0]["demo"])

    def test_load_scan_with_diff_applies_trust_and_diffs_previous(self):
        id1 = save_scan(self.conn, demo.DEMO_SUBNET, demo.demo_scan_1(), demo=True)
        id2 = save_scan(self.conn, demo.DEMO_SUBNET, demo.demo_scan_2(), demo=True)
        set_trusted(self.conn, "DE:AD:BE:EF:00:99", "  Mystery box ", True)

        scan, diff = load_scan_with_diff(self.conn)
        self.assertEqual(scan["id"], id2)
        self.assertEqual([d["ip"] for d in diff["added"]], ["192.168.1.99"])
        new_device = next(d for d in scan["devices"] if d["ip"] == "192.168.1.99")
        self.assertTrue(new_device["trusted"])
        self.assertTrue(new_device["known"])
        self.assertEqual(new_device["label"], "Mystery box")

        first, first_diff = load_scan_with_diff(self.conn, id1)
        self.assertEqual(first["id"], id1)
        self.assertIsNone(first_diff)
        self.assertFalse(first["devices"][0]["trusted"])

    def test_set_trusted_upsert_and_untrust(self):
        set_trusted(self.conn, "aa:bb:cc:dd:ee:ff", "TV", True)
        set_trusted(self.conn, "AA:BB:CC:DD:EE:FF", "", False)
        self.assertEqual(get_trusted(self.conn), {"aa:bb:cc:dd:ee:ff": {"label": None, "trusted": False}})
        with self.assertRaises(ValueError):
            set_trusted(self.conn, "  ", "x", True)

    def test_apply_trust_handles_none_and_missing_mac(self):
        self.assertIsNone(apply_trust(None, {}))
        scan = {"devices": [_dev("10.0.0.1")]}
        apply_trust(scan, {"": {"label": "nope", "trusted": True}})
        self.assertFalse(scan["devices"][0]["trusted"])
        self.assertIsNone(scan["devices"][0]["label"])


class DiffTests(unittest.TestCase):
    def test_mac_keyed_ip_move_and_port_changes(self):
        old = {"devices": [_dev("10.0.0.5", "aa:aa:aa:aa:aa:01", [22, 80]), _dev("10.0.0.9", None, [443])]}
        new = {"devices": [_dev("10.0.0.6", "AA:AA:AA:AA:AA:01", [22, 23]), _dev("10.0.0.7", None, [443])]}
        diff = diff_scans(old, new)
        self.assertEqual([d["ip"] for d in diff["added"]], ["10.0.0.7"])
        self.assertEqual([d["ip"] for d in diff["removed"]], ["10.0.0.9"])
        self.assertEqual(len(diff["changed"]), 1)
        change = diff["changed"][0]
        self.assertEqual(change["old_ip"], "10.0.0.5")
        self.assertEqual(change["device"]["ip"], "10.0.0.6")
        self.assertEqual((change["opened"], change["closed"]), ([23], [80]))

    def test_no_change_is_empty(self):
        scan = {"devices": [_dev("10.0.0.5", "aa:aa:aa:aa:aa:01", [22])]}
        self.assertEqual(diff_scans(scan, scan), {"added": [], "removed": [], "changed": []})


if __name__ == "__main__":
    unittest.main()

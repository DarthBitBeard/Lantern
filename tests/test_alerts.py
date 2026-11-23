"""Alerts: which diff entries are worth a notification, and how they read."""

import os
import tempfile
import unittest

from lantern import alerts, store, webapp


def _device(ip, *ports, label=None, known=False, mac=None):
    return {"ip": ip, "mac": mac, "label": label, "known": known,
            "open_ports": [{"port": p} for p in ports], "findings": []}


class SummarizeTests(unittest.TestCase):
    def test_nothing_new_is_no_alert(self):
        self.assertIsNone(alerts.summarize(None))
        self.assertIsNone(alerts.summarize({"added": [], "removed": [_device("10.0.0.2")], "changed": []}))
        moved = {"device": _device("10.0.0.3"), "opened": [], "closed": [22], "old_ip": "10.0.0.9",
                 "service_changes": []}
        self.assertIsNone(alerts.summarize({"added": [], "removed": [], "changed": [moved]}))

    def test_new_unknown_device(self):
        alert = alerts.summarize({"added": [_device("10.0.0.5", 80, label="Printer")], "removed": [], "changed": []})
        self.assertEqual(alert.title, "Lantern: 1 new device")
        self.assertEqual(alert.text, "New: Printer.")

    def test_a_known_device_coming_back_is_quiet(self):
        diff = {"added": [_device("10.0.0.5", known=True, mac="aa:bb:cc:dd:ee:ff")], "removed": [], "changed": []}
        self.assertIsNone(alerts.summarize(diff))

    def test_risky_ports_on_new_and_existing_devices(self):
        change = {"device": _device("10.0.0.7", label="NAS"), "opened": [80, 3389], "closed": [],
                  "old_ip": "10.0.0.7", "service_changes": []}
        alert = alerts.summarize({"added": [_device("10.0.0.8", 23)], "removed": [], "changed": [change]})
        self.assertEqual(alert.title, "Lantern: 1 new device, 2 risky ports opened")
        self.assertIn("Opened: 10.0.0.8 port 23, NAS port 3389.", alert.text)
        self.assertNotIn("port 80", alert.text)  # low severity is not an alert

    def test_service_change(self):
        change = {"device": _device("10.0.0.9", label="Pi"), "opened": [], "closed": [], "old_ip": "10.0.0.9",
                  "service_changes": [{"port": 22, "old": "OpenSSH 8.9", "new": "OpenSSH 9.6"}]}
        alert = alerts.summarize({"added": [], "removed": [], "changed": [change]})
        self.assertEqual(alert.title, "Lantern: service changed")
        self.assertEqual(alert.text, "Changed: Pi port 22 is now OpenSSH 9.6.")

    def test_names_are_cleaned_and_lists_are_capped(self):
        added = [_device(f"10.0.0.{i}", label=f"Box\u202e{i}") for i in range(10, 16)]
        alert = alerts.summarize({"added": added, "removed": [], "changed": []})
        self.assertNotIn("\u202e", alert.text)
        self.assertIn("and 3 more", alert.text)
        self.assertLessEqual(len(alert.title), alerts.TITLE_MAX)
        self.assertLessEqual(len(alert.text), alerts.TEXT_MAX)

    def test_long_text_is_cut_to_the_notification_limit(self):
        change = {"device": _device("10.0.0.9", label="x" * 40), "opened": [], "closed": [],
                  "old_ip": "10.0.0.9",
                  "service_changes": [{"port": p, "old": "a 1", "new": "B" * 40 + " 2"} for p in range(1, 6)]}
        added = [_device("10.0.0.1", label="y" * 40)]
        alert = alerts.summarize({"added": added, "removed": [], "changed": [change]})
        self.assertLessEqual(len(alert.text), alerts.TEXT_MAX)


class ListenerTests(unittest.TestCase):
    def test_listener_alerts_on_a_new_device_after_a_saved_scan(self):
        db = os.path.join(tempfile.mkdtemp(), "a.db")
        conn = store.connect(db)
        try:
            store.save_scan(conn, "10.0.0.0/24", [_device("10.0.0.2")])
            second = store.save_scan(conn, "10.0.0.0/24", [_device("10.0.0.2"), _device("10.0.0.3", 23)])
        finally:
            conn.close()
        got = []
        webapp.alert_listener(db, got.append)(second)
        self.assertEqual(len(got), 1)
        self.assertIn("1 new device", got[0].title)
        self.assertIn("10.0.0.3 port 23", got[0].text)

    def test_first_scan_has_nothing_to_compare(self):
        db = os.path.join(tempfile.mkdtemp(), "a.db")
        conn = store.connect(db)
        try:
            first = store.save_scan(conn, "10.0.0.0/24", [_device("10.0.0.2")])
        finally:
            conn.close()
        got = []
        webapp.alert_listener(db, got.append)(first)
        self.assertEqual(got, [])


if __name__ == "__main__":
    unittest.main()

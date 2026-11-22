"""Diffs report a changed service product/version on a port open in both scans."""

import unittest

from lantern import report, store


def _port(port, product=None, version=None):
    entry = {"port": port}
    if product:
        entry["fingerprint"] = {"product": product, "version": version}
    return entry


def _scan(*ports, ip="192.168.1.5", mac="aa:bb:cc:dd:ee:ff"):
    return {"devices": [{"ip": ip, "mac": mac, "open_ports": list(ports), "findings": []}]}


class ServiceDiffTests(unittest.TestCase):
    def test_version_change_is_reported(self):
        diff = store.diff_scans(_scan(_port(22, "OpenSSH", "8.9")), _scan(_port(22, "OpenSSH", "9.6")))
        self.assertEqual(len(diff["changed"]), 1)
        change = diff["changed"][0]
        self.assertEqual(change["opened"], [])
        self.assertEqual(change["service_changes"], [{"port": 22, "old": "OpenSSH 8.9", "new": "OpenSSH 9.6"}])
        self.assertIn("port 22 changed from OpenSSH 8.9 to OpenSSH 9.6", report.describe_change(change))

    def test_same_version_is_not_a_change(self):
        diff = store.diff_scans(_scan(_port(22, "OpenSSH", "9.6")), _scan(_port(22, "OpenSSH", "9.6")))
        self.assertEqual(diff["changed"], [])

    def test_scan_without_fingerprints_is_not_noise(self):
        diff = store.diff_scans(_scan(_port(22)), _scan(_port(22, "OpenSSH", "9.6")))
        self.assertEqual(diff["changed"], [])

    def test_port_changes_still_carry_an_empty_list(self):
        diff = store.diff_scans(_scan(_port(22)), _scan(_port(22), _port(80)))
        self.assertEqual(diff["changed"][0]["opened"], [80])
        self.assertEqual(diff["changed"][0]["service_changes"], [])


if __name__ == "__main__":
    unittest.main()

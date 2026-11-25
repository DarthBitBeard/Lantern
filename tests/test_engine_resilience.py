"""One failing host or optional lookup must not discard the rest of a scan."""

import ipaddress
import unittest
from unittest import mock

from lantern import engine


def _fake_device(ip, macs, ports, *, fingerprint=True, **_extra):
    return {"ip": ip, "mac": None, "hostname": None, "open_ports": [],
            "findings": [], "label": None}


class ScanResilienceTests(unittest.TestCase):
    def test_one_failing_host_keeps_the_others(self):
        def flaky(ip, macs, ports, *, fingerprint=True, **_extra):
            if ip == "192.168.1.2":
                raise RuntimeError("boom")
            return _fake_device(ip, macs, ports)

        hosts = ["192.168.1.1", "192.168.1.2", "192.168.1.3"]
        with mock.patch("lantern.engine.arp_table", return_value={}), \
                mock.patch("lantern.engine.ping_host", return_value=True), \
                mock.patch("lantern.engine.scan_one", side_effect=flaky), \
                self.assertLogs("lantern.engine", level="WARNING"):
            devices = engine.scan_hosts(hosts)
        self.assertEqual([d["ip"] for d in devices], ["192.168.1.1", "192.168.1.3"])

    def test_identity_failure_keeps_port_scan(self):
        with mock.patch("lantern.engine.discover_identities", side_effect=OSError("mdns")), \
                mock.patch("lantern.engine.local_ipv4_in", return_value=None), \
                mock.patch("lantern.engine.scan_hosts", return_value=[_fake_device("192.168.1.5", {}, [])]), \
                mock.patch("lantern.engine.default_gateways", return_value=[]), \
                self.assertLogs("lantern.engine", level="WARNING"):
            devices, info = engine.scan_subnet("192.168.1.0/30")
        self.assertEqual(len(devices), 1)
        self.assertIn("gateway_ip", info)

    def test_bad_gateway_candidate_does_not_hide_later_ones(self):
        devices = [{"ip": "192.168.1.1", "mac": "aa:bb:cc:dd:ee:ff"}]
        network = ipaddress.ip_network("192.168.1.0/24")
        with mock.patch("lantern.engine.default_gateways",
                        return_value=["not-an-ip", "192.168.1.1"]):
            info = engine.describe_network(network, devices)
        self.assertEqual(info["gateway_ip"], "192.168.1.1")


if __name__ == "__main__":
    unittest.main()

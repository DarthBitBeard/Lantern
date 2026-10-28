"""Subnet validation, neighbor-cache parsing, and ping flags. Offline."""

import time
import unittest
from unittest import mock

from lantern import discovery
from lantern.discovery import (
    MAX_SCAN_HOSTS,
    MIN_PREFIXLEN,
    guess_subnet,
    merged_address_count,
    parse_neighbors,
    ping_command,
    validate_subnet,
)


class ValidateSubnetTests(unittest.TestCase):
    def test_host_bits_are_dropped(self):
        self.assertEqual(str(validate_subnet(" 192.168.1.37/24 ")), "192.168.1.0/24")

    def test_merged_address_count_collapses_overlap(self):
        wide = validate_subnet("192.168.0.0/22")
        inside = validate_subnet("192.168.2.0/24")
        other = validate_subnet("10.1.0.0/24")
        self.assertEqual(merged_address_count([wide, inside]), wide.num_addresses)
        self.assertEqual(
            merged_address_count([wide, other]),
            wide.num_addresses + other.num_addresses,
        )
        self.assertEqual(merged_address_count([]), 0)

    def test_largest_allowed_prefix(self):
        network = validate_subnet(f"10.1.0.0/{MIN_PREFIXLEN}")
        self.assertEqual(network.num_addresses, MAX_SCAN_HOSTS)
        with self.assertRaises(ValueError) as ctx:
            validate_subnet(f"10.1.0.0/{MIN_PREFIXLEN - 1}")
        self.assertIn(str(MAX_SCAN_HOSTS), str(ctx.exception))

    def test_all_rfc1918_ranges_accepted(self):
        for text in ("10.0.0.0/24", "172.16.5.0/24", "192.168.0.0/24"):
            self.assertEqual(str(validate_subnet(text)), text)

    def test_rejects_blocks_that_is_private_would_allow(self):
        for text in (
            "0.0.0.0/24",
            "240.0.0.0/24",
            "192.0.0.0/24",
            "192.0.2.0/24",
            "198.51.100.0/24",
            "203.0.113.0/24",
            "198.18.0.0/24",
            "100.64.0.0/24",
        ):
            with self.assertRaises(ValueError, msg=text) as ctx:
                validate_subnet(text)
            self.assertIn("10.0.0.0/8", str(ctx.exception), text)

    def test_rejects_ipv6_loopback_link_local_and_garbage(self):
        for text in ("fd00::/64", "127.0.0.0/24", "169.254.0.0/24", "not a subnet", "", "192.168.1.0/"):
            with self.assertRaises(ValueError, msg=text):
                validate_subnet(text)

    def test_rejects_non_string_without_crashing_oddly(self):
        with self.assertRaises(ValueError):
            validate_subnet(["192.168.1.0/24"])


class ParseNeighborsTests(unittest.TestCase):
    def test_proc_net_arp(self):
        text = (
            "IP address       HW type     Flags       HW address            Mask     Device\n"
            "192.168.1.1      0x1         0x2         36:FB:92:09:C4:64     *        eth0\n"
            "192.168.1.77     0x1         0x0         00:00:00:00:00:00     *        eth0\n"
        )
        self.assertEqual(parse_neighbors(text), {"192.168.1.1": "36:fb:92:09:c4:64"})

    def test_arp_a_linux_and_mac_and_windows(self):
        text = (
            "? (192.168.1.1) at 36:fb:92:09:c4:64 [ether] on eth0\n"
            "? (192.168.1.5) at <incomplete> on eth0\n"
            "router.lan (192.168.1.2) at aa:bb:cc:dd:ee:ff on en0 ifscope [ethernet]\n"
            "  192.168.1.3           00-11-22-33-44-55     dynamic\n"
        )
        self.assertEqual(parse_neighbors(text), {
            "192.168.1.1": "36:fb:92:09:c4:64",
            "192.168.1.2": "aa:bb:cc:dd:ee:ff",
            "192.168.1.3": "00:11:22:33:44:55",
        })

    def test_ip_neigh_and_bad_ips_skipped(self):
        text = (
            "192.168.1.9 dev eth0 lladdr 11:22:33:44:55:66 REACHABLE\n"
            "999.1.1.1 dev eth0 lladdr 11:22:33:44:55:67 STALE\n"
            "fe80::1 dev eth0 lladdr 11:22:33:44:55:68 STALE\n"
        )
        self.assertEqual(parse_neighbors(text), {"192.168.1.9": "11:22:33:44:55:66"})

    def test_arp_table_never_raises(self):
        with mock.patch.object(discovery.subprocess, "run", side_effect=OSError("no arp")):
            with mock.patch.object(discovery.Path, "is_file", return_value=False):
                self.assertEqual(discovery.arp_table(), {})


class PingCommandTests(unittest.TestCase):
    def test_per_platform_wait_flags(self):
        self.assertEqual(ping_command("10.0.0.1", 1000, "Linux"), ["ping", "-c", "1", "-W", "1", "10.0.0.1"])
        self.assertEqual(ping_command("10.0.0.1", 1000, "Darwin"), ["ping", "-c", "1", "-t", "1", "10.0.0.1"])
        self.assertEqual(ping_command("10.0.0.1", 500, "Windows"), ["ping", "-n", "1", "-w", "500", "10.0.0.1"])

    def test_ping_host_failure_is_false(self):
        with mock.patch.object(discovery.subprocess, "run", side_effect=OSError("no ping")):
            self.assertFalse(discovery.ping_host("10.0.0.1"))


class GuessSubnetTests(unittest.TestCase):
    def test_skips_loopback_and_public_candidates(self):
        with mock.patch.object(discovery, "_local_ipv4_candidates", return_value=["127.0.0.1", "8.8.8.8", "10.4.5.6"]):
            self.assertEqual(guess_subnet(), "10.4.5.0/24")

    def test_none_when_nothing_private(self):
        with mock.patch.object(discovery, "_local_ipv4_candidates", return_value=["127.0.0.1", "garbage"]):
            self.assertIsNone(guess_subnet())

    def test_hostname_fallback_when_udp_route_fails(self):
        with mock.patch.object(discovery.socket, "socket", side_effect=OSError("no route")), \
                mock.patch.object(discovery.socket, "gethostbyname", return_value="10.4.5.6"), \
                mock.patch.object(discovery.socket, "gethostname", return_value="lantern-test"):
            self.assertEqual(guess_subnet(), "10.4.5.0/24")

    def test_slow_hostname_lookup_does_not_stall(self):
        def hang(_name):
            time.sleep(5)
            return "10.9.9.9"

        started = time.monotonic()
        with mock.patch.object(discovery.socket, "socket", side_effect=OSError("no route")), \
                mock.patch.object(discovery.socket, "gethostbyname", side_effect=hang), \
                mock.patch.object(discovery.socket, "gethostname", return_value="lantern-test"):
            self.assertIsNone(guess_subnet())
        self.assertLess(time.monotonic() - started, 2.0)


if __name__ == "__main__":
    unittest.main()

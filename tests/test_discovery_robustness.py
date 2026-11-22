"""macOS-style ARP octets and undecodable command output."""

import subprocess
import unittest
from unittest import mock

from lantern import discovery


class MacParsingTests(unittest.TestCase):
    def test_macos_unpadded_octets_are_normalized(self):
        text = "? (192.168.1.10) at 0:1a:2b:3c:4d:5e on en0 ifscope [ethernet]"
        self.assertEqual(discovery.parse_neighbors(text), {"192.168.1.10": "00:1a:2b:3c:4d:5e"})

    def test_padded_linux_and_windows_forms_still_work(self):
        text = (
            "192.168.1.1 dev eth0 lladdr AA:BB:CC:DD:EE:FF REACHABLE\n"
            "  192.168.1.2          aa-bb-cc-dd-ee-01     dynamic\n"
        )
        self.assertEqual(
            discovery.parse_neighbors(text),
            {"192.168.1.1": "aa:bb:cc:dd:ee:ff", "192.168.1.2": "aa:bb:cc:dd:ee:01"},
        )

    def test_unpadded_all_zero_and_incomplete_are_skipped(self):
        text = (
            "? (192.168.1.3) at 0:0:0:0:0:0 on en0\n"
            "? (192.168.1.4) at (incomplete) on en0\n"
        )
        self.assertEqual(discovery.parse_neighbors(text), {})

    def test_longer_hex_run_is_not_cut_into_a_mac(self):
        # Seven groups: no six-group MAC may be carved out of the middle.
        self.assertEqual(
            discovery.parse_neighbors("192.168.1.5 at 1:2:3:4:5:6:7"), {},
        )


class RunTextTests(unittest.TestCase):
    def test_undecodable_bytes_do_not_blank_the_output(self):
        result = subprocess.CompletedProcess([], 0, stdout=b"192.168.1.9 \xff\xfe aa:bb:cc:dd:ee:ff\n")
        with mock.patch.object(discovery.subprocess, "run", return_value=result):
            text = discovery._run_text(["arp", "-a"])
        self.assertEqual(discovery.parse_neighbors(text), {"192.168.1.9": "aa:bb:cc:dd:ee:ff"})

    def test_failure_still_returns_empty_text(self):
        with mock.patch.object(discovery.subprocess, "run", side_effect=OSError("missing")):
            self.assertEqual(discovery._run_text(["arp", "-a"]), "")


if __name__ == "__main__":
    unittest.main()

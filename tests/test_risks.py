"""Risk rules and safety guardrails. Offline."""

import unittest

from lantern.discovery import guess_subnet, validate_subnet
from lantern.ports import DEFAULT_PORTS, PORT_RULES, SEVERITY_RANK, findings_for_ports
from lantern.webapp import WEB_DIR


class RiskRuleTests(unittest.TestCase):
    def test_telnet_is_critical(self):
        findings = findings_for_ports([23, 443])
        self.assertEqual(findings[0]["port"], 23)
        self.assertEqual(findings[0]["severity"], "critical")

    def test_findings_sorted_worst_first(self):
        findings = findings_for_ports([443, 22, 3389, 6379])
        severities = [f["severity"] for f in findings]
        self.assertEqual(severities, sorted(severities, key=SEVERITY_RANK.get))

    def test_unknown_port_is_low_with_a_fix(self):
        (finding,) = findings_for_ports([9100])
        self.assertEqual(finding["service"], "unknown")
        self.assertEqual(finding["severity"], "low")
        self.assertTrue(finding["fix"])

    def test_every_rule_has_plain_english_and_known_severity(self):
        for port, (service, severity, title, fix) in PORT_RULES.items():
            self.assertIn(severity, SEVERITY_RANK, port)
            self.assertTrue(service and title and fix, port)
        self.assertEqual(DEFAULT_PORTS, sorted(PORT_RULES))


class SafetyTests(unittest.TestCase):
    def test_public_subnet_refused(self):
        with self.assertRaises(ValueError):
            validate_subnet("8.8.8.0/24")

    def test_too_large_subnet_refused(self):
        with self.assertRaises(ValueError):
            validate_subnet("10.0.0.0/8")

    def test_dashboard_assets_present(self):
        """pip install / Docker must ship lantern/web, not only .py files."""
        for name in ("index.html", "styles.css", "app.js"):
            self.assertTrue((WEB_DIR / name).is_file(), f"missing dashboard asset: {name}")

    def test_guess_subnet_private_or_none(self):
        """Auto-detect must never return a public or loopback network."""
        subnet = guess_subnet()
        if subnet is None:
            return
        network = validate_subnet(subnet)
        self.assertTrue(network.is_private)
        self.assertEqual(network.prefixlen, 24)


if __name__ == "__main__":
    unittest.main()

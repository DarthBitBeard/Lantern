"""Stored banner fingerprints are shown: the report, /api/v1 ports, and the services export."""

import contextlib
import csv
import io
import json
import os
import tempfile
import unittest

from lantern import cli, report, store, v1


def _fp(product, version, service="ssh", status="ok"):
    return {"port": 22, "service": service, "product": product, "version": version,
            "raw_banner": f"SSH-2.0-{product}_{version}", "parse_status": status}


class FingerprintViewTests(unittest.TestCase):
    def setUp(self):
        self.db = os.path.join(tempfile.mkdtemp(), "f.db")
        conn = store.connect(self.db)
        try:
            self.scan_id = store.save_scan(conn, "10.0.0.0/24", [{
                "ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:02", "findings": [],
                "open_ports": [
                    {"port": 22, "banner": "SSH-2.0-OpenSSH_9.6", "fingerprint": _fp("OpenSSH", "9.6")},
                    {"port": 443},
                ],
            }])
        finally:
            conn.close()

    def cli(self, *argv):
        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main([*argv, "--db", self.db])
        return code, out.getvalue(), err.getvalue()

    def test_service_label(self):
        self.assertEqual(report.service_label(_fp("OpenSSH", "9.6")), "OpenSSH 9.6")
        self.assertEqual(report.service_label({"product": "nginx", "version": None}), "nginx")
        self.assertIsNone(report.service_label({"product": None}))
        self.assertIsNone(report.service_label(None))

    def test_api_ports_carry_the_fingerprint_without_the_raw_banner(self):
        conn = store.connect(self.db)
        try:
            doc = v1.devices_document(conn, {"scan_id": [str(self.scan_id)]})
        finally:
            conn.close()
        ports = {p["port"]: p for p in doc["items"][0]["open_ports"]}
        self.assertEqual(ports[22]["fingerprint"],
                         {"service": "ssh", "product": "OpenSSH", "version": "9.6", "parse_status": "ok"})
        self.assertIsNone(ports[443]["fingerprint"])

    def test_large_scan_paths_also_attach_fingerprints(self):
        conn = store.connect(self.db)
        try:
            streamed = list(v1._iter_export_devices(conn, self.scan_id, private=False, tags=[], criticality=None))
            stored = list(v1._iter_stored_devices(conn, self.scan_id))
        finally:
            conn.close()
        self.assertEqual(streamed[0]["open_ports"][0]["fingerprint"]["product"], "OpenSSH")
        ports = {p["port"]: p for p in stored[0]["open_ports"]}
        self.assertEqual(ports[22]["fingerprint"]["version"], "9.6")
        self.assertIsNone(ports[443]["fingerprint"])

    def test_report_lists_services(self):
        conn = store.connect(self.db)
        try:
            scan, diff = store.load_scan_with_diff(conn, self.scan_id)
        finally:
            conn.close()
        self.assertIn("Services (as reported by the device): 22 OpenSSH 9.6", report.to_html(scan, diff))

    def test_services_export_json_and_csv(self):
        code, out, err = self.cli("export", "--what", "services", "--format", "json")
        self.assertEqual(code, 0, err)
        items = json.loads(out)["items"]
        self.assertEqual(items, [{"scan_id": self.scan_id, "ip": "10.0.0.2", "mac": "aa:bb:cc:dd:ee:02",
                                  "port": 22, "service": "ssh", "product": "OpenSSH", "version": "9.6",
                                  "parse_status": "ok"}])
        code, out, err = self.cli("export", "--what", "services", "--format", "csv")
        self.assertEqual(code, 0, err)
        rows = list(csv.reader(io.StringIO(out)))
        self.assertEqual(rows[0], ["scan_id", "ip", "mac", "port", "service", "product", "version", "parse_status"])
        self.assertEqual(rows[1][4:7], ["ssh", "OpenSSH", "9.6"])

    def test_existing_findings_columns_are_unchanged(self):
        code, out, err = self.cli("export", "--what", "findings", "--format", "csv")
        self.assertEqual(code, 0, err)
        self.assertEqual(next(csv.reader(io.StringIO(out))),
                         ["scan_id", "ip", "mac", "port", "service", "severity", "title", "fix"])


if __name__ == "__main__":
    unittest.main()

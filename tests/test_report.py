"""HTML and JSON reports escape untrusted text. No network."""

import json
import unittest

from lantern.report import defuse_csv_cell, to_html, to_json

_PAYLOAD = "<script>alert(1)</script>"


def _scan():
    return {
        "id": 7,
        "started_at": "2026-10-28T00:00:00+00:00",
        "subnet": "192.168.50.0/24",
        "scope_name": _PAYLOAD + "scope",
        "demo": False,
        "devices": [
            {
                "ip": "192.168.50.10",
                "mac": "aa:bb:cc:dd:ee:10",
                "hostname": _PAYLOAD + "hostname",
                "label": _PAYLOAD + "label",
                "owner": _PAYLOAD + "owner",
                "tag": _PAYLOAD + "tag",
                "notes": _PAYLOAD + "notes",
                "open_ports": [{"port": 80, "open": True, "banner": _PAYLOAD + "banner"}],
                "findings": [],
            }
        ],
    }


class ReportEscapeTests(unittest.TestCase):
    def test_html_escapes_scope_and_device_fields(self):
        page = to_html(_scan())
        self.assertNotIn("<script>", page)
        for field in ("scope", "hostname", "label", "owner", "tag", "notes", "banner"):
            self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;" + field, page)

    def test_json_round_trips_the_same_fields(self):
        scan = _scan()
        text = to_json(scan)
        parsed = json.loads(text)
        self.assertEqual(parsed["scope_name"], scan["scope_name"])
        device = parsed["devices"][0]
        self.assertEqual(device["hostname"], scan["devices"][0]["hostname"])
        self.assertEqual(device["label"], scan["devices"][0]["label"])
        self.assertEqual(device["owner"], scan["devices"][0]["owner"])
        self.assertEqual(device["tag"], scan["devices"][0]["tag"])
        self.assertEqual(device["notes"], scan["devices"][0]["notes"])
        self.assertEqual(device["open_ports"][0]["banner"], _PAYLOAD + "banner")
        self.assertIn('\\"', json.dumps({"q": 'say "hi"'}))

    def test_csv_formula_cells_are_prefixed(self):
        for raw in ("=1+1", "+1", "-1", "@sum", "\tcmd", "\rline"):
            self.assertTrue(defuse_csv_cell(raw).startswith("'"), raw)
            self.assertEqual(defuse_csv_cell(raw)[1:], raw)
        self.assertEqual(defuse_csv_cell("router"), "router")
        self.assertEqual(defuse_csv_cell(None), "")
        self.assertEqual(defuse_csv_cell("=cmd")[0], "'")

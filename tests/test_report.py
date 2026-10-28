"""HTML and JSON reports escape untrusted text. No network."""

import json
import unittest

from lantern.report import multi_scope_html, to_html, to_json

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
                "location": _PAYLOAD + "location",
                "tags": [_PAYLOAD + "tag"],
                "criticality": _PAYLOAD + "criticality",
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
        for field in ("scope", "hostname", "label", "owner", "location", "tag", "criticality", "notes", "banner"):
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
        self.assertEqual(device["location"], scan["devices"][0]["location"])
        self.assertEqual(device["tags"], scan["devices"][0]["tags"])
        self.assertEqual(device["criticality"], scan["devices"][0]["criticality"])
        self.assertEqual(device["notes"], scan["devices"][0]["notes"])
        self.assertEqual(device["open_ports"][0]["banner"], _PAYLOAD + "banner")

    def test_inventory_fields_escape_markup_and_bidi(self):
        payloads = ("<img src=x onerror=alert(1)>", '"><script>alert(1)</script>', "safe\u202ehidden")
        for payload in payloads:
            scan = _scan()
            device = scan["devices"][0]
            device["owner"] = payload
            device["location"] = payload
            device["tags"] = [payload]
            device["criticality"] = payload
            device["notes"] = payload
            page = to_html(scan, {"added": [device], "removed": [device], "changed": []})
            self.assertNotIn("<img", page)
            self.assertNotIn("<script>", page)
            self.assertNotIn("\u202e", page)
            if payload.startswith("<"):
                self.assertIn("&lt;img", page)
            if payload.startswith('"'):
                self.assertIn("&quot;&gt;&lt;script&gt;", page)
            text = to_json(scan, {"added": [device], "removed": [], "changed": []})
            parsed = json.loads(text)
            self.assertNotIn("\u202e", text)
            expected = "safehidden" if "\u202e" in payload else payload
            self.assertEqual(parsed["devices"][0]["owner"], expected)
            self.assertEqual(parsed["diff"]["added"][0]["owner"], expected)

    def test_multi_scope_html_escapes_a_failed_scope_error(self):
        page = multi_scope_html([], [("lab", _PAYLOAD)])
        self.assertNotIn("<script>", page)
        self.assertIn("&lt;script&gt;alert(1)&lt;/script&gt;", page)
        self.assertIn("lab", page)

    def test_html_uses_a_dash_when_the_scope_name_strips_away(self):
        planted = "\x1b\u202e\x07\u200b"
        scan = _scan()
        scan["scope_name"] = planted
        scan["devices"] = []
        page = to_html(scan)
        self.assertIn("scope -", page)
        self.assertNotIn("scope  |", page)
        for char in planted:
            self.assertNotIn(char, page)

    def test_multi_scope_html_strips_a_planted_scope_name(self):
        planted = "lab\x1b\u202e\x07\u200bhome"
        scan = _scan()
        scan["scope_name"] = planted
        scan["devices"] = []
        page = multi_scope_html([(scan, None)], [])
        self.assertIn("labhome", page)
        for char in ("\x1b", "\u202e", "\x07", "\u200b"):
            self.assertNotIn(char, page)

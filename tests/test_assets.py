"""Asset inventory. No network. Devices come from saved scans only."""

import json
import os
import stat
import tempfile
import unittest
from pathlib import Path

from lantern import assets, cli
from lantern.store import connect, save_scan


def _device(ip, mac=None):
    return {
        "ip": ip,
        "mac": mac,
        "hostname": None,
        "label": None,
        "open_ports": [],
        "findings": [],
    }


class AssetValidationTests(unittest.TestCase):
    def test_limits_and_character_rules(self):
        self.assertEqual(len(assets.validate_owner("a" * 80)), 80)
        self.assertEqual(len(assets.validate_location("b" * 80)), 80)
        self.assertEqual(len(assets.validate_notes("c" * 500)), 500)
        with self.assertRaises(ValueError):
            assets.validate_owner("a" * 81)
        with self.assertRaises(ValueError):
            assets.validate_location("")
        with self.assertRaises(ValueError):
            assets.validate_notes("n" * 501)
        self.assertEqual(assets.validate_tag("Web_1"), "web_1")
        self.assertEqual(len(assets.validate_tag("a" * 32)), 32)
        for bad in ("", "a" * 33, "has space", "Bad!", "tag/name"):
            with self.assertRaises(ValueError, msg=bad):
                assets.validate_tag(bad)
        self.assertEqual(len(assets.validate_tags([f"t{i}" for i in range(10)])), 10)
        with self.assertRaises(ValueError):
            assets.validate_tags([f"t{i}" for i in range(11)])
        self.assertEqual(assets.validate_criticality("HIGH"), "high")
        with self.assertRaises(ValueError):
            assets.validate_criticality("urgent")
        for value in ("ada\n", "ada\x00", "ada\u202e", "left\u202a", "iso\u2066"):
            with self.assertRaises(ValueError, msg=repr(value)):
                assets.validate_owner(value)
            with self.assertRaises(ValueError, msg=repr(value)):
                assets.validate_location(value)
            with self.assertRaises(ValueError, msg=repr(value)):
                assets.validate_notes(value)
            with self.assertRaises(ValueError, msg=repr(value)):
                assets.validate_tag(value)

    def test_text_output_strips_controls(self):
        self.assertEqual(assets.strip_for_text("ada\x00\n\u202ebob"), "adabob")


class AssetCommandTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "lantern.db")
        self.conn = connect(self.db)
        save_scan(
            self.conn,
            "192.168.50.0/24",
            [_device("192.168.50.10", "AA-BB-CC-DD-EE-10"), _device("192.168.50.11", None)],
            scope_name="home",
        )
        save_scan(
            self.conn,
            "10.50.0.0/24",
            [_device("10.50.0.4", "aa:bb:cc:dd:ee:10")],
            scope_name="lab",
        )
        self.conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def run_cli(self, *args):
        import contextlib
        import io

        out, err = io.StringIO(), io.StringIO()
        with contextlib.redirect_stdout(out), contextlib.redirect_stderr(err):
            code = cli.main(["--db", self.db, *args])
        return code, out.getvalue(), err.getvalue()

    def test_set_requires_a_saved_device_and_persists_across_scans(self):
        code, _, err = self.run_cli("asset", "set", "10.9.9.9", "--owner", "Ada")
        self.assertEqual(code, 2, err)
        self.assertIn("No saved scan contains", err)

        code, out, err = self.run_cli(
            "asset", "set", "aa-bb-cc-dd-ee-10",
            "--owner", "Ada",
            "--location", "Rack A",
            "--tag", "Web",
            "--tag", "db",
            "--criticality", "high",
            "--notes", "Patched",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("aa:bb:cc:dd:ee:10", out)
        self.assertIn("Ada", out)

        code, out, err = self.run_cli("asset", "show", "192.168.50.10", "--format", "json")
        self.assertEqual(code, 0, err)
        shown = json.loads(out)
        self.assertEqual(shown["kind"], "mac")
        self.assertEqual(shown["key"], "aa:bb:cc:dd:ee:10")
        self.assertEqual(shown["owner"], "Ada")
        self.assertEqual(shown["tags"], ["web", "db"])
        self.assertEqual(shown["criticality"], "high")

        conn = connect(self.db)
        try:
            save_scan(
                conn,
                "192.168.50.0/24",
                [_device("192.168.50.20", "aa:bb:cc:dd:ee:10")],
                scope_name="home",
            )
        finally:
            conn.close()
        code, out, err = self.run_cli("report", "--format", "json")
        self.assertEqual(code, 0, err)
        report = json.loads(out)
        device = report["devices"][0]
        self.assertEqual(device["ip"], "192.168.50.20")
        self.assertEqual(device["owner"], "Ada")
        self.assertEqual(device["location"], "Rack A")
        self.assertEqual(device["tags"], ["web", "db"])
        self.assertEqual(device["criticality"], "high")
        self.assertEqual(device["notes"], "Patched")
        code, out, err = self.run_cli("report", "--format", "html")
        self.assertIn("Ada", out)
        self.assertIn("Rack A", out)
        code, out, err = self.run_cli("diff", "--format", "json")
        self.assertEqual(code, 0, err)
        diff = json.loads(out)
        owners = [d.get("owner") for d in diff["added"] + diff["removed"]]
        owners += [c["device"].get("owner") for c in diff["changed"]]
        self.assertIn("Ada", owners)
        tagged = diff["added"] + diff["removed"] + [c["device"] for c in diff["changed"]]
        self.assertTrue(any(d.get("tags") == ["web", "db"] for d in tagged))

        code, out, err = self.run_cli("asset", "list", "--tag", "web", "--owner", "Ada", "--scope", "home")
        self.assertEqual(code, 0, err)
        self.assertIn("Ada", out)
        code, out, err = self.run_cli("asset", "list", "--scope", "lab", "--format", "json")
        self.assertEqual(code, 0, err)
        self.assertEqual(json.loads(out)["assets"][0]["key"], "aa:bb:cc:dd:ee:10")
        code, out, err = self.run_cli("asset", "list", "--criticality", "low", "--format", "json")
        self.assertEqual(json.loads(out)["assets"], [])

        code, _, err = self.run_cli("asset", "clear", "aa:bb:cc:dd:ee:10", "--field", "notes")
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cli("asset", "show", "aa:bb:cc:dd:ee:10", "--format", "json")
        self.assertIsNone(json.loads(out)["notes"])
        self.assertEqual(json.loads(out)["owner"], "Ada")
        code, _, err = self.run_cli("asset", "clear", "aa:bb:cc:dd:ee:10")
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cli("asset", "show", "aa:bb:cc:dd:ee:10")
        self.assertIn("No asset recorded", out)

    def test_ip_only_device_is_keyed_by_ip(self):
        code, _, err = self.run_cli(
            "asset", "set", "192.168.50.11", "--owner", "Bea", "--notes", "solo",
        )
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cli("asset", "show", "192.168.50.11", "--format", "json")
        shown = json.loads(out)
        self.assertEqual(shown["kind"], "ip")
        self.assertEqual(shown["key"], "192.168.50.11")
        self.assertEqual(shown["owner"], "Bea")

    def test_text_list_strips_a_stored_control_character(self):
        conn = connect(self.db)
        try:
            conn.execute(
                "INSERT INTO assets (asset_key, key_kind, owner, location, tags, criticality, notes, updated_at)"
                " VALUES ('mac:aa:bb:cc:dd:ee:10', 'mac', ?, NULL, '[]', NULL, NULL, 't')",
                ("Ada\x00Bee",),
            )
            conn.commit()
        finally:
            conn.close()
        code, out, err = self.run_cli("asset", "list")
        self.assertEqual(code, 0, err)
        self.assertIn("AdaBee", out)
        self.assertNotIn("\x00", out)

    def test_database_stays_private(self):
        if os.name == "nt":
            self.skipTest("POSIX modes")
        self.assertEqual(stat.S_IMODE(Path(self.db).stat().st_mode) & 0o777, 0o600)

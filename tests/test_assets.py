"""Asset inventory. No network. Devices come from saved scans only."""

import json
import os
import sqlite3
import stat
import tempfile
import threading
import time
import unicodedata
import unittest
from pathlib import Path
from unittest import mock

from lantern import assets, cli
from lantern.scopes import MAX_SCOPE_CONFIG_BYTES
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


# Format and separator characters Felix called out. The surrogate is Cs;
# SQLite cannot store it, so the report test uses the scalar values only.
_FORMAT_CHARS = (
    "\u061c",  # Cf Arabic letter mark
    "\u200b",  # Cf zero-width space
    "\u200c",  # Cf zero-width non-joiner
    "\u200d",  # Cf zero-width joiner
    "\u2060",  # Cf word joiner
    "\ufeff",  # Cf BOM
    "\u00ad",  # Cf soft hyphen
    "\U000E0001",  # Cf language tag
    "\u2028",  # Zl line separator
    "\u2029",  # Zp paragraph separator
)
_UNSAFE_CHARS = _FORMAT_CHARS + ("\ud800",)  # Cs surrogate


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

    def test_format_and_separator_characters_are_rejected_and_stripped(self):
        for char in _UNSAFE_CHARS:
            self.assertIn(unicodedata.category(char), assets._UNSAFE_CATEGORIES)
            wrapped = f"Ada{char}Bee"
            for check in (assets.validate_owner, assets.validate_location, assets.validate_notes):
                with self.assertRaises(ValueError, msg=hex(ord(char))):
                    check(wrapped)
                with self.assertRaises(ValueError, msg=hex(ord(char))):
                    check(char)
            self.assertEqual(assets.strip_for_text(wrapped), "AdaBee")
            self.assertEqual(assets.present_text(wrapped), "AdaBee")
            self.assertIsNone(assets.present_text(char))
            self.assertNotIn(char, assets.strip_for_text(wrapped))

    def test_blank_owner_location_and_notes_are_rejected(self):
        for value in ("", " ", "   ", "\u00a0", " \t "):
            for check in (assets.validate_owner, assets.validate_location, assets.validate_notes):
                with self.assertRaises(ValueError, msg=repr(value)):
                    check(value)
        self.assertEqual(assets.validate_owner(" Ada "), " Ada ")

    def test_tag_is_not_rewritten_by_casefold_or_nfkc(self):
        self.assertEqual(assets.validate_tag("Web"), "web")
        for value in ("\u212a", "\u212aelvin", "\u00df", "\uff21", "\uff11"):
            with self.assertRaises(ValueError, msg=repr(value)):
                assets.validate_tag(value)
        self.assertEqual(assets.validate_tags(["web"] * 11), ["web"])
        self.assertEqual(assets.validate_tags(["Web", "web", "WEB"]), ["web"])
        with self.assertRaises(ValueError):
            assets.validate_tags([f"t{i}" for i in range(11)])

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

    def test_blank_values_must_be_cleared(self):
        code, _, err = self.run_cli("asset", "set", "aa:bb:cc:dd:ee:10", "--owner", "   ")
        self.assertEqual(code, 2, err)
        self.assertIn("whitespace", err)
        code, out, err = self.run_cli("asset", "show", "aa:bb:cc:dd:ee:10")
        self.assertIn("No asset recorded", out)
        code, _, err = self.run_cli("asset", "set", "aa:bb:cc:dd:ee:10", "--location", "")
        self.assertEqual(code, 2, err)
        code, _, err = self.run_cli("asset", "set", "aa:bb:cc:dd:ee:10", "--notes", "\u00a0")
        self.assertEqual(code, 2, err)

    def test_kelvin_tag_is_rejected_and_duplicates_do_not_count(self):
        code, _, err = self.run_cli("asset", "set", "aa:bb:cc:dd:ee:10", "--tag", "\u212a")
        self.assertEqual(code, 2, err)
        code, out, err = self.run_cli("asset", "show", "aa:bb:cc:dd:ee:10")
        self.assertIn("No asset recorded", out)
        self.assertNotIn("\u212a", out)
        repeated = []
        for _ in range(11):
            repeated.extend(["--tag", "web"])
        code, _, err = self.run_cli("asset", "set", "aa:bb:cc:dd:ee:10", *repeated)
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cli("asset", "show", "aa:bb:cc:dd:ee:10", "--format", "json")
        self.assertEqual(json.loads(out)["tags"], ["web"])
        unique = []
        for index in range(11):
            unique.extend(["--tag", f"t{index}"])
        code, _, err = self.run_cli("asset", "set", "192.168.50.11", *unique)
        self.assertEqual(code, 2, err)
        self.assertIn("10", err)

    def test_new_inventory_row_stops_at_the_cap(self):
        self.assertEqual(assets.ASSET_ROW_CAP, 10_000)
        conn = connect(self.db)
        try:
            rows = [
                (
                    f"mac:aa:bb:cc:dd:{index // 256:02x}:{index % 256:02x}",
                    "mac",
                    "Old",
                    None,
                    "[]",
                    None,
                    None,
                    "t",
                )
                for index in range(assets.ASSET_ROW_CAP - 1)
            ]
            rows.append(
                ("mac:aa:bb:cc:dd:ee:10", "mac", "Old", None, "[]", None, None, "t")
            )
            conn.executemany(
                "INSERT INTO assets (asset_key, key_kind, owner, location, tags, criticality, notes, updated_at)"
                " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
                rows,
            )
            conn.commit()
        finally:
            conn.close()
        code, _, err = self.run_cli("asset", "set", "192.168.50.11", "--owner", "Bea")
        self.assertEqual(code, 2, err)
        self.assertIn("10000", err)
        self.assertIn("Clear one before adding another", err)
        code, out, err = self.run_cli(
            "asset", "set", "aa:bb:cc:dd:ee:10", "--owner", "Updated",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("Updated", out)

    def test_report_json_and_html_include_inventory_fields(self):
        """Fails if attach_assets is removed from _prepare_report."""
        code, _, err = self.run_cli(
            "asset", "set", "aa:bb:cc:dd:ee:10",
            "--owner", "Ada",
            "--location", "Rack A",
            "--tag", "web",
            "--criticality", "high",
            "--notes", "Patched",
        )
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cli("report", "--format", "json")
        self.assertEqual(code, 0, err)
        device = json.loads(out)["devices"][0]
        self.assertEqual(device["owner"], "Ada")
        self.assertEqual(device["location"], "Rack A")
        self.assertEqual(device["tags"], ["web"])
        self.assertEqual(device["criticality"], "high")
        self.assertEqual(device["notes"], "Patched")
        code, out, err = self.run_cli("report", "--format", "html")
        self.assertEqual(code, 0, err)
        for text in ("Owner: Ada", "Location: Rack A", "Tags: web", "Criticality: high", "Notes: Patched"):
            self.assertIn(text, out)

    def test_report_strips_format_characters(self):
        hidden = "".join(_FORMAT_CHARS)
        conn = connect(self.db)
        try:
            conn.execute(
                "INSERT INTO assets (asset_key, key_kind, owner, location, tags, criticality, notes, updated_at)"
                " VALUES ('mac:aa:bb:cc:dd:ee:10', 'mac', ?, ?, '[]', NULL, ?, 't')",
                (f"Ada{hidden}Bee", f"Rack{hidden}A", f"Note{hidden}s"),
            )
            conn.commit()
        finally:
            conn.close()
        code, out, err = self.run_cli("report", "--format", "json")
        self.assertEqual(code, 0, err)
        device = json.loads(out)["devices"][0]
        self.assertEqual(device["owner"], "AdaBee")
        self.assertEqual(device["location"], "RackA")
        self.assertEqual(device["notes"], "Notes")
        for char in _FORMAT_CHARS:
            self.assertNotIn(char, out)
        code, html, err = self.run_cli("report", "--format", "html")
        self.assertEqual(code, 0, err)
        self.assertIn("AdaBee", html)
        self.assertIn("RackA", html)
        self.assertIn("Notes", html)
        for char in _FORMAT_CHARS:
            self.assertNotIn(char, html)

    def test_asset_list_scope_falls_back_to_a_stored_name(self):
        config = Path(self.tmp.name) / "scopes.toml"
        config.write_text('[scopes.home]\nsubnet = "192.168.50.0/24"\n', encoding="utf-8")
        conn = connect(self.db)
        try:
            save_scan(
                conn,
                "192.168.51.0/24",
                [_device("192.168.51.10", "aa:bb:cc:dd:ee:21")],
                scope_name="Lab-2",
            )
        finally:
            conn.close()
        code, _, err = self.run_cli(
            "asset", "set", "aa:bb:cc:dd:ee:21", "--owner", "Ada",
        )
        self.assertEqual(code, 0, err)
        code, out, err = self.run_cli(
            "asset", "list", "--scope", "lab-2", "--config", str(config), "--format", "json",
        )
        self.assertEqual(code, 0, err)
        listed = json.loads(out)["assets"]
        self.assertEqual([item["owner"] for item in listed], ["Ada"])

    def test_asset_list_scope_keeps_an_exact_stored_spelling(self):
        config = Path(self.tmp.name) / "scopes.toml"
        config.write_text('[scopes.home]\nsubnet = "192.168.50.0/24"\n', encoding="utf-8")
        conn = connect(self.db)
        try:
            save_scan(
                conn,
                "192.168.51.0/24",
                [_device("192.168.51.10", "aa:bb:cc:dd:ee:21")],
                scope_name="Lab-2",
            )
            save_scan(
                conn,
                "192.168.52.0/24",
                [_device("192.168.52.10", "aa:bb:cc:dd:ee:22")],
                scope_name="LAB-2",
            )
        finally:
            conn.close()
        self.run_cli("asset", "set", "aa:bb:cc:dd:ee:21", "--owner", "Ada")
        self.run_cli("asset", "set", "aa:bb:cc:dd:ee:22", "--owner", "Bea")
        code, out, err = self.run_cli(
            "asset", "list", "--scope", "Lab-2", "--config", str(config), "--format", "json",
        )
        self.assertEqual(code, 0, err)
        self.assertEqual([item["owner"] for item in json.loads(out)["assets"]], ["Ada"])
        code, _, err = self.run_cli(
            "asset", "list", "--scope", "lab-2", "--config", str(config),
        )
        self.assertEqual(code, 2, err)
        self.assertIn("more than one stored scope", err)

    def _lab_asset(self):
        conn = connect(self.db)
        try:
            save_scan(
                conn,
                "192.168.51.0/24",
                [_device("192.168.51.10", "aa:bb:cc:dd:ee:21")],
                scope_name="Lab-2",
            )
        finally:
            conn.close()
        code, _, err = self.run_cli("asset", "set", "aa:bb:cc:dd:ee:21", "--owner", "Ada")
        self.assertEqual(code, 0, err)

    def _assert_lab_listed(self, config: Path):
        code, out, err = self.run_cli(
            "asset", "list", "--scope", "lab-2", "--config", str(config), "--format", "json",
        )
        self.assertEqual(code, 0, err)
        self.assertEqual([item["owner"] for item in json.loads(out)["assets"]], ["Ada"])

    def test_asset_list_falls_back_when_the_scope_file_cannot_load(self):
        self._lab_asset()
        bad = [
            ("broken.toml", "this is not [toml\n".encode()),
            ("binary.toml", b"\xff\xfe not utf-8"),
            ("huge.toml", b"x" * (MAX_SCOPE_CONFIG_BYTES + 1)),
        ]
        for name, blob in bad:
            path = Path(self.tmp.name) / name
            path.write_bytes(blob)
            self._assert_lab_listed(path)
        blocked = Path(self.tmp.name) / "blocked.toml"
        blocked.write_text('[scopes.home]\nsubnet = "192.168.50.0/24"\n', encoding="utf-8")
        if os.name == "nt":
            self._assert_lab_listed(Path(self.tmp.name))
        else:
            os.chmod(blocked, 0)
            try:
                self._assert_lab_listed(blocked)
            finally:
                os.chmod(blocked, 0o600)

    def test_asset_list_falls_back_when_the_scope_file_breaks_the_rules(self):
        self._lab_asset()
        texts = [
            'bogus = 1\n[scopes.Lab-2]\nsubnet = "192.168.51.0/24"\n',
            '[scopes.Lab-2]\nsubnet = "8.8.8.0/24"\n',
            '[scopes.Lab-2]\nsubnet = "192.168.51.0/24"\n'
            '[scopes.lab-2]\nsubnet = "192.168.52.0/24"\n',
            'scopes = "not-a-table"\n',
            '[scopes."bad name"]\nsubnet = "192.168.51.0/24"\n',
            "",
        ]
        for index, text in enumerate(texts):
            path = Path(self.tmp.name) / f"rules-{index}.toml"
            path.write_text(text, encoding="utf-8")
            self._assert_lab_listed(path)
        bogus = Path(self.tmp.name) / "bogus.toml"
        bogus.write_text(texts[0], encoding="utf-8")
        code, out, err = self.run_cli(
            "history", "--scope", "Lab-2", "--config", str(bogus), "--format", "json",
        )
        self.assertEqual(code, 0, err)
        self.assertIn("Lab-2", [row["scope_name"] for row in json.loads(out)["scans"]])
        code, _, err = self.run_cli(
            "asset", "list", "--scope", "bad name", "--config", str(bogus),
        )
        self.assertEqual(code, 2, err)
        with mock.patch.object(cli, "_scan_hosts", side_effect=AssertionError("probed")) as scan_hosts, \
                mock.patch.object(cli, "run_scan", side_effect=AssertionError("probed")) as run_scan:
            code, _, err = self.run_cli("scan", "--config", str(bogus), "--scope", "Lab-2")
        self.assertEqual(code, 2, err)
        self.assertIn("bogus", err)
        scan_hosts.assert_not_called()
        run_scan.assert_not_called()

    def test_refused_insert_releases_the_write_lock(self):
        with mock.patch.object(assets, "ASSET_ROW_CAP", 1):
            holder = connect(self.db)
            try:
                assets.set_asset(holder, "mac:aa:bb:cc:dd:ee:01", "mac", owner="One")
                with self.assertRaises(ValueError):
                    assets.set_asset(holder, "mac:aa:bb:cc:dd:ee:02", "mac", owner="Two")
                other = sqlite3.connect(self.db, timeout=0.5)
                try:
                    other.execute("BEGIN IMMEDIATE")
                    other.execute(
                        "UPDATE assets SET owner = ? WHERE asset_key = ?",
                        ("Updated", "mac:aa:bb:cc:dd:ee:01"),
                    )
                    other.commit()
                finally:
                    other.close()
            finally:
                holder.close()
        conn = connect(self.db)
        try:
            self.assertEqual(
                assets.get_asset(conn, "mac:aa:bb:cc:dd:ee:01")["owner"],
                "Updated",
            )
        finally:
            conn.close()

    def test_diff_prints_a_dash_when_the_scope_name_strips_away(self):
        planted = "\x1b\u202e\x07\u200b"
        conn = connect(self.db)
        try:
            save_scan(
                conn,
                "192.168.51.0/24",
                [_device("192.168.51.10", "aa:bb:cc:dd:ee:21")],
                scope_name=planted,
            )
        finally:
            conn.close()
        code, out, err = self.run_cli("diff")
        self.assertEqual(code, 0, err)
        self.assertIn("scope -", out)
        for char in planted:
            self.assertNotIn(char, out)
            self.assertNotIn(char, err)

    def test_two_connections_cannot_both_pass_the_cap(self):
        holder = connect(self.db)
        try:
            holder.execute(
                "INSERT INTO assets (asset_key, key_kind, owner, location, tags, criticality, notes, updated_at)"
                " VALUES ('mac:aa:bb:cc:dd:ee:01', 'mac', 'One', NULL, '[]', NULL, NULL, 't')"
            )
            holder.commit()
            holder.execute("BEGIN IMMEDIATE")
            holder.execute(
                "INSERT INTO assets (asset_key, key_kind, owner, location, tags, criticality, notes, updated_at)"
                " VALUES ('mac:aa:bb:cc:dd:ee:02', 'mac', 'Two', NULL, '[]', NULL, NULL, 't')"
            )
            errors = []

            def second():
                other = connect(self.db)
                try:
                    assets.set_asset(other, "mac:aa:bb:cc:dd:ee:03", "mac", owner="Three")
                except ValueError as exc:
                    errors.append(str(exc))
                finally:
                    other.close()

            with mock.patch.object(assets, "ASSET_ROW_CAP", 2):
                worker = threading.Thread(target=second)
                worker.start()
                time.sleep(0.4)
                self.assertTrue(worker.is_alive())
                holder.commit()
                worker.join(timeout=5)
            self.assertFalse(worker.is_alive())
            self.assertEqual(errors, [
                "Lantern stores at most 2 inventory records. Clear one before adding another."
            ])
            count = holder.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
            self.assertEqual(count, 2)
        finally:
            holder.close()

    def test_diff_json_and_scope_text_strip_planted_controls(self):
        planted = "lab\x1b\u202e2"
        conn = connect(self.db)
        try:
            save_scan(
                conn,
                "192.168.50.0/24",
                [_device("192.168.50.10", "aa:bb:cc:dd:ee:30")],
                scope_name="home",
            )
            save_scan(
                conn,
                "192.168.50.0/24",
                [
                    _device("192.168.50.10", "aa:bb:cc:dd:ee:30"),
                    _device("192.168.50.12", "aa:bb:cc:dd:ee:31"),
                ],
                scope_name="home",
            )
            conn.execute(
                "INSERT INTO assets (asset_key, key_kind, owner, location, tags, criticality, notes, updated_at)"
                " VALUES ('mac:aa:bb:cc:dd:ee:31', 'mac', ?, NULL, '[]', NULL, NULL, 't')",
                ("Ada\x1b\u202eBee",),
            )
            save_scan(
                conn,
                "192.168.51.0/24",
                [_device("192.168.51.10", "aa:bb:cc:dd:ee:40")],
                scope_name=planted,
            )
            conn.commit()
        finally:
            conn.close()
        code, out, err = self.run_cli("diff", "--scope", "home", "--format", "json")
        self.assertEqual(code, 0, err)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\u202e", out)
        self.assertIn("AdaBee", out)
        code, out, err = self.run_cli("history")
        self.assertEqual(code, 0, err)
        self.assertIn("lab2", out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\u202e", out)
        code, out, err = self.run_cli("diff")
        self.assertEqual(code, 0, err)
        self.assertIn("lab2", out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\u202e", out)
        code, out, err = self.run_cli("report", "--format", "html")
        self.assertEqual(code, 0, err)
        self.assertIn("lab2", out)
        self.assertNotIn("\x1b", out)
        self.assertNotIn("\u202e", out)

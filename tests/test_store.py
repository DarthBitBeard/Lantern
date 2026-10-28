"""SQLite history, trust, diff, and schema upgrades. No network."""

import sqlite3
import tempfile
import unittest
from pathlib import Path

from lantern import demo
from lantern.store import (
    SCHEMA_VERSION,
    apply_migrations,
    apply_trust,
    connect,
    diff_scans,
    get_trusted,
    latest_scan_id,
    list_scans,
    load_scan,
    load_scan_with_diff,
    previous_scan_id,
    save_scan,
    schema_version,
    set_trusted,
)

# DDL from Lantern 0.3.0 `connect()`, before `schema_version` existed.
_V030_DDL = """
CREATE TABLE scans (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    started_at TEXT NOT NULL,
    subnet TEXT NOT NULL,
    demo INTEGER NOT NULL DEFAULT 0
);
CREATE TABLE devices (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    scan_id INTEGER NOT NULL,
    ip TEXT NOT NULL,
    mac TEXT,
    hostname TEXT,
    label TEXT,
    open_ports TEXT NOT NULL,
    findings TEXT NOT NULL
);
CREATE INDEX devices_scan_id ON devices (scan_id);
CREATE TABLE trusted_devices (
    mac TEXT PRIMARY KEY,
    label TEXT,
    trusted INTEGER NOT NULL DEFAULT 1,
    updated_at TEXT NOT NULL
);
"""


def _dev(ip, mac=None, ports=()):
    return {"ip": ip, "mac": mac, "hostname": None, "label": None,
            "open_ports": [{"port": p, "open": True, "banner": ""} for p in ports],
            "findings": []}


class StoreTests(unittest.TestCase):
    def setUp(self):
        self.conn = connect(":memory:")

    def tearDown(self):
        self.conn.close()

    def test_empty_db(self):
        self.assertEqual(schema_version(self.conn), SCHEMA_VERSION)
        self.assertIsNone(latest_scan_id(self.conn))
        self.assertEqual(list_scans(self.conn), [])
        self.assertEqual(load_scan_with_diff(self.conn), (None, None))
        self.assertEqual(load_scan_with_diff(self.conn, 42), (None, None))
        self.assertIsNone(load_scan(self.conn, 1))

    def test_devices_sorted_numerically(self):
        scan_id = save_scan(self.conn, "10.0.0.0/24", [_dev("10.0.0.10"), _dev("10.0.0.2"), _dev("10.0.0.1")])
        scan = load_scan(self.conn, scan_id)
        self.assertEqual([d["ip"] for d in scan["devices"]], ["10.0.0.1", "10.0.0.2", "10.0.0.10"])

    def test_history_and_previous(self):
        id1 = save_scan(self.conn, "10.0.0.0/24", [_dev("10.0.0.1")], demo=True)
        id2 = save_scan(self.conn, "10.0.0.0/24", [])
        self.assertEqual(latest_scan_id(self.conn), id2)
        self.assertIsNone(previous_scan_id(self.conn, id1))
        self.assertEqual(previous_scan_id(self.conn, id2), id1)
        scans = list_scans(self.conn)
        self.assertEqual([s["id"] for s in scans], [id2, id1])
        self.assertEqual(scans[1]["device_count"], 1)
        self.assertTrue(scans[1]["demo"])
        self.assertFalse(scans[0]["demo"])

    def test_load_scan_with_diff_applies_trust_and_diffs_previous(self):
        id1 = save_scan(self.conn, demo.DEMO_SUBNET, demo.demo_scan_1(), demo=True)
        id2 = save_scan(self.conn, demo.DEMO_SUBNET, demo.demo_scan_2(), demo=True)
        set_trusted(self.conn, "DE:AD:BE:EF:00:99", "  Mystery box ", True)

        scan, diff = load_scan_with_diff(self.conn)
        self.assertEqual(scan["id"], id2)
        self.assertEqual([d["ip"] for d in diff["added"]], ["192.168.1.99"])
        new_device = next(d for d in scan["devices"] if d["ip"] == "192.168.1.99")
        self.assertTrue(new_device["trusted"])
        self.assertTrue(new_device["known"])
        self.assertEqual(new_device["label"], "Mystery box")

        first, first_diff = load_scan_with_diff(self.conn, id1)
        self.assertEqual(first["id"], id1)
        self.assertIsNone(first_diff)
        self.assertFalse(first["devices"][0]["trusted"])

    def test_set_trusted_upsert_and_untrust(self):
        set_trusted(self.conn, "aa:bb:cc:dd:ee:ff", "TV", True)
        set_trusted(self.conn, "AA:BB:CC:DD:EE:FF", "", False)
        self.assertEqual(get_trusted(self.conn), {"aa:bb:cc:dd:ee:ff": {"label": None, "trusted": False}})
        with self.assertRaises(ValueError):
            set_trusted(self.conn, "  ", "x", True)

    def test_apply_trust_handles_none_and_missing_mac(self):
        self.assertIsNone(apply_trust(None, {}))
        scan = {"devices": [_dev("10.0.0.1")]}
        apply_trust(scan, {"": {"label": "nope", "trusted": True}})
        self.assertFalse(scan["devices"][0]["trusted"])
        self.assertIsNone(scan["devices"][0]["label"])


class DiffTests(unittest.TestCase):
    def test_mac_keyed_ip_move_and_port_changes(self):
        old = {"devices": [_dev("10.0.0.5", "aa:aa:aa:aa:aa:01", [22, 80]), _dev("10.0.0.9", None, [443])]}
        new = {"devices": [_dev("10.0.0.6", "AA:AA:AA:AA:AA:01", [22, 23]), _dev("10.0.0.7", None, [443])]}
        diff = diff_scans(old, new)
        self.assertEqual([d["ip"] for d in diff["added"]], ["10.0.0.7"])
        self.assertEqual([d["ip"] for d in diff["removed"]], ["10.0.0.9"])
        self.assertEqual(len(diff["changed"]), 1)
        change = diff["changed"][0]
        self.assertEqual(change["old_ip"], "10.0.0.5")
        self.assertEqual(change["device"]["ip"], "10.0.0.6")
        self.assertEqual((change["opened"], change["closed"]), ([23], [80]))

    def test_no_change_is_empty(self):
        scan = {"devices": [_dev("10.0.0.5", "aa:aa:aa:aa:aa:01", [22])]}
        self.assertEqual(diff_scans(scan, scan), {"added": [], "removed": [], "changed": []})


def _write_v030(path: Path) -> None:
    """Create a database exactly as Lantern 0.3.0 left it, with rows in it."""
    raw = sqlite3.connect(path)
    raw.executescript(_V030_DDL)
    raw.execute(
        "INSERT INTO scans (started_at, subnet, demo) VALUES (?, ?, ?)",
        ("2026-10-27T12:00:00+00:00", "192.168.1.0/24", 1),
    )
    raw.execute(
        "INSERT INTO devices (scan_id, ip, mac, hostname, label, open_ports, findings)"
        " VALUES (1, ?, ?, ?, ?, ?, ?)",
        (
            "192.168.1.10",
            "aa:bb:cc:dd:ee:10",
            "router.home",
            "Router",
            '[{"port": 80, "open": true, "banner": "ok"}]',
            '[{"severity": "info", "title": "Web", "fix": "none"}]',
        ),
    )
    raw.execute(
        "INSERT INTO devices (scan_id, ip, mac, hostname, label, open_ports, findings)"
        " VALUES (1, ?, ?, ?, ?, ?, ?)",
        ("192.168.1.99", "de:ad:be:ef:00:99", None, None, "[]", "[]"),
    )
    raw.execute(
        "INSERT INTO trusted_devices (mac, label, trusted, updated_at) VALUES (?, ?, ?, ?)",
        ("de:ad:be:ef:00:99", "Mystery box", 1, "2026-10-27T12:01:00+00:00"),
    )
    raw.commit()
    raw.close()


class MigrationTests(unittest.TestCase):
    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.path = Path(self.tmp.name) / "lantern.db"

    def tearDown(self):
        self.tmp.cleanup()

    def test_fresh_database_is_current_and_has_no_backup(self):
        conn = connect(self.path)
        try:
            self.assertEqual(schema_version(conn), SCHEMA_VERSION)
            self.assertEqual(
                conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0], 1
            )
            applied = conn.execute("SELECT applied_at FROM schema_version").fetchone()[0]
            self.assertTrue(applied)
            self.assertEqual(list_scans(conn), [])
        finally:
            conn.close()
        self.assertEqual(list(Path(self.tmp.name).glob("*.bak")), [])

    def test_v030_database_upgrades_without_losing_rows(self):
        _write_v030(self.path)
        conn = connect(self.path)
        try:
            self.assertEqual(schema_version(conn), 1)
            scan = load_scan(conn, 1)
            self.assertEqual(scan["started_at"], "2026-10-27T12:00:00+00:00")
            self.assertEqual(scan["subnet"], "192.168.1.0/24")
            self.assertTrue(scan["demo"])
            self.assertEqual(
                [(d["ip"], d["mac"], d["hostname"], d["label"]) for d in scan["devices"]],
                [
                    ("192.168.1.10", "aa:bb:cc:dd:ee:10", "router.home", "Router"),
                    ("192.168.1.99", "de:ad:be:ef:00:99", None, None),
                ],
            )
            self.assertEqual(scan["devices"][0]["open_ports"], [{"port": 80, "open": True, "banner": "ok"}])
            self.assertEqual(scan["devices"][0]["findings"][0]["title"], "Web")
            self.assertEqual(
                get_trusted(conn),
                {"de:ad:be:ef:00:99": {"label": "Mystery box", "trusted": True}},
            )
            indexes = [row[1] for row in conn.execute("PRAGMA index_list('devices')")]
            self.assertIn("devices_scan_id", indexes)
        finally:
            conn.close()

        backups = list(Path(self.tmp.name).glob("*.bak"))
        self.assertEqual([p.name for p in backups], ["lantern.db.v0.bak"])
        saved = sqlite3.connect(backups[0])
        try:
            self.assertIsNone(saved.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'"
            ).fetchone())
            self.assertEqual(saved.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 1)
            self.assertEqual(saved.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 2)
            self.assertEqual(saved.execute("SELECT label FROM trusted_devices").fetchone()[0], "Mystery box")
        finally:
            saved.close()

        again = connect(self.path)
        again.close()
        self.assertEqual([p.name for p in Path(self.tmp.name).glob("*.bak")], ["lantern.db.v0.bak"])

    def test_newer_schema_is_refused_and_left_in_place(self):
        _write_v030(self.path)
        raw = sqlite3.connect(self.path)
        raw.execute(
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        raw.execute("INSERT INTO schema_version VALUES (99, 'future')")
        raw.commit()
        raw.close()

        with self.assertRaises(ValueError) as ctx:
            connect(self.path)
        self.assertIn("newer", str(ctx.exception))
        self.assertEqual(list(Path(self.tmp.name).glob("*.bak")), [])

        raw = sqlite3.connect(self.path)
        try:
            self.assertEqual(raw.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 99)
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 2)
        finally:
            raw.close()

    def test_migrations_run_in_order_and_stop_when_current(self):
        seen = []

        def step1(conn):
            seen.append(schema_version(conn))
            conn.execute("CREATE TABLE notes (id INTEGER)")
            conn.execute("INSERT INTO notes VALUES (1)")

        def step2(conn):
            seen.append(schema_version(conn))
            conn.execute("ALTER TABLE notes ADD COLUMN extra TEXT")
            conn.execute("UPDATE notes SET extra = 'ok'")

        raw = sqlite3.connect(self.path)
        try:
            version = apply_migrations(
                raw, migrations={1: step1, 2: step2}, target=2, db_path=self.path,
            )
            self.assertEqual(version, 2)
            self.assertEqual(seen, [0, 1])
            self.assertEqual(
                raw.execute("SELECT id, extra FROM notes").fetchone(), (1, "ok")
            )
            seen.clear()
            again = apply_migrations(
                raw, migrations={1: step1, 2: step2}, target=2, db_path=self.path,
            )
            self.assertEqual(again, 2)
            self.assertEqual(seen, [])
        finally:
            raw.close()
        # The file was empty, so the runner did not need a backup.
        self.assertEqual(list(Path(self.tmp.name).glob("*.bak")), [])

    def test_failed_migration_rolls_back_legacy_rows(self):
        _write_v030(self.path)

        def boom(conn):
            conn.execute("DELETE FROM scans")
            conn.execute("CREATE TABLE exploded (id INTEGER)")
            raise RuntimeError("nope")

        raw = sqlite3.connect(self.path)
        try:
            with self.assertRaises(RuntimeError):
                apply_migrations(raw, migrations={1: boom}, target=1, db_path=self.path)
            self.assertEqual(raw.execute("SELECT COUNT(*) FROM scans").fetchone()[0], 1)
            self.assertIsNone(raw.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'exploded'"
            ).fetchone())
            self.assertIsNone(raw.execute(
                "SELECT 1 FROM sqlite_master WHERE name = 'schema_version'"
            ).fetchone())
        finally:
            raw.close()

        saved = sqlite3.connect(self.path.with_name("lantern.db.v0.bak"))
        try:
            self.assertEqual(saved.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 2)
        finally:
            saved.close()

    def test_registry_must_be_contiguous(self):
        raw = sqlite3.connect(":memory:")
        try:
            with self.assertRaises(RuntimeError):
                apply_migrations(raw, migrations={2: lambda conn: None}, target=2)
        finally:
            raw.close()

    def test_cannot_migrate_downwards(self):
        raw = sqlite3.connect(":memory:")
        try:
            apply_migrations(
                raw,
                migrations={1: lambda conn: None, 2: lambda conn: None},
                target=2,
            )
            with self.assertRaises(ValueError):
                apply_migrations(raw, migrations={1: lambda conn: None}, target=1)
            self.assertEqual(schema_version(raw), 2)
        finally:
            raw.close()


if __name__ == "__main__":
    unittest.main()

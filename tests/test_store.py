"""SQLite history, trust, diff, schema upgrades, and file modes. No network."""

import contextlib
import io
import os
import sqlite3
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

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
    warn_loose_permissions,
    write_private_file,
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

    def test_scope_name_filters_history_and_the_previous_scan(self):
        home_a = save_scan(
            self.conn, "192.168.50.0/24", [_dev("192.168.50.10")], scope_name="home",
        )
        save_scan(self.conn, "10.50.0.0/24", [_dev("10.50.0.10")], scope_name="lab")
        home_b = save_scan(
            self.conn, "192.168.50.0/24",
            [_dev("192.168.50.10"), _dev("192.168.50.11")],
            scope_name="home",
        )
        self.assertEqual(load_scan(self.conn, home_a)["scope_name"], "home")
        self.assertEqual(
            [row["id"] for row in list_scans(self.conn, "home")],
            [home_b, home_a],
        )
        self.assertEqual(
            [row["scope_name"] for row in list_scans(self.conn, "lab")],
            ["lab"],
        )
        scan, diff = load_scan_with_diff(self.conn, scope_name="home")
        self.assertEqual(scan["id"], home_b)
        self.assertEqual([d["ip"] for d in diff["added"]], ["192.168.50.11"])
        self.assertTrue(all(not d["ip"].startswith("10.50.") for d in diff["added"]))
        self.assertEqual(previous_scan_id(self.conn, home_b, "home"), home_a)
        self.assertIsNone(load_scan_with_diff(self.conn, home_b, scope_name="lab")[0])

    def test_default_diff_stays_inside_the_scans_own_scope(self):
        save_scan(self.conn, "192.168.50.0/24", [_dev("192.168.50.10")], scope_name="home")
        save_scan(self.conn, "10.50.0.0/24", [_dev("10.50.0.10")], scope_name="lab")
        home_b = save_scan(
            self.conn, "192.168.50.0/24",
            [_dev("192.168.50.10"), _dev("192.168.50.11")],
            scope_name="home",
        )
        lab_b = save_scan(self.conn, "10.50.0.0/24", [_dev("10.50.0.10")], scope_name="lab")
        bare = save_scan(self.conn, "10.9.0.0/24", [_dev("10.9.0.9")])

        scan, diff = load_scan_with_diff(self.conn, lab_b)
        self.assertEqual(scan["scope_name"], "lab")
        self.assertEqual(diff["added"], [])
        self.assertEqual(diff["removed"], [])
        scan, diff = load_scan_with_diff(self.conn, home_b)
        self.assertEqual([d["ip"] for d in diff["added"]], ["192.168.50.11"])
        self.assertFalse(any(d["ip"].startswith("10.") for d in diff["added"] + diff["removed"]))
        scan, diff = load_scan_with_diff(self.conn, bare)
        self.assertIsNone(scan["scope_name"])
        self.assertIsNone(diff)
        self.assertIsNone(previous_scan_id(self.conn, bare, None))

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

    def test_devices_sharing_a_mac_are_not_merged(self):
        """A proxy-ARP router or VM bridge reports one MAC for several IPs."""
        mac = "aa:aa:aa:aa:aa:01"
        scan = {"devices": [_dev("10.0.0.5", mac, [22]), _dev("10.0.0.6", mac, [80])]}
        self.assertEqual(diff_scans(scan, scan), {"added": [], "removed": [], "changed": []})

        old = scan
        new = {"devices": [
            _dev("10.0.0.5", mac, [22]),
            _dev("10.0.0.6", mac, [80, 443]),
            _dev("10.0.0.7", mac, []),
        ]}
        diff = diff_scans(old, new)
        self.assertEqual([d["ip"] for d in diff["added"]], ["10.0.0.7"])
        self.assertEqual(diff["removed"], [])
        self.assertEqual(len(diff["changed"]), 1)
        self.assertEqual(diff["changed"][0]["device"]["ip"], "10.0.0.6")
        self.assertEqual(diff["changed"][0]["opened"], [443])

        gone = diff_scans(new, old)
        self.assertEqual([d["ip"] for d in gone["removed"]], ["10.0.0.7"])
        self.assertEqual(gone["added"], [])

    def test_shared_mac_leftovers_pair_as_a_move(self):
        mac = "aa:aa:aa:aa:aa:01"
        old = {"devices": [_dev("10.0.0.5", mac, [22]), _dev("10.0.0.6", mac, [])]}
        new = {"devices": [_dev("10.0.0.5", mac, [22]), _dev("10.0.0.9", mac, [])]}
        diff = diff_scans(old, new)
        self.assertEqual((diff["added"], diff["removed"]), ([], []))
        self.assertEqual(len(diff["changed"]), 1)
        self.assertEqual(diff["changed"][0]["old_ip"], "10.0.0.6")
        self.assertEqual(diff["changed"][0]["device"]["ip"], "10.0.0.9")


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
    # Migration tests are about rows, not modes. A world-readable file would
    # warn on stderr; that case has its own test. 0600 matches a private file.
    if os.name != "nt":
        os.chmod(path, 0o600)


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
                conn.execute("SELECT COUNT(*) FROM schema_version").fetchone()[0],
                SCHEMA_VERSION,
            )
            applied = conn.execute("SELECT applied_at FROM schema_version").fetchone()[0]
            self.assertTrue(applied)
            self.assertEqual(list_scans(conn), [])
        finally:
            conn.close()
        self.assertEqual(list(Path(self.tmp.name).glob("*.bak")), [])
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)

    def test_v030_database_upgrades_without_losing_rows(self):
        _write_v030(self.path)
        conn = connect(self.path)
        try:
            self.assertEqual(schema_version(conn), SCHEMA_VERSION)
            scan = load_scan(conn, 1)
            self.assertEqual(scan["started_at"], "2026-10-27T12:00:00+00:00")
            self.assertEqual(scan["subnet"], "192.168.1.0/24")
            self.assertTrue(scan["demo"])
            self.assertIsNone(scan["scope_name"])
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
            self.assertIsNotNone(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'assets'"
            ).fetchone())
        finally:
            conn.close()

        backups = list(Path(self.tmp.name).glob("*.bak"))
        self.assertEqual([p.name for p in backups], ["lantern.db.v0.bak"])
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o600)
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

    def test_schema_1_database_gains_scope_name_and_keeps_rows(self):
        """A database stamped at schema 1 upgrades forward to schema 2.

        The previous layout has scans, devices, and trusted devices, plus
        the version table, and no scope_name column. Opening it copies the
        file to `.v1.bak` and leaves that copy on schema 1.
        """
        _write_v030(self.path)
        raw = sqlite3.connect(self.path)
        raw.execute(
            "CREATE TABLE schema_version (version INTEGER PRIMARY KEY, applied_at TEXT NOT NULL)"
        )
        raw.execute("INSERT INTO schema_version VALUES (1, '2026-10-27T00:00:00+00:00')")
        raw.commit()
        raw.close()
        if os.name != "nt":
            os.chmod(self.path, 0o600)

        conn = connect(self.path)
        try:
            self.assertEqual(schema_version(conn), SCHEMA_VERSION)
            self.assertGreaterEqual(SCHEMA_VERSION, 2)
            scan = load_scan(conn, 1)
            self.assertIsNone(scan["scope_name"])
            self.assertEqual(scan["devices"][0]["ip"], "192.168.1.10")
            self.assertEqual(scan["devices"][1]["ip"], "192.168.1.99")
            columns = [row[1] for row in conn.execute("PRAGMA table_info(scans)")]
            self.assertIn("scope_name", columns)
            self.assertEqual(
                get_trusted(conn),
                {"de:ad:be:ef:00:99": {"label": "Mystery box", "trusted": True}},
            )
        finally:
            conn.close()

        backups = list(Path(self.tmp.name).glob("*.bak"))
        self.assertEqual([p.name for p in backups], ["lantern.db.v1.bak"])
        saved = sqlite3.connect(backups[0])
        try:
            saved_columns = [row[1] for row in saved.execute("PRAGMA table_info(scans)")]
            self.assertNotIn("scope_name", saved_columns)
            self.assertEqual(saved.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 1)
            self.assertEqual(saved.execute("SELECT COUNT(*) FROM devices").fetchone()[0], 2)
            self.assertEqual(saved.execute("SELECT label FROM trusted_devices").fetchone()[0], "Mystery box")
        finally:
            saved.close()

        again = connect(self.path)
        again.close()
        self.assertEqual([p.name for p in Path(self.tmp.name).glob("*.bak")], ["lantern.db.v1.bak"])

    def test_schema_2_database_gains_assets_and_keeps_rows(self):
        """A database stamped at schema 2 upgrades forward to schema 3."""
        from lantern.store import _migration_1_v030_baseline, _migration_2_scope_name

        raw = sqlite3.connect(self.path)
        try:
            apply_migrations(
                raw,
                migrations={1: _migration_1_v030_baseline, 2: _migration_2_scope_name},
                target=2,
                db_path=self.path,
            )
            raw.execute(
                "INSERT INTO scans (started_at, subnet, demo, scope_name) VALUES (?, ?, ?, ?)",
                ("2026-10-28T00:00:00+00:00", "10.9.0.0/24", 0, "home"),
            )
            raw.execute(
                "INSERT INTO devices (scan_id, ip, mac, hostname, label, open_ports, findings)"
                " VALUES (1, ?, ?, ?, ?, ?, ?)",
                ("10.9.0.4", "aa:bb:cc:dd:ee:04", None, None, "[]", "[]"),
            )
            raw.commit()
        finally:
            raw.close()
        if os.name != "nt":
            os.chmod(self.path, 0o600)

        conn = connect(self.path)
        try:
            self.assertEqual(schema_version(conn), SCHEMA_VERSION)
            self.assertGreaterEqual(SCHEMA_VERSION, 3)
            scan = load_scan(conn, 1)
            self.assertEqual(scan["scope_name"], "home")
            self.assertEqual(scan["devices"][0]["mac"], "aa:bb:cc:dd:ee:04")
            self.assertIsNotNone(conn.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'assets'"
            ).fetchone())
            self.assertEqual(conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0], 0)
        finally:
            conn.close()

        backups = list(Path(self.tmp.name).glob("*.bak"))
        self.assertEqual([p.name for p in backups], ["lantern.db.v2.bak"])
        if os.name != "nt":
            self.assertEqual(stat.S_IMODE(self.path.stat().st_mode), 0o600)
            self.assertEqual(stat.S_IMODE(backups[0].stat().st_mode), 0o600)
        saved = sqlite3.connect(backups[0])
        try:
            self.assertEqual(saved.execute("SELECT MAX(version) FROM schema_version").fetchone()[0], 2)
            self.assertIsNone(saved.execute(
                "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'assets'"
            ).fetchone())
            self.assertEqual(saved.execute("SELECT scope_name FROM scans").fetchone()[0], "home")
        finally:
            saved.close()

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


def _mode(path: Path) -> int:
    return stat.S_IMODE(path.stat().st_mode)


class PrivateFileTests(unittest.TestCase):
    """Database, backup, and export files stay private. No network."""

    def setUp(self):
        self.tmp = tempfile.TemporaryDirectory()
        self.addCleanup(self.tmp.cleanup)

    def _umask(self, mask: int) -> None:
        previous = os.umask(mask)
        self.addCleanup(os.umask, previous)

    def test_umask_022_new_database_backup_and_directory_are_private(self):
        """sqlite3.connect alone leaves mode 0644 under umask 022.

        Lantern has to create the database and the `.vN.bak` backup at 0600,
        and a directory it creates at 0700, or this test fails.
        """
        if os.name == "nt":
            self.skipTest("POSIX permission bits are not checked on Windows")
        self._umask(0o022)
        nested = Path(self.tmp.name) / "a" / "b" / "lantern.db"
        fresh = connect(nested)
        fresh.close()

        legacy_dir = Path(self.tmp.name) / "legacy"
        legacy_dir.mkdir()
        legacy = legacy_dir / "lantern.db"
        _write_v030(legacy)
        loose_backup = Path(str(legacy) + ".v9.bak")
        loose_backup.write_bytes(b"previous-backup")
        if os.name != "nt":
            os.chmod(legacy_dir, 0o755)
            os.chmod(legacy, 0o644)
            os.chmod(loose_backup, 0o644)

        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            upgraded = connect(legacy)
            upgraded.close()

        check = sqlite3.connect(nested)
        try:
            self.assertEqual(schema_version(check), SCHEMA_VERSION)
        finally:
            check.close()

        self.assertEqual(_mode(nested), 0o600)
        self.assertEqual(_mode(nested.parent), 0o700)
        self.assertEqual(_mode(nested.parent.parent), 0o700)
        self.assertEqual(_mode(legacy_dir), 0o755)
        self.assertEqual(_mode(legacy), 0o644)
        created_backup = Path(str(legacy) + ".v0.bak")
        self.assertEqual(_mode(created_backup), 0o600)
        self.assertEqual(_mode(loose_backup), 0o644)
        warning = buf.getvalue()
        self.assertIn("readable by group or others", warning)
        self.assertIn("0644", warning)
        self.assertIn(legacy.name, warning)
        self.assertIn(loose_backup.name, warning)
        self.assertNotIn(str(nested), warning)

    def test_permissive_umask_cannot_widen_new_files(self):
        if os.name == "nt":
            self.skipTest("POSIX permission bits are not checked on Windows")
        self._umask(0o000)
        root = Path(self.tmp.name) / "wide"
        db_path = root / "lantern.db"
        conn = connect(db_path)
        conn.close()
        export = root / "nested" / "inventory.json"
        write_private_file(export, '{"devices": []}')
        self.assertEqual(export.read_text(encoding="utf-8"), '{"devices": []}')
        self.assertEqual(_mode(db_path), 0o600)
        self.assertEqual(_mode(root), 0o700)
        self.assertEqual(_mode(export.parent), 0o700)
        self.assertEqual(_mode(export), 0o600)
        self.assertEqual(_mode(db_path) & 0o077, 0)
        self.assertEqual(_mode(root) & 0o077, 0)
        self.assertEqual(_mode(export) & 0o077, 0)

    def test_existing_directory_and_database_are_not_chmodded(self):
        if os.name == "nt":
            self.skipTest("POSIX permission bits are not checked on Windows")
        self._umask(0o022)
        parent = Path(self.tmp.name) / "already"
        parent.mkdir()
        db_path = parent / "lantern.db"
        db_path.write_bytes(b"")
        if os.name != "nt":
            os.chmod(parent, 0o755)
            os.chmod(db_path, 0o640)
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            conn = connect(db_path)
            try:
                self.assertEqual(schema_version(conn), SCHEMA_VERSION)
            finally:
                conn.close()
            write_private_file(parent / "export.json", b"{}")
        self.assertEqual((parent / "export.json").read_bytes(), b"{}")
        self.assertEqual(_mode(parent), 0o755)
        self.assertEqual(_mode(db_path), 0o640)
        self.assertEqual(_mode(parent / "export.json"), 0o600)
        warning = buf.getvalue()
        self.assertIn("0640", warning)
        self.assertIn(db_path.name, warning)
        self.assertIn("0755", warning)
        self.assertIn("will not change an existing directory", warning)
        self.assertIn(parent.name, warning)

    def test_private_file_does_not_warn_and_loose_modes_do(self):
        if os.name == "nt":
            self.skipTest("POSIX permission bits are not checked on Windows")
        self._umask(0o022)
        private = Path(self.tmp.name) / "private.db"
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            conn = connect(private)
            conn.close()
            again = connect(private)
            again.close()
        self.assertEqual(buf.getvalue(), "")
        self.assertEqual(_mode(private), 0o600)

        for mode in (0o640, 0o604, 0o644):
            path = Path(self.tmp.name) / f"loose-{mode:04o}.db"
            path.write_bytes(b"")
            os.chmod(path, mode)
            warned = io.StringIO()
            with contextlib.redirect_stderr(warned):
                warn_loose_permissions(path)
                warn_loose_permissions(path)
            text = warned.getvalue()
            self.assertEqual(text.count("readable by group or others"), 1)
            self.assertIn(f"{mode:04o}", text)
            self.assertEqual(_mode(path), mode)

    def test_symlink_database_is_refused(self):
        """A dangling symlink used to be created at the target as mode 0644."""
        if os.name == "nt":
            self.skipTest("POSIX symlink refusal is not checked on Windows")
        self._umask(0o022)
        dangling_target = Path(self.tmp.name) / "outside.db"
        dangling = Path(self.tmp.name) / "lantern.db"
        dangling.symlink_to(dangling_target)
        with self.assertRaises(ValueError) as ctx:
            connect(dangling)
        message = str(ctx.exception)
        self.assertIn("symlink", message)
        self.assertIn("will not follow", message)
        self.assertNotIn(dangling_target.name, message)
        self.assertFalse(dangling_target.exists())
        self.assertTrue(dangling.is_symlink())

        real = Path(self.tmp.name) / "real.db"
        real.write_bytes(b"leave-me")
        os.chmod(real, 0o644)
        linked = Path(self.tmp.name) / "linked.db"
        linked.symlink_to(real)
        with self.assertRaises(ValueError) as ctx:
            connect(linked)
        self.assertIn("symlink", str(ctx.exception))
        self.assertNotIn(real.name, str(ctx.exception))
        self.assertEqual(real.read_bytes(), b"leave-me")
        self.assertEqual(_mode(real), 0o644)

    def test_warn_loose_permissions_does_not_raise(self):
        buf = io.StringIO()
        with contextlib.redirect_stderr(buf):
            warn_loose_permissions(Path(self.tmp.name) / "missing.db")
            warn_loose_permissions(Path(self.tmp.name))
        self.assertEqual(buf.getvalue(), "")

    def test_warn_loose_permissions_skips_windows_modes(self):
        path = Path(self.tmp.name) / "win.db"
        path.write_bytes(b"inventory")
        if os.name != "nt":
            os.chmod(path, 0o644)
        buf = io.StringIO()
        with mock.patch("lantern.store.os.name", "nt"), contextlib.redirect_stderr(buf):
            warn_loose_permissions(path)
        self.assertEqual(buf.getvalue(), "")
        self.assertEqual(path.read_bytes(), b"inventory")

    def test_write_private_file_replaces_without_leaving_a_temp_file(self):
        self._umask(0o000)
        dest = Path(self.tmp.name) / "out.json"
        write_private_file(dest, "one")
        write_private_file(dest, "héllo".encode("utf-8"))
        self.assertEqual(dest.read_bytes(), "héllo".encode("utf-8"))
        if os.name != "nt":
            self.assertEqual(_mode(dest), 0o600)
        blocked = Path(self.tmp.name) / "blocked"
        blocked.mkdir()
        before = {path.name for path in Path(self.tmp.name).iterdir()}
        with self.assertRaises(OSError):
            write_private_file(blocked, "nope")
        after = {path.name for path in Path(self.tmp.name).iterdir()}
        self.assertEqual(before, after)
        with self.assertRaises(TypeError):
            write_private_file(dest, object())


if __name__ == "__main__":
    unittest.main()

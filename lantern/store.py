"""Storage: one local SQLite file, no cloud, no accounts.

A scan is a snapshot: devices found, their open ports, and findings.
Diffing two snapshots is the core value: what is new, what left,
what opened, what closed.

Schema changes are forward-only. The `schema_version` table records each
applied version. `connect` runs any missing migrations in one transaction.
For an existing database file it first writes a copy beside it,
`<file>.v<old>.bak`, and leaves that copy untouched.
"""

from __future__ import annotations

import ipaddress
import json
import sqlite3
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

# Schema 1 is the Lantern 0.3.0 tables (scans, devices, trusted_devices)
# plus this version table. The package version stays put until a release;
# the schema version moves only when the tables change.
SCHEMA_VERSION = 1

Migration = Callable[[sqlite3.Connection], None]


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


def _newer_message(found: int, target: int) -> str:
    return (
        f"Database schema version {found} is newer than this Lantern "
        f"(schema {target}). Refusing to change it. Upgrade Lantern to open this file."
    )


def _require_migration_keys(migrations: dict[int, Migration], target: int) -> None:
    expected = list(range(1, target + 1))
    got = sorted(migrations)
    if target < 1 or got != expected:
        raise RuntimeError(
            f"Migrations must be exactly versions 1..{target}, got {got}."
        )


def schema_version(conn: sqlite3.Connection) -> int:
    """Highest applied schema version, or 0 when the file has never been stamped.

    A Lantern 0.3.0 database has the scan tables and no `schema_version`
    table, so it reports 0.
    """
    row = conn.execute(
        "SELECT 1 FROM sqlite_master WHERE type = 'table' AND name = 'schema_version'"
    ).fetchone()
    if row is None:
        return 0
    found = conn.execute("SELECT MAX(version) FROM schema_version").fetchone()
    if not found or found[0] is None:
        return 0
    return int(found[0])


def _has_user_tables(conn: sqlite3.Connection) -> bool:
    rows = conn.execute(
        "SELECT name FROM sqlite_master WHERE type = 'table' AND name NOT LIKE 'sqlite_%'"
    ).fetchall()
    return any(row[0] != "schema_version" for row in rows)


def _persistent_path(db_path: str | Path | None) -> Path | None:
    if db_path is None:
        return None
    text = str(db_path)
    if text == ":memory:" or text.startswith("file::memory:"):
        return None
    return Path(text)


def _unused_backup_path(source: Path, from_version: int) -> Path:
    """`<file>.v<from>.bak`, or `<file>.v<from>.N.bak` if that name is taken.

    The first file is never overwritten, so a later attempt cannot replace
    the pre-upgrade copy with an already-upgraded one.
    """
    first = Path(str(source) + f".v{from_version}.bak")
    if not first.exists():
        return first
    number = 1
    while True:
        candidate = Path(str(source) + f".v{from_version}.{number}.bak")
        if not candidate.exists():
            return candidate
        number += 1


def _backup_database(conn: sqlite3.Connection, source: Path, from_version: int) -> Path:
    """Write a consistent copy of `source` using the SQLite backup API.

    Call this when `conn` is not already inside a transaction. Backing up
    the same connection while it holds a write lock waits forever.
    """
    dest = _unused_backup_path(source, from_version)
    saved = sqlite3.connect(dest)
    try:
        conn.backup(saved)
    except Exception:
        saved.close()
        dest.unlink(missing_ok=True)
        raise
    saved.close()
    return dest


def _write_schema_version(conn: sqlite3.Connection, version: int) -> None:
    conn.execute(
        """CREATE TABLE IF NOT EXISTS schema_version (
               version INTEGER PRIMARY KEY,
               applied_at TEXT NOT NULL
           )"""
    )
    conn.execute(
        "INSERT INTO schema_version (version, applied_at) VALUES (?, ?)",
        (version, _now()),
    )


def _migration_1_v030_baseline(conn: sqlite3.Connection) -> None:
    """Schema 1: the tables Lantern 0.3.0 already created.

    `CREATE TABLE IF NOT EXISTS` is what makes an on-disk 0.3.0 file
    upgrade without rewriting its rows. Do not add columns here. A later
    change is the next numbered migration, and it must not edit this one.
    Migrations must not commit; the runner owns the transaction.
    """
    conn.execute(
        """CREATE TABLE IF NOT EXISTS scans (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               started_at TEXT NOT NULL,
               subnet TEXT NOT NULL,
               demo INTEGER NOT NULL DEFAULT 0
           )"""
    )
    conn.execute(
        """CREATE TABLE IF NOT EXISTS devices (
               id INTEGER PRIMARY KEY AUTOINCREMENT,
               scan_id INTEGER NOT NULL,
               ip TEXT NOT NULL,
               mac TEXT,
               hostname TEXT,
               label TEXT,
               open_ports TEXT NOT NULL,
               findings TEXT NOT NULL
           )"""
    )
    conn.execute("CREATE INDEX IF NOT EXISTS devices_scan_id ON devices (scan_id)")
    conn.execute(
        """CREATE TABLE IF NOT EXISTS trusted_devices (
               mac TEXT PRIMARY KEY,
               label TEXT,
               trusted INTEGER NOT NULL DEFAULT 1,
               updated_at TEXT NOT NULL
           )"""
    )


_MIGRATIONS: dict[int, Migration] = {
    1: _migration_1_v030_baseline,
}
_require_migration_keys(_MIGRATIONS, SCHEMA_VERSION)


def apply_migrations(
    conn: sqlite3.Connection,
    *,
    migrations: dict[int, Migration] | None = None,
    target: int | None = None,
    db_path: str | Path | None = None,
) -> int:
    """Upgrade `conn` to `target` and return the version now stored.

    Versions only increase. A database newer than `target` raises
    ValueError and is not modified. When `db_path` is a real file that
    already has data, a backup is written beside it before the upgrade.
    """
    migrations = _MIGRATIONS if migrations is None else migrations
    target = SCHEMA_VERSION if target is None else target
    _require_migration_keys(migrations, target)

    current = schema_version(conn)
    if current == target:
        return current
    if current > target:
        raise ValueError(_newer_message(current, target))

    source = _persistent_path(db_path)
    if source is not None and (current > 0 or _has_user_tables(conn)):
        _backup_database(conn, source, current)

    conn.execute("BEGIN IMMEDIATE")
    try:
        current = schema_version(conn)
        if current > target:
            raise ValueError(_newer_message(current, target))
        for version in range(current + 1, target + 1):
            migrations[version](conn)
            _write_schema_version(conn, version)
        conn.commit()
    except Exception:
        conn.rollback()
        raise
    return schema_version(conn)


def connect(db_path: str | Path) -> sqlite3.Connection:
    """Open (and create if needed) the Lantern database.

    A database from Lantern 0.3.0 is upgraded in place after a backup copy
    is written beside the file. A database newer than this process is
    refused and left unchanged.
    """
    conn = sqlite3.connect(str(db_path))
    try:
        apply_migrations(conn, db_path=db_path)
    except Exception:
        conn.close()
        raise
    return conn


def save_scan(conn: sqlite3.Connection, subnet: str, devices: list[dict], demo: bool = False) -> int:
    """Store one scan snapshot and return its id. All-or-nothing."""
    with conn:
        cur = conn.execute(
            "INSERT INTO scans (started_at, subnet, demo) VALUES (?, ?, ?)",
            (_now(), subnet, 1 if demo else 0),
        )
        scan_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO devices (scan_id, ip, mac, hostname, label, open_ports, findings)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    scan_id,
                    device["ip"],
                    device.get("mac"),
                    device.get("hostname"),
                    device.get("label"),
                    json.dumps(device.get("open_ports", [])),
                    json.dumps(device.get("findings", [])),
                )
                for device in devices
            ],
        )
    return scan_id


def ip_sort_key(ip: str):
    """Sort IPv4 addresses numerically, so .2 comes before .10."""
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def load_scan(conn: sqlite3.Connection, scan_id: int) -> dict | None:
    """Load one scan with its devices, or None if the id is unknown."""
    row = conn.execute(
        "SELECT started_at, subnet, demo FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    if not row:
        return None
    devices = []
    for ip, mac, hostname, label, open_ports, findings in conn.execute(
        "SELECT ip, mac, hostname, label, open_ports, findings FROM devices WHERE scan_id = ?",
        (scan_id,),
    ):
        devices.append(
            {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "label": label,
                "open_ports": json.loads(open_ports),
                "findings": json.loads(findings),
            }
        )
    devices.sort(key=lambda d: ip_sort_key(d["ip"]))
    return {"id": scan_id, "started_at": row[0], "subnet": row[1],
            "demo": bool(row[2]), "devices": devices}


def latest_scan_id(conn: sqlite3.Connection) -> int | None:
    row = conn.execute("SELECT MAX(id) FROM scans").fetchone()
    return row[0] if row and row[0] is not None else None


def previous_scan_id(conn: sqlite3.Connection, scan_id: int) -> int | None:
    """The scan saved just before `scan_id`, or None if it is the first."""
    row = conn.execute("SELECT MAX(id) FROM scans WHERE id < ?", (scan_id,)).fetchone()
    return row[0] if row and row[0] is not None else None


def latest_two_scan_ids(conn: sqlite3.Connection) -> list[int]:
    """Newest first, at most two ids."""
    rows = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 2").fetchall()
    return [r[0] for r in rows]


def list_scans(conn: sqlite3.Connection) -> list[dict]:
    """Newest first: id, time, subnet, demo flag, device count."""
    rows = conn.execute(
        "SELECT s.id, s.started_at, s.subnet, s.demo, COUNT(d.id)"
        " FROM scans s LEFT JOIN devices d ON d.scan_id = s.id"
        " GROUP BY s.id ORDER BY s.id DESC"
    ).fetchall()
    return [
        {"id": r[0], "started_at": r[1], "subnet": r[2], "demo": bool(r[3]),
         "device_count": r[4]}
        for r in rows
    ]


def get_trusted(conn: sqlite3.Connection) -> dict[str, dict]:
    """Return {mac_lower: {label, trusted}} for every known device."""
    trusted = {}
    for mac, label, is_trusted in conn.execute(
        "SELECT mac, label, trusted FROM trusted_devices"
    ):
        trusted[mac.lower()] = {"label": label, "trusted": bool(is_trusted)}
    return trusted


def set_trusted(conn: sqlite3.Connection, mac: str, label: str | None, trusted: bool) -> None:
    """Label a device and mark it trusted or unknown. MAC is the key."""
    mac = (mac or "").strip().lower()
    if not mac:
        raise ValueError("A MAC address is required to trust a device.")
    with conn:
        conn.execute(
            "INSERT INTO trusted_devices (mac, label, trusted, updated_at)"
            " VALUES (?, ?, ?, ?)"
            " ON CONFLICT(mac) DO UPDATE SET label=excluded.label,"
            " trusted=excluded.trusted, updated_at=excluded.updated_at",
            (mac, (label or "").strip() or None, 1 if trusted else 0, _now()),
        )


def apply_trust(scan: dict | None, trusted: dict[str, dict]) -> dict | None:
    """Overlay labels and trust flags onto a loaded scan, without mutating the DB rows."""
    if scan is None:
        return None
    for device in scan["devices"]:
        mac = (device.get("mac") or "").lower()
        info = trusted.get(mac) if mac else None
        device["known"] = bool(info)
        device["trusted"] = bool(info and info["trusted"])
        if info and info["label"]:
            device["label"] = info["label"]
    return scan


def load_scan_with_diff(conn: sqlite3.Connection, scan_id: int | None = None) -> tuple[dict | None, dict | None]:
    """Load a scan (latest when scan_id is None) plus its diff against the
    scan before it. Labels and trust flags are applied to both sides.

    Returns (None, None) when there are no scans or the id is unknown.
    """
    if scan_id is None:
        scan_id = latest_scan_id(conn)
        if scan_id is None:
            return None, None
    trusted = get_trusted(conn)
    scan = apply_trust(load_scan(conn, scan_id), trusted)
    if scan is None:
        return None, None
    diff = None
    prev_id = previous_scan_id(conn, scan_id)
    if prev_id is not None:
        diff = diff_scans(apply_trust(load_scan(conn, prev_id), trusted), scan)
    return scan, diff


def diff_scans(old: dict, new: dict) -> dict:
    """Compare two scan dicts. Key devices by MAC when known, else IP.

    A device counts as changed when a port opened or closed, or when it
    kept its MAC but moved to a new IP (old_ip then differs from device.ip).
    """
    def key(device):
        return (device.get("mac") or "").lower() or device["ip"]

    old_map = {key(d): d for d in old["devices"]}
    new_map = {key(d): d for d in new["devices"]}

    added, removed, changed = [], [], []
    for k, device in new_map.items():
        if k not in old_map:
            added.append(device)
            continue
        old_device = old_map[k]
        old_ports = {p["port"] for p in old_device["open_ports"]}
        new_ports = {p["port"] for p in device["open_ports"]}
        opened = sorted(new_ports - old_ports)
        closed = sorted(old_ports - new_ports)
        if opened or closed or device["ip"] != old_device["ip"]:
            changed.append(
                {"device": device, "opened": opened, "closed": closed,
                 "old_ip": old_device["ip"]}
            )
    for k, device in old_map.items():
        if k not in new_map:
            removed.append(device)
    added.sort(key=lambda d: ip_sort_key(d["ip"]))
    removed.sort(key=lambda d: ip_sort_key(d["ip"]))
    changed.sort(key=lambda c: ip_sort_key(c["device"]["ip"]))
    return {"added": added, "removed": removed, "changed": changed}

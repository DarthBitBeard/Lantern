"""Storage: one local SQLite file, no cloud, no accounts.

A scan is a snapshot: devices found, their open ports, and findings.
Diffing two snapshots is the core value: what is new, what left,
what opened, what closed.

Schema changes are forward-only. The `schema_version` table records each
applied version. `connect` runs any missing migrations in one transaction.
For an existing database file it first writes a copy beside it,
`<file>.v<old>.bak`, and leaves that copy untouched.

On Unix the database, that backup, and any directory Lantern creates for
them are private to the owner (0600 and 0700). The mode is set when the
file is created, so umask 022 and a permissive umask both leave it private.
An existing file or directory is not chmod'd. A database or backup that is
already group- or world-readable gets one warning on stderr. A data
directory that already exists and is looser than 0700 (for example 0755)
gets one warning too, and is left unchanged. On Windows those bits are
not set or checked; the user profile ACL is what keeps the file private.
"""

from __future__ import annotations

import ipaddress
import json
import os
import sqlite3
import stat
import sys
import tempfile
import threading
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

# Schema 1 is the Lantern 0.3.0 tables (scans, devices, trusted_devices)
# plus this version table. Schema 2 adds scans.scope_name. The package
# version stays put until a release; the schema version moves only when
# the tables change.
SCHEMA_VERSION = 2

# Owner read/write for files, owner-only for a directory Lantern creates.
# Group and other bits stay off so umask cannot widen them.
_PRIVATE_FILE_MODE = 0o600
_PRIVATE_DIR_MODE = 0o700
_OTHERS_CAN_READ = stat.S_IRGRP | stat.S_IROTH

Migration = Callable[[sqlite3.Connection], None]

# One warning per path per process, so a dashboard that opens the database
# on every request does not fill stderr. Each CLI run is a new process.
# The dashboard serves requests on several threads, so the sets share a lock.
_warned_loose: set[str] = set()
_warned_loose_dirs: set[str] = set()
_scanned_backup_dirs: set[str] = set()
_permission_lock = threading.Lock()


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


def _posix_modes() -> bool:
    """False on Windows, where the user profile ACL is the access check."""
    return os.name != "nt"


def warn_loose_permissions(path: str | Path) -> None:
    """Warn on stderr when an existing file is group- or world-readable.

    Does not change the file and does not raise. Missing paths, directories,
    and unreadable stat results are ignored. On Windows this returns without
    looking at mode bits: Lantern relies on the user profile ACL there.

    The CLI can call this for a database, a ``.vN.bak`` backup, or a future
    export path. `connect` calls it for a database that already exists.
    The same path is reported once per process.
    """
    if not _posix_modes():
        return
    file_path = Path(path)
    try:
        mode = file_path.stat().st_mode
    except OSError:
        return
    if not stat.S_ISREG(mode):
        return
    bits = stat.S_IMODE(mode)
    if bits & _OTHERS_CAN_READ == 0:
        return
    try:
        key = str(file_path.resolve())
    except OSError:
        key = os.fspath(file_path)
    with _permission_lock:
        if key in _warned_loose:
            return
        _warned_loose.add(key)
    try:
        print(
            f"Warning: {file_path} is readable by group or others (mode {bits:04o}). "
            "Lantern will not change an existing file. "
            "Other local accounts can read this inventory.",
            file=sys.stderr,
        )
    except OSError:
        return


def warn_loose_directory(path: str | Path) -> None:
    """Warn on stderr when an existing directory is looser than mode 0700.

    Does not change the directory and does not raise. 0755 is the usual
    case: group and others can enter it and read the names inside. Missing
    paths, files, and unreadable stat results are ignored. On Windows this
    returns without looking at mode bits.

    The working directory (``.``) is not a dedicated data directory and is
    not what callers pass here. ``connect`` warns about the database's
    parent when that parent already existed.
    """
    if not _posix_modes():
        return
    dir_path = Path(path)
    try:
        mode = dir_path.stat().st_mode
    except OSError:
        return
    if not stat.S_ISDIR(mode):
        return
    bits = stat.S_IMODE(mode)
    if bits & 0o077 == 0:
        return
    try:
        key = str(dir_path.resolve())
    except OSError:
        key = os.fspath(dir_path)
    with _permission_lock:
        if key in _warned_loose_dirs:
            return
        _warned_loose_dirs.add(key)
    try:
        print(
            f"Warning: {dir_path} is accessible by group or others (mode {bits:04o}). "
            "Lantern will not change an existing directory.",
            file=sys.stderr,
        )
    except OSError:
        return


def _create_private_directory(path: Path) -> None:
    """Create `path` and any missing parents at mode 0700.

    A directory that already exists is left alone, including one the user
    created before Lantern ran. Lantern does not chmod those.
    """
    if path.exists() or path == path.parent:
        return
    _create_private_directory(path.parent)
    try:
        os.mkdir(path, _PRIVATE_DIR_MODE)
    except FileExistsError:
        return
    if not _posix_modes():
        return
    flags = os.O_RDONLY
    flags |= getattr(os, "O_DIRECTORY", 0)
    flags |= getattr(os, "O_NOFOLLOW", 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return
    try:
        os.fchmod(fd, _PRIVATE_DIR_MODE)
    finally:
        os.close(fd)


def _create_private_file(path: Path) -> None:
    """Create an empty file at `path` with mode 0600. The path must be new.

    `os.open` applies the mode as the file is created, before any other
    library opens it. umask can only clear bits, and 0600 has no group or
    other bits, so umask 022 and umask 0 both leave the file owner-only.
    `fchmod` sets that mode again on platforms that honor it.
    """
    flags = os.O_CREAT | os.O_EXCL | os.O_RDWR
    if _posix_modes():
        flags |= getattr(os, "O_NOFOLLOW", 0)
    fd = os.open(path, flags, _PRIVATE_FILE_MODE)
    try:
        if _posix_modes():
            os.fchmod(fd, _PRIVATE_FILE_MODE)
    finally:
        os.close(fd)


def _write_all(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        count = os.write(fd, payload[offset:])
        if count <= 0:
            raise OSError("short write while creating a private file")
        offset += count


def write_private_file(path: str | Path, data: bytes | str) -> None:
    """Atomically write `data` to `path`, creating the file at mode 0600.

    The bytes land in a temporary file in the same directory and are renamed
    into place, so a reader never sees a partial file. A missing parent
    directory is created at mode 0700. A directory that already exists is
    not modified.

    `data` may be bytes, written unchanged, or str, written as UTF-8.
    On Windows the mode bits are not applied; the user profile ACL is what
    keeps the file private. A later CSV or JSON export should call this
    instead of writing the destination itself.

    This does not warn about a file it replaces. Call
    `warn_loose_permissions` first when the operator should hear that the
    old file was group- or world-readable.
    """
    if isinstance(data, str):
        payload = data.encode("utf-8")
    elif isinstance(data, bytes):
        payload = data
    else:
        raise TypeError("write_private_file data must be str or bytes.")

    destination = Path(path)
    parent = destination.parent
    if parent != Path("") and not parent.exists():
        _create_private_directory(parent)
    directory = parent if parent != Path("") else Path(".")
    fd, tmp_name = tempfile.mkstemp(
        prefix=f".{destination.name}.",
        suffix=".tmp",
        dir=directory,
    )
    tmp_path = Path(tmp_name)
    try:
        try:
            if _posix_modes():
                os.fchmod(fd, _PRIVATE_FILE_MODE)
            _write_all(fd, payload)
            os.fsync(fd)
        finally:
            os.close(fd)
        os.replace(tmp_path, destination)
    except Exception:
        tmp_path.unlink(missing_ok=True)
        raise


def _is_migration_backup(db_name: str, candidate: str) -> bool:
    """True for `<db>.v<version>.bak` and `<db>.v<version>.<n>.bak`."""
    prefix = db_name + ".v"
    suffix = ".bak"
    if not candidate.startswith(prefix) or not candidate.endswith(suffix):
        return False
    middle = candidate[len(prefix):-len(suffix)]
    version, sep, extra = middle.partition(".")
    if not version.isdigit():
        return False
    if sep == "":
        return True
    return extra.isdigit()


def _warn_existing_backups(db_path: Path) -> None:
    """Warn once per directory about sibling migration backups that are loose."""
    if not _posix_modes():
        return
    parent = db_path.parent
    if not parent.is_dir():
        return
    try:
        key = str(parent.resolve())
    except OSError:
        return
    with _permission_lock:
        if key in _scanned_backup_dirs:
            return
        _scanned_backup_dirs.add(key)
    try:
        entries = list(parent.iterdir())
    except OSError:
        return
    db_name = db_path.name
    for candidate in entries:
        if _is_migration_backup(db_name, candidate.name):
            warn_loose_permissions(candidate)


def _refuse_database_symlink(path: Path) -> None:
    """Refuse a symlink, including a dangling one.

    Opening it would follow the link. SQLite then creates the target at
    mode 0644, and a dangling link does not stat, so there is no warning.
    The error does not include the link target.
    """
    if path.is_symlink():
        raise ValueError(
            f"Database path {path} is a symlink. Lantern will not follow it."
        )


def _prepare_database_file(db_path: str | Path) -> None:
    """Create a new database path as a private file, or warn if it is loose.

    An in-memory database is skipped. A symlink is refused. A missing parent
    directory is created at mode 0700. A parent that already exists is not
    chmod'd.
    """
    persistent = _persistent_path(db_path)
    if persistent is None:
        return
    _refuse_database_symlink(persistent)
    parent = persistent.parent
    # "." is the working directory, not a data directory Lantern owns.
    # Any other parent that already exists keeps its mode. Warn when that
    # mode is looser than 0700 so a 0755 ./data is visible and unchanged.
    parent_existed = parent not in (Path(""), Path(".")) and parent.exists()
    if parent != Path("") and not parent.exists():
        _create_private_directory(parent)
    elif parent_existed:
        warn_loose_directory(parent)
    if persistent.exists():
        warn_loose_permissions(persistent)
    else:
        try:
            _create_private_file(persistent)
        except FileExistsError:
            # O_NOFOLLOW|O_EXCL reports a dangling symlink as "file exists".
            _refuse_database_symlink(persistent)
            warn_loose_permissions(persistent)
    _warn_existing_backups(persistent)


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
    # Create the backup before SQLite opens it. sqlite3.connect on a missing
    # path uses mode 0644, which umask 022 leaves world-readable.
    _create_private_file(dest)
    try:
        saved = sqlite3.connect(dest)
    except Exception:
        dest.unlink(missing_ok=True)
        raise
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


def _migration_2_scope_name(conn: sqlite3.Connection) -> None:
    """Schema 2: tag a scan with the scope name that produced it.

    Older rows stay NULL. This migration only adds the column. It does
    not rewrite scan ids or device rows.
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
    if "scope_name" not in columns:
        conn.execute("ALTER TABLE scans ADD COLUMN scope_name TEXT")


_MIGRATIONS: dict[int, Migration] = {
    1: _migration_1_v030_baseline,
    2: _migration_2_scope_name,
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

    A new file is created with mode 0600 before SQLite opens it, and a
    missing parent directory is created with mode 0700. A symlink is
    refused, including a dangling one. An existing database or migration
    backup that is group- or world-readable produces a warning on stderr
    and is left unchanged. On Windows, POSIX modes are not applied; the
    user profile ACL is what keeps the file private.

    A database from Lantern 0.3.0 is upgraded in place after a backup copy
    is written beside the file. A database newer than this process is
    refused and left unchanged.
    """
    _prepare_database_file(db_path)
    conn = sqlite3.connect(str(db_path))
    try:
        apply_migrations(conn, db_path=db_path)
    except Exception:
        conn.close()
        raise
    return conn


def save_scan(
    conn: sqlite3.Connection,
    subnet: str,
    devices: list[dict],
    demo: bool = False,
    scope_name: str | None = None,
) -> int:
    """Store one scan snapshot and return its id. All-or-nothing.

    ``scope_name`` is the named scope that produced the scan, or None for
    ``--subnet``, auto-detect, and demo scans.
    """
    with conn:
        cur = conn.execute(
            "INSERT INTO scans (started_at, subnet, demo, scope_name) VALUES (?, ?, ?, ?)",
            (_now(), subnet, 1 if demo else 0, scope_name),
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
        "SELECT started_at, subnet, demo, scope_name FROM scans WHERE id = ?", (scan_id,)
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
    return {
        "id": scan_id,
        "started_at": row[0],
        "subnet": row[1],
        "demo": bool(row[2]),
        "scope_name": row[3],
        "devices": devices,
    }


def latest_scan_id(conn: sqlite3.Connection, scope_name: str | None = None) -> int | None:
    if scope_name is None:
        row = conn.execute("SELECT MAX(id) FROM scans").fetchone()
    else:
        row = conn.execute(
            "SELECT MAX(id) FROM scans WHERE scope_name = ?", (scope_name,)
        ).fetchone()
    return row[0] if row and row[0] is not None else None


def previous_scan_id(
    conn: sqlite3.Connection, scan_id: int, scope_name: str | None = None,
) -> int | None:
    """The scan saved just before `scan_id`, or None if it is the first.

    When `scope_name` is set, only earlier scans with that same name count.
    """
    if scope_name is None:
        row = conn.execute("SELECT MAX(id) FROM scans WHERE id < ?", (scan_id,)).fetchone()
    else:
        row = conn.execute(
            "SELECT MAX(id) FROM scans WHERE id < ? AND scope_name = ?",
            (scan_id, scope_name),
        ).fetchone()
    return row[0] if row and row[0] is not None else None


def latest_two_scan_ids(conn: sqlite3.Connection, scope_name: str | None = None) -> list[int]:
    """Newest first, at most two ids."""
    if scope_name is None:
        rows = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 2").fetchall()
    else:
        rows = conn.execute(
            "SELECT id FROM scans WHERE scope_name = ? ORDER BY id DESC LIMIT 2",
            (scope_name,),
        ).fetchall()
    return [r[0] for r in rows]


def list_scans(conn: sqlite3.Connection, scope_name: str | None = None) -> list[dict]:
    """Newest first: id, time, subnet, scope name, demo flag, device count."""
    if scope_name is None:
        rows = conn.execute(
            "SELECT s.id, s.started_at, s.subnet, s.scope_name, s.demo, COUNT(d.id)"
            " FROM scans s LEFT JOIN devices d ON d.scan_id = s.id"
            " GROUP BY s.id ORDER BY s.id DESC"
        ).fetchall()
    else:
        rows = conn.execute(
            "SELECT s.id, s.started_at, s.subnet, s.scope_name, s.demo, COUNT(d.id)"
            " FROM scans s LEFT JOIN devices d ON d.scan_id = s.id"
            " WHERE s.scope_name = ?"
            " GROUP BY s.id ORDER BY s.id DESC",
            (scope_name,),
        ).fetchall()
    return [
        {
            "id": r[0],
            "started_at": r[1],
            "subnet": r[2],
            "scope_name": r[3],
            "demo": bool(r[4]),
            "device_count": r[5],
        }
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


def load_scan_with_diff(
    conn: sqlite3.Connection,
    scan_id: int | None = None,
    scope_name: str | None = None,
) -> tuple[dict | None, dict | None]:
    """Load a scan (latest when scan_id is None) plus its diff against the
    scan before it. Labels and trust flags are applied to both sides.

    When `scope_name` is set, the scan and the one before it are limited
    to that scope. Returns (None, None) when there are no scans or the id
    is unknown or belongs to a different scope.
    """
    if scan_id is None:
        scan_id = latest_scan_id(conn, scope_name)
        if scan_id is None:
            return None, None
    trusted = get_trusted(conn)
    scan = apply_trust(load_scan(conn, scan_id), trusted)
    if scan is None:
        return None, None
    if scope_name is not None and scan.get("scope_name") != scope_name:
        return None, None
    diff = None
    prev_scope = scope_name if scope_name is not None else None
    prev_id = previous_scan_id(conn, scan_id, prev_scope)
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

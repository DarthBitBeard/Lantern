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
import re
import sqlite3
import stat
import sys
import tempfile
import threading
from collections.abc import Callable
from datetime import datetime, timedelta, timezone
from pathlib import Path

# Schema 1 is the Lantern 0.3.0 tables (scans, devices, trusted_devices)
# plus this version table. Schema 2 adds scans.scope_name. Schema 3 adds
# the asset table, which is not tied to a scan id. Schema 4 adds an index on
# the device table and changes no rows. Schema 5 adds the gateway and device
# identities for the map; schema 6 adds scans.topology (the switch map). The package version stays put until a
# release; the schema version moves only when the tables or indexes change.
SCHEMA_VERSION = 6

# Owner read/write for files, owner-only for a directory Lantern creates.
# Group and other bits stay off so umask cannot widen them.
_PRIVATE_FILE_MODE = 0o600
_PRIVATE_DIR_MODE = 0o700
_OTHERS_CAN_READ = stat.S_IRGRP | stat.S_IROTH
# CSI and OSC sequences. ESC itself is also dropped with the other controls.
_ANSI_RE = re.compile(
    r"\x1b\[[0-?]*[ -/]*[@-~]|\x1b\][^\x07\x1b]*(?:\x07|\x1b\\)"
)

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


def _decode_db_text(value: bytes) -> str:
    """UTF-8 text from SQLite. Invalid bytes become U+FFFD, not an exception."""
    return value.decode("utf-8", errors="replace")


class DatabaseSymlinkError(ValueError):
    """The database path is a symlink. The message does not include a path."""


class NewerSchemaError(ValueError):
    """The file was written by a newer Lantern. The message does not include a path."""


class CorruptScanError(ValueError):
    """A stored scan row is not valid JSON. The message does not include a path."""


_SYMLINK_MESSAGE = "Database path is a symlink. Lantern will not follow it."
_NEWER_SCHEMA_MESSAGE = (
    "Database schema is newer than this Lantern. Refusing to change it"
)
_CORRUPT_SCAN_MESSAGE = "The saved scan could not be read."


def _newer_message(found: int, target: int) -> str:
    return (
        f"{_NEWER_SCHEMA_MESSAGE} (schema {found} vs {target}). "
        "Upgrade Lantern to open this file."
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


def _path_for_warning(path: Path) -> str:
    """Path text for stderr: no ANSI sequences and no control characters."""
    from .assets import strip_for_text

    return strip_for_text(_ANSI_RE.sub("", os.fspath(path)))


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
            f"Warning: {_path_for_warning(file_path)} is readable by group or others "
            f"(mode {bits:04o}). "
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
            f"Warning: {_path_for_warning(dir_path)} is accessible by group or others "
            f"(mode {bits:04o}). "
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
        raise DatabaseSymlinkError(_SYMLINK_MESSAGE)


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


def _migration_3_assets(conn: sqlite3.Connection) -> None:
    """Schema 3: inventory fields that persist across scans.

    The table is independent of scan ids. Older scans are not rewritten.
    """
    conn.execute(
        """CREATE TABLE IF NOT EXISTS assets (
               asset_key TEXT PRIMARY KEY,
               key_kind TEXT NOT NULL,
               owner TEXT,
               location TEXT,
               tags TEXT NOT NULL DEFAULT '[]',
               criticality TEXT,
               notes TEXT,
               updated_at TEXT NOT NULL
           )"""
    )


def _migration_4_device_ip_index(conn: sqlite3.Connection) -> None:
    """Schema 4: one covering index so history-wide device queries skip the JSON.

    `devices` rows carry the open-port and finding JSON, so a query that has to
    visit every row reads all of it. `asset set <ip>` looks up the newest scan
    that saw an address, and `/api/v1` and export compute first and last
    sighting per device. Both only need `ip`, `scan_id`, and `mac`, and this
    index holds exactly those, so SQLite answers them from the index alone.
    On 30,000 device rows that took the IP lookup from about 46 ms to 0.1 ms
    and the sighting query from about 70 ms to 20 ms. Only an index is added;
    no row is touched.
    """
    conn.execute(
        "CREATE INDEX IF NOT EXISTS devices_ip_scan_mac ON devices (ip, scan_id, mac)"
    )


def _migration_5_network_map(conn: sqlite3.Connection) -> None:
    """Schema 5: what the network map needs.

    `scans` gains the gateway the scan saw (address and MAC) and this
    machine's own address in the subnet. `devices` gains `identity`, the
    JSON a device announced over SSDP or mDNS (see `identify.py`). Older
    rows keep NULL in every new column, and no row is rewritten.
    """
    scan_columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
    for column in ("gateway_ip", "gateway_mac", "local_ip"):
        if column not in scan_columns:
            conn.execute(f"ALTER TABLE scans ADD COLUMN {column} TEXT")
    device_columns = {row[1] for row in conn.execute("PRAGMA table_info(devices)")}
    if "identity" not in device_columns:
        conn.execute("ALTER TABLE devices ADD COLUMN identity TEXT")


def _migration_6_topology(conn: sqlite3.Connection) -> None:
    """Schema 6: `scans.topology`, the switch map for that scan (JSON).

    Filled only when switches were queried (see `topology.py`). It holds
    switch names, port names, and MAC-to-port placements, never the SNMP
    community. Older rows keep NULL.
    """
    columns = {row[1] for row in conn.execute("PRAGMA table_info(scans)")}
    if "topology" not in columns:
        conn.execute("ALTER TABLE scans ADD COLUMN topology TEXT")


_MIGRATIONS: dict[int, Migration] = {
    1: _migration_1_v030_baseline,
    2: _migration_2_scope_name,
    3: _migration_3_assets,
    4: _migration_4_device_ip_index,
    5: _migration_5_network_map,
    6: _migration_6_topology,
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
        raise NewerSchemaError(_newer_message(current, target))

    source = _persistent_path(db_path)
    if source is not None and (current > 0 or _has_user_tables(conn)):
        _backup_database(conn, source, current)

    conn.execute("BEGIN IMMEDIATE")
    try:
        current = schema_version(conn)
        if current > target:
            raise NewerSchemaError(_newer_message(current, target))
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
    conn.text_factory = _decode_db_text
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
    network: dict | None = None,
    topology: dict | None = None,
) -> int:
    """Store one scan snapshot and return its id. All-or-nothing.

    ``scope_name`` is the named scope that produced the scan, or None for
    ``--subnet``, auto-detect, and demo scans. ``network`` holds what the
    scan learned about the subnet itself: ``gateway_ip``, ``gateway_mac``,
    and ``local_ip`` (each may be None). ``topology`` is the switch map
    from `topology.map_switches`, when switches were queried.
    """
    network = network or {}
    with conn:
        cur = conn.execute(
            "INSERT INTO scans (started_at, subnet, demo, scope_name, gateway_ip, gateway_mac, local_ip, topology)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            (
                _now(), subnet, 1 if demo else 0, scope_name,
                network.get("gateway_ip"), network.get("gateway_mac"), network.get("local_ip"),
                json.dumps(topology) if topology else None,
            ),
        )
        scan_id = cur.lastrowid
        conn.executemany(
            "INSERT INTO devices (scan_id, ip, mac, hostname, label, open_ports, findings, identity)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)",
            [
                (
                    scan_id,
                    device["ip"],
                    device.get("mac"),
                    _clean_hostname(device.get("hostname")),
                    device.get("label"),
                    json.dumps(device.get("open_ports", [])),
                    json.dumps(device.get("findings", [])),
                    json.dumps(device["identity"]) if device.get("identity") else None,
                )
                for device in devices
            ],
        )
    return scan_id


def _clean_hostname(value) -> str | None:
    """PTR and other hostnames: no controls, no bidi, at most 253 characters."""
    from .identify import clean_text

    return clean_text(value, 253)


def ip_sort_key(ip: str):
    """Sort IPv4 addresses numerically, so .2 comes before .10."""
    try:
        return (0, int(ipaddress.ip_address(ip)))
    except ValueError:
        return (1, ip)


def _port_number(value) -> bool:
    return isinstance(value, int) and not isinstance(value, bool) and 0 <= value <= 65535


def _require_ports(value):
    if not isinstance(value, list):
        raise CorruptScanError(_CORRUPT_SCAN_MESSAGE)
    for item in value:
        if isinstance(item, dict):
            if not _port_number(item.get("port")):
                raise CorruptScanError(_CORRUPT_SCAN_MESSAGE)
        elif not _port_number(item):
            raise CorruptScanError(_CORRUPT_SCAN_MESSAGE)
    return value


def _require_findings(value):
    if not isinstance(value, list) or any(not isinstance(item, dict) for item in value):
        raise CorruptScanError(_CORRUPT_SCAN_MESSAGE)
    return value


def _require_object(raw: str | None) -> dict | None:
    """A stored JSON object, or None when the column is empty.

    A value that is JSON but not an object is corrupt. Callers used to
    swallow that and keep going.
    """
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except json.JSONDecodeError as exc:
        raise CorruptScanError(_CORRUPT_SCAN_MESSAGE) from exc
    if value is None:
        return None
    if not isinstance(value, dict):
        raise CorruptScanError(_CORRUPT_SCAN_MESSAGE)
    return value


def _load_identity(raw: str | None) -> dict | None:
    if not raw:
        return None
    try:
        value = json.loads(raw)
    except ValueError:
        return None
    return value if isinstance(value, dict) else None


def load_scan(conn: sqlite3.Connection, scan_id: int) -> dict | None:
    """Load one scan with its devices, or None if the id is unknown."""
    row = conn.execute(
        "SELECT started_at, subnet, demo, scope_name, gateway_ip, gateway_mac, local_ip, topology"
        " FROM scans WHERE id = ?",
        (scan_id,),
    ).fetchone()
    if not row:
        return None
    devices = []
    for ip, mac, hostname, label, open_ports, findings, identity in conn.execute(
        "SELECT ip, mac, hostname, label, open_ports, findings, identity FROM devices WHERE scan_id = ?",
        (scan_id,),
    ):
        try:
            ports = json.loads(open_ports)
            found = json.loads(findings)
        except json.JSONDecodeError as exc:
            raise CorruptScanError(_CORRUPT_SCAN_MESSAGE) from exc
        devices.append(
            {
                "ip": ip,
                "mac": mac,
                "hostname": hostname,
                "label": label,
                "open_ports": _require_ports(ports),
                "findings": _require_findings(found),
                "identity": _require_object(identity),
            }
        )
    devices.sort(key=lambda d: ip_sort_key(d["ip"]))
    return {
        "id": scan_id,
        "started_at": row[0],
        "subnet": row[1],
        "demo": bool(row[2]),
        "scope_name": row[3],
        "network": {"gateway_ip": row[4], "gateway_mac": row[5], "local_ip": row[6]},
        "topology": _require_object(row[7]),
        "devices": devices,
    }


def set_topology(conn: sqlite3.Connection, scan_id: int, topology: dict | None) -> bool:
    """Attach (or clear) a switch map on an existing scan. False if the id is unknown."""
    with conn:
        cur = conn.execute(
            "UPDATE scans SET topology = ? WHERE id = ?",
            (json.dumps(topology) if topology else None, scan_id),
        )
    return cur.rowcount == 1


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
    """The earlier scan with the same scope name, or None if this is the first.

    ``scope_name`` None matches only unscoped scans (``scope_name IS NULL``).
    It does not mean "any scope".
    """
    if scope_name is None:
        row = conn.execute(
            "SELECT MAX(id) FROM scans WHERE id < ? AND scope_name IS NULL",
            (scan_id,),
        ).fetchone()
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


def count_scans(conn: sqlite3.Connection, scope_name: str | None = None) -> int:
    """How many scans are stored, optionally for one scope."""
    if scope_name is None:
        return conn.execute("SELECT COUNT(*) FROM scans").fetchone()[0]
    return conn.execute(
        "SELECT COUNT(*) FROM scans WHERE scope_name = ?", (scope_name,)
    ).fetchone()[0]


def list_scans(
    conn: sqlite3.Connection,
    scope_name: str | None = None,
    limit: int | None = None,
    offset: int = 0,
) -> list[dict]:
    """Newest first: id, time, subnet, scope name, demo flag, device count.

    ``limit`` and ``offset`` page through the result. No ``limit`` returns
    every scan.
    """
    sql = (
        "SELECT s.id, s.started_at, s.subnet, s.scope_name, s.demo, COUNT(d.id)"
        " FROM scans s LEFT JOIN devices d ON d.scan_id = s.id"
    )
    params: list = []
    if scope_name is not None:
        sql += " WHERE s.scope_name = ?"
        params.append(scope_name)
    sql += " GROUP BY s.id ORDER BY s.id DESC"
    if limit is not None:
        sql += " LIMIT ? OFFSET ?"
        params += [int(limit), int(offset)]
    return [
        {
            "id": r[0],
            "started_at": r[1],
            "subnet": r[2],
            "scope_name": r[3],
            "demo": bool(r[4]),
            "device_count": r[5],
        }
        for r in conn.execute(sql, params).fetchall()
    ]


def scans_to_prune(
    conn: sqlite3.Connection,
    keep: int | None = None,
    older_than_days: float | None = None,
    scope_name: str | None = None,
    now: datetime | None = None,
) -> list[int]:
    """Ids of scans that ``delete_scans`` would remove, oldest first.

    Each scope (and the unscoped scans) is judged on its own, so a scope
    that is scanned rarely is not wiped by one that is scanned often. The
    newest scan of every scope is always kept, because a diff needs a
    baseline. With ``keep``, a scan is a candidate only when it is not among
    the newest ``keep`` of its scope. With ``older_than_days``, only when it
    started before that many days ago. With both, a scan must satisfy both
    to be removed. With neither, nothing is removed. ``scope_name`` limits
    the candidates to that scope.
    """
    if keep is None and older_than_days is None:
        return []
    if keep is not None and keep < 1:
        raise ValueError("keep must be at least 1.")
    if older_than_days is not None and older_than_days < 0:
        raise ValueError("older-than must not be negative.")
    cutoff = None
    if older_than_days is not None:
        cutoff = (now or datetime.now(timezone.utc)) - timedelta(days=older_than_days)
    by_scope: dict = {}
    for scan_id, started_at, scope in conn.execute(
        "SELECT id, started_at, scope_name FROM scans ORDER BY id DESC"
    ):
        by_scope.setdefault(scope, []).append((scan_id, started_at))
    doomed = []
    for scope, scans in by_scope.items():
        if scope_name is not None and scope != scope_name:
            continue
        for position, (scan_id, started_at) in enumerate(scans):
            if position == 0:
                continue
            if keep is not None and position < keep:
                continue
            if cutoff is not None:
                try:
                    when = datetime.fromisoformat(started_at)
                except (TypeError, ValueError):
                    continue
                if when.tzinfo is None:
                    when = when.replace(tzinfo=timezone.utc)
                if when >= cutoff:
                    continue
            doomed.append(scan_id)
    return sorted(doomed)


def delete_scans(conn: sqlite3.Connection, scan_ids: list[int]) -> int:
    """Delete scans and their device rows in one transaction. Returns the scan count.

    Inventory and trust records are not tied to a scan and are kept.
    """
    ids = [(int(i),) for i in scan_ids]
    if not ids:
        return 0
    with conn:
        conn.executemany("DELETE FROM devices WHERE scan_id = ?", ids)
        conn.executemany("DELETE FROM scans WHERE id = ?", ids)
    return len(ids)


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
    previous scan of the same scope. Labels and trust flags are applied
    to both sides.

    When `scope_name` is set, the loaded scan must already have that name.
    The comparison never crosses into a different scope, including when
    the caller does not pass one. Unscoped scans compare only to earlier
    unscoped scans. Returns (None, None) when there are no scans or the id
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
    prev_id = previous_scan_id(conn, scan_id, scan.get("scope_name"))
    if prev_id is not None:
        diff = diff_scans(apply_trust(load_scan(conn, prev_id), trusted), scan)
    return scan, diff


def _pair_by_key(old_devices: list[dict], new_devices: list[dict]):
    """Match the devices that share one key. Returns (pairs, added, removed).

    Several devices can carry one MAC: a proxy-ARP router, a host with more
    than one address, a VM bridge. Same-IP devices are matched first. What is
    left on both sides is matched in IP order, which is a move, and anything
    still unmatched is added or removed. One device on each side is always a
    pair, so a MAC that kept its identity but changed IP still reads as moved.
    """
    old_left = list(old_devices)
    pairs, new_left = [], []
    for device in new_devices:
        match = next((o for o in old_left if o["ip"] == device["ip"]), None)
        if match is None:
            new_left.append(device)
        else:
            old_left.remove(match)
            pairs.append((match, device))
    old_left.sort(key=lambda d: ip_sort_key(d["ip"]))
    new_left.sort(key=lambda d: ip_sort_key(d["ip"]))
    count = min(len(old_left), len(new_left))
    pairs.extend(zip(old_left[:count], new_left[:count]))
    return pairs, new_left[count:], old_left[count:]


def diff_scans(old: dict, new: dict) -> dict:
    """Compare two scan dicts. Key devices by MAC when known, else IP.

    A device counts as changed when a port opened or closed, or when it
    kept its MAC but moved to a new IP (old_ip then differs from device.ip).
    Devices that share a MAC are matched one by one, never merged.
    """
    def key(device):
        return (device.get("mac") or "").lower() or device["ip"]

    def group(devices):
        grouped: dict[str, list[dict]] = {}
        for device in devices:
            grouped.setdefault(key(device), []).append(device)
        return grouped

    old_groups = group(old["devices"])
    new_groups = group(new["devices"])

    added, removed, changed = [], [], []
    for k, new_devices in new_groups.items():
        pairs, only_new, only_old = _pair_by_key(old_groups.get(k, []), new_devices)
        added.extend(only_new)
        removed.extend(only_old)
        for old_device, device in pairs:
            old_ports = {p["port"] for p in old_device["open_ports"]}
            new_ports = {p["port"] for p in device["open_ports"]}
            opened = sorted(new_ports - old_ports)
            closed = sorted(old_ports - new_ports)
            if opened or closed or device["ip"] != old_device["ip"]:
                changed.append(
                    {"device": device, "opened": opened, "closed": closed,
                     "old_ip": old_device["ip"]}
                )
    for k, old_devices in old_groups.items():
        if k not in new_groups:
            removed.extend(old_devices)
    added.sort(key=lambda d: ip_sort_key(d["ip"]))
    removed.sort(key=lambda d: ip_sort_key(d["ip"]))
    changed.sort(key=lambda c: ip_sort_key(c["device"]["ip"]))
    return {"added": added, "removed": removed, "changed": changed}

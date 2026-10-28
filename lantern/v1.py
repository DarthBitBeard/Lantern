"""Read-only export and /api/v1 documents. Stdlib only.

The HTTP layer turns these values into responses. This module does not
listen, and it does not write a file unless ``write_export_file`` is called
from the CLI.
"""

from __future__ import annotations

import csv
import io
import ipaddress
import json
import os
import re
import stat
import tempfile
import threading
from pathlib import Path

from . import __version__
from .assets import CRITICALITIES, normalize_mac
from .ports import SEVERITY_RANK
from .store import (
    diff_scans,
    get_trusted,
    apply_trust,
    ip_sort_key,
    latest_scan_id,
    list_scans,
    load_scan,
    previous_scan_id,
)

API_VERSION = 1
MAX_V1_ROWS = 100_000
MAX_V1_RESPONSE_BYTES = 32 * 1024 * 1024
DEFAULT_LIMIT = 200
MAX_LIMIT = 1000
_NUM_RE = re.compile(r"^[0-9]{1,9}$")
_DDE_RE = re.compile(r"""(?i)^\s*["']*\s*[=+\-@].*\|""")
_FORMULA_FIRST = set("=+-@\t\r\n|") | {"\uff1d", "\uff0b", "\uff0d", "\uff20"}
_LEADING = set(" \t\r\n\"'")
SEVERITIES = ("critical", "high", "medium", "low", "info")
_EXPORT_WHAT = ("devices", "findings", "history")
_PRIVATE = ("owner", "location", "notes")

_DEVICE_COLUMNS = (
    "scan_id", "key", "key_type", "ip", "mac", "hostname", "label", "trusted",
    "owner", "location", "tags", "criticality", "notes", "updated_at",
    "first_seen", "last_seen", "open_ports", "finding_count",
)
_FINDING_COLUMNS = ("scan_id", "ip", "mac", "port", "service", "severity", "title", "fix")
_HISTORY_COLUMNS = ("id", "started_at", "subnet", "scope_name", "demo", "device_count")

MESSAGES = {
    "bad_request": "The request is not valid.",
    "forbidden": "Forbidden.",
    "not_found": "Not found.",
    "method_not_allowed": "Method not allowed.",
    "conflict": "Conflict.",
    "too_large": "The response is too large.",
    "busy": "An export is already running.",
    "validation": "The request is not valid.",
    "server_error": "Server error.",
}

_export_lock = threading.Lock()


class V1Error(Exception):
    """A v1 failure with a fixed message. The text is never ``str(exc)`` from elsewhere."""

    def __init__(self, status: int, code: str, fields: dict | None = None):
        self.status = status
        self.code = code
        self.fields = fields
        super().__init__(code)


def error_body(code: str, fields: dict | None = None) -> dict:
    error = {"code": code, "message": MESSAGES[code]}
    if fields:
        error["fields"] = fields
    return {"api_version": API_VERSION, "error": error}


def is_v1_path(path: str) -> bool:
    return path == "/api/v1" or path.startswith("/api/v1/")


def header_value(value: str) -> str:
    """Refuse a response header that could split the header block."""
    text = str(value)
    if "\r" in text or "\n" in text:
        raise V1Error(500, "server_error")
    return text


def export_filename(what: str, scan_id: int, fmt: str) -> str:
    ext = "csv" if fmt == "csv" else "json"
    return header_value(
        f'attachment; filename="lantern-{what}-{int(scan_id)}.{ext}"'
    )


def defuse_cell(value) -> str:
    """Quote-prefix a spreadsheet formula. Every caller still quotes the cell."""
    text = "" if value is None else str(value).replace("\x00", "")
    index = 0
    while index < len(text) and text[index] in _LEADING:
        index += 1
    first = text[index] if index < len(text) else ""
    lowered = text.lower()
    if (
        first in _FORMULA_FIRST
        or _DDE_RE.search(text)
        or "cmd|" in lowered
        or "dde(" in lowered
    ):
        return "'" + text
    return text


def csv_bytes(headers: list[str], rows: list[list]) -> bytes:
    buffer = io.StringIO(newline="")
    writer = csv.writer(buffer, dialect="excel", quoting=csv.QUOTE_ALL, lineterminator="\r\n")
    writer.writerow(headers)
    for row in rows:
        writer.writerow([defuse_cell(cell) for cell in row])
    return buffer.getvalue().encode("utf-8")


def as_z(value) -> str | None:
    if value is None:
        return None
    text = str(value)
    if text.endswith("+00:00"):
        return text[:-6] + "Z"
    return text


def _one(query: dict, name: str) -> str | None:
    values = query.get(name) or []
    if not values or values[0] is None or values[0] == "":
        return None
    return str(values[0])


def _many(query: dict, name: str) -> list[str]:
    return [str(item) for item in (query.get(name) or []) if item]


def _number(query: dict, name: str) -> int | None:
    raw = _one(query, name)
    if raw is None:
        return None
    if not _NUM_RE.fullmatch(raw):
        raise V1Error(400, "bad_request")
    return int(raw)


def _limit_offset(query: dict) -> tuple[int, int]:
    limit = _number(query, "limit")
    offset = _number(query, "offset")
    if limit is None:
        limit = DEFAULT_LIMIT
    if offset is None:
        offset = 0
    if limit < 1 or limit > MAX_LIMIT:
        raise V1Error(400, "bad_request")
    return limit, offset


def _criticality(query: dict) -> str | None:
    value = _one(query, "criticality")
    if value is None:
        return None
    if value not in CRITICALITIES:
        raise V1Error(400, "bad_request")
    return value


def _severity(query: dict) -> str | None:
    value = _one(query, "severity")
    if value is None:
        return None
    if value not in SEVERITIES:
        raise V1Error(400, "bad_request")
    return value


def _tags(query: dict) -> list[str]:
    tags = []
    for tag in _many(query, "tag"):
        if not re.fullmatch(r"[a-z0-9._-]{1,32}", tag):
            raise V1Error(422, "validation", {"tag": "invalid"})
        tags.append(tag)
    return tags


def _too_many(count: int) -> None:
    if count > MAX_V1_ROWS:
        raise V1Error(413, "too_large")


def _finish(payload: dict) -> bytes:
    body = json.dumps(payload).encode("utf-8")
    if len(body) > MAX_V1_RESPONSE_BYTES:
        raise V1Error(413, "too_large")
    return body


def _page(rows: list, limit: int, offset: int) -> list:
    return rows[offset:offset + limit]


def _device_identity(device: dict) -> tuple[str, str]:
    mac = normalize_mac(device.get("mac"))
    if mac:
        return mac, "mac"
    return str(ipaddress.ip_address(str(device["ip"]).strip())), "ip"


def _seen_bounds(conn) -> dict[tuple[str, str], tuple[str, str]]:
    found: dict[tuple[str, str], tuple[str, str]] = {}
    rows = conn.execute(
        "SELECT d.ip, d.mac, s.started_at FROM devices d "
        "JOIN scans s ON s.id = d.scan_id"
    )
    for ip, mac, started in rows:
        try:
            key = _device_identity({"ip": ip, "mac": mac})
        except ValueError:
            continue
        previous = found.get(key)
        if previous is None:
            found[key] = (started, started)
        else:
            found[key] = (min(previous[0], started), max(previous[1], started))
    return found


def _assets(conn) -> dict[str, dict]:
    found = {}
    for key, owner, location, tags, criticality, notes, updated in conn.execute(
        "SELECT asset_key, owner, location, tags, criticality, notes, updated_at FROM assets"
    ):
        found[key] = {
            "owner": owner,
            "location": location,
            "tags": json.loads(tags or "[]"),
            "criticality": criticality,
            "notes": notes,
            "updated_at": updated,
        }
    return found


def _ports(device: dict) -> list[dict]:
    ports = []
    for port in device.get("open_ports") or []:
        banner = port.get("banner")
        ports.append({
            "port": int(port["port"]),
            "banner": banner if banner else None,
        })
    return ports


def _device_dict(device: dict, scan: dict, assets: dict, seen: dict, *, private: bool) -> dict:
    key, key_type = _device_identity(device)
    asset = assets.get(f"{key_type}:{key}")
    first, last = seen.get((key_type, key), (scan["started_at"], scan["started_at"]))
    body = {
        "key": key,
        "key_type": key_type,
        "ip": device["ip"],
        "mac": key if key_type == "mac" else None,
        "hostname": device.get("hostname"),
        "label": device.get("label"),
        "trusted": bool(device.get("trusted")),
        "tags": list(asset["tags"]) if asset else [],
        "criticality": asset["criticality"] if asset else None,
        "updated_at": as_z(asset["updated_at"]) if asset and asset.get("updated_at") else None,
        "first_seen": as_z(first),
        "last_seen": as_z(last),
        "open_ports": _ports(device),
        "finding_count": len(device.get("findings") or []),
    }
    if private:
        body["owner"] = asset["owner"] if asset else None
        body["location"] = asset["location"] if asset else None
        body["notes"] = asset["notes"] if asset else None
    return body


def _load_trusted_scan(conn, scan_id: int):
    scan = load_scan(conn, scan_id)
    if scan is None:
        return None
    return apply_trust(scan, get_trusted(conn))


def _resolve_scan_id(conn, query: dict) -> int:
    scan_id = _number(query, "scan_id")
    scope = _one(query, "scope")
    if scan_id is not None:
        row = conn.execute(
            "SELECT scope_name FROM scans WHERE id = ?", (scan_id,)
        ).fetchone()
        if row is None or (scope is not None and row[0] != scope):
            raise V1Error(404, "not_found")
        return scan_id
    found = latest_scan_id(conn, scope)
    if found is None:
        raise V1Error(404, "not_found")
    return found


def _select_scan(conn, query: dict):
    return _load_trusted_scan(conn, _resolve_scan_id(conn, query))


def _matches(device: dict, tags: list[str], criticality: str | None) -> bool:
    if criticality is not None and device.get("criticality") != criticality:
        return False
    owned = set(device.get("tags") or [])
    return all(tag in owned for tag in tags)


def _sort_devices(rows: list[dict]) -> list[dict]:
    return sorted(rows, key=lambda row: (ip_sort_key(row["ip"]), row.get("mac") or ""))


def device_rows(conn, query: dict, *, private: bool) -> tuple[dict, list[dict]]:
    """Return the scan and every matching device, before pagination."""
    scan_id = _resolve_scan_id(conn, query)
    count = conn.execute(
        "SELECT COUNT(*) FROM devices WHERE scan_id = ?", (scan_id,)
    ).fetchone()[0]
    _too_many(count)
    scan = _load_trusted_scan(conn, scan_id)
    assets = _assets(conn)
    seen = _seen_bounds(conn)
    tags = _tags(query)
    criticality = _criticality(query)
    rows = []
    for device in scan["devices"]:
        shown = _device_dict(device, scan, assets, seen, private=private)
        if _matches(shown, tags, criticality):
            rows.append(shown)
    _too_many(len(rows))
    return scan, _sort_devices(rows)


def devices_document(conn, query: dict, *, private: bool = True) -> dict:
    limit, offset = _limit_offset(query)
    scan, rows = device_rows(conn, query, private=private)
    return {
        "api_version": API_VERSION,
        "scan_id": scan["id"],
        "items": _page(rows, limit, offset),
        "total": len(rows),
        "limit": limit,
        "offset": offset,
    }


def _scan_dict(row: dict) -> dict:
    return {
        "id": row["id"],
        "started_at": as_z(row["started_at"]),
        "subnet": row["subnet"],
        "scope_name": row.get("scope_name"),
        "demo": bool(row["demo"]),
        "device_count": row["device_count"],
    }


def scans_document(conn, query: dict) -> dict:
    limit, offset = _limit_offset(query)
    scope = _one(query, "scope")
    rows = list_scans(conn, scope)
    _too_many(len(rows))
    shown = [_scan_dict(row) for row in rows]
    return {
        "api_version": API_VERSION,
        "items": _page(shown, limit, offset),
        "total": len(shown),
        "limit": limit,
        "offset": offset,
    }


def one_scan_document(conn, scan_id: int) -> dict:
    if scan_id < 1:
        raise V1Error(404, "not_found")
    scan = load_scan(conn, scan_id)
    if scan is None:
        raise V1Error(404, "not_found")
    count = conn.execute(
        "SELECT COUNT(*) FROM devices WHERE scan_id = ?", (scan_id,)
    ).fetchone()[0]
    body = _scan_dict({
        "id": scan["id"],
        "started_at": scan["started_at"],
        "subnet": scan["subnet"],
        "scope_name": scan.get("scope_name"),
        "demo": scan["demo"],
        "device_count": count,
    })
    body["api_version"] = API_VERSION
    return body


def findings_rows(conn, query: dict) -> tuple[dict, list[dict]]:
    scan, devices = device_rows(conn, query, private=False)
    severity = _severity(query)
    rows = []
    for device in devices:
        raw = next(item for item in scan["devices"] if item["ip"] == device["ip"])
        for finding in raw.get("findings") or []:
            if severity is not None and finding.get("severity") != severity:
                continue
            rows.append({
                "ip": device["ip"],
                "mac": device["mac"],
                "port": int(finding["port"]),
                "service": finding.get("service") or "",
                "severity": finding.get("severity") or "",
                "title": finding.get("title") or "",
                "fix": finding.get("fix") or "",
            })
    _too_many(len(rows))
    rows.sort(key=lambda row: (
        SEVERITY_RANK.get(row["severity"], 9),
        ip_sort_key(row["ip"]),
        row["port"],
    ))
    return scan, rows


def findings_document(conn, query: dict) -> dict:
    limit, offset = _limit_offset(query)
    scan, rows = findings_rows(conn, query)
    return {
        "api_version": API_VERSION,
        "scan_id": scan["id"],
        "items": _page(rows, limit, offset),
        "total": len(rows),
        "limit": limit,
        "offset": offset,
    }


def diff_document(conn, query: dict) -> dict:
    scan = _select_scan(conn, query)
    prev_id = previous_scan_id(conn, scan["id"], scan.get("scope_name"))
    assets = _assets(conn)
    seen = _seen_bounds(conn)
    added, removed, changed = [], [], []
    if prev_id is not None:
        previous = _load_trusted_scan(conn, prev_id)
        diff = diff_scans(previous, scan)
        added = [
            _device_dict(device, scan, assets, seen, private=True) for device in diff["added"]
        ]
        removed = [
            _device_dict(device, previous, assets, seen, private=True)
            for device in diff["removed"]
        ]
        for change in diff["changed"]:
            device = _device_dict(change["device"], scan, assets, seen, private=True)
            old_ip = change.get("old_ip")
            if old_ip == device["ip"]:
                old_ip = None
            changed.append({
                "device": device,
                "opened": list(change["opened"]),
                "closed": list(change["closed"]),
                "old_ip": old_ip,
            })
    _too_many(len(added) + len(removed) + len(changed))
    return {
        "api_version": API_VERSION,
        "scan_id": scan["id"],
        "previous_scan_id": prev_id,
        "added": _sort_devices(added),
        "removed": _sort_devices(removed),
        "changed": sorted(changed, key=lambda row: (ip_sort_key(row["device"]["ip"]), row["device"].get("mac") or "")),
    }


def scopes_document(conn) -> dict:
    rows = conn.execute(
        "SELECT DISTINCT scope_name FROM scans WHERE scope_name IS NOT NULL ORDER BY scope_name"
    ).fetchall()
    _too_many(len(rows))
    return {
        "api_version": API_VERSION,
        "items": [{"name": name, "description": None} for (name,) in rows],
    }


def status_document() -> dict:
    return {"api_version": API_VERSION, "version": __version__, "role": "admin"}


def _cell(value) -> str:
    if value is None:
        return ""
    if isinstance(value, bool):
        return "true" if value else "false"
    return str(value)


def _device_csv(scan_id: int, device: dict, *, private: bool) -> list:
    ports = []
    for port in device["open_ports"]:
        if port.get("banner"):
            ports.append(f"{port['port']} {port['banner']}")
        else:
            ports.append(str(port["port"]))
    values = {
        "scan_id": scan_id,
        "key": device["key"],
        "key_type": device["key_type"],
        "ip": device["ip"],
        "mac": device["mac"],
        "hostname": device["hostname"],
        "label": device["label"],
        "trusted": device["trusted"],
        "owner": device.get("owner"),
        "location": device.get("location"),
        "tags": ";".join(device["tags"]),
        "criticality": device["criticality"],
        "notes": device.get("notes"),
        "updated_at": device["updated_at"],
        "first_seen": device["first_seen"],
        "last_seen": device["last_seen"],
        "open_ports": ";".join(ports),
        "finding_count": device["finding_count"],
    }
    columns = [name for name in _DEVICE_COLUMNS if private or name not in _PRIVATE]
    return [_cell(values[name]) for name in columns]


def device_csv_table(scan_id: int, rows: list[dict], *, private: bool) -> tuple[list[str], list[list]]:
    headers = [name for name in _DEVICE_COLUMNS if private or name not in _PRIVATE]
    return headers, [_device_csv(scan_id, row, private=private) for row in rows]


def _history_items(conn, query: dict) -> list[dict]:
    if not list_scans(conn):
        raise V1Error(404, "not_found")
    rows = list_scans(conn, _one(query, "scope"))
    _too_many(len(rows))
    return [_scan_dict(row) for row in rows]


def _csv_body(headers: list[str], rows: list[list]) -> bytes:
    body = csv_bytes(headers, rows)
    if len(body) > MAX_V1_RESPONSE_BYTES:
        raise V1Error(413, "too_large")
    return body


def render_export(conn, query: dict, *, private: bool) -> tuple[bytes, str, int, str, str]:
    """Return body, content type, scan id for the filename, what, and format."""
    what = _one(query, "what")
    fmt = (_one(query, "format") or "json").lower()
    if what not in _EXPORT_WHAT or fmt not in ("json", "csv"):
        raise V1Error(400, "bad_request")
    if what == "history" and (_many(query, "tag") or _one(query, "criticality") or _one(query, "severity")):
        raise V1Error(400, "bad_request")
    scan_id = 0
    if what == "history":
        items = _history_items(conn, query)
        if fmt == "json":
            body = _finish({
                "api_version": API_VERSION,
                "items": items,
                "total": len(items),
            })
        else:
            headers = list(_HISTORY_COLUMNS)
            table = [[_cell(item[name]) for name in headers] for item in items]
            body = _csv_body(headers, table)
        return body, fmt, scan_id, what, fmt
    if what == "devices":
        scan, rows = device_rows(conn, query, private=private)
        scan_id = scan["id"]
        if fmt == "json":
            body = _finish({
                "api_version": API_VERSION,
                "scan_id": scan_id,
                "items": rows,
                "total": len(rows),
            })
        else:
            headers, table = device_csv_table(scan_id, rows, private=private)
            body = _csv_body(headers, table)
        return body, fmt, scan_id, what, fmt
    scan, rows = findings_rows(conn, query)
    scan_id = scan["id"]
    if fmt == "json":
        body = _finish({
            "api_version": API_VERSION,
            "scan_id": scan_id,
            "items": rows,
            "total": len(rows),
        })
    else:
        headers = list(_FINDING_COLUMNS)
        table = [[_cell(row[name]) for name in headers] for row in rows]
        body = _csv_body(headers, table)
    return body, fmt, scan_id, what, fmt


def content_type(fmt: str) -> str:
    if fmt == "csv":
        return "text/csv; charset=utf-8; header=present"
    return "application/json; charset=utf-8"


def export_locked(build):
    """Run one API export. A second caller gets 429 without waiting."""
    if not _export_lock.acquire(blocking=False):
        raise V1Error(429, "busy")
    try:
        return build()
    finally:
        _export_lock.release()


def _reject_path_text(path: str) -> None:
    if path is None or path == "" or "\x00" in path:
        raise ValueError("The export path is not allowed.")
    if path.endswith(("/", "\\")) or path.endswith(os.sep):
        raise ValueError("The export path must be a file.")
    if path == "~" or path.startswith("~/") or path.startswith("~\\"):
        raise ValueError("The export path must not use ~.")


def prepare_export_path(path: str, force: bool) -> Path:
    """Check the destination. Does not create a missing directory."""
    _reject_path_text(path)
    candidate = Path(path)
    if not candidate.is_absolute():
        candidate = Path.cwd() / candidate
    parent = candidate.parent
    if not parent.is_dir():
        raise ValueError("The export directory must already exist.")
    if os.path.realpath(parent) != os.path.abspath(parent):
        raise ValueError("The export directory must not be a symlink.")
    try:
        info = os.lstat(candidate)
    except FileNotFoundError:
        info = None
    except OSError as exc:
        raise ValueError("The export path is not allowed.") from exc
    if info is not None:
        if stat.S_ISLNK(info.st_mode):
            raise ValueError("The export path must not be a symlink.")
        if not stat.S_ISREG(info.st_mode):
            raise ValueError("The export path must be a regular file.")
        if not force:
            raise ValueError("The export file already exists. Pass --force to replace it.")
        if info.st_nlink > 1:
            raise ValueError("The export path must not be a hard link.")
    return candidate


def _write_fd(fd: int, payload: bytes) -> None:
    offset = 0
    while offset < len(payload):
        count = os.write(fd, payload[offset:])
        if count <= 0:
            raise OSError("short write")
        offset += count
    os.fsync(fd)
    if os.name != "nt":
        os.fchmod(fd, 0o600)


def write_export_file(path: str, payload: bytes, *, force: bool) -> str:
    """Write ``payload`` to ``path`` at mode 0600. Return the absolute path."""
    destination = prepare_export_path(path, force)
    parent = destination.parent
    directory = None
    try:
        if os.open in getattr(os, "supports_dir_fd", ()):
            flags = os.O_RDONLY
            if hasattr(os, "O_DIRECTORY"):
                flags |= os.O_DIRECTORY
            directory = os.open(parent, flags)
        if not force:
            flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
            if hasattr(os, "O_NOFOLLOW"):
                flags |= os.O_NOFOLLOW
            if directory is not None:
                fd = os.open(destination.name, flags, 0o600, dir_fd=directory)
            else:
                fd = os.open(destination, flags, 0o600)
            try:
                try:
                    _write_fd(fd, payload)
                except Exception:
                    os.close(fd)
                    fd = -1
                    destination.unlink(missing_ok=True)
                    raise
            finally:
                if fd >= 0:
                    os.close(fd)
        else:
            fd, temporary = tempfile.mkstemp(prefix=".lantern-export-", dir=parent)
            temporary_path = Path(temporary)
            try:
                try:
                    _write_fd(fd, payload)
                finally:
                    os.close(fd)
                os.replace(temporary_path, destination)
            except Exception:
                temporary_path.unlink(missing_ok=True)
                raise
    except OSError as exc:
        raise ValueError("The export path is not allowed.") from exc
    finally:
        if directory is not None:
            os.close(directory)
    return os.path.abspath(destination)

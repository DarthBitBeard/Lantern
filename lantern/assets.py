"""Device inventory that outlives any one scan.

An asset is keyed by a normalized MAC (lowercase, colon-separated). When a
saved device has no MAC, the key is its IP. The trust label stays in
``trusted_devices`` and is not stored here.
"""

from __future__ import annotations

import ipaddress
import json
import re
import unicodedata

from .store import _now

OWNER_MAX = 80
LOCATION_MAX = 80
NOTES_MAX = 500
TAG_MAX = 32
TAG_LIMIT = 10
ASSET_ROW_CAP = 10_000
CRITICALITIES = ("low", "medium", "high", "critical")
ASSET_FIELDS = ("owner", "location", "tags", "criticality", "notes")

_MAC_RE = re.compile(r"^([0-9a-f]{2}:){5}[0-9a-f]{2}$")
_TAG_RE = re.compile(r"^[a-z0-9._-]{1,32}$")
# Cc control, Cf format (bidi overrides, word joiner, soft hyphen, BOM, …),
# Zl/Zp line and paragraph separators, Cs surrogates.
_UNSAFE_CATEGORIES = frozenset({"Cc", "Cf", "Zl", "Zp", "Cs"})


def normalize_mac(value: str | None) -> str | None:
    """Lowercase colon form, or None when the text is not a MAC."""
    if not value or not isinstance(value, str):
        return None
    text = value.strip().lower().replace("-", ":")
    if _MAC_RE.fullmatch(text):
        return text
    return None


def _is_unsafe(char: str) -> bool:
    return unicodedata.category(char) in _UNSAFE_CATEGORIES


def _reject_unsafe(text: str, label: str) -> str:
    for char in text:
        if _is_unsafe(char):
            raise ValueError(
                f"{label} contains a control, format, or separator character."
            )
    return text


def _reject_blank(text: str, label: str, limit: int) -> str:
    text = _reject_unsafe(str(text), label)
    if not text.strip() or len(text) > limit:
        raise ValueError(
            f"{label} must be 1 to {limit} characters and must not be only whitespace. "
            "Use asset clear to remove it."
        )
    return text


def validate_owner(value: str) -> str:
    return _reject_blank(value, "Owner", OWNER_MAX)


def validate_location(value: str) -> str:
    return _reject_blank(value, "Location", LOCATION_MAX)


def validate_notes(value: str) -> str:
    return _reject_blank(value, "Notes", NOTES_MAX)


def validate_criticality(value: str) -> str:
    text = _reject_unsafe(str(value), "Criticality").strip().lower()
    if text not in CRITICALITIES:
        listed = ", ".join(CRITICALITIES)
        raise ValueError(f"Criticality must be one of: {listed}.")
    return text


def _ascii_lower(text: str) -> str:
    """Lowercase A-Z only. Other characters stay as typed."""
    return "".join(char.lower() if "A" <= char <= "Z" else char for char in text)


def validate_tag(value: str) -> str:
    """Tags match ``[a-z0-9._-]`` after ASCII lowercase only.

    A character that ``casefold`` or NFKC would rewrite, such as the Kelvin
    sign, is rejected instead of being stored as a different character.
    """
    raw = _reject_unsafe(str(value), "Tag").strip()
    lowered = _ascii_lower(raw)
    if (
        raw.lower() != lowered
        or raw.casefold() != lowered
        or unicodedata.normalize("NFKC", raw) != raw
        or not _TAG_RE.fullmatch(lowered)
    ):
        raise ValueError(
            f"Tag {value!r} is not allowed. "
            f"Use 1 to {TAG_MAX} characters from a-z, 0-9, '.', '_' or '-'."
        )
    return lowered


def validate_tags(values: list[str]) -> list[str]:
    tags = []
    seen = set()
    for value in values:
        tag = validate_tag(value)
        if tag not in seen:
            seen.add(tag)
            tags.append(tag)
    if len(tags) > TAG_LIMIT:
        raise ValueError(f"A device may have at most {TAG_LIMIT} tags.")
    return tags


def strip_for_text(value) -> str:
    """Drop control, format, and separator characters from text shown to a user."""
    if value is None:
        return ""
    return "".join(char for char in str(value) if not _is_unsafe(char))


def present_text(value):
    """Value safe to put in a report. None stays None."""
    if value is None:
        return None
    text = strip_for_text(value)
    return text or None


def device_asset_fields(device: dict) -> dict:
    """The five inventory fields, stripped for display. Trust label is not here."""
    tags = device.get("tags") or []
    if isinstance(tags, str):
        tags = [tags]
    cleaned = []
    for tag in tags:
        shown = present_text(tag)
        if shown:
            cleaned.append(shown)
    return {
        "owner": present_text(device.get("owner")),
        "location": present_text(device.get("location")),
        "tags": cleaned,
        "criticality": present_text(device.get("criticality")),
        "notes": present_text(device.get("notes")),
    }


def _row_to_dict(row) -> dict:
    key, kind, owner, location, tags, criticality, notes, updated_at = row
    return {
        "key": key.split(":", 1)[1],
        "kind": kind,
        "owner": owner,
        "location": location,
        "tags": json.loads(tags),
        "criticality": criticality,
        "notes": notes,
        "updated_at": updated_at,
    }


def _empty_asset(key: str, kind: str) -> dict:
    shown = key.split(":", 1)[1]
    return {
        "key": shown,
        "kind": kind,
        "owner": None,
        "location": None,
        "tags": [],
        "criticality": None,
        "notes": None,
        "updated_at": None,
    }


def key_for_device(device: dict) -> tuple[str, str]:
    """Return (asset_key, kind) for a device dict from a scan."""
    mac = normalize_mac(device.get("mac"))
    if mac:
        return f"mac:{mac}", "mac"
    ip = str(ipaddress.ip_address(str(device["ip"]).strip()))
    return f"ip:{ip}", "ip"


def resolve_asset_key(conn, text: str) -> tuple[str, str]:
    """Map a CLI key to a stored asset key. The device must be in a saved scan."""
    raw = (text or "").strip()
    mac = normalize_mac(raw)
    if mac:
        row = conn.execute(
            "SELECT 1 FROM devices WHERE lower(replace(mac, '-', ':')) = ? LIMIT 1",
            (mac,),
        ).fetchone()
        if row is None:
            raise ValueError(f"No saved scan contains {mac}.")
        return f"mac:{mac}", "mac"
    try:
        ip = str(ipaddress.ip_address(raw))
    except ValueError as exc:
        raise ValueError("Pass a MAC address or an IPv4 address from a saved scan.") from exc
    row = conn.execute(
        "SELECT d.mac FROM devices d JOIN scans s ON s.id = d.scan_id "
        "WHERE d.ip = ? ORDER BY s.id DESC LIMIT 1",
        (ip,),
    ).fetchone()
    if row is None:
        raise ValueError(f"No saved scan contains {ip}.")
    found = normalize_mac(row[0])
    if found:
        return f"mac:{found}", "mac"
    return f"ip:{ip}", "ip"


def get_asset(conn, asset_key: str) -> dict | None:
    row = conn.execute(
        "SELECT asset_key, key_kind, owner, location, tags, criticality, notes, updated_at "
        "FROM assets WHERE asset_key = ?",
        (asset_key,),
    ).fetchone()
    if row is None:
        return None
    return _row_to_dict(row)


def set_asset(
    conn,
    asset_key: str,
    kind: str,
    *,
    owner: str | None = None,
    location: str | None = None,
    tags: list[str] | None = None,
    criticality: str | None = None,
    notes: str | None = None,
) -> dict:
    """Update the fields that were passed. None means leave that field alone.

    A new key is refused once ``ASSET_ROW_CAP`` rows exist. Updating a row
    that is already stored is still allowed.
    """
    current = get_asset(conn, asset_key)
    if current is None:
        count = conn.execute("SELECT COUNT(*) FROM assets").fetchone()[0]
        if count >= ASSET_ROW_CAP:
            raise ValueError(
                f"Lantern stores at most {ASSET_ROW_CAP} inventory records. "
                "Clear one before adding another."
            )
        current = _empty_asset(asset_key, kind)
    if owner is not None:
        current["owner"] = owner
    if location is not None:
        current["location"] = location
    if tags is not None:
        current["tags"] = tags
    if criticality is not None:
        current["criticality"] = criticality
    if notes is not None:
        current["notes"] = notes
    with conn:
        conn.execute(
            "INSERT INTO assets (asset_key, key_kind, owner, location, tags, criticality, notes, updated_at)"
            " VALUES (?, ?, ?, ?, ?, ?, ?, ?)"
            " ON CONFLICT(asset_key) DO UPDATE SET"
            " key_kind=excluded.key_kind, owner=excluded.owner, location=excluded.location,"
            " tags=excluded.tags, criticality=excluded.criticality, notes=excluded.notes,"
            " updated_at=excluded.updated_at",
            (
                asset_key,
                kind,
                current["owner"],
                current["location"],
                json.dumps(current["tags"]),
                current["criticality"],
                current["notes"],
                _now(),
            ),
        )
    return get_asset(conn, asset_key)


def clear_asset(conn, asset_key: str, field: str | None = None) -> None:
    """Delete the row, or blank one field. Unknown keys raise ValueError."""
    current = get_asset(conn, asset_key)
    if current is None:
        shown = asset_key.split(":", 1)[1]
        raise ValueError(f"No asset recorded for {shown}.")
    if field is None:
        with conn:
            conn.execute("DELETE FROM assets WHERE asset_key = ?", (asset_key,))
        return
    if field not in ASSET_FIELDS:
        listed = ", ".join(ASSET_FIELDS)
        raise ValueError(f"Field must be one of: {listed}.")
    blank = [] if field == "tags" else None
    with conn:
        conn.execute(
            f"UPDATE assets SET {field} = ?, updated_at = ? WHERE asset_key = ?",
            (json.dumps(blank) if field == "tags" else blank, _now(), asset_key),
        )
        row = conn.execute(
            "SELECT owner, location, tags, criticality, notes FROM assets WHERE asset_key = ?",
            (asset_key,),
        ).fetchone()
        if row and row[0] is None and row[1] is None and row[2] == "[]" and row[3] is None and row[4] is None:
            conn.execute("DELETE FROM assets WHERE asset_key = ?", (asset_key,))


def list_assets(
    conn,
    *,
    tag: str | None = None,
    criticality: str | None = None,
    owner: str | None = None,
    scope_name: str | None = None,
) -> list[dict]:
    rows = conn.execute(
        "SELECT asset_key, key_kind, owner, location, tags, criticality, notes, updated_at "
        "FROM assets ORDER BY asset_key"
    ).fetchall()
    allowed = _keys_for_scope(conn, scope_name) if scope_name is not None else None
    found = []
    for row in rows:
        item = _row_to_dict(row)
        full_key = row[0]
        if allowed is not None and full_key not in allowed:
            continue
        if owner is not None and item["owner"] != owner:
            continue
        if criticality is not None and item["criticality"] != criticality:
            continue
        if tag is not None and tag not in item["tags"]:
            continue
        found.append(item)
    return found


def _keys_for_scope(conn, scope_name: str) -> set[str]:
    keys = set()
    rows = conn.execute(
        "SELECT d.ip, d.mac FROM devices d JOIN scans s ON s.id = d.scan_id "
        "WHERE s.scope_name = ?",
        (scope_name,),
    )
    for ip, mac in rows:
        norm = normalize_mac(mac)
        if norm:
            keys.add(f"mac:{norm}")
        else:
            keys.add(f"ip:{ip}")
    return keys


def attach_assets(conn, scan: dict | None) -> dict | None:
    """Copy current inventory fields onto each device. Does not write the scan."""
    if scan is None:
        return None
    keys = []
    for device in scan["devices"]:
        asset_key, kind = key_for_device(device)
        keys.append((device, asset_key, kind))
    if not keys:
        return scan
    wanted = [asset_key for _device, asset_key, _kind in keys]
    placeholders = ",".join("?" for _ in wanted)
    rows = conn.execute(
        "SELECT asset_key, key_kind, owner, location, tags, criticality, notes, updated_at "
        f"FROM assets WHERE asset_key IN ({placeholders})",
        wanted,
    ).fetchall()
    by_key = {row[0]: _row_to_dict(row) for row in rows}
    for device, asset_key, _kind in keys:
        asset = by_key.get(asset_key)
        device["owner"] = asset["owner"] if asset else None
        device["location"] = asset["location"] if asset else None
        device["tags"] = list(asset["tags"]) if asset else []
        device["criticality"] = asset["criticality"] if asset else None
        device["notes"] = asset["notes"] if asset else None
    return scan


def attach_assets_to_diff(conn, diff: dict | None) -> dict | None:
    """Inventory fields on added, removed, and changed devices."""
    if diff is None:
        return None
    for device in list(diff.get("added") or []) + list(diff.get("removed") or []):
        _attach_one(conn, device)
    for change in diff.get("changed") or []:
        _attach_one(conn, change.get("device") or {})
    return diff


def _attach_one(conn, device: dict) -> None:
    if not device or "ip" not in device:
        return
    asset_key, _kind = key_for_device(device)
    asset = get_asset(conn, asset_key)
    device["owner"] = asset["owner"] if asset else None
    device["location"] = asset["location"] if asset else None
    device["tags"] = list(asset["tags"]) if asset else []
    device["criticality"] = asset["criticality"] if asset else None
    device["notes"] = asset["notes"] if asset else None

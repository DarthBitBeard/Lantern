"""Storage: one local SQLite file, no cloud, no accounts.

A scan is a snapshot: devices found, their open ports, and findings.
Diffing two snapshots is the core value: what is new, what left,
what opened, what closed.
"""

import json
import sqlite3
from datetime import datetime, timezone


def connect(db_path):
    conn = sqlite3.connect(db_path)
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
    conn.execute(
        """CREATE TABLE IF NOT EXISTS trusted_devices (
               mac TEXT PRIMARY KEY,
               label TEXT,
               trusted INTEGER NOT NULL DEFAULT 1,
               updated_at TEXT NOT NULL
           )"""
    )
    conn.commit()
    return conn


def save_scan(conn, subnet, devices, demo=False):
    started_at = datetime.now(timezone.utc).isoformat()
    cur = conn.execute(
        "INSERT INTO scans (started_at, subnet, demo) VALUES (?, ?, ?)",
        (started_at, subnet, 1 if demo else 0),
    )
    scan_id = cur.lastrowid
    for device in devices:
        conn.execute(
            "INSERT INTO devices (scan_id, ip, mac, hostname, label, open_ports, findings)"
            " VALUES (?, ?, ?, ?, ?, ?, ?)",
            (
                scan_id,
                device["ip"],
                device.get("mac"),
                device.get("hostname"),
                device.get("label"),
                json.dumps(device.get("open_ports", [])),
                json.dumps(device.get("findings", [])),
            ),
        )
    conn.commit()
    return scan_id


def load_scan(conn, scan_id):
    row = conn.execute(
        "SELECT started_at, subnet, demo FROM scans WHERE id = ?", (scan_id,)
    ).fetchone()
    if not row:
        return None
    devices = []
    for ip, mac, hostname, label, open_ports, findings in conn.execute(
        "SELECT ip, mac, hostname, label, open_ports, findings FROM devices"
        " WHERE scan_id = ? ORDER BY ip",
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
    return {"id": scan_id, "started_at": row[0], "subnet": row[1],
            "demo": bool(row[2]), "devices": devices}


def latest_two_scan_ids(conn):
    rows = conn.execute("SELECT id FROM scans ORDER BY id DESC LIMIT 2").fetchall()
    return [r[0] for r in rows]


def list_scans(conn):
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


def get_trusted(conn):
    """Return {mac_lower: {label, trusted}} for every known device."""
    trusted = {}
    for mac, label, is_trusted in conn.execute(
        "SELECT mac, label, trusted FROM trusted_devices"
    ):
        trusted[mac.lower()] = {"label": label, "trusted": bool(is_trusted)}
    return trusted


def set_trusted(conn, mac, label, trusted):
    """Label a device and mark it trusted or unknown. MAC is the key."""
    from datetime import datetime, timezone as _tz

    mac = mac.strip().lower()
    if not mac:
        raise ValueError("A MAC address is required to trust a device.")
    conn.execute(
        "INSERT INTO trusted_devices (mac, label, trusted, updated_at)"
        " VALUES (?, ?, ?, ?)"
        " ON CONFLICT(mac) DO UPDATE SET label=excluded.label,"
        " trusted=excluded.trusted, updated_at=excluded.updated_at",
        (mac, (label or "").strip() or None, 1 if trusted else 0,
         datetime.now(_tz.utc).isoformat()),
    )
    conn.commit()


def apply_trust(scan, trusted):
    """Overlay labels and trust flags onto a loaded scan, without mutating the DB rows."""
    if scan is None:
        return None
    for device in scan["devices"]:
        mac = (device.get("mac") or "").lower()
        info = trusted.get(mac) if mac else None
        device["trusted"] = bool(info and info["trusted"]) if info else False
        device["known"] = bool(info)
        if info and info["label"]:
            device["label"] = info["label"]
    return scan


def diff_scans(old, new):
    """Compare two scan dicts. Key devices by MAC when known, else IP."""
    def key(device):
        return device.get("mac") or device["ip"]

    old_map = {key(d): d for d in old["devices"]}
    new_map = {key(d): d for d in new["devices"]}

    added, removed, changed = [], [], []
    for k, device in new_map.items():
        if k not in old_map:
            added.append(device)
        else:
            old_ports = {p["port"] for p in old_map[k]["open_ports"]}
            new_ports = {p["port"] for p in device["open_ports"]}
            opened = sorted(new_ports - old_ports)
            closed = sorted(old_ports - new_ports)
            if opened or closed or device["ip"] != old_map[k]["ip"]:
                changed.append(
                    {"device": device, "opened": opened, "closed": closed,
                     "old_ip": old_map[k]["ip"]}
                )
    for k, device in old_map.items():
        if k not in new_map:
            removed.append(device)
    return {"added": added, "removed": removed, "changed": changed}

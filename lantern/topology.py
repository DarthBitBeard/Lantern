"""Switch topology: which managed switch, and which port, each device is on.

Lantern asks each switch you name, with a read-only SNMPv2c community, for
standard tables:

- BRIDGE-MIB / Q-BRIDGE-MIB forwarding tables: the MAC addresses each port
  has learned.
- LLDP-MIB: the switch's neighbours (usually other switches and access
  points) and the port each one is on.
- IF-MIB port names and SNMPv2-MIB sysName/sysDescr.

From those it builds a tree: router -> switch -> port -> device. A port that
leads to another queried switch is an uplink, so a device is placed on the
non-uplink port where it is seen with the fewest other MACs. A port with
several devices on it usually has an unmanaged switch or a Wi-Fi access
point behind it; the map marks it as shared.

Only switches in private ranges are queried, at most `MAX_SWITCHES` per run.
The community string is never stored, printed, or logged.
"""

from __future__ import annotations

import ipaddress
import time
from concurrent.futures import ThreadPoolExecutor

from .discovery import validate_subnet
from .identify import clean_text
from .snmp import Client, SnmpError

MAX_SWITCHES = 16
SWITCH_WORKERS = 4
SWITCH_DEADLINE = 30.0  # seconds per switch, for every table together
MAX_COMMUNITY_LENGTH = 64

SYS_DESCR = (1, 3, 6, 1, 2, 1, 1, 1, 0)
SYS_NAME = (1, 3, 6, 1, 2, 1, 1, 5, 0)
IF_DESCR = (1, 3, 6, 1, 2, 1, 2, 2, 1, 2)
IF_NAME = (1, 3, 6, 1, 2, 1, 31, 1, 1, 1, 1)
BRIDGE_ADDRESS = (1, 3, 6, 1, 2, 1, 17, 1, 1, 0)
BRIDGE_PORT_IFINDEX = (1, 3, 6, 1, 2, 1, 17, 1, 4, 1, 2)
DOT1D_FDB_PORT = (1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 2)
DOT1D_FDB_STATUS = (1, 3, 6, 1, 2, 1, 17, 4, 3, 1, 3)
DOT1Q_FDB_PORT = (1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 2)
DOT1Q_FDB_STATUS = (1, 3, 6, 1, 2, 1, 17, 7, 1, 2, 2, 1, 3)
LLDP_LOC_CHASSIS_SUBTYPE = (1, 0, 8802, 1, 1, 2, 1, 3, 1, 0)
LLDP_LOC_CHASSIS_ID = (1, 0, 8802, 1, 1, 2, 1, 3, 2, 0)
LLDP_LOC_PORT_ID = (1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 3)
LLDP_LOC_PORT_DESC = (1, 0, 8802, 1, 1, 2, 1, 3, 7, 1, 4)
LLDP_REM = (1, 0, 8802, 1, 1, 2, 1, 4, 1, 1)
LLDP_REM_CHASSIS_SUBTYPE = 4
LLDP_REM_CHASSIS_ID = 5
LLDP_REM_PORT_ID = 7
LLDP_REM_PORT_DESC = 8
LLDP_REM_SYS_NAME = 9

FDB_LEARNED = 3
CHASSIS_SUBTYPE_MAC = 4


def validate_switch(text: str) -> str:
    """A switch address: one private IPv4 address, same rules as a scan."""
    text = str(text).strip()
    try:
        address = ipaddress.IPv4Address(text)
    except ValueError as exc:
        raise ValueError(f"Switch address must be an IPv4 address: {text!r}.") from exc
    validate_subnet(f"{address}/32")
    return str(address)


def validate_community(text: str) -> str:
    community = text.strip()
    if not community:
        raise ValueError("The SNMP community is empty.")
    if len(community) > MAX_COMMUNITY_LENGTH:
        raise ValueError(f"The SNMP community is longer than {MAX_COMMUNITY_LENGTH} characters.")
    if any(not (0x21 <= ord(ch) <= 0x7E) for ch in community):
        raise ValueError("The SNMP community must be printable ASCII with no spaces.")
    return community


def _mac(raw) -> str | None:
    if isinstance(raw, (bytes, bytearray)) and len(raw) == 6 and any(raw) and raw != b"\xff" * 6:
        return ":".join(f"{b:02x}" for b in raw)
    return None


def _mac_from_index(parts) -> str | None:
    if len(parts) < 6 or any(not 0 <= p <= 255 for p in parts[-6:]):
        return None
    return _mac(bytes(parts[-6:]))


def _text(raw, limit: int = 80) -> str | None:
    if isinstance(raw, (bytes, bytearray)):
        raw = raw.decode("utf-8", "replace")
    if raw is None:
        return None
    return clean_text(str(raw), limit) or None


def _walk(client: Client, base, deadline: float) -> list:
    """Rows under `base`. A table the switch refuses is empty; a timeout is not."""
    try:
        return client.walk(base, deadline=deadline)
    except SnmpError as exc:
        if "timed out" in str(exc) or "took too long" in str(exc):
            raise
        return []


def _column(client: Client, base, deadline: float) -> dict:
    """{index tuple: value} for one table column. A missing table is empty."""
    return {oid[len(base):]: value for oid, value in _walk(client, base, deadline)}


def query_switch(ip: str, community: str, *, client_factory=None) -> dict:
    """Read one switch. Never raises; failures go in the `error` field."""
    result = {
        "ip": ip, "name": None, "description": None, "macs": [],
        "ports": {}, "neighbors": [], "error": None,
    }
    deadline = time.monotonic() + SWITCH_DEADLINE
    try:
        client = (client_factory or Client)(ip, community)
        system = client.get(
            [SYS_NAME, SYS_DESCR, BRIDGE_ADDRESS, LLDP_LOC_CHASSIS_SUBTYPE, LLDP_LOC_CHASSIS_ID],
            deadline=deadline,
        )
        if not system:
            raise SnmpError("the switch answered but shares no system details")
        result["name"] = _text(system.get(SYS_NAME))
        result["description"] = _text(system.get(SYS_DESCR), 120)
        own = {_mac(system.get(BRIDGE_ADDRESS))}
        if system.get(LLDP_LOC_CHASSIS_SUBTYPE) == CHASSIS_SUBTYPE_MAC:
            own.add(_mac(system.get(LLDP_LOC_CHASSIS_ID)))
        result["macs"] = sorted(m for m in own if m)

        if_names = {idx[0]: _text(v) for idx, v in _column(client, IF_NAME, deadline).items() if len(idx) == 1}
        if not if_names:
            if_names = {idx[0]: _text(v) for idx, v in _column(client, IF_DESCR, deadline).items() if len(idx) == 1}
        bridge_to_if = {
            idx[0]: value for idx, value in _column(client, BRIDGE_PORT_IFINDEX, deadline).items()
            if len(idx) == 1 and isinstance(value, int)
        }

        def port_name(bridge_port: int) -> str:
            ifindex = bridge_to_if.get(bridge_port)
            return if_names.get(ifindex) or f"port {bridge_port}"

        ports: dict[int, set] = {}
        fdb = _column(client, DOT1Q_FDB_PORT, deadline)
        status = _column(client, DOT1Q_FDB_STATUS, deadline) if fdb else {}
        if not fdb:
            fdb = _column(client, DOT1D_FDB_PORT, deadline)
            status = _column(client, DOT1D_FDB_STATUS, deadline) if fdb else {}
        for index, bridge_port in fdb.items():
            if not isinstance(bridge_port, int) or bridge_port <= 0:
                continue
            if status and status.get(index, FDB_LEARNED) != FDB_LEARNED:
                continue
            mac = _mac_from_index(index)
            if mac and mac not in result["macs"]:
                ports.setdefault(bridge_port, set()).add(mac)

        # LLDP local port numbers are bridge ports on most switches and
        # ifIndexes on some. Match by name first, then by number.
        loc_names = {}
        for column in (LLDP_LOC_PORT_DESC, LLDP_LOC_PORT_ID):
            for idx, value in _column(client, column, deadline).items():
                if len(idx) == 1 and idx[0] not in loc_names and _text(value):
                    loc_names[idx[0]] = _text(value)
        by_name = {port_name(bp): bp for bp in bridge_to_if}
        if_to_bridge = {ifindex: bp for bp, ifindex in bridge_to_if.items()}

        def lldp_bridge_port(local: int) -> int | None:
            name = loc_names.get(local)
            if name and name in by_name:
                return by_name[name]
            if local in bridge_to_if:
                return local
            return if_to_bridge.get(local)

        remote: dict[tuple, dict] = {}
        for oid, value in _walk(client, LLDP_REM, deadline):
            rest = oid[len(LLDP_REM):]
            # rest = (column, timeMark, localPortNum, remIndex)
            if len(rest) != 4:
                continue
            entry = remote.setdefault(rest[1:], {"local": rest[2]})
            entry[rest[0]] = value
        for entry in remote.values():
            bridge_port = lldp_bridge_port(entry["local"])
            chassis = None
            if entry.get(LLDP_REM_CHASSIS_SUBTYPE) == CHASSIS_SUBTYPE_MAC:
                chassis = _mac(entry.get(LLDP_REM_CHASSIS_ID))
            result["neighbors"].append({
                "port": bridge_port,
                "port_name": port_name(bridge_port) if bridge_port else loc_names.get(entry["local"]),
                "name": _text(entry.get(LLDP_REM_SYS_NAME)),
                "mac": chassis,
                "remote_port": _text(entry.get(LLDP_REM_PORT_DESC)) or _text(entry.get(LLDP_REM_PORT_ID)),
            })
        result["ports"] = {
            bp: {"name": port_name(bp), "macs": sorted(macs)} for bp, macs in sorted(ports.items())
        }
    except SnmpError as exc:
        result["error"] = _friendly_error(exc)
    except Exception:
        result["error"] = "The switch sent a reply Lantern could not read."
    return result


def _friendly_error(exc: SnmpError) -> str:
    text = str(exc)
    if "timed out" in text or "no SNMP agent" in text:
        return "No SNMP reply. Check that SNMP v2c is on, the community is right, and this computer may query it."
    if "took too long" in text:
        return "The switch's tables took longer than 30 seconds to read."
    if "error-status" in text:
        return "The switch refused the request."
    return "The switch sent a reply Lantern could not read."


def query_switches(ips: list[str], community: str, *, client_factory=None) -> list[dict]:
    """Read every switch in parallel, in the order given. Never raises."""
    if not ips:
        return []
    with ThreadPoolExecutor(max_workers=min(SWITCH_WORKERS, len(ips))) as pool:
        return list(pool.map(lambda ip: query_switch(ip, community, client_factory=client_factory), ips))


# ---------------------------------------------------------------------------
# Building the tree
# ---------------------------------------------------------------------------

def build_topology(switches: list[dict], devices: list[dict], gateway_mac: str | None = None) -> dict:
    """Combine switch tables and the scan into a router -> switch -> port -> device tree.

    Returns a JSON-safe dict:
      switches: [{ip, name, description, error, parent, parent_port, port_to_parent, depth}]
                parent is the upstream switch's address (None for a top switch),
                parent_port the port on that switch, port_to_parent the port
                on this one (for a top switch, the port the router is on).
      router:   {switch, port} or None (where the router's MAC is seen)
      locations: {mac: {switch, port, shared, mac_count}}
    """
    ok = [s for s in switches if not s.get("error")]
    owner_of: dict[str, str] = {}
    names: dict[str, str] = {}
    for s in ok:
        for mac in s.get("macs") or []:
            owner_of[mac] = s["ip"]
        if s.get("name"):
            names[s["name"].lower()] = s["ip"]
    # A switch's management address may also show up in the scan with a MAC
    # that is not its bridge address. Count that MAC as the switch too.
    for device in devices:
        mac = (device.get("mac") or "").lower()
        if mac and any(device.get("ip") == s["ip"] for s in ok):
            owner_of.setdefault(mac, device["ip"])

    # Ports that lead to another queried switch.
    uplinks: dict[tuple[str, int], str] = {}
    for s in ok:
        for neighbor in s.get("neighbors") or []:
            other = owner_of.get(neighbor.get("mac") or "") or names.get((neighbor.get("name") or "").lower())
            if other and other != s["ip"] and neighbor.get("port"):
                uplinks[(s["ip"], neighbor["port"])] = other
        for bridge_port, port in (s.get("ports") or {}).items():
            for mac in port["macs"]:
                other = owner_of.get(mac)
                if other and other != s["ip"]:
                    uplinks.setdefault((s["ip"], bridge_port), other)

    def place(mac: str) -> dict | None:
        best = None
        for s in ok:
            for bridge_port, port in (s.get("ports") or {}).items():
                if (s["ip"], bridge_port) in uplinks or mac not in port["macs"]:
                    continue
                key = (len(port["macs"]), s["ip"], bridge_port)
                if best is None or key < best[0]:
                    best = (key, s, bridge_port, port)
        if best is None:
            return None
        _key, s, _bridge_port, port = best
        count = len(port["macs"])
        return {"switch": s["ip"], "port": port["name"], "shared": count > 1, "mac_count": count}

    gateway_mac = (gateway_mac or "").lower() or None
    router = place(gateway_mac) if gateway_mac else None
    locations = {}
    for device in devices:
        mac = (device.get("mac") or "").lower()
        if not mac or mac in owner_of or mac == gateway_mac:
            continue
        found = place(mac)
        if found:
            locations[mac] = found

    # Switch tree: the switch the router hangs off is the root; others hang
    # off the switch whose uplink leads to them, nearest the root first.
    edges: dict[str, dict[str, str]] = {s["ip"]: {} for s in ok}
    for (ip, bridge_port), other in uplinks.items():
        edges[ip].setdefault(other, _port_label(ok, ip, bridge_port))
    parent: dict[str, tuple[str | None, str | None, str | None]] = {}
    depth: dict[str, int] = {}
    roots = [router["switch"]] if router else []
    roots += [s["ip"] for s in ok if s["ip"] not in roots]
    for root in roots:
        if root in depth:
            continue
        depth[root] = 0
        # The root's port toward its parent is the port the router is on.
        parent[root] = (None, None, router["port"] if router and root == router["switch"] else None)
        queue = [root]
        while queue:
            current = queue.pop(0)
            for other, via in sorted(edges.get(current, {}).items()):
                if other in depth:
                    continue
                depth[other] = depth[current] + 1
                parent[other] = (current, via, edges.get(other, {}).get(current))
                queue.append(other)

    shown = []
    for s in switches:
        up, parent_port, to_parent = parent.get(s["ip"], (None, None, None))
        shown.append({
            "ip": s["ip"],
            "name": s.get("name"),
            "description": s.get("description"),
            "error": s.get("error"),
            "parent": up,
            "parent_port": parent_port,
            "port_to_parent": to_parent,
            "depth": depth.get(s["ip"], 0),
        })
    return {"switches": shown, "router": router, "locations": locations}


def _port_label(switches: list[dict], ip: str, bridge_port: int) -> str:
    for s in switches:
        if s["ip"] == ip:
            port = (s.get("ports") or {}).get(bridge_port)
            if port and port.get("name"):
                return port["name"]
            for neighbor in s.get("neighbors") or []:
                if neighbor.get("port") == bridge_port and neighbor.get("port_name"):
                    return neighbor["port_name"]
    return f"port {bridge_port}"


def map_switches(ips: list[str], community: str, devices: list[dict], gateway_mac: str | None,
                 *, client_factory=None) -> dict:
    """Query the switches and build the tree in one call, with a timestamp."""
    results = query_switches(ips, community, client_factory=client_factory)
    tree = build_topology(results, devices, gateway_mac)
    tree["taken_at"] = now_text()
    return tree


def now_text() -> str:
    return time.strftime("%Y-%m-%dT%H:%M:%SZ", time.gmtime())


def annotate_topology(scan: dict | None) -> dict | None:
    """Add `switch_port` to devices the switches placed, and `is_switch` to switches."""
    if not scan:
        return scan
    topo = scan.get("topology")
    if not topo:
        return scan
    names = {s["ip"]: s.get("name") for s in topo.get("switches") or []}
    locations = topo.get("locations") or {}
    for device in scan.get("devices") or []:
        if device.get("ip") in names:
            device["is_switch"] = True
        where = locations.get((device.get("mac") or "").lower())
        if where:
            device["switch_port"] = {**where, "switch_name": names.get(where["switch"])}
    return scan

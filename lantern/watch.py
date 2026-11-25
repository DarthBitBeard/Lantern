"""Watch mode: scan one opted-in network again on a schedule.

`lantern web --watch 60m` starts a `Watcher` beside the server. It reuses
the dashboard's scan job, so a scheduled scan and a manual one never run at
the same time. The schedule is tied to the network the user opted into:
its subnet and the gateway's MAC address, saved when `lantern web --watch`
starts. A scheduled scan is skipped, and a line is logged, when this
machine is not on that same gateway. Being in an address range that looks
the same is not enough, so a laptop on another network does not scan it.
"""

from __future__ import annotations

import errno
import ipaddress
import json
import os
import re
import stat
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone
from pathlib import Path

OPT_IN_NAME = "watch-opt-in.json"
_OPT_IN_MAX = 1024
_EMPTY_MACS = frozenset({"00:00:00:00:00:00", "ff:ff:ff:ff:ff:ff"})
_OPT_IN_KEYS = frozenset({"subnet", "gateway_mac"})

MIN_INTERVAL = 5 * 60
MAX_INTERVAL = 7 * 24 * 60 * 60
FIRST_SCAN_DELAY = 30.0  # let the dashboard come up before the first scheduled scan
BUSY_RETRY = 60.0  # a manual scan was running: try again soon

_INTERVAL_RE = re.compile(r"^\s*(\d{1,6})\s*([mhd])\s*$", re.IGNORECASE)
_UNIT_SECONDS = {"m": 60, "h": 3600, "d": 86400}


def parse_interval(text: str) -> int:
    """``30m``, ``2h`` or ``1d`` as seconds, between 5 minutes and 7 days."""
    match = _INTERVAL_RE.match(str(text or ""))
    if not match:
        raise ValueError("--watch takes a number and a unit, such as 30m, 2h, or 1d.")
    seconds = int(match.group(1)) * _UNIT_SECONDS[match.group(2).lower()]
    if not MIN_INTERVAL <= seconds <= MAX_INTERVAL:
        raise ValueError("--watch must be between 5m and 7d.")
    return seconds


def describe_interval(seconds: int) -> str:
    """The shortest exact spelling: 90 minutes is "90m", two hours is "2h"."""
    for unit in ("d", "h", "m"):
        size = _UNIT_SECONDS[unit]
        if seconds % size == 0:
            return f"{seconds // size}{unit}"
    return f"{seconds}s"


def parse_started_at(text: str | None) -> float | None:
    """A stored scan time (ISO 8601) as a Unix timestamp, or None."""
    if not text:
        return None
    try:
        value = datetime.fromisoformat(str(text).replace("Z", "+00:00"))
    except ValueError:
        return None
    if value.tzinfo is None:
        value = value.replace(tzinfo=timezone.utc)
    return value.timestamp()


def canonical_mac(text: str | None) -> str | None:
    """A gateway MAC as six lower-case octets, or None when it is not one.

    All-zero and all-ones addresses are rejected. They are not a gateway.
    """
    if not isinstance(text, str):
        return None
    from .discovery import MAC_RE, _normalize_mac

    stripped = text.strip()
    if not MAC_RE.fullmatch(stripped):
        return None
    try:
        mac = _normalize_mac(stripped)
    except (TypeError, ValueError):
        return None
    parts = mac.split(":")
    if len(parts) != 6 or any(len(part) != 2 for part in parts):
        return None
    if mac in _EMPTY_MACS:
        return None
    # The I/G bit marks multicast, and the broadcast address is multicast.
    # Neither is a gateway. A locally administered unicast address is kept.
    if int(mac.split(":")[0], 16) & 0x01:
        return None
    return mac


def gateway_mac_for(network: ipaddress.IPv4Network, gateways, arp: dict) -> str | None:
    """MAC of a default gateway that sits inside ``network``, from the ARP cache.

    A gateway outside the subnet is ignored. The first usable MAC wins.
    """
    if not isinstance(arp, dict):
        return None
    for raw in gateways or []:
        try:
            address = ipaddress.IPv4Address(str(raw))
        except ValueError:
            continue
        if address not in network:
            continue
        mac = canonical_mac(arp.get(str(address)))
        if mac:
            return mac
    return None


def identity_problem(network: ipaddress.IPv4Network, expected_mac: str,
                     local_ip: str | None, gateways, arp: dict) -> str | None:
    """None when this machine is on that gateway. Otherwise ``subnet`` or ``gateway``.

    ``subnet`` means this machine has no address in the saved network, or the
    saved MAC is not usable. ``gateway`` means an address is in the subnet
    but the gateway MAC does not match. The address range alone is not enough.
    """
    expected = canonical_mac(expected_mac)
    if expected is None or not local_ip:
        return "subnet"
    try:
        on_subnet = ipaddress.IPv4Address(local_ip) in network
    except ValueError:
        return "subnet"
    if not on_subnet:
        return "subnet"
    if gateway_mac_for(network, gateways, arp) != expected:
        return "gateway"
    return None


def identity_matches(network: ipaddress.IPv4Network, expected_mac: str,
                     local_ip: str | None, gateways, arp: dict) -> bool:
    """True only when this machine is in ``network`` and the gateway MAC matches.

    The address range alone is not the network. A different gateway, or no
    gateway MAC, does not match. A local address outside the subnet does not
    match either, even when a gateway inside the subnet has the saved MAC.
    """
    return identity_problem(network, expected_mac, local_ip, gateways, arp) is None


def current_gateway_mac(subnet: str) -> str | None:
    """The live gateway MAC inside ``subnet``, or None. Does not scan hosts.

    Uses the route table and the ARP cache, and ignores a stale or incomplete
    neighbor entry when the cache line says so. No probe is sent.
    """
    from .discovery import default_gateways, gateway_arp_table

    network = ipaddress.ip_network(subnet, strict=False)
    return gateway_mac_for(network, default_gateways(), gateway_arp_table())


def opt_in_path(db_path: str | Path) -> Path:
    """The saved opt-in sits beside the database. It is not inside the schema."""
    return Path(db_path).parent / OPT_IN_NAME


def legacy_opt_in_paths(db_path: str | Path) -> list[Path]:
    """Other places a start may have written the same opt-in.

    The installer database is ``<root>/lantern.db`` and ``--watch-saved`` reads
    ``<root>/watch-opt-in.json``. The installer's command prompt starts in
    ``<root>`` and, with no ``--db``, writes ``<root>/data/watch-opt-in.json``.
    Each load of one of those two databases checks the other when its own file
    is missing.
    """
    path = Path(db_path)
    parent = path.parent
    primary = opt_in_path(path)
    found: list[Path] = []
    if parent.name != "data":
        found.append(parent / "data" / OPT_IN_NAME)
    if parent.name == "data":
        found.append(parent.parent / OPT_IN_NAME)
    return [item for item in found if item != primary]


def skip_message(subnet: str, reason: str = "subnet") -> str:
    """One fixed line when a scheduled scan does not run.

    ``gateway`` is a same-subnet mismatch. Anything else is a subnet mismatch
    (this machine is not in the saved network, or the gateway could not be read).
    """
    if reason == "gateway":
        return (
            "lantern: scheduled scan skipped. The gateway did not match "
            f"for {subnet}, the network you chose to watch."
        )
    return (
        "lantern: scheduled scan skipped. This machine is not on "
        f"{subnet}, the network you chose to watch."
    )


def no_opt_in_message() -> str:
    """One fixed line when a saved-only start has nothing to reuse."""
    return (
        "lantern: not watching. No network has been chosen yet. "
        "Choose Watch this network in the tray or the dashboard, "
        "or run lantern web --watch with the same --db."
    )


def corrupt_opt_in_message() -> str:
    """One fixed line when a saved file exists but cannot be used."""
    return (
        "lantern: not watching. The saved network file could not be read. "
        "It is corrupt or not a private file, so nothing is scheduled."
    )


def different_network_message(subnet: str) -> str:
    """One fixed line when ``--watch`` would replace a different saved network."""
    return (
        "lantern: not watching. A saved network names a different network "
        f"({subnet}). Pass --watch-adopt to replace it. "
        "An unattended start should use --watch-saved."
    )


class NetworkIdentity:
    """The subnet and gateway MAC saved when the user starts ``--watch``."""

    def __init__(self, subnet: str, gateway_mac: str) -> None:
        self.subnet = str(ipaddress.ip_network(subnet, strict=False))
        self.gateway_mac = canonical_mac(gateway_mac) or ""
        if not self.gateway_mac:
            raise ValueError("A watched network needs a gateway MAC address.")

    def to_json(self) -> str:
        return json.dumps(
            {"subnet": self.subnet, "gateway_mac": self.gateway_mac},
            separators=(",", ":"),
        ) + "\n"


def load_opt_in(db_path: str | Path) -> NetworkIdentity | None:
    """The saved network, or None when there is nothing usable.

    A missing file, a symlink, a file over 1 KiB, a wrong owner, loose
    permissions, or JSON that is not the two expected fields all return None.
    Use `load_opt_in_status` when the caller must tell a missing file from a
    corrupt one. Nothing is scanned.
    """
    status, identity = load_opt_in_status(db_path)
    if status != "ok":
        return None
    return identity


def load_opt_in_status(db_path: str | Path) -> tuple[str, NetworkIdentity | None]:
    """``(ok|missing|unusable, identity)``.

    ``missing`` is only a file that is not there. A symlink, a bad owner, a
    loose mode, a corrupt body, duplicate keys, or a subnet or MAC this
    program would not save is ``unusable``. A usable file in the other of the
    installer path and the command-prompt ``data/`` path is copied beside this
    database and then used.
    """
    primary = opt_in_path(db_path)
    status, identity = _load_opt_in_file(primary)
    if status != "missing":
        return status, identity
    for legacy in legacy_opt_in_paths(db_path):
        legacy_status, legacy_identity = _load_opt_in_file(legacy)
        if legacy_status == "missing":
            continue
        if legacy_status != "ok" or legacy_identity is None:
            return "unusable", None
        try:
            save_opt_in(db_path, legacy_identity)
        except OSError:
            pass
        return "ok", legacy_identity
    return "missing", None


def save_opt_in(db_path: str | Path, identity: NetworkIdentity) -> None:
    """Write the opt-in beside the database at mode 0600. Replaces a previous one."""
    from .store import write_private_file

    write_private_file(opt_in_path(db_path), identity.to_json())


def _current_uid() -> int | None:
    """The user running Lantern, or None where the OS has no uid (Windows)."""
    geteuid = getattr(os, "geteuid", None)
    if geteuid is None:
        return None
    return int(geteuid())


def _reject_duplicate_keys(pairs: list) -> dict:
    seen: set = set()
    data = {}
    for key, value in pairs:
        if key in seen:
            raise ValueError("duplicate key")
        seen.add(key)
        data[key] = value
    return data


def _parse_opt_in(blob: bytes) -> NetworkIdentity | None:
    try:
        text = blob.decode("utf-8")
    except UnicodeDecodeError:
        return None
    try:
        data = json.loads(text, object_pairs_hook=_reject_duplicate_keys)
    except (json.JSONDecodeError, ValueError, UnicodeError):
        return None
    if not isinstance(data, dict) or set(data) != _OPT_IN_KEYS:
        return None
    if not isinstance(data["subnet"], str) or not isinstance(data["gateway_mac"], str):
        return None
    from .discovery import validate_subnet

    try:
        subnet = str(validate_subnet(data["subnet"]))
        return NetworkIdentity(subnet, data["gateway_mac"])
    except ValueError:
        return None


def _load_opt_in_file(path: Path) -> tuple[str, NetworkIdentity | None]:
    """Read one candidate. ``missing`` only when that path is not present."""
    try:
        if path.is_symlink():
            return "unusable", None
    except OSError:
        return "unusable", None
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_BINARY"):
        flags |= getattr(os, name, 0)
    try:
        fd = os.open(path, flags)
    except OSError as exc:
        if exc.errno == errno.ENOENT:
            return "missing", None
        return "unusable", None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _OPT_IN_MAX or info.st_size <= 0:
            return "unusable", None
        uid = _current_uid()
        if uid is not None and info.st_uid != uid:
            return "unusable", None
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            return "unusable", None
        blob = os.read(fd, _OPT_IN_MAX + 1)
    finally:
        os.close(fd)
    if len(blob) > _OPT_IN_MAX:
        return "unusable", None
    identity = _parse_opt_in(blob)
    if identity is None:
        return "unusable", None
    return "ok", identity


class Watcher:
    """Starts a scan every ``interval`` seconds on one opted-in private subnet.

    ``start_scan(subnet)`` returns True when it started a scan and False when
    one was already running. ``on_network(network)`` says whether this
    machine is still on the opted-in network (subnet and gateway MAC). Both,
    and ``clock``, are passed in so the schedule can be tested without a
    network or a real clock. ``on_skip(subnet)`` runs when a due scan is not
    started because the identity does not match.
    """

    def __init__(
        self,
        interval: int,
        subnet: str,
        start_scan: Callable[[str], bool],
        *,
        on_network: Callable[[ipaddress.IPv4Network], bool],
        last_scan_at: float | None = None,
        clock: Callable[[], float] = time.time,
        first_delay: float = FIRST_SCAN_DELAY,
        on_skip: Callable[[str], None] | None = None,
    ) -> None:
        self.interval = int(interval)
        self.network = ipaddress.ip_network(subnet, strict=False)
        self.subnet = str(self.network)
        self._start_scan = start_scan
        self._on_network = on_network
        self._on_skip = on_skip
        self._clock = clock
        now = clock()
        due = now + first_delay
        if last_scan_at is not None:
            due = max(due, last_scan_at + self.interval)
        self._next = due
        self.last_result: str | None = None
        self._stop = threading.Event()
        self._thread: threading.Thread | None = None
        self._lock = threading.Lock()

    @property
    def next_scan_at(self) -> float:
        with self._lock:
            return self._next

    def run_once(self) -> str:
        """Act on one due time. Returns started, busy, or away, and sets the next due time."""
        now = self._clock()
        try:
            here = bool(self._on_network(self.network))
        except Exception:
            here = False
        if not here:
            result, wait = "away", float(self.interval)
            if self._on_skip is not None:
                try:
                    self._on_skip(self.subnet)
                except Exception:
                    pass
        else:
            try:
                started = bool(self._start_scan(self.subnet))
            except Exception:
                started = False
                result, wait = "error", float(self.interval)
            else:
                result, wait = ("started", float(self.interval)) if started else ("busy", BUSY_RETRY)
        with self._lock:
            self._next = now + wait
            self.last_result = result
        return result

    def status(self) -> dict:
        """What /api/status reports about the schedule."""
        next_at = datetime.fromtimestamp(self.next_scan_at, tz=timezone.utc)
        return {
            "interval": describe_interval(self.interval),
            "interval_seconds": self.interval,
            "subnet": self.subnet,
            "next_scan_at": next_at.isoformat().replace("+00:00", "Z"),
            "last_result": self.last_result,
        }

    def start(self) -> None:
        self._thread = threading.Thread(target=self._loop, name="lantern-watch", daemon=True)
        self._thread.start()

    def stop(self, timeout: float = 5.0) -> None:
        self._stop.set()
        if self._thread is not None:
            self._thread.join(timeout)

    def _loop(self) -> None:
        while not self._stop.is_set():
            delay = self.next_scan_at - self._clock()
            if delay > 0:
                # Wake at least once a minute so a changed clock cannot strand the schedule.
                if self._stop.wait(min(delay, 60.0)):
                    return
                continue
            self.run_once()

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


def identity_matches(network: ipaddress.IPv4Network, expected_mac: str,
                     local_ip: str | None, gateways, arp: dict) -> bool:
    """True only when this machine is in ``network`` and the gateway MAC matches.

    The address range alone is not the network. A different gateway, or no
    gateway MAC, does not match.
    """
    expected = canonical_mac(expected_mac)
    if expected is None or not local_ip:
        return False
    try:
        if ipaddress.IPv4Address(local_ip) not in network:
            return False
    except ValueError:
        return False
    return gateway_mac_for(network, gateways, arp) == expected


def current_gateway_mac(subnet: str) -> str | None:
    """The live gateway MAC inside ``subnet``, or None. Does not scan hosts."""
    from .discovery import arp_table, default_gateways

    network = ipaddress.ip_network(subnet, strict=False)
    return gateway_mac_for(network, default_gateways(), arp_table())


def opt_in_path(db_path: str | Path) -> Path:
    """The saved opt-in sits beside the database. It is not inside the schema."""
    return Path(db_path).parent / OPT_IN_NAME


def skip_message(subnet: str) -> str:
    """One fixed line when a scheduled scan does not run."""
    return (
        "lantern: scheduled scan skipped. This machine is not on "
        f"{subnet}, the network you chose to watch."
    )


def no_opt_in_message() -> str:
    """One fixed line when a saved-only start has nothing to reuse."""
    return (
        "lantern: not watching. No network has been chosen yet. "
        "Run lantern web --watch once on the network you want to watch."
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
    """The saved network, or None when there is no usable opt-in file.

    A symlink, a non-file, a file over 1 KiB, or JSON that is not the two
    expected fields is treated as no opt-in. Nothing is scanned.
    """
    path = opt_in_path(db_path)
    blob = _read_opt_in(path)
    if blob is None:
        return None
    try:
        data = json.loads(blob.decode("utf-8"))
    except (UnicodeDecodeError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict) or set(data) != {"subnet", "gateway_mac"}:
        return None
    if not isinstance(data["subnet"], str) or not isinstance(data["gateway_mac"], str):
        return None
    from .discovery import validate_subnet

    try:
        subnet = str(validate_subnet(data["subnet"]))
        return NetworkIdentity(subnet, data["gateway_mac"])
    except ValueError:
        return None


def save_opt_in(db_path: str | Path, identity: NetworkIdentity) -> None:
    """Write the opt-in beside the database at mode 0600. Replaces a previous one."""
    from .store import write_private_file

    write_private_file(opt_in_path(db_path), identity.to_json())


def _read_opt_in(path: Path) -> bytes | None:
    flags = os.O_RDONLY
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_BINARY"):
        flags |= getattr(os, name, 0)
    try:
        fd = os.open(path, flags)
    except OSError:
        return None
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode) or info.st_size > _OPT_IN_MAX:
            return None
        blob = os.read(fd, _OPT_IN_MAX + 1)
    finally:
        os.close(fd)
    if len(blob) > _OPT_IN_MAX:
        return None
    return blob


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

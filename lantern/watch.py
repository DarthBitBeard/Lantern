"""Watch mode: scan the network again on a schedule while the dashboard runs.

`lantern web --watch 60m` starts a `Watcher` beside the server. It reuses
the dashboard's scan job, so a scheduled scan and a manual one never run at
the same time. The subnet is fixed when the dashboard starts, and a
scheduled scan is skipped while this machine has no address inside it: a
laptop that moves to another network does not scan that network on its own.
"""

from __future__ import annotations

import ipaddress
import re
import threading
import time
from collections.abc import Callable
from datetime import datetime, timezone

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


class Watcher:
    """Starts a scan every ``interval`` seconds on one fixed private subnet.

    ``start_scan(subnet)`` returns True when it started a scan and False when
    one was already running. ``on_network(network)`` says whether this
    machine is on that network right now. Both, and ``clock``, are passed in
    so the schedule can be tested without a network or a real clock.
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
    ) -> None:
        self.interval = int(interval)
        self.network = ipaddress.ip_network(subnet, strict=False)
        self.subnet = str(self.network)
        self._start_scan = start_scan
        self._on_network = on_network
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

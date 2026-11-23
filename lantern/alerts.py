"""Turn a scan diff into a short alert: what is worth telling someone right away.

An alert is raised for three things only, so it stays rare enough to read:

- a new device that has not been labelled or trusted before,
- a high or critical risk port that opened (on a new or an existing device),
- a service on a port open in both scans that changed product or version.

Moved IPs and closed ports are not alerts; they stay in the diff. The text is
plain, with device-supplied names cleaned of control and bidi characters, and
short enough for a Windows notification (title 63, message 255 characters).
"""

from __future__ import annotations

from dataclasses import dataclass

from .assets import strip_for_text
from .ports import PORT_RULES

ALERT_SEVERITIES = ("critical", "high")
TITLE_MAX = 63
TEXT_MAX = 255
_NAMES_SHOWN = 3


@dataclass(frozen=True)
class Alert:
    title: str
    text: str


def _name(device: dict) -> str:
    identity = device.get("identity") or {}
    raw = device.get("label") or identity.get("name") or device.get("hostname") or device.get("ip") or "?"
    name = strip_for_text(str(raw)) or str(device.get("ip") or "?")
    return name[:40]


def _risky(port: int) -> bool:
    rule = PORT_RULES.get(port)
    return bool(rule and rule[1] in ALERT_SEVERITIES)


def _list(items: list[str]) -> str:
    shown = ", ".join(items[:_NAMES_SHOWN])
    extra = len(items) - _NAMES_SHOWN
    return f"{shown} and {extra} more" if extra > 0 else shown


def summarize(diff: dict | None) -> Alert | None:
    """The alert for one diff, or None when nothing in it needs attention."""
    if not diff:
        return None
    new_devices = [d for d in diff.get("added") or [] if not d.get("known")]
    risky: list[str] = []
    for device in new_devices:
        ports = sorted(p.get("port") for p in device.get("open_ports") or [] if _risky(p.get("port")))
        risky.extend(f"{_name(device)} port {p}" for p in ports)
    services: list[str] = []
    for change in diff.get("changed") or []:
        device = change.get("device") or {}
        risky.extend(f"{_name(device)} port {p}" for p in sorted(change.get("opened") or []) if _risky(p))
        for item in change.get("service_changes") or []:
            services.append(f"{_name(device)} port {item['port']} is now {strip_for_text(str(item['new']))}")

    parts, headline = [], []
    if new_devices:
        noun = "device" if len(new_devices) == 1 else "devices"
        headline.append(f"{len(new_devices)} new {noun}")
        parts.append(f"New: {_list([_name(d) for d in new_devices])}.")
    if risky:
        noun = "risky port" if len(risky) == 1 else "risky ports"
        headline.append(f"{len(risky)} {noun} opened")
        parts.append(f"Opened: {_list(risky)}.")
    if services:
        headline.append("service changed" if len(services) == 1 else f"{len(services)} services changed")
        parts.append(f"Changed: {_list(services)}.")
    if not parts:
        return None
    title = ("Lantern: " + ", ".join(headline))[:TITLE_MAX]
    text = " ".join(parts)
    if len(text) > TEXT_MAX:
        text = text[: TEXT_MAX - 1].rstrip() + "…"
    return Alert(title, text)

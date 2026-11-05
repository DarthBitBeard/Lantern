"""Guess what kind of device each scanned host is, for the map and the cards.

No network calls. The guess uses what a scan already stored: open ports,
the SSDP/mDNS identity (see `identify.py`), the hostname, whether the MAC
is randomized, and whether the address is the scan's gateway. It is
computed when a scan is shown, not stored, so better rules apply to old
scans too. Every result carries a short plain-English reason.
"""

from __future__ import annotations

import re

KINDS = (
    "router",
    "network",
    "computer",
    "server",
    "nas",
    "printer",
    "camera",
    "media",
    "smart_home",
    "phone",
    "other",
    "unknown",
)

_PRINTER_SERVICES = {"_printer._tcp", "_ipp._tcp", "_ipps._tcp", "_pdl-datastream._tcp", "_scanner._tcp", "_uscan._tcp"}
_MEDIA_SERVICES = {
    "_googlecast._tcp", "_airplay._tcp", "_raop._tcp", "_spotify-connect._tcp",
    "_sonos._tcp", "_amzn-wplay._tcp", "_androidtvremote2._tcp",
}
_SMART_HOME_SERVICES = {"_hap._tcp", "_homekit._tcp", "_matter._tcp", "_hap._udp"}
_COMPUTER_SERVICES = {"_workstation._tcp", "_rfb._tcp", "_afpovertcp._tcp", "_smb._tcp"}
_SERVER_PORTS = {1433, 3306, 5432, 6379, 2375, 9200, 11211, 27017, 25, 110, 143}
_WINDOWS_PORTS = {135, 139, 445, 3389}
_WEB_PORTS = {80, 443, 8080, 8443, 8888, 9000, 9090}

_SERVER_NAME_RE = re.compile(r"(^|[-_.])(srv|server|dc\d*|hv\d*|hyperv|esx\w*|dns\d*|sql\w*|db\d*|proxmox|pve\d*|vm\d*)([-_.\d]|$)", re.I)
_NAS_NAME_RE = re.compile(r"(nas|synology|diskstation|qnap|truenas|unraid)", re.I)
_CAMERA_NAME_RE = re.compile(r"(cam|camera|ipc|nvr|dvr|doorbell|reolink|hikvision|dahua|wyze)", re.I)
_PHONE_NAME_RE = re.compile(r"(iphone|ipad|android|galaxy|pixel|phone)", re.I)
_PRINTER_NAME_RE = re.compile(r"(printer|laserjet|officejet|deskjet|epson|brother|lexmark|sharp|canon|kyocera|xerox|ricoh)", re.I)
_ROUTER_NAME_RE = re.compile(r"(router|gateway|firewall|pfsense|opnsense|unifi|edgerouter|mikrotik|ubnt)", re.I)


def is_randomized_mac(mac: str | None) -> bool:
    """True when the locally administered bit is set (a private Wi-Fi address)."""
    if not mac:
        return False
    try:
        first = int(mac.replace("-", ":").split(":")[0], 16)
    except ValueError:
        return False
    return bool(first & 0x02)


def _text(device: dict) -> str:
    identity = device.get("identity") or {}
    parts = [device.get("hostname"), device.get("label"), identity.get("name"),
             identity.get("model"), identity.get("manufacturer"), identity.get("device_type")]
    parts += identity.get("names") or []
    return " ".join(p for p in parts if p)


def classify(device: dict, gateway_ip: str | None = None, gateway_guessed: bool = False) -> tuple[str, str]:
    """Return (kind, reason) for one device dict as stored by a scan."""
    ports = {p.get("port") for p in device.get("open_ports") or [] if isinstance(p, dict)}
    identity = device.get("identity") or {}
    services = set(identity.get("services") or [])
    upnp = " ".join(s for s in services if s.startswith("upnp:")).lower()
    text = _text(device)

    if gateway_ip and device.get("ip") == gateway_ip:
        if gateway_guessed:
            return "router", "It looks like this network's router (DNS and a web page at a router address)."
        return "router", "This is the network's gateway (the default route)."
    if "internetgatewaydevice" in upnp or "wandevice" in upnp:
        return "router", "It announces itself as an internet gateway (UPnP)."
    if "wlanaccesspoint" in upnp:
        return "network", "It announces itself as a Wi-Fi access point (UPnP)."
    if services & _PRINTER_SERVICES or 9100 in ports or "printer" in upnp:
        return "printer", "It offers printing (IPP, LPD, or raw port 9100)."
    if 554 in ports or "camera" in upnp or _CAMERA_NAME_RE.search(text):
        return "camera", "It streams video (RTSP) or is named like a camera."
    if services & _SMART_HOME_SERVICES or 8123 in ports or 1883 in ports:
        return "smart_home", "It speaks HomeKit, Matter, MQTT, or runs Home Assistant."
    if _NAS_NAME_RE.search(text):
        return "nas", "Its name or model looks like network storage."
    if services & _MEDIA_SERVICES or "mediarenderer" in upnp:
        return "media", "It is a cast, AirPlay, or speaker target."
    if 8096 in ports or 32400 in ports or "mediaserver" in upnp:
        return "server", "It runs a media server (Plex or Jellyfin)."
    if ports & _SERVER_PORTS:
        return "server", "It runs a database, mail, or container service."
    if _SERVER_NAME_RE.search(device.get("hostname") or ""):
        return "server", "Its hostname looks like a server."
    if ports & _WINDOWS_PORTS or services & _COMPUTER_SERVICES:
        return "computer", "It has Windows, Mac, or file-sharing services."
    if _ROUTER_NAME_RE.search(text) or (53 in ports and ports & _WEB_PORTS):
        return "network", "It answers DNS with a web admin page, like a router or access point."
    if _PRINTER_NAME_RE.search(text):
        return "printer", "Its name or model looks like a printer."
    if _PHONE_NAME_RE.search(text) or "_companion-link._tcp" in services:
        return "phone", "Its name or services look like a phone or tablet."
    if 22 in ports:
        return "server", "It accepts SSH logins, like a Linux server or appliance."
    if is_randomized_mac(device.get("mac")) and not ports:
        return "phone", "It uses a private (randomized) Wi-Fi address and offers no services, like a phone."
    if ports and ports <= _WEB_PORTS:
        return "other", "It only has a web page, like an appliance or IoT device."
    if ports or services:
        return "other", "It offers services Lantern does not recognise."
    return "unknown", "It answered discovery but offers no services Lantern checks."


def gateway_score(ip: str | None, ports) -> tuple | None:
    """Sort key for one router candidate (lower is better), or None if it is not one.

    Scores DNS +2, a web page +1, and a `.1` or `.254` address +2, and needs
    at least 3. Exposed so a streaming caller can pick the router without
    holding every device in memory.
    """
    if not ip:
        return None
    ports = set(ports)
    last = ip.rsplit(".", 1)[-1]
    score = 0
    if 53 in ports:
        score += 2
    if ports & _WEB_PORTS:
        score += 1
    if last in ("1", "254"):
        score += 2
    if score < 3:
        return None
    return (-score, int(last) if last.isdigit() else 999, ip)


def device_ports(device: dict) -> set:
    return {p.get("port") for p in device.get("open_ports") or [] if isinstance(p, dict)}


def likely_gateway(devices: list[dict], network_text: str | None = None) -> str | None:
    """Best guess at the router when the OS default route is outside the scanned subnet.

    Prefers a host that answers DNS and has a web page, then the .1 or .254
    address, which home routers use by convention.
    """
    by_ip = {d.get("ip"): d for d in devices}
    candidates = [
        key for key in (gateway_score(ip, device_ports(device)) for ip, device in by_ip.items())
        if key is not None
    ]
    return min(candidates)[2] if candidates else None


def annotate_scan(scan: dict | None) -> dict | None:
    """Add `kind` and `kind_reason` to each device, and fill in the gateway.

    Scans saved before schema 5 have no stored gateway; for those the
    likely router is used and `network.gateway_guessed` is true.
    """
    if not scan:
        return scan
    network = scan.get("network") or {}
    network = {"gateway_ip": None, "gateway_mac": None, "local_ip": None, **network}
    devices = scan.get("devices") or []
    ips = {d.get("ip") for d in devices}
    if network["gateway_ip"] not in ips:
        guessed = likely_gateway(devices)
        network["gateway_guessed"] = guessed is not None
        network["gateway_ip"] = guessed
    else:
        network["gateway_guessed"] = False
    scan["network"] = network
    for device in devices:
        kind, reason = classify(device, network["gateway_ip"], network["gateway_guessed"])
        device["kind"] = kind
        device["kind_reason"] = reason
    return scan

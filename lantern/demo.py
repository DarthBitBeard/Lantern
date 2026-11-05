"""Demo data: a fake home network, so anyone can try Lantern
without scanning anything. Scan 2 adds one unknown device with
Telnet open, to show the diff and the critical finding.
"""

from .ports import findings_for_ports

DEMO_SUBNET = "192.168.1.0/24"

# What a real scan learns about the subnet itself (see engine.describe_network).
DEMO_NETWORK = {"gateway_ip": "192.168.1.1", "gateway_mac": "aa:bb:cc:00:00:01", "local_ip": "192.168.1.10"}


def _identity(name=None, model=None, manufacturer=None, services=(), source="mdns"):
    return {
        "name": name, "model": model, "manufacturer": manufacturer, "device_type": None,
        "services": list(services), "names": [name] if name else [], "sources": [source],
    }


def _device(ip, mac, hostname, label, ports, identity=None):
    ports = sorted(ports)
    open_ports = [{"port": p, "open": True, "banner": ""} for p in ports]
    device = {
        "ip": ip, "mac": mac, "hostname": hostname, "label": label,
        "open_ports": open_ports, "findings": findings_for_ports(ports),
    }
    if identity:
        device["identity"] = identity
    return device


def demo_scan_1():
    return [
        _device("192.168.1.1", "aa:bb:cc:00:00:01", "router", "Router", [53, 80, 443],
                _identity("Home Router", "AX3000", "Example Networks",
                          ["upnp:InternetGatewayDevice"], source="ssdp")),
        _device("192.168.1.10", "aa:bb:cc:00:00:02", "desktop-pc", "Desktop PC", [135, 445, 3389]),
        _device("192.168.1.20", "aa:bb:cc:00:00:03", "media-server", "Media server", [8096, 22]),
        _device("192.168.1.30", "aa:bb:cc:00:00:04", "printer", "Printer", [80, 9100],
                _identity("Office Printer", "LaserJet M110", None, ["_ipp._tcp", "_printer._tcp"])),
        _device("192.168.1.40", "aa:bb:cc:00:00:05", None, "Smart TV", [8009],
                _identity("Living Room TV", "Chromecast", None, ["_googlecast._tcp"])),
    ]


def demo_scan_2():
    devices = demo_scan_1()
    devices.append(
        _device("192.168.1.99", "de:ad:be:ef:00:99", None, None, [23, 80])
    )
    return devices


def _demo_switches(devices: list[dict]) -> list[dict]:
    """What two managed switches would report, in `topology.query_switch` form.

    Living room switch: the router on port 1, the media server on port 2,
    a Wi-Fi access point on port 4 (the TV, two phones, and any new device),
    and the office switch on port 8. Office switch: the desktop on port 3
    and the printer on port 5.
    """
    macs = {d["ip"]: d["mac"] for d in devices}
    wifi = [macs["192.168.1.40"], "3a:11:22:33:44:01", "3a:11:22:33:44:02"]
    if "192.168.1.99" in macs:
        wifi.append(macs["192.168.1.99"])
    office_side = [macs["192.168.1.10"], macs["192.168.1.30"], "aa:bb:cc:00:00:30"]
    living_side = [macs["192.168.1.1"], macs["192.168.1.20"], "aa:bb:cc:00:00:20", *wifi]
    return [
        {
            "ip": "192.168.1.2", "name": "Living room switch", "description": "Example 8-port managed switch",
            "macs": ["aa:bb:cc:00:00:20"], "error": None,
            "ports": {
                1: {"name": "Port 1", "macs": [macs["192.168.1.1"]]},
                2: {"name": "Port 2", "macs": [macs["192.168.1.20"]]},
                4: {"name": "Port 4", "macs": sorted(wifi)},
                8: {"name": "Port 8", "macs": sorted(office_side)},
            },
            "neighbors": [{"port": 8, "port_name": "Port 8", "name": "Office switch",
                           "mac": "aa:bb:cc:00:00:30", "remote_port": "Port 1"}],
        },
        {
            "ip": "192.168.1.3", "name": "Office switch", "description": "Example 8-port managed switch",
            "macs": ["aa:bb:cc:00:00:30"], "error": None,
            "ports": {
                1: {"name": "Port 1", "macs": sorted(living_side)},
                3: {"name": "Port 3", "macs": [macs["192.168.1.10"]]},
                5: {"name": "Port 5", "macs": [macs["192.168.1.30"]]},
            },
            "neighbors": [{"port": 1, "port_name": "Port 1", "name": "Living room switch",
                           "mac": "aa:bb:cc:00:00:20", "remote_port": "Port 8"}],
        },
    ]


def demo_topology(devices: list[dict]) -> dict:
    """A switch map for the demo scans, built the same way as a real one."""
    from .topology import build_topology

    tree = build_topology(_demo_switches(devices), devices, DEMO_NETWORK["gateway_mac"])
    tree["taken_at"] = None
    return tree

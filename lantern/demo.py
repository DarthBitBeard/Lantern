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

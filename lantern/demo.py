"""Demo data: a fake home network, so anyone can try Lantern
without scanning anything. Scan 2 adds one unknown device with
Telnet open, to show the diff and the critical finding.
"""

from .ports import findings_for_ports


def _device(ip, mac, hostname, label, ports):
    open_ports = [{"port": p, "open": True, "banner": ""} for p in ports]
    return {
        "ip": ip, "mac": mac, "hostname": hostname, "label": label,
        "open_ports": open_ports, "findings": findings_for_ports(ports),
    }


def demo_scan_1():
    return [
        _device("192.168.1.1", "aa:bb:cc:00:00:01", "router", "Router", [53, 80, 443]),
        _device("192.168.1.10", "aa:bb:cc:00:00:02", "desktop-pc", "Desktop PC", [135, 445, 3389]),
        _device("192.168.1.20", "aa:bb:cc:00:00:03", "media-server", "Media server", [8096, 22]),
        _device("192.168.1.30", "aa:bb:cc:00:00:04", "printer", "Printer", [80, 9100]),
        _device("192.168.1.40", "aa:bb:cc:00:00:05", None, "Smart TV", [8009]),
    ]


def demo_scan_2():
    devices = demo_scan_1()
    devices.append(
        _device("192.168.1.99", "de:ad:be:ef:00:99", None, None, [23, 80])
    )
    return devices

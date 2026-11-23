"""The scan pipeline: find live hosts on one private subnet, then port-scan them.

This lives apart from the command line so the dashboard can use it without
importing `cli`. Tests that stop a scan from touching the network patch the
names in this module (`ping_host`, `tcp_alive`, `arp_table`, `scan_host`,
`reverse_hostname`, `discover_identities`, `default_gateways`, or
`scan_hosts` itself).
"""

from __future__ import annotations

import ipaddress
import logging
import threading
from concurrent.futures import ThreadPoolExecutor

from . import demo
from .classify import likely_gateway
from .discovery import (
    arp_table,
    default_gateways,
    local_ipv4_in,
    ping_host,
    reverse_hostname,
    tcp_alive,
    validate_subnet,
)
from .identify import discover_identities
from .ports import DEFAULT_PORTS, findings_for_ports
from .scanner import scan_host

log = logging.getLogger(__name__)

PING_WORKERS = 50
TCP_DISCOVERY_WORKERS = 64
HOST_WORKERS = 8  # hosts port-scanned at once; each uses up to MAX_PORT_WORKERS sockets


def scan_one(ip: str, macs: dict[str, str], ports, *, fingerprint: bool = True) -> dict:
    open_ports = scan_host(ip, ports, fingerprint=fingerprint)
    return {
        "ip": ip,
        "mac": macs.get(ip),
        "hostname": reverse_hostname(ip),
        "open_ports": open_ports,
        "findings": findings_for_ports([p["port"] for p in open_ports]),
        "label": None,
    }


def _counting(fn, report):
    """Wrap ``fn`` so each finished call bumps a shared counter and calls ``report(done)``."""
    lock = threading.Lock()
    done = [0]

    def run(item):
        try:
            return fn(item)
        finally:
            with lock:
                done[0] += 1
                count = done[0]
            try:
                report(count)
            except Exception:
                pass  # progress is for display only; never fail a scan over it

    return run


def scan_hosts(hosts: list[str], ports=DEFAULT_PORTS, *, fingerprint: bool = True,
               progress=None) -> list[dict]:
    """Ping and port-scan these addresses. An empty list does not touch the network.

    ``progress(phase, done, total)``, when given, is called as work finishes:
    phase "discover" counts addresses checked, then "ports" counts live
    hosts whose ports were checked. It runs on worker threads.
    """
    if not hosts:
        return []
    report = progress or (lambda phase, done, total: None)
    report("discover", 0, len(hosts))
    macs = arp_table()

    with ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
        ping = _counting(ping_host, lambda n: report("discover", n, len(hosts)))
        live = {ip for ip, alive in zip(hosts, pool.map(ping, hosts)) if alive}

    # Pinging is what fills the ARP cache, so a host found only by ping has
    # no MAC in the snapshot taken above. Read the table again and let the
    # fresh entries win; keep the first snapshot for entries that expired
    # while the sweep ran.
    macs = {**macs, **arp_table()}

    # Hosts in the ARP cache count as live even if they ignore ping.
    host_set = set(hosts)
    live.update(ip for ip in macs if ip in host_set)

    # Last resort for hosts that block ping and are not in the cache (and for
    # machines with no `ping` binary): a short TCP connect to a few ports.
    silent = [ip for ip in hosts if ip not in live]
    if silent:
        with ThreadPoolExecutor(max_workers=TCP_DISCOVERY_WORKERS) as pool:
            found = [ip for ip, alive in zip(silent, pool.map(tcp_alive, silent)) if alive]
        if found:
            live.update(found)
            macs = {**macs, **arp_table()}

    ordered = sorted(live, key=lambda ip: int(ipaddress.IPv4Address(ip)))

    def safe_scan_one(ip: str) -> dict | None:
        # One misbehaving host must not discard every other host's results.
        try:
            return scan_one(ip, macs, ports, fingerprint=fingerprint)
        except Exception as exc:
            log.warning("skipping %s: scan failed (%s)", ip, type(exc).__name__)
            return None

    report("ports", 0, len(ordered))
    with ThreadPoolExecutor(max_workers=HOST_WORKERS) as pool:
        counted = _counting(safe_scan_one, lambda n: report("ports", n, len(ordered)))
        return [d for d in pool.map(counted, ordered) if d is not None]


def describe_network(network, devices: list[dict], identities: dict | None = None,
                     local_ip: str | None = None) -> dict:
    """Attach SSDP/mDNS identities to `devices` and work out the gateway.

    The gateway is this machine's default route when that address is inside
    `network` (and was seen by the scan). Otherwise it is the scanned host
    that looks most like a router (see `classify.likely_gateway`), or None.
    Returns {gateway_ip, gateway_mac, local_ip}.
    """
    identities = identities or {}
    for device in devices:
        identity = identities.get(device.get("ip"))
        if identity:
            device["identity"] = identity
    seen = {d.get("ip"): d for d in devices}
    gateway = None
    try:
        candidates = list(default_gateways())
    except Exception:
        candidates = []
    for candidate in candidates:
        # A malformed entry must not hide the valid ones after it.
        try:
            if candidate in seen and ipaddress.IPv4Address(candidate) in network:
                gateway = candidate
                break
        except ValueError:
            continue
    if gateway is None:
        gateway = likely_gateway(devices)
    return {
        "gateway_ip": gateway,
        "gateway_mac": (seen.get(gateway) or {}).get("mac") if gateway else None,
        "local_ip": local_ip,
    }


def scan_subnet(
    subnet_text: str,
    ports=DEFAULT_PORTS,
    demo_mode: bool = False,
    *,
    fingerprint: bool = True,
    progress=None,
) -> tuple[list[dict], dict]:
    """Scan one private subnet. Returns (devices, network info for `save_scan`).

    SSDP and mDNS run alongside the ping and port sweep, so they add little
    or no time. Raises ValueError for an invalid or unsafe subnet. Never
    touches the network in demo mode.
    """
    if demo_mode:
        return demo.demo_scan_1(), dict(demo.DEMO_NETWORK)
    network = validate_subnet(subnet_text)
    hosts = [str(ip) for ip in network.hosts()]
    local_ip = local_ipv4_in(network)
    with ThreadPoolExecutor(max_workers=1) as pool:
        identities = pool.submit(discover_identities, network, local_ip)
        if progress is None:
            devices = scan_hosts(hosts, ports, fingerprint=fingerprint)
        else:
            devices = scan_hosts(hosts, ports, fingerprint=fingerprint, progress=progress)
        try:
            found = identities.result()
        except Exception as exc:
            # SSDP/mDNS is optional enrichment; never lose the port scan over it.
            log.warning("device identity discovery failed (%s)", type(exc).__name__)
            found = {}
    return devices, describe_network(network, devices, found, local_ip)


def run_scan(
    subnet_text: str,
    ports=DEFAULT_PORTS,
    demo_mode: bool = False,
    *,
    fingerprint: bool = True,
) -> list[dict]:
    """Discover live hosts on one private subnet and port-scan each.

    The devices only; `scan_subnet` also returns the gateway and this
    machine's address. Raises ValueError for an invalid or unsafe subnet.
    Never touches the network in demo mode.
    """
    return scan_subnet(subnet_text, ports, demo_mode, fingerprint=fingerprint)[0]

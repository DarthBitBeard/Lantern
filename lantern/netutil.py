"""Small network helpers shared by the command line and the dashboard."""

from __future__ import annotations

import ipaddress


def is_loopback_host(host: str) -> bool:
    """True when `host` cannot be reached from another machine.

    localhost (any case), ::1, and any address ipaddress treats as loopback
    (the whole 127.0.0.0/8, plus IPv4-mapped loopback). 0.0.0.0, ::, LAN
    addresses, and any other name are not loopback.
    """
    if not isinstance(host, str) or not host or host != host.strip():
        return False
    if host.lower() == "localhost":
        return True
    try:
        addr = ipaddress.ip_address(host)
    except ValueError:
        return False
    if addr.is_loopback:
        return True
    mapped = getattr(addr, "ipv4_mapped", None)
    return bool(mapped is not None and mapped.is_loopback)

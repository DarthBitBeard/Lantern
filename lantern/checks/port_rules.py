"""The port-rules check: today's port findings, unchanged.

This wraps ``ports.findings_for_ports``. The dicts it returns are the
same objects a scan stored before the check registry existed, so a scan
with nothing disabled stays byte-identical. ``check_id`` and
``confidence`` live on the ``Finding`` the registry builds around those
dicts; they are not written into the stored row.
"""

from __future__ import annotations

from ..ports import findings_for_ports


def port_rule_dicts(open_ports) -> list[dict]:
    """Findings for these open ports, in the historical shape and order."""
    return findings_for_ports(list(open_ports))

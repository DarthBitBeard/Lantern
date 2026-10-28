"""Reports: JSON for machines, HTML for humans. No tracking, no cloud."""

from __future__ import annotations

import html
import json


def scan_to_dict(scan: dict, diff: dict | None = None) -> dict:
    return {
        "id": scan["id"],
        "started_at": scan["started_at"],
        "subnet": scan["subnet"],
        "scope_name": scan.get("scope_name"),
        "demo": scan["demo"],
        "device_count": len(scan["devices"]),
        "devices": scan["devices"],
        "diff": diff,
    }


def describe_change(change: dict) -> str:
    """One plain-English line for a changed device, shared by CLI and reports."""
    ip = change["device"]["ip"]
    parts = []
    old_ip = change.get("old_ip")
    if old_ip and old_ip != ip:
        parts.append(f"moved from {old_ip}")
    if change["opened"]:
        parts.append("opened " + ", ".join(str(p) for p in change["opened"]))
    if change["closed"]:
        parts.append("closed " + ", ".join(str(p) for p in change["closed"]))
    return f"{ip}: " + "; ".join(parts) if parts else f"{ip}: no change"


def _device_extra(device: dict) -> str:
    """Escaped lines for fields a report may show beside the address."""
    lines = []
    if device.get("label") and device.get("hostname"):
        lines.append(f"<p>Hostname: {html.escape(str(device['hostname']))}</p>")
    for key, title in (("owner", "Owner"), ("tag", "Tag"), ("notes", "Notes")):
        value = device.get(key)
        if value:
            lines.append(f"<p>{title}: {html.escape(str(value))}</p>")
    return "".join(lines)


def _finding_rows(device: dict) -> str:
    rows = ""
    for finding in device["findings"]:
        rows += (
            f"<tr><td>{int(finding['port'])}</td><td>{html.escape(str(finding['service']))}</td>"
            f"<td><strong>{html.escape(str(finding['severity']))}</strong></td>"
            f"<td>{html.escape(str(finding['title']))}<br><small>{html.escape(str(finding['fix']))}</small></td></tr>"
        )
    return rows or "<tr><td colspan='4'>No risky open ports found.</td></tr>"


def to_html(scan: dict, diff: dict | None = None) -> str:
    devices_html = ""
    for device in scan["devices"]:
        name = device.get("label") or device.get("hostname") or device["ip"]
        ports = ", ".join(str(p["port"]) for p in device["open_ports"]) or "none"
        banners = [
            str(port.get("banner"))
            for port in device.get("open_ports") or []
            if port.get("banner")
        ]
        banner_html = ""
        if banners:
            banner_html = f"<p>Banner: {html.escape(' | '.join(banners))}</p>"
        trust = ""
        if device.get("trusted"):
            trust = " <small>(trusted)</small>"
        devices_html += f"""
        <section>
          <h2>{html.escape(str(name))} <small>{html.escape(device['ip'])}</small>{trust}</h2>
          <p>MAC: {html.escape(device.get('mac') or 'unknown')} | Open ports: {html.escape(ports)}</p>
          {_device_extra(device)}
          {banner_html}
          <table><tr><th>Port</th><th>Service</th><th>Risk</th><th>What it means</th></tr>
          {_finding_rows(device)}
          </table>
        </section>"""

    diff_html = ""
    if diff:
        added = ", ".join(d["ip"] for d in diff["added"]) or "none"
        removed = ", ".join(d["ip"] for d in diff["removed"]) or "none"
        changed = "; ".join(describe_change(c) for c in diff["changed"]) or "none"
        diff_html = f"""
        <section><h2>What changed since the last scan</h2>
        <p><strong>New devices:</strong> {html.escape(added)}</p>
        <p><strong>Devices gone:</strong> {html.escape(removed)}</p>
        <p><strong>Port changes:</strong> {html.escape(changed)}</p></section>"""

    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lantern scan report</title>
<style>body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.4rem;text-align:left;vertical-align:top}}
h1{{margin-bottom:.2rem}}</style></head><body>
<h1>Lantern scan report</h1>
<p>Scan #{int(scan['id'])} | {html.escape(str(scan['started_at']))} | {html.escape(str(scan['subnet']))} | scope {html.escape(str(scan.get('scope_name') or ''))} | {len(scan['devices'])} devices
{'| demo data' if scan['demo'] else ''}</p>
{diff_html}
{devices_html}
<p><small>Lantern is defensive only. It scans your own private network, with your permission. It never guesses passwords or sends exploits.</small></p>
</body></html>"""


def to_json(scan: dict, diff: dict | None = None) -> str:
    return json.dumps(scan_to_dict(scan, diff), indent=2)

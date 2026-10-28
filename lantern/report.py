"""Reports: JSON for machines, HTML for humans. No tracking, no cloud."""

from __future__ import annotations

import html
import json

from .assets import device_asset_fields, strip_for_text


def _device_for_report(device: dict) -> dict:
    shown = dict(device)
    shown.update(device_asset_fields(device))
    return shown


def _diff_for_report(diff: dict | None) -> dict | None:
    if diff is None:
        return None
    changed = []
    for change in diff.get("changed") or []:
        copied = dict(change)
        if change.get("device"):
            copied["device"] = _device_for_report(change["device"])
        changed.append(copied)
    return {
        "added": [_device_for_report(device) for device in diff.get("added") or []],
        "removed": [_device_for_report(device) for device in diff.get("removed") or []],
        "changed": changed,
    }


def scan_to_dict(scan: dict, diff: dict | None = None) -> dict:
    devices = [_device_for_report(device) for device in scan["devices"]]
    return {
        "id": scan["id"],
        "started_at": scan["started_at"],
        "subnet": scan["subnet"],
        "scope_name": scan.get("scope_name"),
        "demo": scan["demo"],
        "device_count": len(devices),
        "devices": devices,
        "diff": _diff_for_report(diff),
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


def _html_text(value) -> str:
    return html.escape(str(value), quote=True)


def _device_extra(device: dict) -> str:
    """Escaped inventory lines. The trust label is rendered separately."""
    fields = device_asset_fields(device)
    lines = []
    if device.get("label") and device.get("hostname"):
        lines.append(f"<p>Hostname: {_html_text(device['hostname'])}</p>")
    for key, title in (
        ("owner", "Owner"),
        ("location", "Location"),
        ("criticality", "Criticality"),
        ("notes", "Notes"),
    ):
        value = fields[key]
        if value:
            lines.append(f"<p>{title}: {_html_text(value)}</p>")
    if fields["tags"]:
        lines.append(f"<p>Tags: {_html_text(', '.join(fields['tags']))}</p>")
    return "".join(lines)


def _device_diff_label(device: dict) -> str:
    """Escaped IP plus any inventory fields, for the diff section."""
    fields = device_asset_fields(device)
    bits = [_html_text(device.get("ip") or "")]
    if fields["owner"]:
        bits.append("owner " + _html_text(fields["owner"]))
    if fields["location"]:
        bits.append("location " + _html_text(fields["location"]))
    if fields["criticality"]:
        bits.append("criticality " + _html_text(fields["criticality"]))
    if fields["tags"]:
        bits.append("tags " + _html_text(", ".join(fields["tags"])))
    if fields["notes"]:
        bits.append("notes " + _html_text(fields["notes"]))
    return " ".join(bits)


def _finding_rows(device: dict) -> str:
    rows = ""
    for finding in device["findings"]:
        rows += (
            f"<tr><td>{int(finding['port'])}</td><td>{html.escape(str(finding['service']))}</td>"
            f"<td><strong>{html.escape(str(finding['severity']))}</strong></td>"
            f"<td>{html.escape(str(finding['title']))}<br><small>{html.escape(str(finding['fix']))}</small></td></tr>"
        )
    return rows or "<tr><td colspan='4'>No risky open ports found.</td></tr>"


def scan_body(scan: dict, diff: dict | None = None) -> str:
    """Escaped HTML for one scan, without the document wrapper."""
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
        added = ", ".join(_device_diff_label(d) for d in diff["added"]) or "none"
        removed = ", ".join(_device_diff_label(d) for d in diff["removed"]) or "none"
        changed = "; ".join(_html_text(describe_change(c)) for c in diff["changed"]) or "none"
        diff_html = f"""
        <section><h2>What changed since the last scan</h2>
        <p><strong>New devices:</strong> {added}</p>
        <p><strong>Devices gone:</strong> {removed}</p>
        <p><strong>Port changes:</strong> {changed}</p></section>"""

    return f"""<h1>Lantern scan report</h1>
<p>Scan #{int(scan['id'])} | {html.escape(str(scan['started_at']))} | {html.escape(str(scan['subnet']))} | scope {_html_text(strip_for_text(scan.get('scope_name') or '') or '-')} | {len(scan['devices'])} devices
{'| demo data' if scan['demo'] else ''}</p>
{diff_html}
{devices_html}
<p><small>Lantern is defensive only. It scans your own private network, with your permission. It never guesses passwords or sends exploits.</small></p>"""


def _html_document(body: str) -> str:
    return f"""<!doctype html><html lang="en"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width, initial-scale=1">
<title>Lantern scan report</title>
<style>body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.4rem;text-align:left;vertical-align:top}}
h1{{margin-bottom:.2rem}}</style></head><body>
{body}
</body></html>"""


def to_html(scan: dict, diff: dict | None = None) -> str:
    return _html_document(scan_body(scan, diff))


def multi_scope_html(scans: list[tuple[dict, dict | None]], failed: list[tuple[str, str]]) -> str:
    """One HTML document for every scope in a multi-scope run."""
    ran = [strip_for_text(scan.get("scope_name") or "") for scan, _diff in scans]
    parts = [
        "<h1>Lantern multi-scope scan</h1>",
        f"<p>Scopes ran: {html.escape(', '.join(ran) if ran else '(none)')}</p>",
    ]
    if failed:
        names = ", ".join(name for name, _error in failed)
        parts.append(f"<p>Scopes failed: {html.escape(names)}</p>")
        for name, error in failed:
            parts.append(f"<p>{html.escape(name)}: {html.escape(error)}</p>")
    else:
        parts.append("<p>Scopes failed: (none)</p>")
    for scan, diff in scans:
        parts.append(scan_body(scan, diff))
    return _html_document("".join(parts))


def to_json(scan: dict, diff: dict | None = None) -> str:
    return json.dumps(scan_to_dict(scan, diff), indent=2)


def diff_to_json(diff: dict) -> str:
    """Diff JSON with the same inventory-field stripping as a report."""
    return json.dumps(_diff_for_report(diff), indent=2)

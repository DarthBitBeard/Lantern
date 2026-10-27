"""Reports: JSON for machines, HTML for humans. No tracking, no cloud."""

import html
import json


def scan_to_dict(scan, diff=None):
    return {
        "id": scan["id"],
        "started_at": scan["started_at"],
        "subnet": scan["subnet"],
        "demo": scan["demo"],
        "device_count": len(scan["devices"]),
        "devices": scan["devices"],
        "diff": diff,
    }


def _finding_rows(device):
    rows = ""
    for finding in device["findings"]:
        rows += (
            f"<tr><td>{finding['port']}</td><td>{html.escape(finding['service'])}</td>"
            f"<td><strong>{html.escape(finding['severity'])}</strong></td>"
            f"<td>{html.escape(finding['title'])}<br><small>{html.escape(finding['fix'])}</small></td></tr>"
        )
    return rows or "<tr><td colspan='4'>No risky open ports found.</td></tr>"


def to_html(scan, diff=None):
    devices_html = ""
    for device in scan["devices"]:
        name = device.get("label") or device.get("hostname") or device["ip"]
        ports = ", ".join(str(p["port"]) for p in device["open_ports"]) or "none"
        devices_html += f"""
        <section>
          <h2>{html.escape(name)} <small>{html.escape(device['ip'])}</small></h2>
          <p>MAC: {html.escape(device.get('mac') or 'unknown')} | Open ports: {html.escape(ports)}</p>
          <table><tr><th>Port</th><th>Service</th><th>Risk</th><th>What it means</th></tr>
          {_finding_rows(device)}
          </table>
        </section>"""

    diff_html = ""
    if diff:
        added = ", ".join(d["ip"] for d in diff["added"]) or "none"
        removed = ", ".join(d["ip"] for d in diff["removed"]) or "none"
        changed = "; ".join(
            f"{c['device']['ip']} opened {c['opened']}, closed {c['closed']}"
            for c in diff["changed"]
        ) or "none"
        diff_html = f"""
        <section><h2>What changed since the last scan</h2>
        <p><strong>New devices:</strong> {html.escape(added)}</p>
        <p><strong>Devices gone:</strong> {html.escape(removed)}</p>
        <p><strong>Port changes:</strong> {html.escape(changed)}</p></section>"""

    return f"""<!doctype html><html><head><meta charset="utf-8">
<title>Lantern scan report</title>
<style>body{{font-family:system-ui,sans-serif;max-width:900px;margin:2rem auto;padding:0 1rem}}
table{{border-collapse:collapse;width:100%}}td,th{{border:1px solid #ccc;padding:.4rem;text-align:left}}
h1{{margin-bottom:.2rem}}</style></head><body>
<h1>Lantern scan report</h1>
<p>{html.escape(scan['started_at'])} | {html.escape(scan['subnet'])} | {len(scan['devices'])} devices
{'| demo data' if scan['demo'] else ''}</p>
{diff_html}
{devices_html}
<p><small>Lantern is defensive only. It scans your own private network, with your permission. It never guesses passwords or sends exploits.</small></p>
</body></html>"""


def to_json(scan, diff=None):
    return json.dumps(scan_to_dict(scan, diff), indent=2)

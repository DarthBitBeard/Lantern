"""CLI: scan, demo, diff, report. Local only, private subnets only."""

import argparse
import ipaddress
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import demo
from .discovery import arp_table, guess_subnet, ping_host, reverse_hostname, validate_subnet
from .ports import DEFAULT_PORTS, findings_for_ports
from .report import to_html, to_json
from .scanner import scan_host
from .store import connect, diff_scans, latest_two_scan_ids, load_scan, save_scan

DEFAULT_DB = Path("data/lantern.db")


def _enrich(ip, macs):
    mac = macs.get(ip)
    return {"ip": ip, "mac": mac, "hostname": reverse_hostname(ip)}


def run_scan(subnet_text, ports, db_path, demo_mode=False):
    if demo_mode:
        return demo.demo_scan_1()
    network = validate_subnet(subnet_text)
    hosts = [str(ip) for ip in network.hosts()]
    if len(hosts) > 1024:
        raise ValueError("Subnet too large for a home scan in v0.1. Use a /24.")
    macs = arp_table()

    def check(ip):
        if ping_host(ip):
            return ip
        return None

    with ThreadPoolExecutor(max_workers=50) as pool:
        live = [ip for ip in pool.map(check, hosts) if ip]

    # Hosts in the ARP cache count as live even if ping is blocked.
    for ip in macs:
        if ipaddress.ip_address(ip) in network and ip not in live:
            live.append(ip)

    devices = []
    for ip in sorted(live, key=lambda x: tuple(int(o) for o in x.split("."))):
        open_ports = scan_host(ip, ports)
        port_numbers = [p["port"] for p in open_ports]
        info = _enrich(ip, macs)
        info["open_ports"] = open_ports
        info["findings"] = findings_for_ports(port_numbers)
        info["label"] = None
        devices.append(info)
    return devices


def main(argv=None):
    parser = argparse.ArgumentParser(prog="lantern", description="Local-first home network scanner.")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="SQLite file, default data/lantern.db")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan your private subnet.")
    scan_p.add_argument("--db", default=argparse.SUPPRESS, help="SQLite file.")
    scan_p.add_argument("--subnet", help="e.g. 192.168.1.0/24. Auto-detected if omitted.")
    scan_p.add_argument("--demo", action="store_true", help="Use fake demo data, no network scan.")
    scan_p.add_argument("--format", choices=["text", "json", "html"], default="text")

    sub.add_parser("demo", help="Run two demo scans and show the diff. No network touched.").add_argument("--db", default=argparse.SUPPRESS, help="SQLite file.")
    diff_p = sub.add_parser("diff", help="Show what changed between the last two saved scans.")
    diff_p.add_argument("--db", default=argparse.SUPPRESS, help="SQLite file.")
    diff_p.add_argument("--format", choices=["text", "json"], default="text")
    report_p = sub.add_parser("report", help="Print the latest scan as JSON or HTML.")
    report_p.add_argument("--db", default=argparse.SUPPRESS, help="SQLite file.")
    report_p.add_argument("--format", choices=["json", "html"], default="json")

    web_p = sub.add_parser("web", help="Start the local web dashboard. No pip install needed.")
    web_p.add_argument("--db", default=argparse.SUPPRESS, help="SQLite file.")
    web_p.add_argument("--host", default="127.0.0.1", help="Bind address, default 127.0.0.1 (local only).")
    web_p.add_argument("--port", type=int, default=8068, help="Port, default 8068.")
    web_p.add_argument("--debug", action="store_true", help="Log each HTTP request to stderr.")

    args = parser.parse_args(argv)
    db_path = Path(getattr(args, "db", str(DEFAULT_DB)))
    db_path.parent.mkdir(parents=True, exist_ok=True)

    if args.command == "web":
        from .webapp import serve

        serve(db_path, host=args.host, port=args.port, debug=args.debug)
        return 0

    conn = connect(db_path)

    if args.command == "demo":
        subnet = "192.168.1.0/24"
        id1 = save_scan(conn, subnet, demo.demo_scan_1(), demo=True)
        id2 = save_scan(conn, subnet, demo.demo_scan_2(), demo=True)
        old, new = load_scan(conn, id1), load_scan(conn, id2)
        diff = diff_scans(old, new)
        html_path = db_path.parent / "demo-report.html"
        html_path.write_text(to_html(new, diff))
        print(f"Demo scan 1: {len(old['devices'])} devices")
        print(f"Demo scan 2: {len(new['devices'])} devices")
        print(f"New devices: {[d['ip'] for d in diff['added']]}")
        print(f"Devices gone: {[d['ip'] for d in diff['removed']]}")
        print(f"Port changes: {[(c['device']['ip'], c['opened'], c['closed']) for c in diff['changed']]}")
        print(f"HTML report: {html_path}")
        return 0

    if args.command == "scan":
        subnet = args.subnet or guess_subnet()
        if not subnet:
            print("Could not auto-detect your subnet. Pass --subnet 192.168.1.0/24", file=sys.stderr)
            return 2
        try:
            devices = run_scan(subnet, DEFAULT_PORTS, db_path, demo_mode=args.demo)
        except ValueError as exc:
            print(str(exc), file=sys.stderr)
            return 2
        scan_id = save_scan(conn, subnet, devices, demo=args.demo)
        scan = load_scan(conn, scan_id)
        ids = latest_two_scan_ids(conn)
        diff = None
        if len(ids) == 2:
            diff = diff_scans(load_scan(conn, ids[1]), scan)
        if args.format == "json":
            print(to_json(scan, diff))
        elif args.format == "html":
            print(to_html(scan, diff))
        else:
            print(f"Scan {scan_id}: {len(devices)} devices on {subnet}")
            for device in devices:
                ports = ", ".join(str(p["port"]) for p in device["open_ports"]) or "none"
                worst = device["findings"][0]["severity"] if device["findings"] else "none"
                print(f"  {device['ip']}  ports: {ports}  worst: {worst}")
            if diff:
                print(f"New: {[d['ip'] for d in diff['added']]}  Gone: {[d['ip'] for d in diff['removed']]}")
        return 0

    if args.command == "diff":
        ids = latest_two_scan_ids(conn)
        if len(ids) < 2:
            print("Need at least two saved scans. Run `lantern demo` or `lantern scan` twice.")
            return 0
        diff = diff_scans(load_scan(conn, ids[1]), load_scan(conn, ids[0]))
        if args.format == "json":
            import json as _json
            print(_json.dumps(diff, indent=2))
        else:
            print(f"New: {[d['ip'] for d in diff['added']]}")
            print(f"Gone: {[d['ip'] for d in diff['removed']]}")
            for change in diff["changed"]:
                print(f"{change['device']['ip']}: opened {change['opened']}, closed {change['closed']}")
        return 0

    if args.command == "report":
        ids = latest_two_scan_ids(conn)
        if not ids:
            print("No scans yet. Run `lantern demo` or `lantern scan` first.")
            return 0
        scan = load_scan(conn, ids[0])
        print(to_json(scan) if args.format == "json" else to_html(scan))
        return 0

    return 2


if __name__ == "__main__":
    raise SystemExit(main())

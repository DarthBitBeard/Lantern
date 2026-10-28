"""CLI: scan, demo, diff, report, history, web. Local only, private subnets only."""

from __future__ import annotations

import argparse
import ipaddress
import json
import sqlite3
import sys
from concurrent.futures import ThreadPoolExecutor
from pathlib import Path

from . import __version__, demo
from .discovery import arp_table, guess_subnet, ping_host, reverse_hostname, validate_subnet
from .ports import DEFAULT_PORTS, findings_for_ports
from .report import describe_change, to_html, to_json
from .scanner import scan_host
from .store import connect, list_scans, load_scan_with_diff, save_scan

DEFAULT_DB = Path("data/lantern.db")
PING_WORKERS = 50
HOST_WORKERS = 8  # hosts port-scanned at once; each uses up to 25 sockets


def _scan_one(ip: str, macs: dict[str, str], ports) -> dict:
    open_ports = scan_host(ip, ports)
    return {
        "ip": ip,
        "mac": macs.get(ip),
        "hostname": reverse_hostname(ip),
        "open_ports": open_ports,
        "findings": findings_for_ports([p["port"] for p in open_ports]),
        "label": None,
    }


def run_scan(subnet_text: str, ports=DEFAULT_PORTS, demo_mode: bool = False) -> list[dict]:
    """Discover live hosts on one private subnet and port-scan each.

    Raises ValueError for an invalid or unsafe subnet. Never touches the
    network in demo mode.
    """
    if demo_mode:
        return demo.demo_scan_1()
    network = validate_subnet(subnet_text)
    hosts = [str(ip) for ip in network.hosts()]
    macs = arp_table()

    with ThreadPoolExecutor(max_workers=PING_WORKERS) as pool:
        live = {ip for ip, alive in zip(hosts, pool.map(ping_host, hosts)) if alive}

    # Hosts in the ARP cache count as live even if they ignore ping.
    host_set = set(hosts)
    live.update(ip for ip in macs if ip in host_set)

    ordered = sorted(live, key=lambda ip: int(ipaddress.IPv4Address(ip)))
    with ThreadPoolExecutor(max_workers=HOST_WORKERS) as pool:
        return list(pool.map(lambda ip: _scan_one(ip, macs, ports), ordered))


def _add_db_arg(parser: argparse.ArgumentParser) -> None:
    parser.add_argument("--db", default=argparse.SUPPRESS, help="SQLite file, default data/lantern.db")


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(prog="lantern", description="Local-first home network scanner.")
    parser.add_argument("--version", action="version", version=f"lantern {__version__}")
    parser.add_argument("--db", default=str(DEFAULT_DB), help="SQLite file, default data/lantern.db")
    sub = parser.add_subparsers(dest="command", required=True)

    scan_p = sub.add_parser("scan", help="Scan your private subnet.")
    _add_db_arg(scan_p)
    scan_p.add_argument("--subnet", help="e.g. 192.168.1.0/24. Auto-detected if omitted.")
    scan_p.add_argument("--demo", action="store_true", help="Use fake demo data, no network scan.")
    scan_p.add_argument("--format", choices=["text", "json", "html"], default="text")

    demo_p = sub.add_parser("demo", help="Run two demo scans and show the diff. No network touched.")
    _add_db_arg(demo_p)

    diff_p = sub.add_parser("diff", help="Show what changed between the last two saved scans.")
    _add_db_arg(diff_p)
    diff_p.add_argument("--format", choices=["text", "json"], default="text")

    report_p = sub.add_parser("report", help="Print a saved scan (latest by default) as JSON or HTML.")
    _add_db_arg(report_p)
    report_p.add_argument("--scan-id", type=int, help="Scan id from `lantern history`. Default: latest.")
    report_p.add_argument("--format", choices=["json", "html"], default="json")

    history_p = sub.add_parser("history", help="List saved scans, newest first.")
    _add_db_arg(history_p)
    history_p.add_argument("--format", choices=["text", "json"], default="text")

    web_p = sub.add_parser("web", help="Start the local web dashboard. No pip install needed.")
    _add_db_arg(web_p)
    web_p.add_argument("--host", default="127.0.0.1", help="Bind address, default 127.0.0.1 (local only).")
    web_p.add_argument("--port", type=int, default=8068, help="Port, default 8068.")
    web_p.add_argument("--debug", action="store_true", help="Log each HTTP request to stderr.")
    return parser


def _err(message: str) -> int:
    print(f"lantern: {message}", file=sys.stderr)
    return 2


def _print_text_scan(scan: dict, diff: dict | None) -> None:
    devices = scan["devices"]
    print(f"Scan {scan['id']}: {len(devices)} devices on {scan['subnet']}"
          f"{' (demo data)' if scan['demo'] else ''}")
    for device in devices:
        name = device.get("label") or device.get("hostname") or ""
        ports = ", ".join(str(p["port"]) for p in device["open_ports"]) or "none"
        worst = device["findings"][0]["severity"] if device["findings"] else "none"
        print(f"  {device['ip']:<15} {name:<24} ports: {ports}  worst: {worst}")
    if diff:
        _print_text_diff(diff)


def _print_text_diff(diff: dict) -> None:
    print(f"New: {[d['ip'] for d in diff['added']]}")
    print(f"Gone: {[d['ip'] for d in diff['removed']]}")
    for change in diff["changed"]:
        print(describe_change(change))
    if not (diff["added"] or diff["removed"] or diff["changed"]):
        print("Nothing changed since the previous scan.")


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    db_path = Path(getattr(args, "db", str(DEFAULT_DB)))

    if args.command == "web":
        if not 1 <= args.port <= 65535:
            return _err("--port must be between 1 and 65535.")

    try:
        db_path.parent.mkdir(parents=True, exist_ok=True)
        conn = connect(db_path)
    except (OSError, sqlite3.Error, ValueError) as exc:
        return _err(f"Cannot open database {db_path}: {exc}")

    try:
        return _dispatch(args, conn, db_path)
    except sqlite3.Error as exc:
        return _err(f"Database error ({db_path}): {exc}")
    finally:
        conn.close()


def _dispatch(args, conn, db_path: Path) -> int:
    if args.command == "web":
        from .webapp import serve

        conn.close()
        try:
            serve(db_path, host=args.host, port=args.port, debug=args.debug)
        except OSError as exc:
            return _err(f"Cannot bind {args.host}:{args.port} ({exc.strerror or exc}). "
                        "Is another Lantern running? Try --port 8069.")
        return 0

    if args.command == "demo":
        save_scan(conn, demo.DEMO_SUBNET, demo.demo_scan_1(), demo=True)
        id2 = save_scan(conn, demo.DEMO_SUBNET, demo.demo_scan_2(), demo=True)
        new, diff = load_scan_with_diff(conn, id2)
        html_path = db_path.parent / "demo-report.html"
        html_path.write_text(to_html(new, diff), encoding="utf-8")
        print(f"Demo scan 1: {len(demo.demo_scan_1())} devices")
        print(f"Demo scan 2: {len(new['devices'])} devices")
        print(f"New devices: {[d['ip'] for d in diff['added']]}")
        print(f"Devices gone: {[d['ip'] for d in diff['removed']]}")
        print(f"Port changes: {[describe_change(c) for c in diff['changed']]}")
        print(f"HTML report: {html_path}")
        return 0

    if args.command == "scan":
        if args.demo:
            subnet = demo.DEMO_SUBNET
        else:
            subnet = args.subnet or guess_subnet()
            if not subnet:
                return _err("Could not auto-detect your subnet. Pass --subnet 192.168.1.0/24")
        try:
            network = validate_subnet(subnet)
            subnet = str(network)
            if not args.demo and args.format == "text":
                print(f"Scanning {subnet} ({network.num_addresses} addresses)...", file=sys.stderr)
            devices = run_scan(subnet, DEFAULT_PORTS, demo_mode=args.demo)
        except ValueError as exc:
            return _err(str(exc))
        scan_id = save_scan(conn, subnet, devices, demo=args.demo)
        scan, diff = load_scan_with_diff(conn, scan_id)
        if args.format == "json":
            print(to_json(scan, diff))
        elif args.format == "html":
            print(to_html(scan, diff))
        else:
            _print_text_scan(scan, diff)
        return 0

    if args.command == "diff":
        scan, diff = load_scan_with_diff(conn)
        if scan is None or diff is None:
            print("Need at least two saved scans. Run `lantern demo` or `lantern scan` twice.")
            return 0
        if args.format == "json":
            print(json.dumps(diff, indent=2))
        else:
            _print_text_diff(diff)
        return 0

    if args.command == "report":
        scan, diff = load_scan_with_diff(conn, args.scan_id)
        if scan is None:
            if args.scan_id is not None:
                return _err(f"No scan with id {args.scan_id}. See `lantern history`.")
            print("No scans yet. Run `lantern demo` or `lantern scan` first.")
            return 0
        print(to_json(scan, diff) if args.format == "json" else to_html(scan, diff))
        return 0

    if args.command == "history":
        scans = list_scans(conn)
        if args.format == "json":
            print(json.dumps({"scans": scans}, indent=2))
            return 0
        if not scans:
            print("No scans yet. Run `lantern demo` or `lantern scan` first.")
            return 0
        print(f"{'id':>4}  {'started (UTC)':<26} {'subnet':<18} {'devices':>7}  demo")
        for scan in scans:
            print(f"{scan['id']:>4}  {scan['started_at'][:26]:<26} {scan['subnet']:<18} "
                  f"{scan['device_count']:>7}  {'yes' if scan['demo'] else ''}")
        return 0

    return _err(f"Unknown command: {args.command}")


if __name__ == "__main__":
    raise SystemExit(main())

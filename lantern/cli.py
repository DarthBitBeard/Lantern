"""CLI: scan, demo, diff, report, history, web. Local only, private subnets only."""

from __future__ import annotations

import argparse
import errno
import ipaddress
import json
import os
import secrets
import sqlite3
import stat
import sys
from concurrent.futures import ThreadPoolExecutor
from dataclasses import asdict
from pathlib import Path
from typing import NamedTuple

from . import __version__, demo
from .discovery import arp_table, guess_subnet, ping_host, reverse_hostname, validate_subnet
from .ports import DEFAULT_PORTS, findings_for_ports
from .report import describe_change, to_html, to_json
from .scanner import scan_host
from .scopes import DEFAULT_CONFIG_NAME, load_scopes, select_scope
from .store import connect, list_scans, load_scan_with_diff, save_scan, write_private_file

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
    scan_p.add_argument("--config", help="TOML file of named scopes. With --scope, default is ./lantern.toml.")
    scan_p.add_argument("--scope", help="Scope name in --config. Required when the file defines more than one.")
    scan_p.add_argument("--demo", action="store_true", help="Use fake demo data, no network scan.")
    scan_p.add_argument("--format", choices=["text", "json", "html"], default="text")

    scopes_p = sub.add_parser("scopes", help="List named scan scopes from a TOML file. Does not scan.")
    scopes_p.add_argument("--config", help="TOML file, default ./lantern.toml.")
    scopes_p.add_argument("--format", choices=["text", "json"], default="text")

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
    web_p.add_argument(
        "--host",
        default="127.0.0.1",
        help="Bind address. Default 127.0.0.1. Any non-loopback address also needs --allow-lan.",
    )
    web_p.add_argument("--port", type=int, default=8068, help="Port, default 8068.")
    web_p.add_argument(
        "--allow-host",
        action="append",
        default=[],
        metavar="HOST",
        help="Extra Host header to accept. On loopback the defaults are "
             "127.0.0.1, localhost, and [::1] on the bound port. With --allow-lan, "
             "only this list and the explicit bind address are accepted. "
             "Repeatable. A value with no port uses the bound port. "
             "Unspecified addresses and zone ids are rejected.",
    )
    web_p.add_argument("--debug", action="store_true", help="Log each HTTP request to stderr.")
    web_p.add_argument(
        "--allow-lan",
        action="store_true",
        help=(
            "Allow a non-loopback bind. Requires one startup API token from "
            "LANTERN_API_TOKEN_FILE, else LANTERN_API_TOKEN, else an interactive "
            "terminal. The token is never written to the log. Binding 0.0.0.0 or "
            ":: also needs --allow-host with the LAN address clients will use."
        ),
    )
    return parser


def _err(message: str) -> int:
    print(f"lantern: {message}", file=sys.stderr)
    return 2


TOKEN_FILE_ENV = "LANTERN_API_TOKEN_FILE"
TOKEN_ENV = "LANTERN_API_TOKEN"


class WebBind(NamedTuple):
    """Decision for `lantern web` before the server is constructed.

    ``token`` is passed into ``serve(api_token=...)`` when ``lan_bound`` is
    set. It is printed only when ``print_token`` is true, which is an
    auto-generated token on an interactive terminal. ``warning`` never
    contains the token.
    """

    error: str | None = None
    warning: str | None = None
    token: str | None = None
    lan_bound: bool = False
    print_token: bool = False


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


def new_api_token() -> str:
    """One startup token. 256 bits. Never written to the database or the log."""
    return secrets.token_urlsafe(32)


def _stderr_is_tty() -> bool:
    try:
        return bool(sys.stderr.isatty())
    except Exception:
        return False


def _load_serve():
    from .webapp import serve
    return serve


# A token file larger than this is refused before it is read into memory.
MAX_TOKEN_FILE_BYTES = 4 * 1024


def _token_open_flags() -> int:
    flags = os.O_RDONLY
    # O_NOFOLLOW refuses a symlink. O_NONBLOCK keeps a FIFO from hanging
    # the open. Either flag is omitted where the platform does not have it.
    for name in ("O_NOFOLLOW", "O_NONBLOCK", "O_BINARY"):
        flags |= getattr(os, name, 0)
    return flags


def _read_token_file(path: str) -> str:
    """Read a regular token file. The error does not include the contents.

    Symlinks are refused. A FIFO or other non-regular file is refused
    without a blocking read. Files larger than 4 KiB are refused. On POSIX,
    a mode other than 0400 or 0600 (any group or other bit) is refused.
    Docker's 0444 secret mount is not accepted: the host file must be
    mode 0400 and owned by the user that runs Lantern.
    """
    file_path = Path(path)
    try:
        if file_path.is_symlink():
            raise ValueError(
                f"{TOKEN_FILE_ENV} must be a regular file, not a symlink. "
                "Refusing to start."
            )
    except OSError as exc:
        raise ValueError(
            f"Cannot read {TOKEN_FILE_ENV} ({file_path}): {exc.strerror or exc}. "
            "Refusing to start."
        ) from exc
    try:
        fd = os.open(file_path, _token_open_flags())
    except OSError as exc:
        if exc.errno == errno.ELOOP:
            raise ValueError(
                f"{TOKEN_FILE_ENV} must be a regular file, not a symlink. "
                "Refusing to start."
            ) from exc
        # A FIFO with no writer can fail open immediately under O_NONBLOCK
        # (ENXIO) instead of returning a descriptor. That is still a refusal,
        # and it must not block.
        if exc.errno == errno.ENXIO:
            raise ValueError(
                f"{TOKEN_FILE_ENV} must be a regular file. Refusing to start."
            ) from exc
        raise ValueError(
            f"Cannot read {TOKEN_FILE_ENV} ({file_path}): {exc.strerror or exc}. "
            "Refusing to start."
        ) from exc
    try:
        info = os.fstat(fd)
        if not stat.S_ISREG(info.st_mode):
            raise ValueError(
                f"{TOKEN_FILE_ENV} must be a regular file. Refusing to start."
            )
        if os.name != "nt" and stat.S_IMODE(info.st_mode) & 0o077:
            mode = stat.S_IMODE(info.st_mode)
            raise ValueError(
                f"{TOKEN_FILE_ENV} is readable by group or others (mode {mode:04o}). "
                "Use mode 0400, owned by the user that runs Lantern. "
                "Refusing to start."
            )
        if info.st_size > MAX_TOKEN_FILE_BYTES:
            raise ValueError(
                f"{TOKEN_FILE_ENV} is larger than 4 KiB. Refusing to start."
            )
        blob = os.read(fd, MAX_TOKEN_FILE_BYTES + 1)
    finally:
        os.close(fd)
    if len(blob) > MAX_TOKEN_FILE_BYTES:
        raise ValueError(
            f"{TOKEN_FILE_ENV} is larger than 4 KiB. Refusing to start."
        )
    try:
        text = blob.decode("utf-8")
    except UnicodeError as exc:
        raise ValueError(
            f"{TOKEN_FILE_ENV} is not valid UTF-8. Refusing to start."
        ) from exc
    token = text.strip()
    from .webapp import api_token_error

    if api_token_error(token):
        raise ValueError(
            f"{TOKEN_FILE_ENV} does not contain a valid API token "
            "(at least 128 bits, 22 to 512 urlsafe characters). Refusing to start."
        )
    return token


def load_api_token(environ: dict, *, tty: bool, debug: bool = False, token_factory=None):
    """Resolve the LAN token. Returns (token, error, print_token, source).

    Precedence is ``LANTERN_API_TOKEN_FILE``, then ``LANTERN_API_TOKEN``,
    then an auto-generated token. Generation happens only on an interactive
    terminal, because a non-TTY stderr is what ``docker logs`` stores.
    ``error`` and the caller’s warning never contain the token. ``source``
    is ``file``, ``env``, ``generated``, or None.
    """
    from .webapp import api_token_error

    if TOKEN_FILE_ENV in environ:
        raw_path = environ.get(TOKEN_FILE_ENV)
        if not isinstance(raw_path, str) or not raw_path.strip():
            return None, (
                f"{TOKEN_FILE_ENV} is empty. Refusing to start."
            ), False, None
        try:
            token = _read_token_file(raw_path.strip())
        except ValueError as exc:
            return None, str(exc), False, None
        return token, None, False, "file"

    if TOKEN_ENV in environ:
        raw = environ.get(TOKEN_ENV)
        token = raw.strip() if isinstance(raw, str) else ""
        if api_token_error(token):
            return None, (
                f"refusing to start: {TOKEN_ENV} is missing or not 22 to 512 "
                "urlsafe characters (at least 128 bits)."
            ), False, None
        return token, None, False, "env"

    # --debug must not print a generated token, including on a TTY.
    # Require a file or the environment variable instead of minting one
    # that the operator cannot see.
    if debug:
        return None, (
            "refusing to start without a valid API token. "
            "--debug does not print a generated token. "
            f"Set {TOKEN_FILE_ENV} or {TOKEN_ENV}."
        ), False, None

    if not tty:
        return None, (
            "refusing to start without a valid API token. "
            f"Set {TOKEN_FILE_ENV} or {TOKEN_ENV}. "
            "An auto-generated token is printed only on an interactive terminal "
            "and is never written to logs."
        ), False, None

    token = (token_factory or new_api_token)()
    if api_token_error(token):
        return None, (
            "refusing to start without a valid API token "
            "(at least 128 bits, 22 urlsafe characters)."
        ), False, None
    return token, None, True, "generated"


def _lan_warning(host: str, allowed: frozenset[str], source: str | None) -> str:
    lines = [
        "WARNING: Lantern is binding beyond loopback.",
        f"WARNING: listen address {host} is reachable from other machines.",
        "WARNING: allowed Host values: " + ", ".join(sorted(allowed)),
        "WARNING: anyone with the token has full control; GET data is also protected.",
        "WARNING: do not expose this port to the internet or an untrusted LAN.",
    ]
    if source == "file":
        lines.append(
            f"WARNING: API token loaded from {TOKEN_FILE_ENV}. It is not printed."
        )
    elif source == "env":
        lines.append(
            f"WARNING: API token loaded from {TOKEN_ENV}. It is not printed."
        )
    return "\n".join(lines)


def resolve_web_bind(
    host: str,
    allow_lan: bool,
    *,
    allow_hosts: list[str] | None = None,
    port: int = 8068,
    environ: dict | None = None,
    tty: bool = False,
    debug: bool = False,
    token_factory=None,
) -> WebBind:
    """Decide whether `lantern web` may bind `host`.

    Loopback is always allowed and does not mint a LAN token. Any other
    address needs ``--allow-lan`` and one valid startup token. This function
    does not open a socket and does not put the token in ``warning``.
    """
    if is_loopback_host(host):
        return WebBind()
    if not allow_lan:
        return WebBind(error=(
            f"refusing to bind {host}. The dashboard listens on loopback "
            f"only (127.0.0.1, localhost, or ::1) unless you pass --allow-lan."
        ))
    env = os.environ if environ is None else environ
    token, error, print_token, source = load_api_token(
        env, tty=tty, debug=debug, token_factory=token_factory,
    )
    if error:
        return WebBind(error=error)
    from .webapp import build_lan_allowlist

    try:
        allowed = build_lan_allowlist(host, port, list(allow_hosts or []))
    except ValueError as exc:
        # Drop the token. A refused bind must not print it.
        return WebBind(error=str(exc))
    return WebBind(
        warning=_lan_warning(host, allowed, source),
        token=token,
        lan_bound=True,
        print_token=print_token,
    )


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


def _scope_config_path(args) -> Path:
    if getattr(args, "config", None):
        return Path(args.config)
    return Path(DEFAULT_CONFIG_NAME)


def _resolve_scan_subnet(args) -> str:
    """Choose the subnet string before any discovery or probing.

    `--subnet` still works on its own. A scope file is optional and is
    checked with the same rules as `--subnet`.
    """
    if args.demo:
        if args.config or args.scope:
            raise ValueError("--demo cannot be combined with --config or --scope.")
        return demo.DEMO_SUBNET
    if args.subnet and (args.config or args.scope):
        raise ValueError("Pass either --subnet or --config/--scope, not both.")
    if args.config or args.scope:
        scope = select_scope(load_scopes(_scope_config_path(args)), args.scope)
        return scope.subnet
    if args.subnet:
        return args.subnet
    guessed = guess_subnet()
    if not guessed:
        raise ValueError("Could not auto-detect your subnet. Pass --subnet 192.168.1.0/24")
    return guessed


def _cmd_scopes(args) -> int:
    try:
        scopes = list(load_scopes(_scope_config_path(args)).values())
    except ValueError as exc:
        return _err(str(exc))
    if args.format == "json":
        print(json.dumps({"scopes": [asdict(scope) for scope in scopes]}, indent=2))
        return 0
    if not scopes:
        print("No scopes defined.")
        return 0
    name_width = max(len(scope.name) for scope in scopes)
    subnet_width = max(len(scope.subnet) for scope in scopes)
    print(f"{'name':<{name_width}}  {'subnet':<{subnet_width}}  description")
    for scope in scopes:
        print(f"{scope.name:<{name_width}}  {scope.subnet:<{subnet_width}}  {scope.description or ''}")
    return 0


def main(argv=None) -> int:
    parser = build_parser()
    args = parser.parse_args(argv)
    if args.command == "scopes":
        return _cmd_scopes(args)
    db_path = Path(getattr(args, "db", str(DEFAULT_DB)))

    web_bind = None
    if args.command == "web":
        if not 1 <= args.port <= 65535:
            return _err("--port must be between 1 and 65535.")
        # Refuse a bad Host allowlist or a LAN bind before creating the
        # database or opening a socket.
        from .webapp import parse_allow_host

        try:
            for item in args.allow_host:
                parse_allow_host(item)
        except ValueError as exc:
            return _err(str(exc))
        web_bind = resolve_web_bind(
            args.host,
            bool(args.allow_lan),
            allow_hosts=args.allow_host,
            port=args.port,
            environ=os.environ,
            tty=_stderr_is_tty(),
            debug=bool(args.debug),
        )
        if web_bind.error:
            return _err(web_bind.error)

    try:
        # connect() creates a missing parent at mode 0700. A mkdir here
        # would leave that directory at 0755 under umask 022.
        conn = connect(db_path)
    except (OSError, sqlite3.Error, ValueError) as exc:
        return _err(f"Cannot open database {db_path}: {exc}")

    try:
        return _dispatch(args, conn, db_path, web_bind)
    except sqlite3.Error as exc:
        return _err(f"Database error ({db_path}): {exc}")
    finally:
        conn.close()


def _dispatch(args, conn, db_path: Path, web_bind: WebBind | None = None) -> int:
    if args.command == "web":
        serve = _load_serve()
        if web_bind is None:
            web_bind = resolve_web_bind(
                args.host,
                bool(getattr(args, "allow_lan", False)),
                allow_hosts=getattr(args, "allow_host", None),
                port=args.port,
                environ=os.environ,
                tty=_stderr_is_tty(),
                debug=bool(getattr(args, "debug", False)),
            )
            if web_bind.error:
                return _err(web_bind.error)
        conn.close()
        if web_bind.warning:
            print(web_bind.warning, file=sys.stderr, flush=True)
        if web_bind.print_token and web_bind.token and not args.debug:
            # Interactive console only, and never with --debug. print_token
            # is also false when stderr is not a TTY (`docker logs`).
            print(
                f"API token (printed once, not logged): {web_bind.token}",
                file=sys.stderr,
                flush=True,
            )
        kwargs = {
            "host": args.host,
            "port": args.port,
            "debug": args.debug,
            "allow_hosts": args.allow_host,
            "lan_bound": web_bind.lan_bound,
        }
        if web_bind.lan_bound:
            kwargs["api_token"] = web_bind.token
        try:
            serve(db_path, **kwargs)
        except OSError as exc:
            return _err(f"Cannot bind {args.host}:{args.port} ({exc.strerror or exc}). "
                        "Is another Lantern running? Try --port 8069.")
        except ValueError as exc:
            return _err(str(exc))
        return 0

    if args.command == "demo":
        save_scan(conn, demo.DEMO_SUBNET, demo.demo_scan_1(), demo=True)
        id2 = save_scan(conn, demo.DEMO_SUBNET, demo.demo_scan_2(), demo=True)
        new, diff = load_scan_with_diff(conn, id2)
        html_path = db_path.parent / "demo-report.html"
        write_private_file(html_path, to_html(new, diff))
        print(f"Demo scan 1: {len(demo.demo_scan_1())} devices")
        print(f"Demo scan 2: {len(new['devices'])} devices")
        print(f"New devices: {[d['ip'] for d in diff['added']]}")
        print(f"Devices gone: {[d['ip'] for d in diff['removed']]}")
        print(f"Port changes: {[describe_change(c) for c in diff['changed']]}")
        print(f"HTML report: {html_path}")
        return 0

    if args.command == "scan":
        try:
            subnet = _resolve_scan_subnet(args)
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

"""Web dashboard: stdlib only, no pip install needed.

Plain HTML/CSS/JS, a JSON API, and static files served by the app,
without a web framework, so Lantern stays a zero-dependency tool:
python3 -m lantern web, open the URL.

Binds to 127.0.0.1 by default. A non-loopback bind needs the CLI's
--allow-lan flag and one startup API token. Never expose this to the
internet.

Local-tool hygiene, enforced here:
- Every request must send a Host header on the allowlist. On loopback
  that is 127.0.0.1, localhost, or [::1] on the bound port, plus hosts
  named with --allow-host. When LAN-bound, the allowlist is only the
  explicit bind address and --allow-host values. A public name that
  rebinds to 127.0.0.1 is still refused.
- Loopback, by default: the token is not embedded, and every /api route
  requires X-Lantern-Token, compared with hmac.compare_digest. The token
  is not logged. --no-strict-auth embeds it in the page and checks it on
  POST only.
- LAN-bound: the same token, supplied by the CLI, is required on every
  API route including GET inventory and reports. It is not embedded in
  the page. Static files other than that rule stay unauthenticated.
- A POST that includes Origin must use http or https, and that origin's
  host:port must be on the same allowlist. A missing Origin is accepted
  only together with a valid token. POST /api/login has no token yet, so
  its Origin must be present and on the allowlist. The body is a single-use
  nonce; the response is the session token, which is valid until restart.
- Request targets must be origin-form (a path). An absolute-form URL is
  rejected with 400.
- POST bodies must be JSON (Content-Type application/json) and at most
  64 KiB. Reading the request line, headers, and body shares one total
  deadline, not only a per-read socket timeout. The response is sent in
  chunks: each chunk has an idle write timeout, and the whole response
  has a longer cap. The process caps connections overall and per client
  address. A full cap gets 503.
- OPTIONS, PUT, DELETE, and PATCH get 405 after the Host check and, when
  LAN-bound, the token check. Transfer-Encoding is rejected and the
  connection is closed. Every POST closes the connection.
- Unexpected errors return a generic 500. The exception text is written
  only when --debug is on, and only to stderr.
- Responses carry nosniff, a strict CSP on HTML, and no-store caching.
"""

from __future__ import annotations

import hmac
import html
import io
import ipaddress
import json
import re
import secrets
import signal
import socket
import sys
import threading
import time
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, quote, urlparse, urlsplit

from . import __version__, assets as assetlib, demo, engine, topology
from .classify import annotate_scan
from .discovery import MAC_RE, guess_subnet, validate_subnet
from .netutil import is_loopback_host
from .ports import DEFAULT_PORTS
from .report import to_html, to_json
from .store import (
    CorruptScanError,
    NewerSchemaError,
    connect,
    count_scans,
    list_scans,
    delete_scans,
    load_scan_with_diff,
    save_scan,
    scans_to_prune,
    set_trusted,
)
from .v1 import header_value

WEB_DIR = Path(__file__).resolve().parent / "web"
# For SVG files served on their own (the brand images).
SVG_CSP = "default-src 'none'; style-src 'unsafe-inline'; sandbox"

STATIC_TYPES = {
    ".html": "text/html; charset=utf-8",
    ".css": "text/css; charset=utf-8",
    ".js": "text/javascript; charset=utf-8",
    ".json": "application/json",
    ".png": "image/png",
    ".svg": "image/svg+xml",
}
MAX_BODY_BYTES = 64 * 1024
MAX_LABEL_CHARS = 80
# Signed 64-bit SQLite INTEGER. Larger values used to raise OverflowError
# and leak the exception text to the client.
MAX_SCAN_ID = 2**63 - 1
SCANS_PAGE_DEFAULT = 200
SCANS_PAGE_MAX = 1000
REQUEST_TIMEOUT_SECONDS = 10
# Total time allowed to read one request line, its headers, and its body.
# A client that drips a byte just inside the per-read timeout cannot refresh this.
HEADER_DEADLINE_SECONDS = 10
# Response bodies are written in chunks. Each chunk may block only for
# the idle timeout or the time left on the overall deadline, whichever
# is shorter. A reader that keeps accepting data may take longer than
# one idle timeout. The whole response stops at WRITE_DEADLINE_SECONDS.
WRITE_CHUNK_BYTES = 16 * 1024
WRITE_DEADLINE_SECONDS = 60
MAX_CONNECTIONS = 32
MAX_CONNECTIONS_PER_IP = 8
# A presented token that does not match waits this long. Guessing a
# 128-bit token is not practical; the delay only slows a tight loop.
TOKEN_FAILURE_DELAY_SECONDS = 0.05
# A tray or launcher open puts this nonce in the fragment. It is not the
# session token. One POST spends it, and it dies after this many seconds.
LOGIN_NONCE_SECONDS = 60.0
_LOGIN_NONCE_RE = re.compile(r"^[A-Za-z0-9_-]{22,128}$")
# style-src keeps 'unsafe-inline' because the saved HTML report carries its own
# <style> block. base-uri, form-action, and object-src close the ways a stray
# injected tag could redirect a form or a relative URL.
CSP = (
    "default-src 'self'; style-src 'self' 'unsafe-inline'; img-src 'self' data:; "
    "frame-ancestors 'none'; base-uri 'none'; form-action 'self'; object-src 'none'"
)
TOKEN_HEADER = "X-Lantern-Token"
TOKEN_PLACEHOLDER = "__LANTERN_TOKEN__"
AUTH_PLACEHOLDER = "__LANTERN_AUTH__"
FORBIDDEN_MESSAGE = "Forbidden."
SERVER_ERROR_MESSAGE = "Server error."
SCAN_FAILED_MESSAGE = "The scan failed."
BAD_REQUEST_MESSAGE = "Bad request."
# 32 bytes is 256 bits. The LAN gate accepts anything of at least 128 bits,
# which is 22 characters of urlsafe text (token_urlsafe(16) with no padding).
_TOKEN_BYTES = 32
MIN_API_TOKEN_CHARS = 22
MAX_API_TOKEN_CHARS = 512
_TOKEN_RE = re.compile(r"[A-Za-z0-9_-]+")
_NUMERIC_HOST_RE = re.compile(r"\d+")
_BUSY_BODY = b'{"error": "Server is busy."}'
_HOSTNAME_RE = re.compile(
    r"(?=.{1,253}$)"
    r"[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?"
    r"(?:\.[a-z0-9](?:[a-z0-9-]{0,61}[a-z0-9])?)*"
)
_scan_lock = threading.Lock()


class _ScanJob:
    """Outcome of the latest dashboard scan, for `GET /api/scan`.

    A scan takes about a minute on a /24, so `POST /api/scan` starts it on a
    background thread and the page polls this. `state` is idle, running,
    done, or error. `error` is a fixed message: the exception text stays on
    stderr, and only with --debug.
    """

    def __init__(self):
        self._lock = threading.Lock()
        self._state = {"state": "idle", "subnet": None, "scan_id": None, "error": None,
                       "progress": None}

    def start(self, subnet: str) -> None:
        with self._lock:
            self._state = {
                "state": "running", "subnet": subnet, "scan_id": None, "error": None,
                "progress": {"phase": "starting", "done": 0, "total": 0,
                             "started_at": time.time()},
            }

    def report(self, phase: str, done: int, total: int) -> None:
        """Record scan progress for `GET /api/scan`. Called from worker threads."""
        with self._lock:
            progress = self._state.get("progress")
            if self._state.get("state") != "running" or progress is None:
                return
            if progress["phase"] == phase and done < progress["done"]:
                return  # a late report from a slower worker
            self._state["progress"] = {**progress, "phase": phase, "done": int(done),
                                       "total": int(total)}

    def progress_text(self) -> str | None:
        """A short line such as "Checking ports 8/21", or None when idle."""
        snapshot = self.snapshot()
        progress = snapshot.get("progress")
        if snapshot.get("state") != "running" or not progress:
            return None
        label = {"discover": "Finding devices", "ports": "Checking ports"}.get(progress["phase"])
        if not label or not progress["total"]:
            return "Starting scan"
        return f"{label} {progress['done']}/{progress['total']}"

    def finish(self, scan_id: int) -> None:
        with self._lock:
            self._state = {**self._state, "state": "done", "scan_id": scan_id}

    def fail(self) -> None:
        with self._lock:
            self._state = {**self._state, "state": "error", "error": SCAN_FAILED_MESSAGE}

    def abandon(self) -> None:
        """The scan was refused before it probed. Leave the job idle."""
        with self._lock:
            self._state = {
                "state": "idle", "subnet": None, "scan_id": None, "error": None,
                "progress": None,
            }

    def snapshot(self) -> dict:
        with self._lock:
            state = dict(self._state)
            if state.get("progress"):
                progress = dict(state["progress"])
                progress["elapsed_seconds"] = round(time.time() - progress.pop("started_at"), 1)
                state["progress"] = progress
            return state


class _SubnetGuess:
    """Remember the auto-detected subnet for a short while.

    The dashboard polls /api/status, and finding the subnet can wait on the
    OS for up to half a second, so it is not redone on every poll. A failed
    guess is retried sooner, in case the network has just come up.
    """

    FOUND_TTL = 30.0
    MISSING_TTL = 5.0

    def __init__(self) -> None:
        self._lock = threading.Lock()
        self._value: str | None = None
        self._expires = 0.0

    def get(self) -> str | None:
        with self._lock:
            now = time.monotonic()
            if now >= self._expires:
                self._value = guess_subnet()
                self._expires = now + (self.FOUND_TTL if self._value else self.MISSING_TTL)
            return self._value


def _run_scan_job(job: _ScanJob, db_path: str, subnet: str, debug: bool,
                  switches: tuple | None = None, fingerprint: bool = True,
                  keep_days: float | None = None,
                  listeners: tuple = (),
                  confirm=None, on_refused=None) -> None:
    """Scan and save on a background thread, record the outcome, free the scan lock.

    ``switches`` is (switch addresses, SNMP community) from `lantern web
    --switch`, or None. The switch map is built after the sweep. With
    ``keep_days``, scans older than that are deleted after the save (the new
    scan is never one of them). Each of ``listeners`` is called with the new
    scan id after the save; a listener that fails does not fail the scan.

    ``confirm``, when set, is called immediately before any probe. A false
    result abandons the job. A scheduled scan uses it to read the gateway
    again after sleep, when the earlier check is no longer fresh. It only
    reads the route table and the ARP cache.
    """
    scan_id = None
    try:
        if confirm is not None:
            try:
                allowed = bool(confirm())
            except Exception:
                allowed = False
            if not allowed:
                if on_refused is not None:
                    try:
                        on_refused()
                    except Exception:
                        pass
                job.abandon()
                return
        devices, network = engine.scan_subnet(
            subnet, DEFAULT_PORTS, fingerprint=fingerprint, progress=job.report,
        )
        topo = None
        if switches:
            ips, community = switches
            topo = topology.map_switches(ips, community, devices, network.get("gateway_mac"))
        conn = connect(db_path)
        try:
            scan_id = save_scan(conn, subnet, devices, demo=False, network=network, topology=topo)
            if keep_days:
                doomed = [i for i in scans_to_prune(conn, older_than_days=keep_days) if i != scan_id]
                delete_scans(conn, doomed)
        finally:
            conn.close()
        job.finish(scan_id)
    except Exception as exc:
        if debug:
            try:
                print(
                    f"Lantern scan error: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
            except OSError:
                pass
        job.fail()
    except BaseException:
        # SystemExit and the like skip the handler above; without this the
        # job would read "running" forever and the dashboard would poll it.
        job.fail()
        raise
    finally:
        _scan_lock.release()
    if scan_id is not None:
        for listener in listeners:
            try:
                listener(scan_id)
            except Exception:
                pass


def start_scan_job(handler, subnet: str, *, confirm=None, on_refused=None) -> bool:
    """Start a background scan of ``subnet`` for this server. False if one is running.

    Used by `POST /api/scan`, the watch schedule, and the tray's Scan now.
    ``subnet`` must already be validated. ``confirm`` runs on the scan thread
    immediately before the probe. See `_run_scan_job`.
    """
    if not _scan_lock.acquire(blocking=False):
        return False
    handler.scan_job.start(subnet)
    try:
        threading.Thread(
            target=_run_scan_job,
            args=(
                handler.scan_job, handler.db_path, subnet, bool(handler.debug),
                handler.switch_config, bool(handler.fingerprint),
                handler.keep_days, tuple(handler.scan_listeners),
            ),
            kwargs={"confirm": confirm, "on_refused": on_refused},
            name="lantern-scan",
            daemon=True,
        ).start()
    except Exception:
        handler.scan_job.fail()
        _scan_lock.release()
        raise
    return True


def _load_view(conn, scan_id: int | None = None) -> tuple[dict | None, dict | None]:
    """A scan and its diff with trust labels and inventory fields applied.

    The CLI does the same in `_prepare_report`. Without it the dashboard and
    the HTML report would never show owner, location, tags, criticality, or
    notes.
    """
    scan, diff = load_scan_with_diff(conn, scan_id)
    assetlib.attach_assets(conn, scan)
    assetlib.attach_assets_to_diff(conn, diff)
    annotate_scan(scan)
    topology.annotate_topology(scan)
    return scan, diff


def _canonical_host(host: str) -> str:
    """Return a bracketed IPv6 address, an IPv4 address, or a lowercase DNS name.

    IPv6 must already be in brackets. Bare IPv6 is rejected so a port cannot
    be confused with the address. DNS names are compared in punycode.
    """
    text = host.strip().lower().rstrip(".")
    if not text:
        raise ValueError("not a host")
    if text.startswith("["):
        if not text.endswith("]"):
            raise ValueError("not a host")
        try:
            ip = ipaddress.IPv6Address(text[1:-1])
        except ValueError as exc:
            raise ValueError("not a host") from exc
        return f"[{ip.compressed}]"
    try:
        parsed = ipaddress.ip_address(text)
    except ValueError:
        parsed = None
    if isinstance(parsed, ipaddress.IPv6Address):
        raise ValueError("IPv6 hosts must be written in brackets")
    if isinstance(parsed, ipaddress.IPv4Address):
        return str(parsed)
    try:
        ascii_host = text.encode("idna").decode("ascii")
    except UnicodeError as exc:
        raise ValueError("not a host") from exc
    if not _HOSTNAME_RE.fullmatch(ascii_host):
        raise ValueError("not a host")
    return ascii_host


def parse_host_port(value: str) -> tuple[str, int | None]:
    """Split a host or host:port into (canonical host, port or None).

    Raises ValueError when the text is not a hostname, an IPv4 address,
    or a bracketed IPv6 address, with an optional numeric port.
    """
    if not isinstance(value, str):
        raise ValueError("not a host")
    raw = value.strip()
    if not raw or any(ch in raw for ch in " \t\r\n\x00@\\/#?"):
        raise ValueError("not a host")
    if raw.startswith("["):
        end = raw.find("]")
        if end < 2 or raw.count("]") != 1:
            raise ValueError("not a host")
        host_text = raw[: end + 1]
        rest = raw[end + 1 :]
        if rest == "":
            port = None
        elif rest.startswith(":") and rest[1:].isdigit():
            port = int(rest[1:])
        else:
            raise ValueError("not a host")
    else:
        if raw.count(":") > 1:
            raise ValueError("not a host")
        if ":" in raw:
            host_text, port_text = raw.rsplit(":", 1)
            if not port_text.isdigit():
                raise ValueError("not a host")
            port = int(port_text)
        else:
            host_text, port = raw, None
    if port is not None and not 1 <= port <= 65535:
        raise ValueError("port out of range")
    return _canonical_host(host_text), port


def api_token_error(token) -> str | None:
    """Return an error when `token` is not at least 128 bits of urlsafe text.

    The message never includes the token. None means the token is acceptable.
    """
    if (
        isinstance(token, str)
        and MIN_API_TOKEN_CHARS <= len(token) <= MAX_API_TOKEN_CHARS
        and _TOKEN_RE.fullmatch(token)
    ):
        return None
    return (
        "refusing to start without a valid API token "
        "(at least 128 bits, 22 to 512 urlsafe characters)"
    )


def _ip_from_canonical_host(canonical: str):
    text = canonical[1:-1] if canonical.startswith("[") and canonical.endswith("]") else canonical
    try:
        return ipaddress.ip_address(text)
    except ValueError:
        return None


def _is_unspecified_bind(host: str) -> bool:
    if not isinstance(host, str):
        return False
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return bool(ipaddress.ip_address(text).is_unspecified)
    except ValueError:
        return False


def _is_specific_ip_text(host: str) -> bool:
    """True for a unicast IP with no zone id. Hostnames are not specific IPs."""
    if not isinstance(host, str) or "%" in host:
        return False
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        return False
    if getattr(ip, "scope_id", None):
        return False
    return not ip.is_unspecified


def _canonical_is_specific_ip(canonical: str) -> bool:
    ip = _ip_from_canonical_host(canonical)
    if ip is None or getattr(ip, "scope_id", None):
        return False
    return not ip.is_unspecified


def _bind_host_key(host: str, port: int) -> str:
    """Allowlist key for a configured bind address, which may be bare IPv6."""
    text = host.strip()
    if text.startswith("["):
        canonical, _parsed_port = parse_host_port(text)
        return f"{canonical}:{port}"
    try:
        ip = ipaddress.ip_address(text)
    except ValueError:
        canonical, _parsed_port = parse_host_port(text)
        return f"{canonical}:{port}"
    if isinstance(ip, ipaddress.IPv6Address):
        if ip.scope_id:
            raise ValueError(
                f"bind address {host!r} must not include a zone id."
            )
        return f"[{ip.compressed}]:{port}"
    return f"{ip}:{port}"


def _loose_ipv4(host: str) -> bool:
    """True for forms ``inet_aton`` accepts and ``ipaddress`` rejects.

    That is shorthand (``127.1``), hex (``0x7f.1``, ``0x7f000001``), octal
    (``0177.0.0.1``), and leading zeros (``127.000.000.001``).
    """
    label_re = re.compile(r"(?:0x[0-9a-f]+|\d+)")
    labels = host.split(".")
    if 1 <= len(labels) <= 4 and all(label_re.fullmatch(label) for label in labels):
        if len(labels) != 4 or any(
            label.startswith("0x") or (len(label) > 1 and label.startswith("0"))
            for label in labels
        ):
            return True
    try:
        socket.inet_aton(host)
    except OSError:
        return False
    return True


def parse_allow_host(value: str) -> tuple[str, int | None]:
    """Parse one --allow-host value. Raises ValueError with a CLI-facing message.

    Unspecified addresses (0.0.0.0, ::) and zone-scoped IPv6
    ([fe80::1%eth0]) are rejected. Wildcards and CIDR are not hosts.
    """
    if isinstance(value, str) and "%" in value:
        raise ValueError(
            f"--allow-host value {value!r} must not include a zone id."
        )
    try:
        host, port = parse_host_port(value)
    except ValueError as exc:
        raise ValueError(
            f"--allow-host value {value!r} is not a hostname or IP address with an optional port."
        ) from exc
    ip = _ip_from_canonical_host(host)
    if ip is not None and getattr(ip, "scope_id", None):
        raise ValueError(
            f"--allow-host value {value!r} must not include a zone id."
        )
    if ip is not None and ip.is_unspecified:
        raise ValueError(
            f"--allow-host value {value!r} must be a specific host, not an unspecified address."
        )
    # "0" and other all-digit names are not dotted IPv4. Some resolvers
    # treat "0" as 0.0.0.0, which must not be an allowed Host.
    if ip is None and _NUMERIC_HOST_RE.fullmatch(host):
        raise ValueError(
            f"--allow-host value {value!r} must be a specific host, not an unspecified address."
        )
    # inet_aton accepts 127.1, 0x7f.1, 0177.0.0.1, and 127.000.000.001.
    # ipaddress does not. None of those are allowed Host values.
    if ip is None and _loose_ipv4(host):
        raise ValueError(
            f"--allow-host value {value!r} is not a full dotted IPv4 address. "
            "Use the full dotted form."
        )
    return host, port


def allowlist_for(bound_port: int, parsed: list[tuple[str, int | None]]) -> frozenset[str]:
    """Host:port values that may call this process. Loopback is always included."""
    if isinstance(bound_port, bool) or not isinstance(bound_port, int) or not 1 <= bound_port <= 65535:
        raise ValueError("port must be between 1 and 65535.")
    allowed = set()
    for spec in ("127.0.0.1", "localhost", "[::1]"):
        host, _port = parse_host_port(spec)
        allowed.add(f"{host}:{bound_port}")
    for host, port in parsed:
        allowed.add(f"{host}:{bound_port if port is None else port}")
    return frozenset(allowed)


def build_allowed_hosts(bound_port: int, extra_hosts: list[str] | None = None) -> frozenset[str]:
    """Loopback allowlist for a bound port. Extra names without a port use that port."""
    parsed = [parse_allow_host(item) for item in (extra_hosts or [])]
    return allowlist_for(bound_port, parsed)


def build_lan_allowlist(
    bind_host: str,
    bound_port: int,
    extra_hosts: list[str] | None = None,
) -> frozenset[str]:
    """Host:port values for a LAN bind. No automatic loopback and no wildcard.

    The explicit bind address is included when it is a specific address.
    0.0.0.0 and :: are not added. That bind is refused unless one
    --allow-host value is a specific IP (the address clients will send).
    """
    if isinstance(bound_port, bool) or not isinstance(bound_port, int) or not 1 <= bound_port <= 65535:
        raise ValueError("port must be between 1 and 65535.")
    parsed = [parse_allow_host(item) for item in (extra_hosts or [])]
    allowed: set[str] = set()
    unspecified = _is_unspecified_bind(bind_host)
    specific_ip = False
    if not unspecified:
        if "%" in bind_host:
            raise ValueError(f"bind address {bind_host!r} must not include a zone id.")
        allowed.add(_bind_host_key(bind_host, bound_port))
        specific_ip = _is_specific_ip_text(bind_host)
    for host, port in parsed:
        allowed.add(f"{host}:{bound_port if port is None else port}")
        if _canonical_is_specific_ip(host):
            specific_ip = True
    if unspecified and not specific_ip:
        raise ValueError(
            f"refusing to bind {bind_host}: pass --allow-host with the LAN address "
            "clients will use. An unspecified address is not added to the Host allowlist."
        )
    if not allowed:
        raise ValueError(f"refusing to bind {bind_host}: the Host allowlist is empty.")
    return frozenset(allowed)


def is_origin_form(target: str) -> bool:
    """True for an origin-form request target: a path, optional query.

    Absolute-form (http://host/path), authority-form, and asterisk-form
    are rejected. A scheme-relative target that starts with // is too.
    """
    if not isinstance(target, str) or not target.startswith("/") or target.startswith("//"):
        return False
    parts = urlsplit(target)
    return not parts.scheme and not parts.netloc


def _is_ipv6_literal(host: str) -> bool:
    text = host.strip()
    if text.startswith("[") and text.endswith("]"):
        text = text[1:-1]
    try:
        return isinstance(ipaddress.ip_address(text), ipaddress.IPv6Address)
    except ValueError:
        return False


def _format_url_host(host: str) -> str:
    text = str(host)
    if ":" in text and not text.startswith("["):
        return f"[{text}]"
    return text


def startup_lines(
    bound_host: str,
    bound_port: int,
    *,
    lan_bound: bool,
    allowed_hosts: frozenset[str],
    strict_auth: bool = False,
) -> list[str]:
    """Banner lines for one mode. Never includes the API token."""
    shown = _format_url_host(bound_host)
    if lan_bound:
        allowed = ", ".join(sorted(allowed_hosts))
        return [
            f"Lantern dashboard: LAN bind on {shown}:{bound_port}/  "
            "(every API call requires the startup token)",
            f"Allowed Host values: {allowed}",
        ]
    if strict_auth:
        return [
            f"Lantern dashboard: http://{shown}:{bound_port}/  "
            "(strict auth; the page does not hold the API token)",
        ]
    return [
        f"Lantern dashboard: http://{shown}:{bound_port}/  "
        "(loopback only; the page holds the API token)",
    ]


def request_host_key(value: str, bound_port: int) -> str | None:
    """Canonical Host key, or None if the header is not a host we can compare.

    Browsers omit the port only for 80 and 443. On any other port a missing
    port does not match, so `127.0.0.1` is not treated as `127.0.0.1:8068`.
    """
    try:
        host, port = parse_host_port(value)
    except ValueError:
        return None
    if port is None:
        if bound_port in (80, 443):
            port = bound_port
        else:
            return None
    return f"{host}:{port}"


def origin_allowlist_key(origin: str) -> str | None:
    """host:port from an Origin, or None when it is not an http(s) origin.

    An omitted port means 80 for http and 443 for https, which is what the
    header means. It is not filled in with the dashboard's port.
    """
    if not isinstance(origin, str):
        return None
    text = origin.strip()
    if not text or text.lower() == "null":
        return None
    parts = urlsplit(text)
    scheme = parts.scheme.lower()
    if scheme not in ("http", "https"):
        return None
    if parts.username is not None or parts.password is not None:
        return None
    if parts.path not in ("", "/"):
        return None
    if parts.query or parts.fragment:
        return None
    hostname = parts.hostname
    if not hostname:
        return None
    try:
        port = parts.port
    except ValueError:
        return None
    if port is None:
        port = 443 if scheme == "https" else 80
    rendered = f"[{hostname}]:{port}" if ":" in hostname else f"{hostname}:{port}"
    try:
        host, parsed_port = parse_host_port(rendered)
    except ValueError:
        return None
    if parsed_port is None:
        return None
    return f"{host}:{parsed_port}"


def _extra_allowed_hosts(allowed: frozenset[str], bound_port: int) -> list[str]:
    defaults = {
        f"127.0.0.1:{bound_port}",
        f"localhost:{bound_port}",
        f"[::1]:{bound_port}",
    }
    return sorted(allowed - defaults)


class _DeadlineRaw(io.RawIOBase):
    """Socket reader whose blocking calls cannot outlive the request deadline.

    The deadline covers the request line, the headers, and the body. Each
    ``recv`` is capped at the time still left, so a byte that arrives just
    before the per-read timeout does not start a new full window. Response
    writes are not read through this object; the handler restores the idle
    timeout before it writes.
    """

    def __init__(self, sock, deadline_fn, per_read: float):
        self._sock = sock
        self._deadline_fn = deadline_fn
        self._per_read = per_read

    def readable(self) -> bool:
        return True

    def readinto(self, buffer) -> int:
        remaining = self._deadline_fn() - time.monotonic()
        if remaining <= 0:
            raise TimeoutError("request deadline exceeded")
        self._sock.settimeout(min(self._per_read, remaining))
        try:
            return self._sock.recv_into(buffer)
        except TimeoutError:
            raise TimeoutError("request deadline exceeded") from None


class LanternHandler(BaseHTTPRequestHandler):
    db_path = None
    debug = False
    # make_server gives each server its own job record.
    scan_job = None
    subnet_guess = None
    # (switch addresses, SNMP community) from --switch, or None. Never sent
    # to a client.
    switch_config = None
    # Fail closed until make_server fills these in for this process.
    api_token = ""
    allowed_hosts = frozenset()
    bound_port = 0
    # The CLI default sets strict_auth: the page does not contain the token
    # and every API route requires it. strict_auth False is --no-strict-auth:
    # loopback embeds the token and checks it on POST only. LAN mode checks
    # it on every API route and does not embed it.
    lan_bound = False
    strict_auth = False
    # Per-read idle timeout, and one deadline for reading the request
    # line, headers, and body. The deadline is what stops a slow drip.
    # Response writes use a fresh idle timeout per chunk, plus an overall cap.
    timeout = REQUEST_TIMEOUT_SECONDS
    header_timeout = HEADER_DEADLINE_SECONDS
    write_timeout = REQUEST_TIMEOUT_SECONDS
    write_deadline = WRITE_DEADLINE_SECONDS
    write_chunk_bytes = WRITE_CHUNK_BYTES
    protocol_version = "HTTP/1.1"

    def setup(self):
        self.connection = self.request
        if self.timeout is not None:
            self.connection.settimeout(self.timeout)
        self._header_deadline = time.monotonic() + float(self.header_timeout)
        raw = _DeadlineRaw(
            self.connection,
            lambda: self._header_deadline,
            float(self.timeout),
        )
        self.rfile = io.BufferedReader(raw)
        self.wfile = self.connection.makefile("wb", self.wbufsize)

    def handle_one_request(self):
        # One deadline for this request's line, headers, and body.
        # Keep-alive gets a fresh window. Response writes restore the
        # idle timeout so a large report is not cut off.
        self._header_deadline = time.monotonic() + float(self.header_timeout)
        self._body_read = False
        super().handle_one_request()

    def finish(self):
        try:
            super().finish()
        finally:
            self._linger_if_body_unread()

    def _linger_if_body_unread(self) -> None:
        # A refused POST is answered and closed with its body unread. Closing
        # a socket that still holds unread bytes sends a reset on Windows
        # (and often Linux), and the reset can reach the client before the
        # response does, so it sees "connection aborted" instead of the 403.
        # Stop writing, then discard the declared body for a short, capped
        # time. Requests without a declared body skip this, so a slow
        # header drip gains nothing from it.
        headers = getattr(self, "headers", None)
        if headers is None or getattr(self, "_body_read", True):
            return
        try:
            declared = int(headers.get("Content-Length") or 0)
        except ValueError:
            return
        if declared <= 0:
            return
        try:
            self.connection.shutdown(socket.SHUT_WR)
        except OSError:
            return
        _drain_unread(self.connection, max_bytes=min(declared, LINGER_MAX_BYTES))

    def parse_request(self) -> bool:
        ok = super().parse_request()
        # Do not restore the idle timeout here. The body is still unread,
        # and a slow POST must stay under this same deadline.
        if not ok:
            return False
        if self._content_length_invalid():
            # Every method, including ones that would otherwise 200 or 404.
            self.close_connection = True
            self._send_json(400, {"error": BAD_REQUEST_MESSAGE})
            return False
        if self._framing_requires_close():
            self.close_connection = True
        return True

    def _restore_idle_timeout(self) -> None:
        try:
            self.connection.settimeout(self.timeout)
        except OSError:
            pass

    def _connection_close_already_queued(self) -> bool:
        for line in getattr(self, "_headers_buffer", ()) or ():
            if line.lower().startswith(b"connection:") and b"close" in line.lower():
                return True
        return False

    def end_headers(self) -> None:
        # The read deadline must not carry into the response. A slow client
        # reading a report gets the normal idle timeout from here on.
        self._restore_idle_timeout()
        # send_error already queues Connection: close. Adding it again
        # makes TRACE and CONNECT replies list the header twice.
        if self.close_connection and not self._connection_close_already_queued():
            self.send_header("Connection", "close")
        super().end_headers()

    def version_string(self):
        return "Lantern"

    def log_message(self, format, *args):
        # Request line, status, and size only. Never log headers: POST calls
        # carry X-Lantern-Token, and that value must not be written here.
        if self.debug:
            super().log_message(format, *args)

    # -- helpers ------------------------------------------------------

    def _send_bytes(
        self, status: int, data: bytes, content_type: str,
        cache: str = "no-store", headers: dict | None = None,
    ) -> None:
        extra = {str(key): header_value(value) for key, value in (headers or {}).items()}
        content_type = header_value(content_type)
        cache = header_value(cache)
        self.send_response(status)
        self.send_header("Content-Type", content_type)
        self.send_header("Content-Length", str(len(data)))
        self.send_header("Cache-Control", cache)
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Referrer-Policy", "no-referrer")
        if content_type.startswith("text/html"):
            self.send_header("Content-Security-Policy", CSP)
        elif content_type.startswith("image/svg+xml"):
            # An SVG opened on its own is a document: no scripts, no loads.
            self.send_header("Content-Security-Policy", SVG_CSP)
        for key, value in extra.items():
            self.send_header(key, value)
        self.end_headers()
        if self.command != "HEAD":
            self._write_all(data)

    def _write_all(self, data: bytes) -> None:
        """Write every byte, in chunks, without one timeout for the whole body.

        ``makefile('wb', 0)`` is unbuffered, and a single ``send`` of the
        whole buffer returns when the kernel buffer fills and drops the
        rest. Each chunk waits at most ``write_timeout``, and never longer
        than the time left on ``write_deadline``. A reader that keeps
        accepting data may take longer than one idle timeout, up to that
        deadline. A reader that stalls is dropped when the chunk's wait
        runs out.
        """
        view = memoryview(data)
        chunk = int(self.write_chunk_bytes)
        if chunk < 1:
            chunk = WRITE_CHUNK_BYTES
        deadline = time.monotonic() + float(self.write_deadline)
        while len(view):
            remaining = deadline - time.monotonic()
            if remaining <= 0:
                self.close_connection = True
                return
            try:
                self.connection.settimeout(min(float(self.write_timeout), remaining))
                sent = self.connection.send(view[:chunk])
            except OSError:
                self.close_connection = True
                return
            if sent <= 0:
                self.close_connection = True
                return
            view = view[sent:]

    def _send_json(self, status: int, payload) -> None:
        self._send_bytes(status, json.dumps(payload).encode(), "application/json")

    def _send_text(self, status: int, body: str, content_type: str) -> None:
        self._send_bytes(status, body.encode(), content_type)

    def _read_json(self) -> dict:
        try:
            length = int(self.headers.get("Content-Length") or 0)
        except ValueError as exc:
            raise ValueError("Content-Length must be a number.") from exc
        if length < 0:
            raise ValueError("Content-Length must not be negative.")
        if length > MAX_BODY_BYTES:
            raise RequestTooLarge(f"Request body is too large (max {MAX_BODY_BYTES} bytes).")
        if not length:
            return {}
        content_type = (self.headers.get("Content-Type") or "").split(";")[0].strip().lower()
        if content_type != "application/json":
            raise UnsupportedMediaType("Send JSON with Content-Type: application/json.")
        raw = self.rfile.read(length)
        self._body_read = True
        try:
            value = json.loads(raw.decode("utf-8"))
        except Exception as exc:
            raise ValueError("Request body is not valid JSON.") from exc
        if not isinstance(value, dict):
            raise ValueError("Request body must be a JSON object.")
        return value

    def _host_allowed(self) -> bool:
        values = self.headers.get_all("Host")
        if not values or len(values) != 1:
            return False
        key = request_host_key(values[0], self.bound_port)
        return key is not None and key in self.allowed_hosts

    def _token_ok(self) -> bool:
        values = self.headers.get_all(TOKEN_HEADER)
        if not values or len(values) != 1:
            return False
        provided = values[0]
        expected = self.api_token
        if not isinstance(provided, str) or not isinstance(expected, str) or not expected:
            return False
        try:
            matched = hmac.compare_digest(provided, expected)
        except (TypeError, ValueError):
            # Non-ASCII or mixed types. Reject without echoing the header.
            matched = False
        if not matched:
            # Fixed delay only when a token was presented and rejected.
            # A missing header stays immediate so ordinary 403s stay cheap.
            time.sleep(TOKEN_FAILURE_DELAY_SECONDS)
        return matched

    def _origin_ok(self) -> bool:
        """True when Origin is absent or its host:port is on the allowlist.

        Absent is only safe because POST /api/* has already required the token.
        """
        values = self.headers.get_all("Origin")
        if not values:
            return True
        if len(values) != 1:
            return False
        key = origin_allowlist_key(values[0])
        return key is not None and key in self.allowed_hosts

    def _origin_present_and_allowed(self) -> bool:
        """True when one Origin is present and its host:port is on the allowlist.

        POST /api/login has no session token yet, so a missing Origin is refused.
        """
        values = self.headers.get_all("Origin")
        if not values or len(values) != 1:
            return False
        key = origin_allowlist_key(values[0])
        return key is not None and key in self.allowed_hosts

    def _forbid(self, *, unread_body: bool) -> None:
        if unread_body:
            self.close_connection = True
        self._send_json(403, {"error": FORBIDDEN_MESSAGE})

    def _server_error(self, exc: BaseException) -> None:
        """Generic 500. The exception text stays on stderr, and only with --debug."""
        if self.debug:
            try:
                print(
                    f"Lantern server error: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
            except OSError:
                pass
        self._send_json(500, {"error": SERVER_ERROR_MESSAGE})

    def _reject_bad_target(self, *, unread_body: bool) -> None:
        if unread_body:
            self.close_connection = True
        self._send_json(400, {"error": BAD_REQUEST_MESSAGE})

    def _api_get_allowed(self) -> bool:
        """Loopback GET is open to an allowed Host. LAN and strict auth need the token."""
        if self.lan_bound or self.strict_auth:
            return self._token_ok()
        return True

    def _content_length_values(self) -> list[str] | None:
        values = self.headers.get_all("Content-Length")
        if not values:
            return None
        return [str(value).strip() for value in values]

    def _content_length_invalid(self) -> bool:
        """Duplicate, negative, or non-integer Content-Length values.

        ``+2``, ``-1``, ``abc``, ``1e3``, and ``5, 5`` are invalid. A single
        non-negative integer is not.
        """
        values = self._content_length_values()
        if values is None:
            return False
        if len(values) != 1:
            return True
        return re.fullmatch(r"\d+", values[0]) is None

    def _framing_requires_close(self) -> bool:
        """True when unread bytes must not be parsed as another request."""
        if "Transfer-Encoding" in self.headers:
            return True
        if self._content_length_invalid():
            return True
        values = self._content_length_values()
        if not values:
            return False
        return int(values[0]) > 0

    def _reject_transfer_encoding(self) -> bool:
        """True when any Transfer-Encoding header was present and a 400 was sent.

        An empty value still counts. Truthiness would ignore ``Transfer-Encoding:``.
        The connection is closed so leftover bytes are not a second request.
        """
        if "Transfer-Encoding" not in self.headers:
            return False
        self.close_connection = True
        self._send_json(400, {"error": BAD_REQUEST_MESSAGE})
        return True

    def _unsupported_method(self) -> None:
        """405 after the Host check and, on a LAN API route, the token check."""
        if self._reject_host(unread_body=True):
            return
        if not is_origin_form(self.path):
            self._reject_bad_target(unread_body=True)
            return
        if self._reject_transfer_encoding():
            return
        path = urlparse(self.path).path
        if self._is_v1(path):
            self.close_connection = True
            if not self._token_ok():
                self._send_v1_error(403, "forbidden")
                return
            from .v1 import asset_post_key

            allow = "POST" if asset_post_key(path) else "GET, HEAD"
            self._send_v1_error(405, "method_not_allowed", headers={"Allow": allow})
            return
        if (self.lan_bound or self.strict_auth) and path.startswith("/api/") and not self._token_ok():
            self._forbid(unread_body=True)
            return
        self.close_connection = True
        self.send_response(405)
        self.send_header("Content-Type", "application/json")
        body = json.dumps({"error": "Method not allowed."}).encode()
        self.send_header("Content-Length", str(len(body)))
        self.send_header("Cache-Control", "no-store")
        self.send_header("X-Content-Type-Options", "nosniff")
        self.send_header("Allow", "GET, HEAD, POST")
        self.end_headers()
        self._write_all(body)

    def do_OPTIONS(self):
        self._unsupported_method()

    def do_PUT(self):
        self._unsupported_method()

    def do_DELETE(self):
        self._unsupported_method()

    def do_PATCH(self):
        self._unsupported_method()

    def do_TRACE(self):
        self._v1_method_or_stdlib("TRACE")

    def do_CONNECT(self):
        self._v1_method_or_stdlib("CONNECT")

    def _v1_method_or_stdlib(self, name: str) -> None:
        """v1 answers TRACE and CONNECT with JSON. Other paths keep the 501 reply."""
        path = urlparse(self.path).path
        if self._is_v1(path):
            self._unsupported_method()
            return
        self.send_error(501, "Unsupported method (%r)" % name)

    def _db(self):
        return connect(self.db_path)

    # -- static --------------------------------------------------------

    def _serve_static(self, name: str) -> None:
        if name in ("", "/"):
            name = "index.html"
        path = (WEB_DIR / name.lstrip("/")).resolve()
        if WEB_DIR not in path.parents or not path.is_file() or path.suffix not in STATIC_TYPES:
            self._send_json(404, {"error": "Not found."})
            return
        if path.name == "index.html":
            # no-store: the page contains this process's token.
            self._send_bytes(200, self._index_bytes(path), STATIC_TYPES[".html"], cache="no-store")
            return
        self._send_bytes(200, path.read_bytes(), STATIC_TYPES[path.suffix], cache="no-cache")

    def _index_bytes(self, path: Path) -> bytes:
        text = path.read_text(encoding="utf-8")
        if text.count(TOKEN_PLACEHOLDER) != 1 or text.count(AUTH_PLACEHOLDER) != 1:
            raise RuntimeError("Dashboard index is missing its token placeholder.")
        if self.lan_bound or self.strict_auth:
            # The page must not contain the token. A client that can GET /
            # must not learn it from the HTML or from a response header.
            marker = "token" if self.lan_bound else "strict"
            page = (
                text.replace(TOKEN_PLACEHOLDER, "", 1)
                .replace(AUTH_PLACEHOLDER, marker, 1)
            )
            if self.api_token and self.api_token in page:
                raise RuntimeError("Refusing to embed the API token in the page.")
            return page.encode("utf-8")
        # token_urlsafe is already [A-Za-z0-9_-]. Escape anyway so a future
        # generator cannot break out of the attribute. Do not log the token.
        escaped = html.escape(self.api_token, quote=True)
        page = (
            text.replace(TOKEN_PLACEHOLDER, escaped, 1)
            .replace(AUTH_PLACEHOLDER, "page", 1)
        )
        return page.encode("utf-8")

    # -- GET -----------------------------------------------------------

    def do_HEAD(self):
        self.do_GET()

    def _reject_host(self, *, unread_body: bool) -> bool:
        if self._host_allowed():
            return False
        path = urlparse(self.path).path
        if self._is_v1(path):
            if unread_body:
                self.close_connection = True
            self._send_v1_error(403, "forbidden")
        else:
            self._forbid(unread_body=unread_body)
        return True

    def do_GET(self):
        if self._reject_host(unread_body=False):
            return
        if not is_origin_form(self.path):
            self._reject_bad_target(unread_body=False)
            return
        if self._reject_transfer_encoding():
            return
        parsed = urlparse(self.path)
        query = parse_qs(parsed.query)
        if self._is_v1(parsed.path):
            self._dispatch_v1("GET", parsed, query)
            return
        if parsed.path.startswith("/api/") and not self._api_get_allowed():
            self._forbid(unread_body=False)
            return
        try:
            if parsed.path.startswith("/api/"):
                self._handle_api_get(parsed.path, query)
            elif parsed.path == "/favicon.ico":
                # Browsers ask for this name. The artwork is the SVG, served
                # with its own type. This redirect stays on this host.
                self._send_bytes(
                    302, b"", "text/plain; charset=utf-8",
                    cache="max-age=86400",
                    headers={"Location": "/favicon.svg"},
                )
            else:
                self._serve_static(parsed.path)
        except (CorruptScanError, NewerSchemaError) as exc:
            self._send_data_error(exc)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:
            self._server_error(exc)

    @staticmethod
    def _int_param(value, name: str) -> int:
        try:
            number = int(value)
        except (TypeError, ValueError) as exc:
            raise ValueError(f"{name} must be a number.") from exc
        if number < 1 or number > MAX_SCAN_ID:
            raise ValueError(f"{name} must be a positive number.")
        return number

    @staticmethod
    def _page_param(query: dict, name: str, default: int, maximum: int | None) -> int:
        raw = query.get(name, [None])[0]
        if raw is None or raw == "":
            return default
        try:
            number = int(raw)
        except ValueError as exc:
            raise ValueError(f"{name} must be a number.") from exc
        low = 1 if name == "limit" else 0
        if number < low or (maximum is not None and number > maximum) or number > MAX_SCAN_ID:
            raise ValueError(f"{name} is out of range.")
        return number

    @staticmethod
    def _is_v1(path: str) -> bool:
        from .v1 import is_v1_path

        return is_v1_path(path)

    def _send_v1_error(self, status: int, code: str, fields: dict | None = None, headers: dict | None = None) -> None:
        from .v1 import content_type, error_body

        self._send_bytes(
            status,
            json.dumps(error_body(code, fields)).encode("utf-8"),
            content_type("json"),
            headers=headers,
        )

    def _dispatch_v1(self, method: str, parsed, query: dict) -> None:
        """v1 has its own errors. Legacy handlers must not answer these paths."""
        from .v1 import V1Error

        try:
            if not self._token_ok():
                self._send_v1_error(403, "forbidden")
                return
            from .v1 import asset_post_key

            if asset_post_key(parsed.path) is not None:
                if method != "POST":
                    self._send_v1_error(405, "method_not_allowed", headers={"Allow": "POST"})
                    return
                # Same order as legacy POST: token, then Origin. A missing
                # Origin is allowed only because the token already matched.
                # This route does not send CORS headers.
                if not self._origin_ok():
                    self._send_v1_error(403, "forbidden")
                    return
                self._handle_v1_asset_post(parsed.path)
                return
            if method != "GET":
                self._send_v1_error(405, "method_not_allowed", headers={"Allow": "GET, HEAD"})
                return
            if not self._api_get_allowed():
                self._send_v1_error(403, "forbidden")
                return
            self._handle_v1_get(parsed.path, query)
        except V1Error as exc:
            self._send_v1_error(exc.status, exc.code, exc.fields)
        except NewerSchemaError:
            self._send_v1_error(409, "conflict")
        except CorruptScanError:
            self._send_v1_error(500, "server_error")
        except Exception as exc:
            self._server_error_v1(exc)

    def _server_error_v1(self, exc: BaseException) -> None:
        if self.debug:
            try:
                print(
                    f"Lantern server error: {type(exc).__name__}: {exc}",
                    file=sys.stderr,
                    flush=True,
                )
            except OSError:
                pass
        self._send_v1_error(500, "server_error")

    def _handle_v1_get(self, path: str, query: dict) -> None:
        from .v1 import (
            V1Error,
            content_type,
            devices_document,
            diff_document,
            export_filename,
            export_locked,
            findings_document,
            one_scan_document,
            render_export,
            scans_document,
            scopes_document,
            status_document,
            _finish,
            _number,
        )

        conn = self._db()
        try:
            if path in ("/api/v1", "/api/v1/"):
                raise V1Error(404, "not_found")
            if path == "/api/v1/status":
                body = _finish(status_document())
                self._send_bytes(200, body, content_type("json"))
                return
            if path == "/api/v1/scopes":
                body = _finish(scopes_document(conn))
                self._send_bytes(200, body, content_type("json"))
                return
            if path == "/api/v1/devices":
                body = _finish(devices_document(conn, query))
                self._send_bytes(200, body, content_type("json"))
                return
            if path == "/api/v1/scans":
                body = _finish(scans_document(conn, query))
                self._send_bytes(200, body, content_type("json"))
                return
            if path.startswith("/api/v1/scans/"):
                scan_id = _number({"scan_id": [path[len("/api/v1/scans/"):]]}, "scan_id")
                if scan_id is None:
                    raise V1Error(404, "not_found")
                body = _finish(one_scan_document(conn, scan_id))
                self._send_bytes(200, body, content_type("json"))
                return
            if path == "/api/v1/diffs":
                body = _finish(diff_document(conn, query))
                self._send_bytes(200, body, content_type("json"))
                return
            if path == "/api/v1/findings":
                body = _finish(findings_document(conn, query))
                self._send_bytes(200, body, content_type("json"))
                return
            if path == "/api/v1/export":
                include = (query.get("include") or [""])[0] == "private"
                if query.get("include") and query["include"][0] not in ("", "private"):
                    raise V1Error(400, "bad_request")

                def build():
                    payload, fmt, scan_id, what, _fmt = render_export(
                        conn, query, private=include,
                    )
                    return payload, fmt, scan_id, what

                payload, fmt, scan_id, what = export_locked(build)
                self._send_bytes(
                    200,
                    payload,
                    content_type(fmt),
                    headers={
                        "Content-Disposition": export_filename(what, scan_id, fmt),
                        "Content-Security-Policy": "default-src 'none'; sandbox",
                    },
                )
                return
            raise V1Error(404, "not_found")
        finally:
            conn.close()

    def _handle_v1_asset_post(self, path: str) -> None:
        from .v1 import V1Error, apply_asset_update, asset_post_key

        try:
            body = self._read_json()
        except RequestTooLarge:
            self._send_v1_error(413, "too_large")
            return
        except UnsupportedMediaType:
            self._send_v1_error(415, "unsupported_media_type")
            return
        except ValueError:
            self._send_v1_error(400, "bad_request")
            return
        raw_key = asset_post_key(path)
        conn = self._db()
        try:
            payload = apply_asset_update(conn, raw_key or "", body)
        except V1Error as exc:
            self._send_v1_error(exc.status, exc.code, exc.fields)
            return
        finally:
            conn.close()
        from .v1 import content_type

        self._send_bytes(200, json.dumps(payload).encode("utf-8"), content_type("json"))

    def _handle_api_get(self, path: str, query: dict) -> None:
        conn = self._db()
        try:
            if path == "/api/status":
                newest = list_scans(conn, limit=1)
                self._send_json(200, {
                    "version": __version__,
                    "guessed_subnet": self.subnet_guess.get(),
                    "scan_count": count_scans(conn),
                    "latest_scan_id": newest[0]["id"] if newest else None,
                    "scan_running": _scan_lock.locked(),
                    "watch": self.watcher.status() if self.watcher else None,
                    "watch_status": watch_status_text(self),
                    "keep_days": self.keep_days,
                })
                return
            if path == "/api/scan":
                self._send_json(200, self.scan_job.snapshot())
                return
            if path == "/api/scans":
                limit = self._page_param(query, "limit", SCANS_PAGE_DEFAULT, SCANS_PAGE_MAX)
                offset = self._page_param(query, "offset", 0, None)
                self._send_json(200, {
                    "scans": list_scans(conn, limit=limit, offset=offset),
                    "total": count_scans(conn),
                    "limit": limit,
                    "offset": offset,
                })
                return
            if path in ("/api/scans/latest", "/api/diff"):
                scan, diff = _load_view(conn)
                self._send_json(200, {"scan": scan, "diff": diff})
                return
            if path.startswith("/api/scans/"):
                scan_id = self._int_param(path[len("/api/scans/"):], "Scan id")
                scan, diff = _load_view(conn, scan_id)
                if scan is None:
                    self._send_json(404, {"error": "Scan not found."})
                else:
                    self._send_json(200, {"scan": scan, "diff": diff})
                return
            if path == "/api/report":
                scan_id = query.get("scan_id", [None])[0]
                fmt = query.get("format", ["json"])[0]
                if fmt not in ("json", "html"):
                    raise ValueError("format must be json or html.")
                if scan_id:
                    scan_id = self._int_param(scan_id, "scan_id")
                scan, diff = _load_view(conn, scan_id)
                if scan is None:
                    self._send_json(404, {"error": "Scan not found." if scan_id else "No scans yet."})
                    return
                if fmt == "html":
                    self._send_text(200, to_html(scan, diff), "text/html; charset=utf-8")
                else:
                    self._send_text(200, to_json(scan, diff), "application/json")
                return
            self._send_json(404, {"error": "Unknown API route."})
        finally:
            conn.close()

    # -- POST ----------------------------------------------------------

    def do_POST(self):
        # Always close. Extra bytes after the body must not be a new request.
        self.close_connection = True
        parsed = urlparse(self.path)
        if self._reject_host(unread_body=True):
            return
        if not is_origin_form(self.path):
            self._reject_bad_target(unread_body=True)
            return
        if "Transfer-Encoding" in self.headers:
            self.close_connection = True
            if self._is_v1(parsed.path):
                if not self._token_ok():
                    self._send_v1_error(403, "forbidden")
                    return
                self._send_v1_error(400, "bad_request")
                return
            self._send_json(400, {"error": BAD_REQUEST_MESSAGE})
            return
        if self._is_v1(parsed.path):
            self._dispatch_v1("POST", parsed, {})
            return
        if not parsed.path.startswith("/api/"):
            self.close_connection = True  # body left unread
            self._send_json(404, {"error": "Not found."})
            return
        if parsed.path == "/api/login":
            # No session token yet. Host was checked above. Origin must be
            # present and on the allowlist, then the nonce is spent.
            self._handle_login()
            return
        # Token first, then Origin. A missing Origin is allowed only because
        # the token matched. A present Origin must itself be on the allowlist.
        if not self._token_ok() or not self._origin_ok():
            self._forbid(unread_body=True)
            return
        try:
            body = self._read_json()
        except RequestTooLarge as exc:
            self._send_json(413, {"error": str(exc)})
            self.close_connection = True
            return
        except UnsupportedMediaType as exc:
            self._send_json(415, {"error": str(exc)})
            self.close_connection = True
            return
        except (CorruptScanError, NewerSchemaError) as exc:
            self._send_data_error(exc)
            self.close_connection = True
            return
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            self.close_connection = True
            return
        try:
            if parsed.path == "/api/demo":
                self._handle_demo()
            elif parsed.path == "/api/scan":
                self._handle_scan(body)
            elif parsed.path == "/api/trust":
                self._handle_trust(body)
            elif parsed.path == "/api/watch":
                self._handle_watch(body)
            else:
                self._send_json(404, {"error": "Unknown API route."})
        except (CorruptScanError, NewerSchemaError) as exc:
            self._send_data_error(exc)
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
        except Exception as exc:
            self._server_error(exc)

    def _send_data_error(self, exc: BaseException) -> None:
        """A bad database is not a bad request, and the body is a fixed line."""
        if isinstance(exc, NewerSchemaError):
            status, message = 409, "The database schema is newer than this Lantern."
        else:
            status, message = 500, "The saved scan could not be read."
        self._send_bytes(
            status,
            json.dumps({"error": message}).encode("utf-8"),
            "application/json",
            headers={"Content-Security-Policy": CSP},
        )

    def _handle_demo(self) -> None:
        conn = self._db()
        try:
            first, second = demo.demo_scan_1(), demo.demo_scan_2()
            save_scan(conn, demo.DEMO_SUBNET, first, demo=True, network=demo.DEMO_NETWORK,
                      topology=demo.demo_topology(first))
            save_scan(conn, demo.DEMO_SUBNET, second, demo=True, network=demo.DEMO_NETWORK,
                      topology=demo.demo_topology(second))
            scan, diff = _load_view(conn)
            self._send_json(200, {"scan_id": scan["id"], "scan": scan, "diff": diff})
        finally:
            conn.close()

    def _handle_scan(self, body: dict) -> None:
        # Validate before taking the lock, so a typo never blocks a real scan.
        subnet = body.get("subnet")
        if subnet is not None and not isinstance(subnet, str):
            raise ValueError("subnet must be a string like 192.168.1.0/24.")
        subnet = (subnet or "").strip() or guess_subnet()
        if not subnet:
            raise ValueError(
                "Could not auto-detect your subnet. Send {\"subnet\": \"192.168.1.0/24\"}."
            )
        subnet = str(validate_subnet(subnet))

        # The scan runs on its own thread, which releases the lock when it
        # ends. The request returns at once so a proxy or tunnel with a short
        # timeout cannot cut it off, and the scan does not hold a connection
        # slot for a minute.
        if not start_scan_job(type(self), subnet):
            self._send_json(409, {"error": "A scan is already running. Wait for it to finish."})
            return
        self._send_json(202, {"state": "running", "subnet": subnet})

    def _handle_trust(self, body: dict) -> None:
        mac = str(body.get("mac") or "").strip().lower()
        if not MAC_RE.fullmatch(mac):
            raise ValueError("mac must look like aa:bb:cc:dd:ee:ff.")
        mac = mac.replace("-", ":")
        label = body.get("label")
        if label is not None and not isinstance(label, str):
            raise ValueError("label must be text.")
        label = (label or "").strip()[:MAX_LABEL_CHARS]
        trusted = body.get("trusted", True)
        if not isinstance(trusted, bool):
            raise ValueError("trusted must be true or false.")
        conn = self._db()
        try:
            set_trusted(conn, mac, label, trusted)
        finally:
            conn.close()
        self._send_json(200, {"mac": mac, "label": label or None, "trusted": trusted})

    def _handle_login(self) -> None:
        """Spend a single-use nonce and return the session token.

        The nonce comes from a tray or launcher open. It is not the session
        token, and the token is not written into the URL. A second use, an
        expired nonce, or a missing Origin is refused. The token itself stays
        valid until this process restarts.
        """
        if not self._origin_present_and_allowed():
            self._forbid(unread_body=True)
            return
        try:
            body = self._read_json()
        except RequestTooLarge as exc:
            self._send_json(413, {"error": str(exc)})
            self.close_connection = True
            return
        except UnsupportedMediaType as exc:
            self._send_json(415, {"error": str(exc)})
            self.close_connection = True
            return
        except ValueError as exc:
            self._send_json(400, {"error": str(exc)})
            self.close_connection = True
            return
        exchange = getattr(self, "login_exchange", None)
        nonce = body.get("nonce") if isinstance(body, dict) else None
        token = exchange.redeem(nonce) if isinstance(exchange, LoginExchange) else None
        if not token:
            time.sleep(TOKEN_FAILURE_DELAY_SECONDS)
            self._send_json(403, {"error": FORBIDDEN_MESSAGE})
            return
        self._send_json(200, {"token": token})

    def _handle_watch(self, body: dict) -> None:
        """Save the network to watch beside this process's database.

        The gateway MAC is read from the route table and the ARP cache. No
        host is probed. A different saved network is left in place unless
        ``adopt`` is true.
        """
        saved, message = apply_watch_opt_in(self, body)
        if not saved and message.startswith("A different network"):
            self._send_json(409, {"error": message})
            return
        if not saved:
            raise ValueError(message)
        self._send_json(200, {
            "saved": True,
            "message": message,
            "watch_status": watch_status_text(self),
        })


class RequestTooLarge(ValueError):
    pass


class UnsupportedMediaType(ValueError):
    pass


def _reject_busy(request) -> None:
    body = _BUSY_BODY
    raw = (
        b"HTTP/1.1 503 Service Unavailable\r\n"
        b"Content-Type: application/json\r\n"
        b"Cache-Control: no-store\r\n"
        b"Content-Length: " + str(len(body)).encode("ascii") + b"\r\n"
        b"Connection: close\r\n"
        b"\r\n"
        + body
    )
    try:
        # Drop anything already buffered so close() is a FIN, not a RST
        # that would discard the 503.
        request.settimeout(0.05)
        try:
            request.recv(65536)
        except OSError:
            pass
        request.sendall(raw)
    except OSError:
        pass
    finally:
        try:
            request.close()
        except OSError:
            pass


LINGER_SECONDS = 1.0
LINGER_MAX_BYTES = MAX_BODY_BYTES


def _drain_unread(request, seconds: float = LINGER_SECONDS, max_bytes: int = LINGER_MAX_BYTES) -> int:
    """Read and discard what the client still sends, until it closes or a cap is hit."""
    deadline = time.monotonic() + seconds
    drained = 0
    try:
        while drained < max_bytes:
            left = deadline - time.monotonic()
            if left <= 0:
                break
            request.settimeout(left)
            chunk = request.recv(min(8192, max_bytes - drained))
            if not chunk:
                break
            drained += len(chunk)
    except OSError:  # includes socket.timeout
        pass
    return drained


class _LanternServer(ThreadingHTTPServer):
    """Threading server with an IPv6 option, a connection cap, and quiet errors.

    ``address_family`` and ``max_connections`` are set on a subclass before
    the socket is created. ``daemon_threads`` keeps a request thread from
    blocking process exit. ``handle_error`` stays silent unless --debug is
    on, so a traceback cannot land in ``docker logs`` by default.
    """

    daemon_threads = True
    max_connections = MAX_CONNECTIONS
    max_per_ip = MAX_CONNECTIONS_PER_IP

    def server_bind(self):
        if self.address_family == socket.AF_INET6:
            try:
                self.socket.setsockopt(socket.IPPROTO_IPV6, socket.IPV6_V6ONLY, 1)
            except OSError:
                pass
        super().server_bind()

    def server_activate(self):
        self._slots = threading.BoundedSemaphore(self.max_connections)
        self._ip_lock = threading.Lock()
        self._ip_counts: dict[str, int] = {}
        super().server_activate()

    def _acquire_client(self, ip: str) -> bool:
        with self._ip_lock:
            count = self._ip_counts.get(ip, 0)
            if count >= self.max_per_ip:
                return False
            self._ip_counts[ip] = count + 1
            return True

    def _release_client(self, ip: str) -> None:
        with self._ip_lock:
            count = self._ip_counts.get(ip, 0) - 1
            if count <= 0:
                self._ip_counts.pop(ip, None)
            else:
                self._ip_counts[ip] = count

    def handle_error(self, request, client_address):
        if getattr(self.RequestHandlerClass, "debug", False):
            super().handle_error(request, client_address)

    def process_request(self, request, client_address):
        ip = client_address[0] if client_address else ""
        if not self._slots.acquire(blocking=False):
            _reject_busy(request)
            return
        if not self._acquire_client(ip):
            self._slots.release()
            _reject_busy(request)
            return
        try:
            super().process_request(request, client_address)
        except Exception:
            self._release_client(ip)
            self._slots.release()
            raise

    def process_request_thread(self, request, client_address):
        try:
            super().process_request_thread(request, client_address)
        finally:
            ip = client_address[0] if client_address else ""
            self._release_client(ip)
            self._slots.release()


def _server_class(family: int, connection_limit: int, per_ip_limit: int):
    if family not in (socket.AF_INET, socket.AF_INET6):
        raise ValueError("unsupported address family")
    if isinstance(connection_limit, bool) or not isinstance(connection_limit, int) or connection_limit < 1:
        raise ValueError("max_connections must be a positive number.")
    if isinstance(per_ip_limit, bool) or not isinstance(per_ip_limit, int) or per_ip_limit < 1:
        raise ValueError("max_connections_per_ip must be a positive number.")

    class BoundServer(_LanternServer):
        address_family = family
        max_connections = connection_limit
        max_per_ip = per_ip_limit

    return BoundServer


def _loopback_host(host: str) -> bool:
    # netutil.is_loopback_host is the one list. serve() used to keep a second,
    # shorter one, and the banner disagreed with it.
    return is_loopback_host(host)


class LoginExchange:
    """Single-use nonces a browser open trades for the session token.

    The session token is valid until this process restarts and is never put
    in a URL. Each open mints a new nonce. ``redeem`` returns the token once.
    A second call, or a nonce older than ``ttl`` seconds, returns None.
    """

    def __init__(self, token: str, *, ttl: float = LOGIN_NONCE_SECONDS, clock=None) -> None:
        self._token = token
        self._ttl = float(ttl)
        self._clock = time.monotonic if clock is None else clock
        self._lock = threading.Lock()
        self._pending: dict[str, float] = {}

    def mint(self) -> str:
        nonce = secrets.token_urlsafe(32)
        with self._lock:
            self._drop_expired()
            self._pending[nonce] = self._clock() + self._ttl
        return nonce

    def redeem(self, nonce: str) -> str | None:
        if not isinstance(nonce, str) or not _LOGIN_NONCE_RE.fullmatch(nonce):
            return None
        with self._lock:
            self._drop_expired()
            expiry = self._pending.pop(nonce, None)
            if expiry is None or self._clock() >= expiry:
                return None
            return self._token

    def _drop_expired(self) -> None:
        now = self._clock()
        dead = [key for key, expiry in self._pending.items() if expiry <= now]
        for key in dead:
            del self._pending[key]


def make_server(
    db_path,
    host: str = "127.0.0.1",
    port: int = 8068,
    debug: bool = False,
    allow_hosts: list[str] | None = None,
    api_token: str | None = None,
    lan_bound: bool = False,
    strict_auth: bool = False,
    listen_host: str | None = None,
    max_connections: int = MAX_CONNECTIONS,
    max_connections_per_ip: int = MAX_CONNECTIONS_PER_IP,
    request_timeout: float = REQUEST_TIMEOUT_SECONDS,
    header_timeout: float = HEADER_DEADLINE_SECONDS,
    write_timeout: float = REQUEST_TIMEOUT_SECONDS,
    write_deadline: float = WRITE_DEADLINE_SECONDS,
    switches: tuple | None = None,
    fingerprint: bool = True,
    keep_days: float | None = None,
) -> ThreadingHTTPServer:
    """Build the dashboard server without starting it. Used by serve() and tests.

    ``api_token``, when passed, is the only token for this process. Loopback
    generates one when it is omitted and embeds it in the page. LAN mode
    requires the CLI token and does not embed it. ``strict_auth`` also
    requires that token, does not embed it, and checks it on every API route.

    ``listen_host`` is the socket address. Tests simulate a LAN allowlist
    while binding ``127.0.0.1`` by setting ``host`` to the LAN address and
    ``listen_host`` to loopback. The CLI does not pass ``listen_host``.

    Validation runs before the listening socket is opened.
    """
    index_path = WEB_DIR / "index.html"
    if not index_path.is_file():
        raise FileNotFoundError(
            f"Dashboard files missing under {WEB_DIR}. "
            "Reinstall Lantern from the repo so lantern/web is included."
        )
    index_text = index_path.read_text(encoding="utf-8")
    if index_text.count(TOKEN_PLACEHOLDER) != 1 or index_text.count(AUTH_PLACEHOLDER) != 1:
        raise ValueError(
            "Dashboard index is missing its token placeholder. "
            "Reinstall Lantern from the repo so lantern/web is intact."
        )
    if isinstance(request_timeout, bool) or not isinstance(request_timeout, (int, float)) or request_timeout <= 0:
        raise ValueError("request timeout must be a positive number of seconds.")
    if isinstance(header_timeout, bool) or not isinstance(header_timeout, (int, float)) or header_timeout <= 0:
        raise ValueError("header deadline must be a positive number of seconds.")
    if isinstance(write_timeout, bool) or not isinstance(write_timeout, (int, float)) or write_timeout <= 0:
        raise ValueError("write timeout must be a positive number of seconds.")
    if isinstance(write_deadline, bool) or not isinstance(write_deadline, (int, float)) or write_deadline <= 0:
        raise ValueError("write deadline must be a positive number of seconds.")

    socket_host = host if listen_host is None else listen_host
    # Reject a bad --allow-host before opening a socket.
    parsed_hosts = [parse_allow_host(item) for item in (allow_hosts or [])]
    if strict_auth and api_token is None:
        raise ValueError("strict auth requires an API token.")
    if lan_bound or strict_auth or api_token is not None:
        token_problem = api_token_error(api_token)
        if token_problem:
            raise ValueError(token_problem)
        token = api_token
    else:
        token = secrets.token_urlsafe(_TOKEN_BYTES)
    if lan_bound:
        # Port 0 is assigned at bind. The host rules do not depend on it.
        build_lan_allowlist(host, port or 1, allow_hosts)
    elif not _loopback_host(socket_host):
        raise ValueError(
            f"refusing to bind {socket_host}. The dashboard listens on loopback "
            "unless it is started with a LAN token."
        )

    handler = type(
        "BoundHandler",
        (LanternHandler,),
        {
            "db_path": str(db_path),
            "debug": bool(debug),
            "lan_bound": bool(lan_bound),
            "strict_auth": bool(strict_auth),
            "scan_job": _ScanJob(),
            "switch_config": tuple(switches) if switches else None,
            "fingerprint": bool(fingerprint),
            "keep_days": keep_days,
            "scan_listeners": [],
            "watcher": None,
            "watch_note": "",
            "watch_problem": None,
            "watch_gateway_mac": None,
            "watch_pending_seconds": None,
            "login_exchange": LoginExchange(token),
            "subnet_guess": _SubnetGuess(),
            "timeout": float(request_timeout),
            "header_timeout": float(header_timeout),
            "write_timeout": float(write_timeout),
            "write_deadline": float(write_deadline),
        },
    )
    family = socket.AF_INET6 if _is_ipv6_literal(socket_host) else socket.AF_INET
    server = _server_class(family, max_connections, max_connections_per_ip)((socket_host, port), handler)
    bound_port = int(server.server_address[1])
    handler.bound_port = bound_port
    if lan_bound:
        handler.allowed_hosts = build_lan_allowlist(host, bound_port, allow_hosts)
    else:
        handler.allowed_hosts = allowlist_for(bound_port, parsed_hosts)
    handler.api_token = token
    return server


def _browser_open_url(handler, url: str | None) -> str | None:
    """The URL handed to the browser. Strict auth uses a fresh login nonce.

    Any ``#token=`` fragment on ``url`` is discarded. The session token is
    not placed on the browser command line or in history.
    """
    if not url:
        return None
    bare = str(url).split("#", 1)[0]
    if not getattr(handler, "strict_auth", False):
        return bare
    exchange = getattr(handler, "login_exchange", None)
    if not isinstance(exchange, LoginExchange):
        token = getattr(handler, "api_token", None)
        if not token:
            return bare
        exchange = LoginExchange(token)
        handler.login_exchange = exchange
    return DashboardOpen(bare, exchange).url()


def _open_browser(url: str) -> bool:
    import webbrowser

    try:
        opened = webbrowser.open(url, new=2)
    except Exception:
        opened = False
    if not opened:
        print("Could not open a browser. Use the link printed above.", file=sys.stderr, flush=True)
    return bool(opened)


def alert_listener(db_path: str, deliver):
    """A scan listener that calls ``deliver(alert)`` when a saved scan needs attention.

    The new scan is compared with the previous scan of its scope, with trust
    labels applied, and summarised by `alerts.summarize`.
    """
    from .alerts import summarize

    def listener(scan_id: int) -> None:
        conn = connect(db_path)
        try:
            _scan, diff = load_scan_with_diff(conn, scan_id)
        finally:
            conn.close()
        alert = summarize(diff)
        if alert is not None:
            deliver(alert)

    return listener


def _print_alert(alert) -> None:
    print(f"{alert.title}. {alert.text}", flush=True)


def _gateway_problem(handler, network) -> str | None:
    """``subnet``, ``gateway``, or None. Reads routes and the ARP cache only."""
    from .discovery import default_gateways, gateway_arp_table, local_ipv4_in
    from .watch import identity_problem

    mac = getattr(handler, "watch_gateway_mac", None)
    if not mac:
        return "subnet"
    try:
        problem = identity_problem(
            network, mac, local_ipv4_in(network), default_gateways(), gateway_arp_table(),
        )
    except Exception:
        problem = "subnet"
    handler.watch_problem = problem
    return problem


def _note_skip(handler, subnet: str) -> None:
    from .watch import skip_message

    reason = getattr(handler, "watch_problem", None) or "subnet"
    print(skip_message(subnet, reason), file=sys.stderr, flush=True)
    if reason == "gateway":
        handler.watch_note = f"Skipped: the gateway did not match for {subnet}."
    else:
        handler.watch_note = f"Skipped: this machine is not on {subnet}."


def _make_watcher(handler, watch_seconds: int, watch_subnet: str | None,
                  gateway_mac: str | None = None):
    """The schedule for `--watch`, pinned to the opted-in subnet and gateway MAC."""
    from .watch import Watcher, parse_started_at

    subnet = str(validate_subnet(watch_subnet))
    handler.watch_gateway_mac = gateway_mac

    def on_network(network) -> bool:
        return _gateway_problem(handler, network) is None

    def on_skip(skipped: str) -> None:
        _note_skip(handler, skipped)

    def start(target: str) -> bool:
        # Check again on the scan thread, immediately before any probe, so a
        # wake from sleep cannot scan the network that is current then.
        return start_scan_job(
            handler, target,
            confirm=lambda: on_network(watcher.network),
            on_refused=lambda: on_skip(watcher.subnet),
        )

    conn = connect(handler.db_path)
    try:
        newest = list_scans(conn, limit=1)
    finally:
        conn.close()
    watcher = Watcher(
        watch_seconds,
        subnet,
        start,
        on_network=on_network,
        on_skip=on_skip,
        last_scan_at=parse_started_at(newest[0]["started_at"]) if newest else None,
    )
    handler.watcher = watcher
    handler.watch_note = f"Watching {subnet}."
    return watcher


def _ago(seconds: float) -> str:
    minutes = int(max(seconds, 0) // 60)
    if minutes < 1:
        return "just now"
    if minutes < 60:
        return f"{minutes} min ago"
    hours = minutes // 60
    return f"{hours} h ago" if hours < 48 else f"{hours // 24} days ago"


def _in(seconds: float) -> str:
    minutes = int(max(seconds, 0) // 60)
    if minutes < 1:
        return "in under a minute"
    return f"in {minutes} min" if minutes < 60 else f"in {minutes // 60} h {minutes % 60} min"


def tray_status_line(handler, now: float | None = None) -> str:
    """The greyed first line of the tray menu: last scan, and the next one with --watch."""
    from .watch import parse_started_at

    now = time.time() if now is None else now
    if _scan_lock.locked():
        return handler.scan_job.progress_text() or "Scanning now…"
    conn = connect(handler.db_path)
    try:
        newest = list_scans(conn, limit=1)
    finally:
        conn.close()
    started = parse_started_at(newest[0]["started_at"]) if newest else None
    parts = [f"Last scan {_ago(now - started)}" if started is not None else "No scans yet"]
    note = str(getattr(handler, "watch_note", "") or "").strip()
    watcher = getattr(handler, "watcher", None)
    if note:
        parts.append(note.rstrip("."))
    elif watcher is not None:
        parts.append(f"Watching {watcher.subnet}")
    lowered = note.lower()
    if watcher is not None and not lowered.startswith("skipped") and not lowered.startswith("not watching"):
        parts.append(f"next {_in(watcher.next_scan_at - now)}")
    return " · ".join(parts)


def watch_status_text(handler) -> str:
    """One sentence for the tray and the dashboard. Empty when watch was not asked for."""
    note = str(getattr(handler, "watch_note", "") or "").strip()
    if note:
        return note if note.endswith(".") else note + "."
    watcher = getattr(handler, "watcher", None)
    if watcher is not None:
        return f"Watching {watcher.subnet}."
    return ""


def tray_may_scan(handler) -> tuple[bool, str]:
    """Whether Scan now may run. A watched network that does not match is refused.

    The menu still labels the command manual. With no watched network, the
    user is choosing the scan themselves and this returns True.
    """
    watcher = getattr(handler, "watcher", None)
    if watcher is None:
        return True, ""
    problem = _gateway_problem(handler, watcher.network)
    if problem is None:
        return True, ""
    if problem == "gateway":
        return False, (
            "Scan now was not started. The gateway did not match the network you chose to watch."
        )
    return False, (
        "Scan now was not started. This machine is not on the network you chose to watch."
    )


def apply_watch_opt_in(handler, body: dict) -> tuple[bool, str]:
    """Save the opted-in network beside ``handler.db_path``. No host is probed.

    Returns ``(saved, message)``. A different saved network is not replaced
    unless ``body["adopt"]`` is true. On success, a process that was started
    with a watch interval but had nothing to schedule starts that schedule.
    """
    from .watch import (
        NetworkIdentity,
        current_gateway_mac,
        load_opt_in_status,
        save_opt_in,
    )

    adopt = body.get("adopt", False)
    if not isinstance(adopt, bool):
        return False, "adopt must be true or false."
    subnet = body.get("subnet")
    if subnet is not None and not isinstance(subnet, str):
        return False, "subnet must be a string like 192.168.1.0/24."
    subnet = (subnet or "").strip() or guess_subnet()
    if not subnet:
        return False, "Could not detect your subnet."
    try:
        subnet = str(validate_subnet(subnet))
    except ValueError as exc:
        return False, str(exc)
    mac = current_gateway_mac(subnet)
    if not mac:
        return False, "Could not confirm the gateway for this network."
    status, existing = load_opt_in_status(handler.db_path)
    if status == "unusable":
        return False, "The saved network file could not be read."
    if existing is not None and (existing.subnet != subnet or existing.gateway_mac != mac) and not adopt:
        return False, "A different network is already saved. Confirm to replace it."
    try:
        save_opt_in(handler.db_path, NetworkIdentity(subnet, mac))
    except OSError:
        return False, "Could not save the network chosen for watch."
    handler.watch_gateway_mac = mac
    old = getattr(handler, "watcher", None)
    pending = getattr(handler, "watch_pending_seconds", None)
    seconds = pending or (getattr(old, "interval", None) if old is not None else None)
    changed = existing is not None and (existing.subnet != subnet or existing.gateway_mac != mac)
    if old is not None and (changed or getattr(old, "subnet", None) != subnet):
        old.stop()
        handler.watcher = None
    if getattr(handler, "watcher", None) is None and seconds:
        _make_watcher(handler, int(seconds), subnet, mac).start()
        handler.watch_pending_seconds = None
    else:
        handler.watch_note = f"Watching {subnet}."
    if getattr(handler, "watcher", None) is None:
        return True, f"Saved {subnet}. The next start with --watch-saved will scan this network."
    return True, f"Watching {subnet}."


def watch_menu_label(handler) -> str:
    """Tray label. 'instead' is the explicit replace, the same choice as --watch-adopt."""
    from .watch import current_gateway_mac, load_opt_in_status

    subnet = ""
    guess = getattr(handler, "subnet_guess", None)
    if guess is not None:
        try:
            subnet = str(guess.get() or "")
        except Exception:
            subnet = ""
    status, existing = load_opt_in_status(handler.db_path)
    if status == "ok" and existing is not None and subnet:
        mac = current_gateway_mac(subnet)
        if existing.subnet != subnet or (mac and existing.gateway_mac != mac):
            return "Watch this network instead"
    return "Watch this network"


class DashboardOpen:
    """Each open gets a fresh single-use login nonce, never the session token.

    The page POSTs the nonce once and stores the session token in that tab.
    The token stays valid until restart. It is not put in the URL, on the
    browser command line, or in history. Without an exchange (strict auth is
    off and the page already contains the token) the bare address is used.
    """

    def __init__(self, bare: str, exchange: LoginExchange | None = None) -> None:
        self.bare = str(bare).split("#", 1)[0]
        self.exchange = exchange

    def url(self) -> str:
        if self.exchange is None:
            return self.bare
        nonce = self.exchange.mint()
        return f"{self.bare}#login={quote(nonce, safe='-_.~')}"


def _serve_in_tray(server, host: str, port: int, url: str | None) -> None:
    """Run the server on a background thread and a tray icon on this one.

    Returns when the user chooses Quit or the server stops by itself.
    Every open mints a new login nonce when strict auth is on. The session
    token is not placed in the URL.
    """
    from .tray import TrayIcon

    handler = server.RequestHandlerClass
    bare = f"http://{host if host != 'localhost' else '127.0.0.1'}:{port}/"
    if url:
        bare = str(url).split("#", 1)[0]
    exchange = getattr(handler, "login_exchange", None)
    if not isinstance(exchange, LoginExchange):
        exchange = None
    if not getattr(handler, "strict_auth", False):
        exchange = None
    opener = DashboardOpen(bare, exchange)
    requested = threading.Event()  # a Scan now from the tray waits for its result

    def scan_now() -> None:
        allowed, refusal = tray_may_scan(handler)
        if not allowed:
            icon.notify("Lantern", refusal)
            return
        watcher = getattr(handler, "watcher", None)
        subnet = watcher.subnet if watcher else handler.subnet_guess.get()
        if not subnet:
            icon.notify("Lantern", "Could not detect your network. Use the dashboard to pick a subnet.")
            return
        try:
            subnet = str(validate_subnet(subnet))
        except ValueError:
            icon.notify("Lantern", "The detected network is not one Lantern scans.")
            return
        if start_scan_job(handler, subnet):
            requested.set()
            icon.notify("Lantern", f"Scanning {subnet}. This takes about a minute.")
        else:
            icon.notify("Lantern", "A scan is already running.")

    def watch_this() -> None:
        subnet = handler.subnet_guess.get()
        adopt = watch_menu_label(handler).endswith("instead")
        saved, message = apply_watch_opt_in(handler, {"subnet": subnet or "", "adopt": adopt})
        icon.notify("Lantern", message if saved or message else "Could not save that network.")

    note = watch_status_text(handler)
    tooltip = f"Lantern · {note}" if note else (
        f"Lantern dashboard (http://127.0.0.1:{port})" if host in ("127.0.0.1", "localhost")
        else f"Lantern dashboard ({host}:{port})"
    )
    icon = TrayIcon(
        tooltip,
        on_open=lambda: _open_browser(opener.url()),
        on_quit=lambda: threading.Thread(target=server.shutdown, name="lantern-shutdown", daemon=True).start(),
        on_scan=scan_now,
        status=lambda: tray_status_line(handler),
        on_watch=watch_this,
        watch_label=lambda: watch_menu_label(handler),
    )
    if note and not note.lower().startswith("watching"):
        icon.notify("Lantern", note)

    def deliver(alert) -> None:
        requested.clear()
        icon.notify(alert.title, alert.text)

    def after_scan(_scan_id: int) -> None:
        # Runs after the alert listener: a Scan now with nothing new still gets an answer.
        if requested.is_set():
            requested.clear()
            icon.notify("Lantern", "Scan finished. Nothing new.")

    handler.scan_listeners.append(alert_listener(handler.db_path, deliver))
    handler.scan_listeners.append(after_scan)

    def run_server() -> None:
        try:
            server.serve_forever()
        finally:
            icon.stop()  # the server ended on its own: take the icon down too

    thread = threading.Thread(target=run_server, name="lantern-http", daemon=True)
    thread.start()
    try:
        icon.run()
    finally:
        server.shutdown()
        thread.join(timeout=10)


def serve(
    db_path,
    host: str = "127.0.0.1",
    port: int = 8068,
    debug: bool = False,
    allow_hosts: list[str] | None = None,
    api_token: str | None = None,
    lan_bound: bool = False,
    strict_auth: bool = False,
    open_url: str | None = None,
    switches: tuple | None = None,
    fingerprint: bool = True,
    tray: bool = False,
    tray_url: str | None = None,
    watch_seconds: int | None = None,
    watch_subnet: str | None = None,
    watch_gateway_mac: str | None = None,
    watch_note: str | None = None,
    watch_pending_seconds: int | None = None,
    keep_days: float | None = None,
) -> None:
    server = make_server(
        db_path,
        host=host,
        port=port,
        debug=debug,
        allow_hosts=allow_hosts,
        api_token=api_token,
        lan_bound=lan_bound,
        strict_auth=strict_auth,
        switches=switches,
        fingerprint=fingerprint,
        keep_days=keep_days,
    )
    bound_host, bound_port = server.server_address[:2]
    handler = server.RequestHandlerClass
    if not tray:
        # In the tray, alerts are notifications instead (see _serve_in_tray).
        handler.scan_listeners.append(alert_listener(handler.db_path, _print_alert))
    handler.watch_pending_seconds = watch_pending_seconds
    watcher = (
        _make_watcher(handler, watch_seconds, watch_subnet, watch_gateway_mac)
        if watch_seconds and watch_gateway_mac else None
    )
    if watcher is None and watch_note:
        handler.watch_note = watch_note
    # Install the SIGTERM handler before announcing the address: anything
    # that stops Lantern right after it reads the startup line must get a
    # clean shutdown, not the default kill. shutdown() before serve_forever
    # starts is fine: serve_forever then returns at once.
    previous_term = None
    if (
        hasattr(signal, "SIGTERM")
        and threading.current_thread() is threading.main_thread()
    ):
        def _on_sigterm(_signum, _frame):
            # shutdown() must not run on the serve_forever thread.
            threading.Thread(target=server.shutdown, name="lantern-shutdown", daemon=True).start()

        try:
            previous_term = signal.signal(signal.SIGTERM, _on_sigterm)
        except (ValueError, OSError):
            previous_term = None
    try:
        for line in startup_lines(
            str(bound_host),
            int(bound_port),
            lan_bound=bool(handler.lan_bound),
            allowed_hosts=handler.allowed_hosts,
            strict_auth=bool(handler.strict_auth),
        ):
            print(line, flush=True)
        print(f"Database: {db_path}", flush=True)
        if not handler.lan_bound:
            extras = _extra_allowed_hosts(handler.allowed_hosts, int(bound_port))
            if extras:
                print("Additional allowed Host headers: " + ", ".join(extras), flush=True)
        if debug:
            print("Debug request logging on.", flush=True)
        if watcher is not None:
            kept = f"; keeping {keep_days:g} days of scans" if keep_days else ""
            print(f"Watching {watcher.subnet} every {watcher.status()['interval']}{kept}. "
                  "Scheduled scans run only while this gateway is still the one you opted in to.",
                  flush=True)
            watcher.start()
        elif keep_days:
            print(f"Keeping {keep_days:g} days of scans.", flush=True)
        print("Press Ctrl+C to stop.", flush=True)
        if open_url:
            # The socket is already listening, so the browser's first request
            # waits in the backlog until serve_forever starts. Strict auth
            # opens a single-use nonce. The session token is not in the URL.
            _open_browser(_browser_open_url(handler, open_url) or open_url)
        if tray:
            _serve_in_tray(server, str(bound_host), int(bound_port), tray_url)
        else:
            server.serve_forever()
    except KeyboardInterrupt:
        pass
    finally:
        if watcher is not None:
            watcher.stop()
        if previous_term is not None:
            try:
                signal.signal(signal.SIGTERM, previous_term)
            except (ValueError, OSError):
                pass
        server.server_close()

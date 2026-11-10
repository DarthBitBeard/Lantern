"""Name devices from what they announce on the local network: SSDP and mDNS.

Both are ordinary discovery protocols that phones, TVs, printers, speakers,
and smart-home hubs already answer. Lantern asks once per scan and listens
for a few seconds:

* SSDP (UPnP): one M-SEARCH to 239.255.255.250:1900. A reply may name a
  description URL; Lantern fetches that XML only from the device that sent
  the reply, only over plain HTTP on a private address, with a short timeout
  and a 64 KiB cap, and refuses any document with a DTD.
* mDNS (Bonjour): DNS-SD queries to 224.0.0.251:5353, sent from an ordinary
  port. Responders answer such "legacy unicast" queries straight back to
  that port (RFC 6762 section 6.7), so Lantern never binds port 5353, which
  Windows and Bonjour often hold.

Everything a device says about itself is untrusted. Each text value is
stripped of control and format characters and cut to `MAX_TEXT` characters,
and each device keeps at most a few names and service types. Nothing here
logs in, sends credentials, or talks to an address outside the scanned
subnet.
"""

from __future__ import annotations

import ipaddress
import re
import socket
import struct
import time
import unicodedata
import urllib.parse
import xml.etree.ElementTree as ET
from concurrent.futures import ThreadPoolExecutor

SSDP_GROUP = ("239.255.255.250", 1900)
MDNS_GROUP = ("224.0.0.251", 5353)
LISTEN_SECONDS = 2.5
DESCRIPTION_TIMEOUT = 2.0
DESCRIPTION_MAX_BYTES = 64 * 1024
DESCRIPTION_HEADER_MAX = 8 * 1024
DESCRIPTION_DEADLINE = 5.0
DESCRIPTION_WORKERS = 8
MAX_DEVICES = 1024  # same cap as the scan itself
MAX_TEXT = 80
MAX_ITEMS = 8
MAX_PACKET = 9000

# DNS-SD service types worth asking about directly, in addition to the
# meta-query that lists every type a responder offers.
MDNS_SERVICE_TYPES = (
    "_services._dns-sd._udp.local",
    "_device-info._tcp.local",
    "_http._tcp.local",
    "_ipp._tcp.local",
    "_printer._tcp.local",
    "_pdl-datastream._tcp.local",
    "_airplay._tcp.local",
    "_raop._tcp.local",
    "_googlecast._tcp.local",
    "_spotify-connect._tcp.local",
    "_sonos._tcp.local",
    "_hap._tcp.local",
    "_homekit._tcp.local",
    "_smb._tcp.local",
    "_afpovertcp._tcp.local",
    "_companion-link._tcp.local",
    "_sleep-proxy._udp.local",
    "_workstation._tcp.local",
    "_ssh._tcp.local",
    "_rfb._tcp.local",
    "_amzn-wplay._tcp.local",
    "_androidtvremote2._tcp.local",
    "_matter._tcp.local",
)

# TXT keys that carry a model or a friendly name. Everything else in TXT
# records (which can include serial numbers and account ids) is ignored.
_TXT_MODEL_KEYS = ("md", "model", "usb_mdl", "ty", "product", "am")
_TXT_NAME_KEYS = ("fn", "n", "name")

_STRIP_CATEGORIES = {"Cc", "Cf", "Cs", "Co", "Cn", "Zl", "Zp"}


def clean_text(value, limit: int = MAX_TEXT) -> str | None:
    """Untrusted device text made safe to store and show, or None if empty."""
    if value is None:
        return None
    if isinstance(value, bytes):
        value = value.decode("utf-8", "replace")
    text = "".join(
        " " if unicodedata.category(ch) in _STRIP_CATEGORIES else ch
        for ch in str(value)
    )
    text = " ".join(text.split())
    if not text:
        return None
    return text[:limit]


def _add_unique(items: list, value, limit: int = MAX_ITEMS) -> None:
    value = clean_text(value)
    if value and value not in items and len(items) < limit:
        items.append(value)


def empty_identity() -> dict:
    return {
        "name": None,
        "model": None,
        "manufacturer": None,
        "device_type": None,
        "services": [],
        "names": [],
        "sources": [],
    }


def merge_identity(target: dict, update: dict) -> dict:
    """Fold `update` into `target`: first non-empty scalar wins, lists merge."""
    for key in ("name", "model", "manufacturer", "device_type"):
        if not target.get(key) and update.get(key):
            target[key] = clean_text(update[key])
    for key in ("services", "names", "sources"):
        items = target.setdefault(key, [])
        for value in update.get(key) or []:
            _add_unique(items, value)
    return target


def identity_is_empty(identity: dict | None) -> bool:
    if not identity:
        return True
    return not any(identity.get(k) for k in ("name", "model", "manufacturer", "device_type", "services", "names"))


# ---------------------------------------------------------------------------
# SSDP
# ---------------------------------------------------------------------------

SSDP_SEARCH = (
    "M-SEARCH * HTTP/1.1\r\n"
    "HOST: 239.255.255.250:1900\r\n"
    'MAN: "ssdp:discover"\r\n'
    "MX: 2\r\n"
    "ST: ssdp:all\r\n"
    "USER-AGENT: Lantern/1 UPnP/1.1\r\n"
    "\r\n"
).encode("ascii")


def parse_ssdp_response(data: bytes) -> dict[str, str]:
    """Header fields of one SSDP reply, lower-cased names. Empty if not a reply."""
    try:
        text = data[:MAX_PACKET].decode("utf-8", "replace")
    except Exception:
        return {}
    lines = text.split("\r\n") if "\r\n" in text else text.split("\n")
    if not lines or not lines[0].upper().startswith("HTTP/1."):
        return {}
    headers: dict[str, str] = {}
    for line in lines[1:40]:
        if ":" not in line:
            continue
        name, _, value = line.partition(":")
        name = name.strip().lower()
        if name in ("location", "server", "st", "usn", "nt") and name not in headers:
            headers[name] = value.strip()[:512]
    return headers


def _ssdp_type_name(st: str | None) -> str | None:
    """`urn:schemas-upnp-org:device:MediaRenderer:1` -> `MediaRenderer`."""
    if not st or not st.startswith("urn:"):
        return None
    parts = st.split(":")
    if len(parts) >= 5 and parts[2] in ("device", "service"):
        return parts[3]
    return None


def description_url_allowed(location: str, sender_ip: str, network) -> bool:
    """Fetch a description only from the device that replied, over plain HTTP, inside the subnet."""
    try:
        parts = urllib.parse.urlsplit(location)
    except ValueError:
        return False
    if parts.scheme != "http" or not parts.hostname:
        return False
    try:
        host = ipaddress.IPv4Address(parts.hostname)
    except ValueError:
        return False
    if str(host) != sender_ip:
        return False
    if network is not None and host not in network:
        return False
    try:
        port = parts.port or 80
    except ValueError:
        return False
    return 1 <= port <= 65535


_DTD_RE = re.compile(rb"<!\s*(DOCTYPE|ENTITY)", re.IGNORECASE)


def parse_description(xml_bytes: bytes) -> dict:
    """friendlyName, manufacturer, modelName, and deviceType from a UPnP description."""
    if not xml_bytes or len(xml_bytes) > DESCRIPTION_MAX_BYTES or _DTD_RE.search(xml_bytes):
        return {}
    try:
        root = ET.fromstring(xml_bytes)
    except ET.ParseError:
        return {}
    found: dict[str, str] = {}
    for element in root.iter():
        tag = element.tag.rsplit("}", 1)[-1]
        if tag in ("friendlyName", "manufacturer", "modelName", "deviceType") and tag not in found:
            value = clean_text(element.text)
            if value:
                found[tag] = value
    result = {}
    if "friendlyName" in found:
        result["name"] = found["friendlyName"]
    if "manufacturer" in found:
        result["manufacturer"] = found["manufacturer"]
    if "modelName" in found:
        result["model"] = found["modelName"]
    if "deviceType" in found:
        result["device_type"] = _ssdp_type_name(found["deviceType"]) or found["deviceType"]
    return result


def _deadline_left(started: float) -> float:
    return DESCRIPTION_DEADLINE - (time.monotonic() - started)


def _io_timeout(started: float, timeout: float) -> float | None:
    """Per-read cap, and never longer than the time left on the deadline."""
    remaining = _deadline_left(started)
    if remaining <= 0:
        return None
    return min(float(timeout), remaining)


def _recv_some(sock: socket.socket, started: float, limit: int, timeout: float) -> bytes | None:
    """One read of the status line, a header, or the body."""
    wait = _io_timeout(started, timeout)
    if wait is None or limit <= 0:
        return None
    sock.settimeout(wait)
    try:
        return sock.recv(limit)
    except (TimeoutError, socket.timeout, OSError):
        return None


def _send_all(sock: socket.socket, payload: bytes, started: float, timeout: float) -> bool:
    view = memoryview(payload)
    while view:
        wait = _io_timeout(started, timeout)
        if wait is None:
            return False
        sock.settimeout(wait)
        try:
            sent = sock.send(view)
        except (TimeoutError, socket.timeout, OSError):
            return False
        if sent <= 0:
            return False
        view = view[sent:]
    return True


def _http_headers(head: bytes) -> tuple[bytes, dict[bytes, bytes]] | None:
    lines = head.split(b"\r\n")
    if not lines or not lines[0]:
        return None
    headers: dict[bytes, bytes] = {}
    for line in lines[1:]:
        if not line or b":" not in line:
            return None
        name, value = line.split(b":", 1)
        headers[name.strip().lower()] = value.strip()
    return lines[0], headers


def fetch_description(location: str, timeout: float = DESCRIPTION_TIMEOUT) -> bytes:
    """GET one description document. Returns b"" on any failure or oversize body.

    The request is raw HTTP/1.0. ``timeout`` caps the connect and every later
    read and write. The status line, headers, and body also share
    ``DESCRIPTION_DEADLINE``: each wait is the shorter of ``timeout`` and the
    time still left. A stalled read returns b"", not the bytes gathered so
    far. Headers stop at ``DESCRIPTION_HEADER_MAX``. A chunked response is
    refused. A Content-Length above ``DESCRIPTION_MAX_BYTES`` (64 KiB) is
    refused; a body of exactly that size is kept.
    """
    parts = urllib.parse.urlsplit(location)
    if parts.scheme not in ("http", ""):
        return b""
    host = parts.hostname
    if not host:
        return b""
    port = parts.port or 80
    path = parts.path or "/"
    if parts.query:
        path = path + "?" + parts.query
    if any(char in path or char in host for char in "\r\n"):
        return b""
    host_header = host if port == 80 else f"{host}:{port}"
    if ":" in host and not host.startswith("["):
        host_header = f"[{host}]" if port == 80 else f"[{host}]:{port}"
    try:
        request = (
            f"GET {path} HTTP/1.0\r\n"
            f"Host: {host_header}\r\n"
            "User-Agent: Lantern/1\r\n"
            "Connection: close\r\n"
            "\r\n"
        ).encode("ascii")
    except UnicodeEncodeError:
        return b""
    started = time.monotonic()
    try:
        sock = socket.create_connection((host, port), timeout=timeout)
    except OSError:
        return b""
    try:
        if not _send_all(sock, request, started, timeout):
            return b""
        buf = bytearray()
        while b"\r\n\r\n" not in buf:
            if len(buf) >= DESCRIPTION_HEADER_MAX:
                return b""
            piece = _recv_some(sock, started, DESCRIPTION_HEADER_MAX - len(buf), timeout)
            if not piece:
                return b""
            buf += piece
        marker = buf.find(b"\r\n\r\n")
        if marker > DESCRIPTION_HEADER_MAX:
            return b""
        parsed = _http_headers(bytes(buf[:marker]))
        if parsed is None:
            return b""
        status, headers = parsed
        parts_status = status.split(b" ", 2)
        if len(parts_status) < 2 or parts_status[1] != b"200":
            return b""
        encoding = headers.get(b"transfer-encoding", b"")
        if b"chunked" in encoding.lower():
            return b""
        declared = headers.get(b"content-length")
        if declared is None:
            want = DESCRIPTION_MAX_BYTES
        elif declared.isdigit():
            want = int(declared)
            if want > DESCRIPTION_MAX_BYTES:
                return b""
        else:
            return b""
        body = bytearray(buf[marker + 4:])
        while len(body) < want:
            piece = _recv_some(sock, started, min(4096, want - len(body)), timeout)
            if piece is None:
                return b""
            if not piece:
                break
            body += piece
        return b"" if len(body) > DESCRIPTION_MAX_BYTES else bytes(body)
    except Exception:
        return b""
    finally:
        sock.close()


def _collect(sock: socket.socket, seconds: float) -> list[tuple[bytes, str]]:
    replies: list[tuple[bytes, str]] = []
    deadline = time.monotonic() + seconds
    while len(replies) < 4 * MAX_DEVICES:
        left = deadline - time.monotonic()
        if left <= 0:
            break
        sock.settimeout(left)
        try:
            data, addr = sock.recvfrom(MAX_PACKET)
        except socket.timeout:
            break
        except OSError:
            break
        replies.append((data, addr[0]))
    return replies


def _multicast_socket(local_ip: str | None) -> socket.socket:
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
    sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_TTL, 1)
    if local_ip:
        try:
            sock.setsockopt(socket.IPPROTO_IP, socket.IP_MULTICAST_IF, socket.inet_aton(local_ip))
        except OSError:
            pass
    sock.bind((local_ip or "", 0))
    return sock


def ssdp_identities(network, local_ip: str | None, seconds: float = LISTEN_SECONDS) -> dict[str, dict]:
    """{ip: identity} for devices in `network` that answer an SSDP search."""
    try:
        sock = _multicast_socket(local_ip)
    except OSError:
        return {}
    try:
        try:
            sock.sendto(SSDP_SEARCH, SSDP_GROUP)
        except OSError:
            return {}
        replies = _collect(sock, seconds)
    finally:
        sock.close()

    results: dict[str, dict] = {}
    locations: dict[str, str] = {}
    for data, sender in replies:
        if not _in_network(sender, network):
            continue
        headers = parse_ssdp_response(data)
        if not headers:
            continue
        identity = results.setdefault(sender, empty_identity())
        if len(results) > MAX_DEVICES:
            results.pop(sender)
            break
        _add_unique(identity["sources"], "ssdp")
        type_name = _ssdp_type_name(headers.get("st") or headers.get("nt"))
        if type_name:
            _add_unique(identity["services"], f"upnp:{type_name}")
        location = headers.get("location")
        if location and sender not in locations and description_url_allowed(location, sender, network):
            locations[sender] = location

    if locations:
        with ThreadPoolExecutor(max_workers=DESCRIPTION_WORKERS) as pool:
            bodies = dict(zip(locations, pool.map(fetch_description, locations.values())))
        for sender, body in bodies.items():
            merge_identity(results[sender], parse_description(body))
    return results


# ---------------------------------------------------------------------------
# mDNS / DNS-SD
# ---------------------------------------------------------------------------

_TYPE_A, _TYPE_PTR, _TYPE_TXT, _TYPE_SRV = 1, 12, 16, 33
_MAX_POINTER_JUMPS = 16
_MAX_RECORDS = 256


def _encode_name(name: str) -> bytes:
    out = b""
    for label in name.strip(".").split("."):
        raw = label.encode("utf-8")
        if not raw or len(raw) > 63:
            raise ValueError("bad DNS label")
        out += bytes([len(raw)]) + raw
    return out + b"\x00"


def build_mdns_query(names, query_id: int = 0x4C41) -> bytes:
    """One DNS query packet asking PTR for each name (legacy unicast: non-zero id)."""
    names = list(names)
    header = struct.pack("!HHHHHH", query_id, 0, len(names), 0, 0, 0)
    body = b"".join(_encode_name(n) + struct.pack("!HH", _TYPE_PTR, 1) for n in names)
    return header + body


def _read_name(packet: bytes, offset: int) -> tuple[str, int]:
    """Decode a possibly compressed name. Returns (name, offset after it in place)."""
    labels: list[str] = []
    jumps = 0
    end_offset = None
    total = 0
    while True:
        if offset >= len(packet):
            raise ValueError("name past end")
        length = packet[offset]
        if length == 0:
            offset += 1
            break
        if length & 0xC0 == 0xC0:
            if offset + 1 >= len(packet):
                raise ValueError("pointer past end")
            pointer = ((length & 0x3F) << 8) | packet[offset + 1]
            if end_offset is None:
                end_offset = offset + 2
            jumps += 1
            if jumps > _MAX_POINTER_JUMPS or pointer >= len(packet):
                raise ValueError("bad pointer")
            offset = pointer
            continue
        if length & 0xC0:
            raise ValueError("reserved label type")
        offset += 1
        if offset + length > len(packet):
            raise ValueError("label past end")
        labels.append(packet[offset:offset + length].decode("utf-8", "replace"))
        total += length + 1
        if total > 255:
            raise ValueError("name too long")
        offset += length
    return ".".join(labels), (end_offset if end_offset is not None else offset)


def parse_mdns_packet(packet: bytes) -> list[dict]:
    """Records in a DNS reply as dicts: {name, type, data}. Malformed input gives []."""
    if len(packet) < 12 or len(packet) > MAX_PACKET:
        return []
    try:
        _id, flags, qd, an, ns, ar = struct.unpack("!HHHHHH", packet[:12])
        if not flags & 0x8000:  # not a response
            return []
        offset = 12
        for _ in range(qd):
            _, offset = _read_name(packet, offset)
            offset += 4
        records = []
        for _ in range(min(an + ns + ar, _MAX_RECORDS)):
            name, offset = _read_name(packet, offset)
            if offset + 10 > len(packet):
                break
            rtype, _rclass, _ttl, rdlength = struct.unpack("!HHIH", packet[offset:offset + 10])
            offset += 10
            rdata_start = offset
            offset += rdlength
            if offset > len(packet):
                break
            record = {"name": name, "type": rtype, "data": None}
            if rtype == _TYPE_PTR:
                record["data"], _ = _read_name(packet, rdata_start)
            elif rtype == _TYPE_SRV and rdlength >= 7:
                target, _ = _read_name(packet, rdata_start + 6)
                record["data"] = target
            elif rtype == _TYPE_A and rdlength == 4:
                record["data"] = socket.inet_ntoa(packet[rdata_start:rdata_start + 4])
            elif rtype == _TYPE_TXT:
                record["data"] = _parse_txt(packet[rdata_start:offset])
            records.append(record)
        return records
    except (ValueError, struct.error, IndexError):
        return []


def _parse_txt(rdata: bytes) -> dict[str, str]:
    values: dict[str, str] = {}
    offset = 0
    while offset < len(rdata) and len(values) < 32:
        length = rdata[offset]
        offset += 1
        item = rdata[offset:offset + length]
        offset += length
        key, sep, value = item.partition(b"=")
        key_text = key.decode("ascii", "replace").lower()
        if sep and key_text in _TXT_MODEL_KEYS + _TXT_NAME_KEYS and key_text not in values:
            cleaned = clean_text(value)
            if cleaned:
                values[key_text] = cleaned
    return values


def _service_type(name: str) -> str | None:
    """`Kitchen._googlecast._tcp.local` -> `_googlecast._tcp`."""
    labels = name.split(".")
    for i in range(len(labels) - 2):
        if labels[i].startswith("_") and labels[i + 1] in ("_tcp", "_udp"):
            return f"{labels[i]}.{labels[i + 1]}"
    return None


def _instance_name(name: str) -> str | None:
    service = _service_type(name)
    if not service:
        return None
    head = name.split("." + service, 1)[0]
    return head if head and not head.startswith("_") else None


def identity_from_mdns(records: list[dict]) -> dict:
    identity = empty_identity()
    _add_unique(identity["sources"], "mdns")
    for record in records:
        rtype, name, data = record["type"], record["name"], record["data"]
        if rtype == _TYPE_PTR and isinstance(data, str):
            if name == "_services._dns-sd._udp.local":
                service = _service_type(data + ".local") or _service_type(data)
                if service:
                    _add_unique(identity["services"], service)
                continue
            service = _service_type(name)
            if service:
                _add_unique(identity["services"], service)
            instance = _instance_name(data)
            if instance:
                _add_unique(identity["names"], instance)
        elif rtype in (_TYPE_SRV, _TYPE_TXT):
            service = _service_type(name)
            if service:
                _add_unique(identity["services"], service)
            instance = _instance_name(name)
            if instance:
                _add_unique(identity["names"], instance)
            if rtype == _TYPE_TXT and isinstance(data, dict):
                for key in _TXT_NAME_KEYS:
                    if data.get(key) and not identity["name"]:
                        identity["name"] = data[key]
                for key in _TXT_MODEL_KEYS:
                    if data.get(key) and not identity["model"]:
                        # Printers often send ty=(Brand Model).
                        identity["model"] = clean_text(data[key].strip("()")) or data[key]
    if not identity["name"] and identity["names"]:
        identity["name"] = identity["names"][0]
    return identity


def mdns_identities(network, local_ip: str | None, seconds: float = LISTEN_SECONDS) -> dict[str, dict]:
    """{ip: identity} for devices in `network` that answer DNS-SD queries."""
    try:
        sock = _multicast_socket(local_ip)
    except OSError:
        return {}
    try:
        try:
            # A packet holds the meta-query plus the common types.
            sock.sendto(build_mdns_query(MDNS_SERVICE_TYPES), MDNS_GROUP)
        except (OSError, ValueError):
            return {}
        replies = _collect(sock, seconds)
    finally:
        sock.close()

    by_sender: dict[str, list[dict]] = {}
    for data, sender in replies:
        if not _in_network(sender, network):
            continue
        records = parse_mdns_packet(data)
        if records and (sender in by_sender or len(by_sender) < MAX_DEVICES):
            by_sender.setdefault(sender, []).extend(records[:_MAX_RECORDS])
    return {ip: identity_from_mdns(records) for ip, records in by_sender.items()}


def _in_network(ip: str, network) -> bool:
    try:
        address = ipaddress.IPv4Address(ip)
    except ValueError:
        return False
    return network is None or address in network


def discover_identities(network, local_ip: str | None = None, seconds: float = LISTEN_SECONDS) -> dict[str, dict]:
    """SSDP and mDNS together, run side by side. Never raises; {} when nothing answers."""
    try:
        with ThreadPoolExecutor(max_workers=2) as pool:
            ssdp_future = pool.submit(ssdp_identities, network, local_ip, seconds)
            mdns_future = pool.submit(mdns_identities, network, local_ip, seconds)
            ssdp, mdns = ssdp_future.result(), mdns_future.result()
    except Exception:
        return {}
    merged: dict[str, dict] = {}
    for source in (mdns, ssdp):
        for ip, identity in source.items():
            merge_identity(merged.setdefault(ip, empty_identity()), identity)
    return {ip: identity for ip, identity in merged.items() if not identity_is_empty(identity)}

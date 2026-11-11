"""A small, read-only SNMPv2c client in the standard library.

Lantern uses it only to ask managed switches who is plugged in where (see
`topology.py`). It can send GetRequest, GetNextRequest, and GetBulkRequest,
and nothing else: there is no SetRequest encoder, so it cannot change a
device. SNMPv3 is not supported, because its privacy mode needs AES and the
standard library has no AES.

Every reply is parsed with bounds checks: lengths must fit inside their
parent, long-form lengths are at most 4 bytes, OIDs are at most 128
sub-identifiers, and a walk stops at the end of its subtree, at
endOfMibView, when an OID does not increase, at a row cap, or at a deadline.
A malformed reply raises `SnmpError` and is never partly used.
"""

from __future__ import annotations

import inspect
import secrets
import socket
import time

SNMP_PORT = 161
VERSION_2C = 1
TIMEOUT = 2.0
RETRIES = 1
MAX_REPETITIONS = 25
MAX_ROWS = 20_000
MAX_OID_PARTS = 128
MAX_DATAGRAM = 65_535

# BER tags.
INTEGER = 0x02
OCTET_STRING = 0x04
NULL = 0x05
OBJECT_ID = 0x06
SEQUENCE = 0x30
IP_ADDRESS = 0x40
COUNTER32 = 0x41
GAUGE32 = 0x42
TIMETICKS = 0x43
OPAQUE = 0x44
COUNTER64 = 0x46
NO_SUCH_OBJECT = 0x80
NO_SUCH_INSTANCE = 0x81
END_OF_MIB_VIEW = 0x82

GET = 0xA0
GET_NEXT = 0xA1
RESPONSE = 0xA2
GET_BULK = 0xA5
_REQUESTS = (GET, GET_NEXT, GET_BULK)


class SnmpError(Exception):
    """A timeout, an error-status reply, or a malformed packet."""


class _Missing:
    """noSuchObject, noSuchInstance, or endOfMibView in a varbind."""

    __slots__ = ("tag",)

    def __init__(self, tag: int):
        self.tag = tag

    def __repr__(self) -> str:
        return {NO_SUCH_OBJECT: "noSuchObject", NO_SUCH_INSTANCE: "noSuchInstance",
                END_OF_MIB_VIEW: "endOfMibView"}.get(self.tag, "missing")


def parse_oid(text: str | tuple) -> tuple[int, ...]:
    if isinstance(text, tuple):
        return text
    parts = tuple(int(part) for part in str(text).strip(".").split("."))
    if len(parts) < 2 or any(part < 0 for part in parts):
        raise ValueError(f"bad OID {text!r}")
    return parts


def oid_text(oid: tuple[int, ...]) -> str:
    return ".".join(str(part) for part in oid)


# ---------------------------------------------------------------------------
# Encoding
# ---------------------------------------------------------------------------

def _length(n: int) -> bytes:
    if n < 0x80:
        return bytes([n])
    body = n.to_bytes((n.bit_length() + 7) // 8, "big")
    return bytes([0x80 | len(body)]) + body


def _tlv(tag: int, body: bytes) -> bytes:
    return bytes([tag]) + _length(len(body)) + body


def _integer(value: int) -> bytes:
    size = max(1, (value.bit_length() + 8) // 8)
    return _tlv(INTEGER, value.to_bytes(size, "big", signed=True))


def _encode_oid(oid: tuple[int, ...]) -> bytes:
    if len(oid) < 2 or oid[0] > 2 or (oid[0] < 2 and oid[1] >= 40):
        raise ValueError(f"bad OID {oid!r}")
    out = bytearray()
    for part in (oid[0] * 40 + oid[1],) + tuple(oid[2:]):
        if part < 0:
            raise ValueError(f"bad OID {oid!r}")
        chunk = [part & 0x7F]
        part >>= 7
        while part:
            chunk.append(0x80 | (part & 0x7F))
            part >>= 7
        out.extend(reversed(chunk))
    return _tlv(OBJECT_ID, bytes(out))


def encode_request(pdu: int, request_id: int, community: bytes, oids,
                   non_repeaters: int = 0, max_repetitions: int = 0) -> bytes:
    """One SNMPv2c request message. Only read requests can be built."""
    if pdu not in _REQUESTS:
        raise ValueError("only Get, GetNext, and GetBulk requests are supported")
    varbinds = b"".join(_tlv(SEQUENCE, _encode_oid(parse_oid(oid)) + _tlv(NULL, b"")) for oid in oids)
    if pdu == GET_BULK:
        second, third = non_repeaters, max_repetitions
    else:
        second, third = 0, 0
    body = _integer(request_id) + _integer(second) + _integer(third) + _tlv(SEQUENCE, varbinds)
    return _tlv(SEQUENCE, _integer(VERSION_2C) + _tlv(OCTET_STRING, community) + _tlv(pdu, body))


# ---------------------------------------------------------------------------
# Decoding
# ---------------------------------------------------------------------------

def _read(data: bytes, pos: int, end: int) -> tuple[int, int, int]:
    """Return (tag, body_start, body_end) of the TLV at `pos`, inside [pos, end)."""
    if pos + 2 > end:
        raise SnmpError("truncated packet")
    tag = data[pos]
    first = data[pos + 1]
    pos += 2
    if first < 0x80:
        length = first
    else:
        count = first & 0x7F
        if count == 0 or count > 4:
            raise SnmpError("unsupported length encoding")
        if pos + count > end:
            raise SnmpError("truncated length")
        length = int.from_bytes(data[pos:pos + count], "big")
        pos += count
    if pos + length > end:
        raise SnmpError("length runs past its container")
    return tag, pos, pos + length


def _expect(data: bytes, pos: int, end: int, tag: int) -> tuple[int, int]:
    found, start, stop = _read(data, pos, end)
    if found != tag:
        raise SnmpError(f"expected tag 0x{tag:02x}, got 0x{found:02x}")
    return start, stop


def _decode_int(body: bytes) -> int:
    if not body or len(body) > 9:
        raise SnmpError("bad integer")
    return int.from_bytes(body, "big", signed=True)


def _decode_unsigned(body: bytes) -> int:
    if not body or len(body) > 9:
        raise SnmpError("bad unsigned integer")
    return int.from_bytes(body, "big", signed=False)


def decode_oid(body: bytes) -> tuple[int, ...]:
    if not body:
        raise SnmpError("empty OID")
    parts: list[int] = []
    value = 0
    for byte in body:
        value = (value << 7) | (byte & 0x7F)
        if value >= 2 ** 32:
            raise SnmpError("OID part too large")
        if not byte & 0x80:
            parts.append(value)
            value = 0
            if len(parts) > MAX_OID_PARTS:
                raise SnmpError("OID too long")
    if body[-1] & 0x80:
        raise SnmpError("truncated OID")
    first = parts[0]
    head = (0, first) if first < 40 else ((1, first - 40) if first < 80 else (2, first - 80))
    return head + tuple(parts[1:])


def _decode_value(tag: int, body: bytes):
    if tag == INTEGER:
        return _decode_int(body)
    if tag in (OCTET_STRING, OPAQUE):
        return bytes(body)
    if tag == NULL:
        return None
    if tag == OBJECT_ID:
        return decode_oid(body)
    if tag == IP_ADDRESS:
        if len(body) != 4:
            raise SnmpError("bad IpAddress")
        return ".".join(str(b) for b in body)
    if tag in (COUNTER32, GAUGE32, TIMETICKS, COUNTER64):
        return _decode_unsigned(body)
    if tag in (NO_SUCH_OBJECT, NO_SUCH_INSTANCE, END_OF_MIB_VIEW):
        return _Missing(tag)
    raise SnmpError(f"unsupported value type 0x{tag:02x}")


def decode_response(data: bytes) -> tuple[int, int, int, list[tuple[tuple[int, ...], object]]]:
    """Return (request_id, error_status, error_index, varbinds) of a Response PDU."""
    start, stop = _expect(data, 0, len(data), SEQUENCE)
    if stop != len(data):
        raise SnmpError("trailing bytes after the message")
    pos = start
    tag, a, b = _read(data, pos, stop)
    if tag != INTEGER or _decode_int(data[a:b]) != VERSION_2C:
        raise SnmpError("not an SNMPv2c reply")
    pos = b
    a, b = _expect(data, pos, stop, OCTET_STRING)
    pos = b
    tag, pdu_start, pdu_stop = _read(data, pos, stop)
    if tag != RESPONSE:
        raise SnmpError("not a Response PDU")
    pos = pdu_start
    numbers = []
    for _ in range(3):
        a, b = _expect(data, pos, pdu_stop, INTEGER)
        numbers.append(_decode_int(data[a:b]))
        pos = b
    list_start, list_stop = _expect(data, pos, pdu_stop, SEQUENCE)
    varbinds = []
    pos = list_start
    while pos < list_stop:
        vb_start, vb_stop = _expect(data, pos, list_stop, SEQUENCE)
        a, b = _expect(data, vb_start, vb_stop, OBJECT_ID)
        oid = decode_oid(data[a:b])
        tag, c, d = _read(data, b, vb_stop)
        if d != vb_stop:
            raise SnmpError("extra data in a varbind")
        varbinds.append((oid, _decode_value(tag, data[c:d])))
        pos = vb_stop
    return numbers[0], numbers[1], numbers[2], varbinds


# ---------------------------------------------------------------------------
# Client
# ---------------------------------------------------------------------------

def udp_transport(host: str, port: int, timeout: float):
    """Send one datagram and return replies from that host until a deadline.

    The socket is connected, so the OS drops datagrams from any other
    address or port.
    """
    def exchange(packet: bytes, accept, timeout_override: float | None = None) -> bytes:
        limit = timeout if timeout_override is None else timeout_override
        with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as sock:
            sock.connect((host, port))
            sock.send(packet)
            deadline = time.monotonic() + limit
            while True:
                left = deadline - time.monotonic()
                if left <= 0:
                    raise SnmpError("timed out")
                sock.settimeout(left)
                try:
                    reply = sock.recv(MAX_DATAGRAM)
                except socket.timeout as exc:
                    raise SnmpError("timed out") from exc
                except OSError as exc:
                    # ICMP port unreachable surfaces as ConnectionRefusedError.
                    raise SnmpError("no SNMP agent answered") from exc
                if accept(reply):
                    return reply
    return exchange


class Client:
    """Read-only SNMPv2c requests to one agent."""

    def __init__(self, host: str, community: str, *, port: int = SNMP_PORT,
                 timeout: float = TIMEOUT, retries: int = RETRIES, transport=None):
        self.host = host
        self.community = community.encode("utf-8")
        self.timeout = timeout
        self.retries = retries
        self.transport = transport or udp_transport(host, port, timeout)

    def _exchange(self, packet: bytes, accept, timeout: float):
        """Call the transport. A third argument is the remaining budget.

        Transports written before the budget was passed take two arguments
        and keep their own timeout.
        """
        params = inspect.signature(self.transport).parameters
        if len(params) >= 3 or any(
            item.kind is inspect.Parameter.VAR_POSITIONAL for item in params.values()
        ):
            return self.transport(packet, accept, timeout)
        return self.transport(packet, accept)

    def _request(self, pdu: int, oids, max_repetitions: int = 0, deadline: float | None = None):
        last: Exception | None = None
        for _ in range(self.retries + 1):
            if deadline is not None:
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    raise last or SnmpError("timed out")
                timeout = min(self.timeout, remaining)
            else:
                timeout = self.timeout
            request_id = secrets.randbelow(2 ** 31 - 1) + 1
            packet = encode_request(pdu, request_id, self.community, oids,
                                    max_repetitions=max_repetitions)
            decoded = {}

            def accept(reply: bytes, request_id=request_id, decoded=decoded) -> bool:
                # Ignore late replies to an earlier attempt, and garbage.
                try:
                    found = decode_response(reply)
                except SnmpError:
                    return False
                if found[0] != request_id:
                    return False
                decoded["reply"] = found
                return True

            try:
                self._exchange(packet, accept, timeout)
            except SnmpError as exc:
                last = exc
                continue
            _rid, status, _index, varbinds = decoded["reply"]
            if status:
                raise SnmpError(f"agent returned error-status {status}")
            return varbinds
        raise last or SnmpError("no reply")

    def get(self, oids, *, deadline: float | None = None) -> dict:
        """Values by OID; objects the agent does not have are left out."""
        wanted = [parse_oid(oid) for oid in oids]
        found = {}
        for oid, value in self._request(GET, wanted, deadline=deadline):
            if not isinstance(value, _Missing):
                found[oid] = value
        return found

    def walk(self, base, *, max_rows: int = MAX_ROWS, deadline: float | None = None) -> list:
        """Every (oid, value) under `base`, in order, using GetBulk."""
        base = parse_oid(base)
        rows: list = []
        current = base
        while True:
            if deadline is not None and time.monotonic() > deadline:
                raise SnmpError("walk took too long")
            varbinds = self._request(GET_BULK, [current], MAX_REPETITIONS, deadline=deadline)
            if not varbinds:
                return rows
            for oid, value in varbinds:
                if isinstance(value, _Missing) or oid[:len(base)] != base:
                    return rows
                if oid <= current:
                    raise SnmpError("agent returned OIDs out of order")
                rows.append((oid, value))
                if len(rows) >= max_rows:
                    return rows
                current = oid

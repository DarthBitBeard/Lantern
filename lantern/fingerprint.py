"""Passive banner parsers. No sockets, no regex, and no format strings.

A fingerprint is what the service says about itself. It can be wrong.
This module does not read the network and does not store anything.
"""

from __future__ import annotations

from dataclasses import dataclass

# Applied to the bytes before they are decoded.
_READ_CAP = {"ssh": 256, "ftp": 256, "smtp": 256, "http": 2048}
PRODUCT_CAP = 40
VERSION_CAP = 64
RAW_CAP = 120
_VERSION_CHARS = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._+~-")
# Letters, digits, dot, underscore, plus, hyphen. The first character must be alphanumeric.
_PRODUCT_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789._+-")
_PRODUCTS = {
    "ftp": ("vsFTPd", "ProFTPD", "Pure-FTPd"),
    "smtp": ("Postfix", "Exim", "Sendmail"),
}
_LINE_CAP = 64
_TOKEN_CAP = 8


@dataclass(frozen=True)
class Fingerprint:
    service: str
    product: str | None
    version: str | None
    parse_status: str
    raw: str


def _sanitise(text: str) -> str:
    """ASCII 0x20–0x7E only. Anything else, including U+FFFD, becomes ``?``."""
    out: list[str] = []
    spaced = False
    for char in text:
        char = char if " " <= char <= "~" else "?"
        if char == " ":
            if spaced:
                continue
            spaced = True
        else:
            spaced = False
        out.append(char)
    return "".join(out).strip()


def _first_line(text: str) -> str:
    line = text.partition("\n")[0]
    if line.endswith("\r"):
        line = line[:-1]
    return line


def _header_lines(text: str, limit: int) -> list[str]:
    """Status line and headers. Stops at the first empty line or at ``limit`` lines."""
    found = []
    rest = text
    while rest and len(found) < limit:
        line, sep, rest = rest.partition("\n")
        if line.endswith("\r"):
            line = line[:-1]
        if line == "":
            break
        found.append(line)
        if not sep:
            break
    return found


def _tokens(text: str) -> list[str]:
    return text.split(None, _TOKEN_CAP)


def _strip_ends(token: str) -> str:
    while token and token[0] in "()?":
        token = token[1:]
    while token and token[-1] in "()?":
        token = token[:-1]
    return token


def _version(value: str | None) -> str | None:
    """A version is digits and ``._+~-``. ``?`` is not a version character.

    Sendmail writes ``8.15.2/8.15.2``. The part before ``/`` is the version.
    """
    if value and "/" in value:
        value = value.split("/", 1)[0]
    if not value or len(value) > VERSION_CAP or not value[0].isdigit():
        return None
    for char in value:
        if char not in _VERSION_CHARS:
            return None
    return value


def _product(value: str | None) -> str | None:
    """A strict name of at most 40 characters, or None.

    A longer name is dropped. It is not shortened into a different name.
    """
    if not value or len(value) > PRODUCT_CAP or not value[0].isalnum():
        return None
    for char in value:
        if char not in _PRODUCT_CHARS:
            return None
    return value


def _result(service: str, product: str | None, version: str | None, raw: str) -> Fingerprint:
    product = _product(product)
    version = _version(version) if product else None
    status = "ok" if product and version else "unknown"
    return Fingerprint(service, product, version, status, raw[:RAW_CAP])


def _rejected(service: str, raw: str) -> Fingerprint:
    return Fingerprint(service, None, None, "rejected", raw[:RAW_CAP])


def parse(service_hint: str, raw: bytes) -> Fingerprint | None:
    """Read one banner. Empty input and an unknown hint return None.

    Bytes past the protocol cap are dropped before decode. The text is ASCII
    with ``errors="replace"``, then anything outside 0x20–0x7E becomes ``?``.
    ``raw`` must be bytes. A ``str`` raises ``TypeError``.
    """
    if not isinstance(raw, (bytes, bytearray)):
        raise TypeError("a banner is bytes")
    cap = _READ_CAP.get(service_hint)
    if cap is None or not raw:
        return None
    text = raw[:cap].decode("ascii", errors="replace")
    if service_hint == "ssh":
        line = _sanitise(_first_line(text))
        if not line.startswith("SSH-"):
            return _rejected("ssh", line)
        head = _tokens(line)[0] if _tokens(line) else ""
        parts = head.split("-", 2)
        if len(parts) < 3 or parts[1] not in ("2.0", "1.99") or not parts[2]:
            return _rejected("ssh", line)
        name, separator, version = parts[2].partition("_")
        return _result("ssh", name, version if separator else None, line)
    if service_hint == "http":
        lines = _header_lines(text, _LINE_CAP)
        value = ""
        for line in lines[1:]:
            if line[:7].lower() == "server:":
                value = _sanitise(line[7:])
                break
        tokens = _tokens(value)
        if not tokens:
            return _result("http", None, None, value)
        name, slash, version = tokens[0].partition("/")
        return _result("http", name or None, version if slash else None, value)
    line = _sanitise(_first_line(text))
    greeting = _tokens(line)
    if not greeting or greeting[0] != "220":
        return _rejected(service_hint, line)
    tokens = [_strip_ends(token) for token in _tokens(line)]
    table = _PRODUCTS[service_hint]
    for index, token in enumerate(tokens):
        if token in table:
            version = tokens[index + 1] if index + 1 < len(tokens) else None
            return _result(service_hint, token, version, line)
    return _result(service_hint, None, None, line)

"""Passive service fingerprints from banners the host already sent.

The parsers are pure: no sockets, no regex, and no use of banner text as
a format string. A fingerprint is a best-effort reading of one greeting.
It is not a vulnerability check.
"""

from __future__ import annotations

from .assets import strip_for_text

# Byte caps applied before decode. HTTP is larger because Server is not on line 1.
READ_CAP = {"ssh": 256, "ftp": 256, "smtp": 256, "http": 2048}
PRODUCT_CAP = 40
VERSION_CAP = 64
RAW_CAP = 120
_VERSION_CHARS = set("0123456789abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ._+~-")
# Letters, digits, and a few separators. A name must start with a letter or digit.
_PRODUCT_CHARS = set("abcdefghijklmnopqrstuvwxyzABCDEFGHIJKLMNOPQRSTUVWXYZ0123456789 ._-+/")
_PRODUCT_TABLE = {"ftp": ("vsFTPd", "ProFTPD"), "smtp": ("Postfix", "Exim")}
_STATUSES = ("ok", "unknown", "rejected")


def sanitise(text: str) -> str:
    """Keep ASCII 0x20–0x7E. Everything else, including U+FFFD, becomes ``?``."""
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


def _version(value: str | None) -> str | None:
    if not value or len(value) > VERSION_CAP or not value[0].isdigit():
        return None
    if any(char not in _VERSION_CHARS for char in value):
        return None
    return value


def _screen_product(value: str | None) -> tuple[str | None, str | None]:
    """Return ``(name, None)`` or ``(None, reason)``.

    A missing name is incomplete, not rejected. A name that is present but
    uses any other character is rejected, including characters that would
    otherwise be cut off by the length cap.
    """
    if not value:
        return None, None
    if not value[0].isalnum() or any(char not in _PRODUCT_CHARS for char in value):
        return None, "unsafe product"
    return value[:PRODUCT_CAP], None


def _accepted(service: str, product: str | None, version: str | None, raw: str) -> dict:
    product, reject_reason = _screen_product(product)
    if reject_reason:
        return _rejected(reject_reason)
    version = _version(version) if product else None
    status = "ok" if product and version else "unknown"
    return {
        "accepted": True,
        "service": service,
        "product": product,
        "version": version,
        "parse_status": status,
        "raw": raw[:RAW_CAP],
    }


def _rejected(reason: str) -> dict:
    return {"accepted": False, "reason": reason}


def parse_banner(protocol: str, raw: bytes) -> dict:
    """Parse one capped banner. Empty input is rejected as ``empty`` and not stored."""
    if protocol not in READ_CAP:
        return _rejected("unsupported protocol")
    if not raw:
        return _rejected("empty")
    text = raw[: READ_CAP[protocol]].decode("ascii", errors="replace")
    if protocol == "ssh":
        line = sanitise(_first_line(text))
        if not line.startswith("SSH-"):
            return _rejected("no SSH- prefix")
        parts = line.split(None, 8)[0].split("-", 2)
        if len(parts) < 3 or not parts[2]:
            return _rejected("malformed SSH identification")
        product, separator, version = parts[2].partition("_")
        return _accepted("ssh", product, version if separator else None, line)
    if protocol == "http":
        # Skip the status line. At most 64 header lines are examined.
        for line in text.split("\r\n", 64)[1:64]:
            if line[:7].lower() == "server:":
                value = sanitise(line[7:])
                tokens = value.split(None, 8)
                product, _slash, version = tokens[0].partition("/") if tokens else ("", "", "")
                return _accepted("http", product or None, version or None, value)
        return _accepted("http", None, None, "")
    line = sanitise(_first_line(text))
    if not line.startswith("220"):
        return _rejected("not 220 greeting")
    tokens = [token.strip("()?") for token in line.split(None, 8)]
    for index, token in enumerate(tokens):
        if token in _PRODUCT_TABLE[protocol]:
            version = tokens[index + 1] if index + 1 < len(tokens) else None
            return _accepted(protocol, token, version, line)
    return _accepted(protocol, None, None, line)


def fingerprint_for_storage(protocol: str | None, raw: bytes) -> dict | None:
    """A row to store, or None when the read was empty.

    A banner that fails the prefix check is stored as ``rejected`` so it is
    distinct from a scan that was never fingerprinted. Product and version
    stay empty in that case.
    """
    if not protocol or not raw:
        return None
    parsed = parse_banner(protocol, raw)
    if not parsed.get("accepted"):
        if parsed.get("reason") == "empty":
            return None
        return {
            "service": protocol,
            "product": None,
            "version": None,
            "raw_banner": None,
            "parse_status": "rejected",
        }
    return {
        "service": parsed["service"],
        "product": parsed["product"],
        "version": parsed["version"],
        "raw_banner": parsed["raw"] or None,
        "parse_status": parsed["parse_status"] if parsed["parse_status"] in _STATUSES else "rejected",
    }


def summary_line(rows: list[dict] | None, *, has_ports: bool) -> str:
    """One stripped line for text, CSV, and HTML. Empty when there is nothing to say."""
    if not rows:
        return "not fingerprinted" if has_ports else ""
    return "; ".join(_one_summary(row) for row in rows)


def _one_summary(row: dict) -> str:
    service = strip_for_text(row.get("service") or "")
    product = strip_for_text(row.get("product") or "")
    version = strip_for_text(row.get("version") or "")
    status = strip_for_text(row.get("parse_status") or "")
    port = row.get("port")
    bits = [str(port) if port is not None else "", service, product, version]
    text = " ".join(bit for bit in bits if bit)
    if status == "rejected":
        return f"{text} (banner rejected)".strip()
    if status == "unknown" and not version:
        note = "version unknown" if product else "not identified"
        return f"{text} ({note})".strip()
    return text or "not fingerprinted"

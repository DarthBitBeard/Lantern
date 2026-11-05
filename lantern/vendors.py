"""Who made a device's network card, from the first half of its MAC address.

The table is the IEEE Registration Authority public listing (MA-L, MA-M, and
MA-S assignments), shipped as `data/oui.tsv.gz` and rebuilt by
`tools/update_oui.py`. Nothing here touches the network. The table is loaded
once, on first use, and the longest matching prefix wins (an MA-S block
inside an MA-L block belongs to the smaller company).

A locally administered (randomized, "private Wi-Fi") address has no vendor:
the bits are chosen by the device, so any prefix match would be a
coincidence.
"""

from __future__ import annotations

import gzip
import re
import threading
from importlib import resources

_LENGTHS = (9, 7, 6)  # MA-S, MA-M, MA-L hex digits; longest first
_table: dict[str, str] | None = None
_lock = threading.Lock()

# Legal-form words dropped from the end of a name for display.
_SUFFIX_RE = re.compile(
    r"[\s,.]+(co|company|corp|corporation|inc|incorporated|ltd|limited|llc|l\.l\.c|gmbh|ag|sa|s\.a|"
    r"sas|srl|s\.r\.l|spa|s\.p\.a|bv|b\.v|nv|n\.v|oy|ab|as|a/s|kg|plc|pte|pty|pvt|kk|k\.k|"
    r"technologies|technology|electronics|international|holdings|group|corporate|industries)\.?$",
    re.I,
)
_LOWER_WORDS = {"of", "and", "the", "for", "de"}
# Registrations that name no real maker: hidden ("Private") entries, and the
# IEEE's own parent blocks for the smaller MA-M and MA-S assignments.
_NO_VENDOR = {"private", "ieee registration authority"}


def _load() -> dict[str, str]:
    global _table
    if _table is None:
        with _lock:
            if _table is None:
                raw = resources.files("lantern").joinpath("data/oui.tsv.gz").read_bytes()
                table: dict[str, str] = {}
                for line in gzip.decompress(raw).decode("utf-8").splitlines():
                    if not line or line.startswith("#"):
                        continue
                    prefix, _, name = line.partition("\t")
                    if name:
                        table[prefix] = name
                _table = table
    return _table


def table_size() -> int:
    return len(_load())


def _hex(mac: str | None) -> str | None:
    if not mac:
        return None
    digits = re.sub(r"[^0-9A-Fa-f]", "", str(mac)).upper()
    return digits if len(digits) == 12 else None


def is_private_mac(mac: str | None) -> bool:
    """True when the locally administered bit is set (a randomized address)."""
    digits = _hex(mac)
    return bool(digits) and bool(int(digits[:2], 16) & 0x02)


def short_name(name: str) -> str:
    """'Synology Incorporated' -> 'Synology', 'XEROX CORPORATION' -> 'Xerox'."""
    text = name.strip().strip(",. ")
    for _ in range(4):
        trimmed = _SUFFIX_RE.sub("", text).strip(",. ")
        if trimmed == text or not trimmed:
            break
        text = trimmed
    letters = [ch for ch in text if ch.isalpha()]
    if letters and all(ch.isupper() for ch in letters) and len(text) > 4:
        words = []
        for i, word in enumerate(text.split(" ")):
            lower = word.lower()
            words.append(lower if i and lower in _LOWER_WORDS else word.capitalize())
        text = " ".join(words)
    return text[:40] or name[:40]


def lookup(mac: str | None) -> dict | None:
    """{'vendor': short name, 'vendor_name': IEEE name} or None.

    None for a missing, malformed, randomized, or unregistered address.
    """
    digits = _hex(mac)
    if not digits or int(digits[:2], 16) & 0x02:
        return None
    table = _load()
    for length in _LENGTHS:
        name = table.get(digits[:length])
        if name:
            if name.strip().lower() in _NO_VENDOR:
                return None
            return {"vendor": short_name(name), "vendor_name": name}
    return None


def annotate_vendors(devices) -> None:
    """Set `vendor` (short name or None) and `private_mac` on each device dict."""
    for device in devices or []:
        found = lookup(device.get("mac"))
        device["vendor"] = found["vendor"] if found else None
        device["private_mac"] = is_private_mac(device.get("mac"))

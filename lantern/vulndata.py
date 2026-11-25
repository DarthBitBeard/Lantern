"""Offline vulnerability dataset: load, check, and compare versions.

The packaged file is ``lantern/data/vulns.json``. This module never fetches
it and never reads a path the user supplies at scan time. A missing file is
status ``missing``. A file that fails these checks is status ``invalid``:
one fixed message, no path, and no traceback.

Every entry must say ``text_origin`` is ``lantern``. The top-level
``license`` must be exactly ``CC0-1.0``. The SHA-256 is recomputed over the
canonical entries. Those checks catch a damaged file, not a malicious author.
"""

from __future__ import annotations

import hashlib
import json
import re
import sys
from dataclasses import dataclass
from pathlib import Path

MAX_BYTES = 5 * 1024 * 1024
MAX_DEPTH = 32
MAX_ENTRIES = 5000
MAX_RANGES = 16
MAX_REFS = 8
MAX_ALIASES = 8
MAX_SUMMARY = 300
MAX_FIX = 300
MAX_VERSION_CHARS = 64
MAX_VERSION_PARTS = 16
MAX_INT_DIGITS = 18
_SHA_PREFIX = 16

_MSG_SIZE = "lantern: vulnerability data was refused: file is larger than 5 MB."
_MSG_ENCODING = "lantern: vulnerability data was refused: not UTF-8 JSON."
_MSG_JSON = "lantern: vulnerability data was refused: not valid JSON."
_MSG_DEPTH = "lantern: vulnerability data was refused: nesting is too deep."
_MSG_NUMBER = "lantern: vulnerability data was refused: non-finite number."
_MSG_INTEGER = "lantern: vulnerability data was refused: integer is too large."
_MSG_DUPLICATE = "lantern: vulnerability data was refused: duplicate key."
_MSG_SCHEMA = "lantern: vulnerability data was refused: schema."
_MSG_CHECKSUM = "lantern: vulnerability data was refused: checksum."
_MSG_PLACEHOLDER = "lantern: vulnerability data was refused: placeholder."
_MSG_REFERENCE = "lantern: vulnerability data was refused: reference."
_MSG_ORIGIN = "lantern: vulnerability data was refused: text origin."
_MSG_LICENSE = "lantern: vulnerability data was refused: license."
_MSG_LIMITS = "lantern: vulnerability data was refused: limits."
_MSG_READ = "lantern: vulnerability data was refused: file could not be read."

_DATA_VERSION_RE = r"^(0|[1-9][0-9]{0,7})(?:\.(0|[1-9][0-9]{0,7})){1,3}$"
_ENTRY_ID_RE = r"^LV-[0-9]{1,8}$"
_REF_ID_RE = (
    r"^(?:CVE-\d{4}-\d{4,7}|GHSA(?:-[23456789cfghjmpqrvwx]{4}){3}"
    r"|[A-Z][A-Z0-9]{1,15}-[A-Za-z0-9._:-]{1,40})$"
)
_PRODUCT_RE = r"^[A-Za-z0-9][A-Za-z0-9._+-]{0,39}$"
_SERVICE_RE = r"^[a-z][a-z0-9]{0,15}$"
_SEVERITIES = frozenset({"critical", "high", "medium", "low", "info"})
_TOP_KEYS = frozenset({"license", "data_version", "sha256", "entries"})
_ENTRY_KEYS = frozenset({
    "id", "text_origin", "product", "aliases", "service", "severity",
    "summary", "fix", "ranges", "refs",
})
_RANGE_KEYS = frozenset({"introduced", "fixed", "last_affected"})
_REF_KEYS = frozenset({"id", "url"})
_PLACEHOLDER_MARKERS = ("EXAMPLE", "PLACEHOLDER")
_SEPARATORS = set("._-+")


class DatasetError(ValueError):
    """The dataset was refused. The message is one fixed line and has no path."""


@dataclass(frozen=True)
class Dataset:
    """One validated snapshot. ``entries`` is empty unless ``status`` is ``ok``."""

    status: str
    source: str | None
    data_version: str | None
    sha256: str | None
    entries: tuple
    message: str | None = None

    @property
    def entry_count(self) -> int:
        return len(self.entries)

    def sha256_prefix(self) -> str:
        if not self.sha256:
            return ""
        return self.sha256[:_SHA_PREFIX]


def packaged_path() -> Path:
    """The dataset shipped inside the package. It may be absent."""
    return Path(__file__).resolve().parent / "data" / "vulns.json"


def missing_dataset() -> Dataset:
    """No file. ``vuln-match`` produces nothing."""
    return Dataset(
        status="missing", source=None, data_version=None, sha256=None, entries=(),
    )


def load_packaged() -> Dataset:
    """Read and check the packaged file. Does not print. Never raises."""
    path = packaged_path()
    try:
        if not path.is_file():
            return missing_dataset()
        blob = _read_packaged(path)
    except DatasetError as exc:
        return _invalid(str(exc))
    except OSError:
        return _invalid(_MSG_READ)
    return dataset_from_bytes(blob)


def load_for_scan(dataset: Dataset | None = None) -> Dataset:
    """The dataset for one scan run.

    A caller that already chose a snapshot passes it through, so a second
    scope does not read the file again and does not repeat the error line.
    """
    if dataset is not None:
        return dataset
    chosen = load_packaged()
    if chosen.message:
        print(chosen.message, file=sys.stderr, flush=True)
    return chosen


def dataset_from_bytes(blob: bytes, *, source: str = "bundled") -> Dataset:
    """Validate ``blob``. A failure is an invalid dataset, not an exception."""
    try:
        parsed = validate(blob)
    except DatasetError as exc:
        return _invalid(str(exc), source=source)
    return Dataset(
        status="ok",
        source=source,
        data_version=parsed["data_version"],
        sha256=parsed["sha256"],
        entries=tuple(parsed["entries"]),
    )


def _invalid(message: str, *, source: str | None = "bundled") -> Dataset:
    return Dataset(
        status="invalid", source=source, data_version=None, sha256=None,
        entries=(), message=message,
    )


def _read_packaged(path: Path) -> bytes:
    """Read at most 5 MB + 1 byte. A larger file is refused and not parsed."""
    with path.open("rb") as handle:
        blob = handle.read(MAX_BYTES + 1)
    if len(blob) > MAX_BYTES:
        raise DatasetError(_MSG_SIZE)
    return blob


def validate(blob: bytes) -> dict:
    """Check ``blob`` and return the parsed object. Raises ``DatasetError``.

    The same function will check a bundled file and, later, an imported one.
    There is no relaxed mode.
    """
    if isinstance(blob, str) or not isinstance(blob, (bytes, bytearray)):
        raise DatasetError(_MSG_JSON)
    if len(blob) > MAX_BYTES:
        raise DatasetError(_MSG_SIZE)
    if (
        blob.startswith((b"\xef\xbb\xbf", b"\xff\xfe", b"\xfe\xff"))
        or b"\x00" in blob
    ):
        raise DatasetError(_MSG_ENCODING)
    try:
        text = bytes(blob).decode("utf-8")
    except UnicodeDecodeError as exc:
        raise DatasetError(_MSG_ENCODING) from exc
    if _nesting_too_deep(text):
        raise DatasetError(_MSG_DEPTH)
    try:
        data = json.loads(
            text,
            parse_constant=_reject_constant,
            parse_int=_parse_int,
            parse_float=_reject_float,
            object_pairs_hook=_pairs,
        )
    except DatasetError:
        raise
    except RecursionError as exc:
        raise DatasetError(_MSG_DEPTH) from exc
    except (json.JSONDecodeError, ValueError, TypeError) as exc:
        raise DatasetError(_message_from_parse(exc)) from exc
    _check_document(data)
    return data


def canonical_bytes(entries: list) -> bytes:
    """The bytes the SHA-256 is computed over. Key order does not matter."""
    return json.dumps(
        entries, sort_keys=True, separators=(",", ":"), ensure_ascii=True,
    ).encode("ascii")


def canonical_sha256(entries: list) -> str:
    """Lower-case hex SHA-256 of :func:`canonical_bytes`."""
    return hashlib.sha256(canonical_bytes(entries)).hexdigest()


def parse_data_version(text: object) -> tuple[int, ...]:
    """``YYYY.MM.N`` style dotted numbers, compared later as integer tuples.

    ``2026.9.0`` is less than ``2026.10.0``. String order is not used.
    """
    if not isinstance(text, str) or re.fullmatch(_DATA_VERSION_RE, text) is None:
        raise DatasetError(_MSG_SCHEMA)
    return tuple(int(part) for part in text.split("."))


def data_version_newer(left: str, right: str) -> bool:
    """True when ``left`` is strictly newer than ``right``."""
    return parse_data_version(left) > parse_data_version(right)


def compare_versions(left: object, right: object) -> int | None:
    """-1, 0, or 1. None when either version is unparseable.

    Parts are digit runs and letter runs. ``2.4.58`` is greater than
    ``2.4.9``. ``1.0`` equals ``1.0.0``. A version longer than 64 characters,
    or with more than 16 parts, does not compare.
    """
    parsed_left = _parse_version(left)
    parsed_right = _parse_version(right)
    if parsed_left is None or parsed_right is None:
        return None
    width = max(len(parsed_left), len(parsed_right))
    for index in range(width):
        side_left = parsed_left[index] if index < len(parsed_left) else None
        side_right = parsed_right[index] if index < len(parsed_right) else None
        if side_left is None:
            side_left = 0 if isinstance(side_right, int) else ""
        if side_right is None:
            side_right = 0 if isinstance(side_left, int) else ""
        if isinstance(side_left, int) and isinstance(side_right, int):
            if side_left != side_right:
                return -1 if side_left < side_right else 1
        elif isinstance(side_left, str) and isinstance(side_right, str):
            if side_left != side_right:
                return -1 if side_left < side_right else 1
        elif isinstance(side_left, int):
            return 1
        else:
            return -1
    return 0


def version_in_range(version: object, introduced: object, *,
                     fixed: object = None, last_affected: object = None) -> bool:
    """``introduced`` is inclusive, ``fixed`` is exclusive, ``last_affected`` is inclusive.

    An unparseable version or bound does not match.
    """
    if compare_versions(version, introduced) is None:
        return False
    if compare_versions(version, introduced) < 0:
        return False
    if fixed is not None:
        if compare_versions(version, fixed) is None or compare_versions(version, fixed) >= 0:
            return False
    if last_affected is not None:
        if (
            compare_versions(version, last_affected) is None
            or compare_versions(version, last_affected) > 0
        ):
            return False
    return True


def format_dataset(dataset: Dataset) -> list[str]:
    """Lines ``lantern checks`` prints after the check ids."""
    return [
        f"dataset source: {dataset.source or '-'}",
        f"dataset version: {dataset.data_version or '-'}",
        f"dataset entries: {dataset.entry_count}",
        f"dataset sha256: {dataset.sha256_prefix() or '-'}",
        f"dataset status: {dataset.status}",
    ]


def _parse_version(text: object) -> tuple | None:
    if not isinstance(text, str) or not text or len(text) > MAX_VERSION_CHARS:
        return None
    parts: list[int | str] = []
    buf: list[str] = []
    kind: str | None = None

    def flush() -> None:
        nonlocal buf, kind
        if not buf:
            return
        token = "".join(buf)
        parts.append(int(token) if kind == "d" else token)
        buf = []
        kind = None

    for char in text:
        if char.isdigit():
            if kind not in (None, "d"):
                flush()
            kind = "d"
            buf.append(char)
        elif char.isalpha():
            if kind not in (None, "a"):
                flush()
            kind = "a"
            buf.append(char)
        elif char in _SEPARATORS:
            flush()
        else:
            return None
    flush()
    if not parts or len(parts) > MAX_VERSION_PARTS:
        return None
    return tuple(parts)


def _nesting_too_deep(text: str) -> bool:
    depth = 0
    in_string = False
    escape = False
    for char in text:
        if in_string:
            if escape:
                escape = False
            elif char == "\\":
                escape = True
            elif char == '"':
                in_string = False
            continue
        if char == '"':
            in_string = True
        elif char in "{[":
            depth += 1
            if depth > MAX_DEPTH:
                return True
        elif char in "}]" and depth:
            depth -= 1
    return False


def _reject_constant(_name: str):
    raise DatasetError(_MSG_NUMBER)


def _reject_float(_text: str):
    raise DatasetError(_MSG_NUMBER)


def _parse_int(text: str) -> int:
    digits = text[1:] if text.startswith("-") else text
    if len(digits) > MAX_INT_DIGITS:
        raise DatasetError(_MSG_INTEGER)
    return int(text)


def _pairs(pairs: list) -> dict:
    found = {}
    for key, value in pairs:
        if key in found:
            raise DatasetError(_MSG_DUPLICATE)
        found[key] = value
    return found


def _message_from_parse(exc: BaseException) -> str:
    if isinstance(exc, DatasetError):
        return str(exc)
    text = str(exc)
    for message in (_MSG_INTEGER, _MSG_DUPLICATE, _MSG_NUMBER, _MSG_DEPTH):
        if message in text:
            return message
    return _MSG_JSON


def _check_document(data: object) -> None:
    if not isinstance(data, dict) or set(data) != _TOP_KEYS:
        raise DatasetError(_MSG_SCHEMA)
    if data["license"] != "CC0-1.0":
        raise DatasetError(_MSG_LICENSE)
    parse_data_version(data["data_version"])
    entries = data["entries"]
    if not isinstance(entries, list):
        raise DatasetError(_MSG_SCHEMA)
    if len(entries) > MAX_ENTRIES:
        raise DatasetError(_MSG_LIMITS)
    seen: set[str] = set()
    for entry in entries:
        _check_entry(entry, seen)
    digest = data["sha256"]
    if not isinstance(digest, str) or re.fullmatch(r"[0-9a-f]{64}", digest) is None:
        raise DatasetError(_MSG_CHECKSUM)
    if digest != canonical_sha256(entries):
        raise DatasetError(_MSG_CHECKSUM)


def _check_entry(entry: object, seen: set[str]) -> None:
    if not isinstance(entry, dict) or set(entry) != _ENTRY_KEYS:
        raise DatasetError(_MSG_SCHEMA)
    entry_id = entry["id"]
    if not isinstance(entry_id, str) or re.fullmatch(_ENTRY_ID_RE, entry_id) is None:
        raise DatasetError(_MSG_SCHEMA)
    if entry_id in seen:
        raise DatasetError(_MSG_SCHEMA)
    seen.add(entry_id)
    if entry["text_origin"] != "lantern":
        raise DatasetError(_MSG_ORIGIN)
    if not isinstance(entry["product"], str) or re.fullmatch(_PRODUCT_RE, entry["product"]) is None:
        raise DatasetError(_MSG_SCHEMA)
    aliases = entry["aliases"]
    if (
        not isinstance(aliases, list)
        or len(aliases) > MAX_ALIASES
        or any(not isinstance(alias, str) or re.fullmatch(_PRODUCT_RE, alias) is None for alias in aliases)
    ):
        raise DatasetError(_MSG_LIMITS if isinstance(aliases, list) and len(aliases) > MAX_ALIASES else _MSG_SCHEMA)
    folded = {entry["product"].casefold()}
    for alias in aliases if isinstance(aliases, list) else []:
        if not isinstance(alias, str):
            continue
        key = alias.casefold()
        if key in folded:
            raise DatasetError(_MSG_SCHEMA)
        folded.add(key)
    if not isinstance(entry["service"], str) or re.fullmatch(_SERVICE_RE, entry["service"]) is None:
        raise DatasetError(_MSG_SCHEMA)
    if entry["severity"] not in _SEVERITIES:
        raise DatasetError(_MSG_SCHEMA)
    _check_text(entry["summary"], _MSG_LIMITS if _too_long(entry.get("summary"), MAX_SUMMARY) else _MSG_SCHEMA, MAX_SUMMARY)
    _check_text(entry["fix"], _MSG_LIMITS if _too_long(entry.get("fix"), MAX_FIX) else _MSG_SCHEMA, MAX_FIX)
    _reject_placeholder(entry_id, entry["summary"])
    _check_ranges(entry["ranges"])
    _check_refs(entry["refs"])


def _too_long(value: object, limit: int) -> bool:
    return isinstance(value, str) and len(value) > limit


def _check_text(value: object, message: str, limit: int) -> None:
    if not isinstance(value, str) or not value or len(value) > limit:
        raise DatasetError(message)
    if any(char < " " or char > "~" for char in value):
        raise DatasetError(_MSG_SCHEMA)


def _reject_placeholder(*values: str) -> None:
    for value in values:
        folded = value.upper()
        if any(marker in folded for marker in _PLACEHOLDER_MARKERS):
            raise DatasetError(_MSG_PLACEHOLDER)


def _check_ranges(ranges: object) -> None:
    if not isinstance(ranges, list) or not ranges:
        raise DatasetError(_MSG_SCHEMA)
    if len(ranges) > MAX_RANGES:
        raise DatasetError(_MSG_LIMITS)
    for item in ranges:
        if not isinstance(item, dict):
            raise DatasetError(_MSG_SCHEMA)
        extra = set(item) - _RANGE_KEYS
        if extra or "introduced" not in item:
            raise DatasetError(_MSG_SCHEMA)
        has_fixed = "fixed" in item
        has_last = "last_affected" in item
        if has_fixed == has_last:
            raise DatasetError(_MSG_SCHEMA)
        if _parse_version(item["introduced"]) is None:
            raise DatasetError(_MSG_SCHEMA)
        end_key = "fixed" if has_fixed else "last_affected"
        if _parse_version(item[end_key]) is None:
            raise DatasetError(_MSG_SCHEMA)


def _check_refs(refs: object) -> None:
    if not isinstance(refs, list) or not refs:
        raise DatasetError(_MSG_SCHEMA)
    if len(refs) > MAX_REFS:
        raise DatasetError(_MSG_LIMITS)
    for item in refs:
        if not isinstance(item, dict) or set(item) != _REF_KEYS:
            raise DatasetError(_MSG_SCHEMA)
        ref_id = item["id"]
        if not isinstance(ref_id, str) or re.fullmatch(_REF_ID_RE, ref_id) is None:
            raise DatasetError(_MSG_REFERENCE)
        _reject_placeholder(ref_id)
        if not _https_host_ok(item["url"]):
            raise DatasetError(_MSG_REFERENCE)


def _https_host_ok(url: object) -> bool:
    if not isinstance(url, str) or not url.startswith("https://"):
        return False
    rest = url[len("https://"):]
    if not rest or any(char in rest for char in " \t\r\n\\"):
        return False
    hostport = rest.split("/", 1)[0].split("?", 1)[0].split("#", 1)[0]
    if not hostport or "@" in hostport or hostport.startswith("["):
        return False
    host = hostport.split(":", 1)[0].lower().rstrip(".")
    if not host or ".." in host or re.fullmatch(r"[a-z0-9.-]+", host) is None:
        return False
    if host in {"localhost", "invalid", "test", "example"}:
        return False
    if host.startswith("example."):
        return False
    for suffix in (".invalid", ".test", ".example", ".localhost"):
        if host.endswith(suffix):
            return False
    return True

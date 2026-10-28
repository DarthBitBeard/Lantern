"""Named scan scopes from a TOML file.

A scope is a name plus one private subnet. Loading a file does not scan.
Every subnet is checked with `validate_subnet`, so a scope cannot widen
the rules used by `lantern scan --subnet`: RFC1918 only, at most 1024
addresses, no loopback, no link-local, no IPv6.

The file may only contain `[scopes.<name>]` tables with `subnet` and an
optional `description`. Other keys are rejected so a config cannot quietly
add excludes, extra CIDRs, or a different port list.
"""

from __future__ import annotations

import re
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .discovery import validate_subnet

DEFAULT_CONFIG_NAME = "lantern.toml"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SCOPE_KEYS = frozenset({"subnet", "description"})
_MAX_DESCRIPTION = 200


@dataclass(frozen=True)
class Scope:
    name: str
    subnet: str
    description: str | None = None


def load_scopes(path: str | Path) -> dict[str, Scope]:
    """Read named scopes from a TOML file. Raise ValueError if unsafe or malformed.

    The returned dict keeps the file order. `subnet` is the normalized
    network (`192.168.1.5/24` becomes `192.168.1.0/24`).
    """
    path = Path(path)
    try:
        text = path.read_text(encoding="utf-8")
    except UnicodeDecodeError as exc:
        raise ValueError(f"Scope config {path} is not UTF-8.") from exc
    except OSError as exc:
        raise ValueError(f"Cannot read scope config {path}: {exc}") from exc
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ValueError(f"Invalid TOML in {path}: {exc}") from exc
    if not isinstance(data, dict):
        raise ValueError(f"{path} is not a TOML table.")

    extra_root = sorted(set(data) - {"scopes"})
    if extra_root:
        listed = ", ".join(extra_root)
        raise ValueError(
            f"Unsupported setting(s) in {path}: {listed}. "
            "The file may only contain [scopes.<name>] tables."
        )
    if "scopes" not in data:
        raise ValueError(f"{path} has no [scopes] table.")
    raw_scopes = data["scopes"]
    if not isinstance(raw_scopes, dict):
        raise ValueError(
            f"{path}: 'scopes' must be a table of named scopes, like [scopes.home]."
        )
    if not raw_scopes:
        raise ValueError(f"{path} does not define any scopes.")

    scopes: dict[str, Scope] = {}
    for name, body in raw_scopes.items():
        scopes[name] = _parse_scope(name, body)
    return scopes


def select_scope(scopes: dict[str, Scope], name: str | None) -> Scope:
    """Pick one scope. A file with exactly one scope may omit the name."""
    if not scopes:
        raise ValueError("No scopes defined.")
    if name is None:
        if len(scopes) == 1:
            return next(iter(scopes.values()))
        choices = ", ".join(scopes)
        raise ValueError(f"Config defines more than one scope. Pass --scope. Choices: {choices}")
    if name not in scopes:
        choices = ", ".join(scopes)
        raise ValueError(f"Unknown scope {name!r}. Choices: {choices}")
    return scopes[name]


def _parse_scope(name: str, body: object) -> Scope:
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise ValueError(
            f"Scope name {name!r} is not allowed. "
            "Use 1 to 64 letters, digits, '.', '_' or '-', starting with a letter or digit."
        )
    if not isinstance(body, dict):
        raise ValueError(f"Scope {name!r} must be a table with a 'subnet' string.")
    extra = sorted(set(body) - _SCOPE_KEYS)
    if extra:
        listed = ", ".join(extra)
        raise ValueError(
            f"Scope {name!r} has unsupported setting(s): {listed}. "
            "Only 'subnet' and 'description' are allowed."
        )
    if "subnet" not in body:
        raise ValueError(f"Scope {name!r} is missing 'subnet'.")
    subnet = body["subnet"]
    if not isinstance(subnet, str):
        raise ValueError(f"Scope {name!r}: 'subnet' must be a string like 192.168.1.0/24.")
    try:
        network = validate_subnet(subnet)
    except ValueError as exc:
        raise ValueError(f"Scope {name!r}: {exc}") from exc

    description = None
    if "description" in body:
        raw = body["description"]
        if not isinstance(raw, str):
            raise ValueError(f"Scope {name!r}: 'description' must be a string.")
        description = raw.strip()
        if len(description) > _MAX_DESCRIPTION:
            raise ValueError(
                f"Scope {name!r}: 'description' is longer than {_MAX_DESCRIPTION} characters."
            )
        description = description or None
    return Scope(name=name, subnet=str(network), description=description)

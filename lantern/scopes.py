"""Named scan scopes from a TOML file.

A scope is a name plus one private subnet. Loading a file does not scan.
Every subnet is checked with `validate_subnet`, so a scope cannot widen
the rules used by `lantern scan --subnet`: RFC1918 only, at most 1024
addresses, no loopback, no link-local, no IPv6.

The file may only contain `[scopes.<name>]` tables with `subnet` and an
optional `description`, plus an optional root `[checks]` table whose only
key is `disabled` (a list of check ids). Other keys are rejected so a
config cannot quietly add excludes, extra CIDRs, a different port list,
or a check the program does not ship.

A file larger than 64 KiB is refused before it is parsed. A scope file is
a short list of names and subnets; the limit keeps a huge file from being
read into memory.
"""

from __future__ import annotations

import re
import stat
import tomllib
from dataclasses import dataclass
from pathlib import Path

from .assets import strip_for_text
from .checks import LOCKED_CHECK_IDS, REGISTRY, locked_check_message, unknown_check_message
from .discovery import validate_subnet

DEFAULT_CONFIG_NAME = "lantern.toml"
_NAME_RE = re.compile(r"^[A-Za-z0-9][A-Za-z0-9_.-]{0,63}$")
_SCOPE_KEYS = frozenset({"subnet", "description"})
_ROOT_KEYS = frozenset({"scopes", "checks"})
_CHECK_KEYS = frozenset({"disabled"})
_MAX_DESCRIPTION = 200
# 64 KiB is the same cap the dashboard uses for a POST body. A scope file
# is a handful of names and subnets, so anything larger is refused outright.
MAX_SCOPE_CONFIG_BYTES = 64 * 1024


@dataclass(frozen=True)
class Scope:
    name: str
    subnet: str
    description: str | None = None


@dataclass(frozen=True)
class LoadedConfig:
    """Named scopes, and the check ids the file turns off.

    ``scopes`` is empty when the file has no ``[scopes]`` table.
    ``disabled`` is empty when the file has no ``[checks]`` table.
    """

    scopes: dict[str, Scope]
    disabled: frozenset[str]


class ScopeConfigError(ValueError):
    """The scope file could not be read, or it breaks the scope rules.

    A typed name that fails the name check, or a name missing from a file
    that did load, is a different error. Callers that only read stored scans
    can catch this type instead of matching error text.
    """


class UnknownScopeError(ValueError):
    """The name is not in a scope file that loaded."""


def _shown_config_path(path: Path) -> str:
    """Path text for an error. Control, bidi, and zero-width characters are removed."""
    shown = strip_for_text(str(path))
    return shown or "(path omitted)"


def _scope_too_large(path: Path) -> ScopeConfigError:
    return ScopeConfigError(
        f"Scope config {_shown_config_path(path)} is too large. "
        "Lantern refuses scope files larger than 64 KiB."
    )


def _read_scope_text(path: Path) -> str:
    """Read a scope file, refusing anything larger than 64 KiB.

    The size is checked before the body is parsed, and the read itself is
    capped, so a huge file is never loaded. The error does not include the
    file contents.
    """
    try:
        info = path.stat()
    except OSError as exc:
        raise ScopeConfigError(
            f"Cannot read scope config {_shown_config_path(path)}: {strip_for_text(str(exc))}"
        ) from exc
    if not stat.S_ISREG(info.st_mode):
        raise ScopeConfigError(
            f"Cannot read scope config {_shown_config_path(path)}: not a regular file."
        )
    if info.st_size > MAX_SCOPE_CONFIG_BYTES:
        raise _scope_too_large(path)
    try:
        with path.open("rb") as handle:
            blob = handle.read(MAX_SCOPE_CONFIG_BYTES + 1)
    except OSError as exc:
        raise ScopeConfigError(
            f"Cannot read scope config {_shown_config_path(path)}: {strip_for_text(str(exc))}"
        ) from exc
    if len(blob) > MAX_SCOPE_CONFIG_BYTES:
        raise _scope_too_large(path)
    try:
        return blob.decode("utf-8")
    except UnicodeDecodeError as exc:
        raise ScopeConfigError(f"Scope config {_shown_config_path(path)} is not UTF-8.") from exc


def load_config(path: str | Path) -> LoadedConfig:
    """Read scopes and the optional ``[checks]`` table.

    A file with neither table is refused. A file may contain checks and
    no scopes; ``load_scopes`` still requires the scopes table.
    """
    path = Path(path)
    shown = _shown_config_path(path)
    text = _read_scope_text(path)
    try:
        data = tomllib.loads(text)
    except tomllib.TOMLDecodeError as exc:
        raise ScopeConfigError(f"Invalid TOML in {shown}: {exc}") from exc
    except RecursionError as exc:
        raise ScopeConfigError(
            f"Invalid TOML in {shown}: the file is nested too deeply."
        ) from exc
    if not isinstance(data, dict):
        raise ScopeConfigError(f"{shown} is not a TOML table.")

    extra_root = sorted(set(data) - _ROOT_KEYS)
    if extra_root:
        listed = ", ".join(extra_root)
        raise ScopeConfigError(
            f"Unsupported setting(s) in {shown}: {listed}. "
            "The file may only contain [scopes.<name>] tables and an optional [checks] table."
        )
    if "scopes" not in data and "checks" not in data:
        raise ScopeConfigError(f"{shown} has no [scopes] table.")

    disabled = _parse_checks(data["checks"]) if "checks" in data else frozenset()
    scopes = _parse_scopes(path, data["scopes"]) if "scopes" in data else {}
    return LoadedConfig(scopes=scopes, disabled=disabled)


def load_scopes(path: str | Path) -> dict[str, Scope]:
    """Read named scopes from a TOML file. Raise ValueError if unsafe or malformed.

    The returned dict keeps the file order. `subnet` is the normalized
    network (`192.168.1.5/24` becomes `192.168.1.0/24`). A file larger than
    64 KiB is refused before it is parsed; the error does not include the
    file contents. An optional ``[checks]`` table is checked and ignored
    here; use ``load_disabled_checks`` for the ids it turns off.
    """
    loaded = load_config(path)
    if not loaded.scopes:
        raise ScopeConfigError(f"{_shown_config_path(Path(path))} has no [scopes] table.")
    return loaded.scopes


def load_disabled_checks(path: str | Path) -> frozenset[str]:
    """Check ids turned off by ``[checks] disabled``. Empty when that table is absent.

    The rest of the file is validated too, including the scope tables when
    they are present. An unknown check id is an error and names the valid ids.
    ``port-rules`` is refused until a scan records which checks ran. Callers
    that only need scopes use ``load_scopes``, which does not apply this list.
    """
    disabled = load_config(path).disabled
    locked = sorted(name for name in disabled if name in LOCKED_CHECK_IDS)
    if locked:
        raise ScopeConfigError(locked_check_message(locked))
    return disabled


def _parse_checks(body: object) -> frozenset[str]:
    if not isinstance(body, dict):
        raise ScopeConfigError("[checks] must be a table.")
    extra = sorted(set(body) - _CHECK_KEYS)
    if extra:
        listed = ", ".join(extra)
        raise ScopeConfigError(
            f"Unsupported setting(s) in [checks]: {listed}. Only 'disabled' is allowed."
        )
    raw = body.get("disabled", [])
    if not isinstance(raw, list) or any(not isinstance(item, str) for item in raw):
        raise ScopeConfigError("[checks] disabled must be a list of check ids.")
    unknown = [item for item in raw if item not in REGISTRY]
    if unknown:
        raise ScopeConfigError(unknown_check_message(unknown))
    return frozenset(raw)


def _parse_scopes(path: Path, raw_scopes: object) -> dict[str, Scope]:
    if not isinstance(raw_scopes, dict):
        raise ScopeConfigError(
            f"{_shown_config_path(path)}: 'scopes' must be a table of named scopes, like [scopes.home]."
        )
    if not raw_scopes:
        raise ScopeConfigError(f"{_shown_config_path(path)} does not define any scopes.")

    scopes: dict[str, Scope] = {}
    folded: dict[str, str] = {}
    for name, body in raw_scopes.items():
        key = name.casefold() if isinstance(name, str) else name
        if key in folded:
            raise ScopeConfigError(
                f"Scope name {name!r} repeats {folded[key]!r} except for case."
            )
        folded[key] = name
        scopes[name] = _parse_scope(name, body)
    return scopes


def validate_scope_name(name: str) -> str:
    """Reject a scope name that is not a short token. Does not scan."""
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise ValueError(
            f"Scope name {name!r} is not allowed. "
            "Use 1 to 64 letters, digits, '.', '_' or '-', starting with a letter or digit."
        )
    return name


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
        # Reject Kelvin sign, ß, and other non-ASCII before casefold.
        # casefold() maps U+212A to "k" and U+00DF to "ss".
        validate_scope_name(name)
        folded = name.casefold()
        matches = [scope for key, scope in scopes.items() if key.casefold() == folded]
        if len(matches) == 1:
            return matches[0]
        choices = ", ".join(scopes)
        raise UnknownScopeError(f"Unknown scope {name!r}. Choices: {choices}")
    return scopes[name]


def _parse_scope(name: str, body: object) -> Scope:
    if not isinstance(name, str) or not _NAME_RE.fullmatch(name):
        raise ScopeConfigError(
            f"Scope name {name!r} is not allowed. "
            "Use 1 to 64 letters, digits, '.', '_' or '-', starting with a letter or digit."
        )
    if not isinstance(body, dict):
        raise ScopeConfigError(f"Scope {name!r} must be a table with a 'subnet' string.")
    extra = sorted(set(body) - _SCOPE_KEYS)
    if extra:
        listed = ", ".join(extra)
        raise ScopeConfigError(
            f"Scope {name!r} has unsupported setting(s): {listed}. "
            "Only 'subnet' and 'description' are allowed."
        )
    if "subnet" not in body:
        raise ScopeConfigError(f"Scope {name!r} is missing 'subnet'.")
    subnet = body["subnet"]
    if not isinstance(subnet, str):
        raise ScopeConfigError(f"Scope {name!r}: 'subnet' must be a string like 192.168.1.0/24.")
    try:
        network = validate_subnet(subnet)
    except ValueError as exc:
        raise ScopeConfigError(f"Scope {name!r}: {exc}") from exc

    description = None
    if "description" in body:
        raw = body["description"]
        if not isinstance(raw, str):
            raise ScopeConfigError(f"Scope {name!r}: 'description' must be a string.")
        description = raw.strip()
        if len(description) > _MAX_DESCRIPTION:
            raise ScopeConfigError(
                f"Scope {name!r}: 'description' is longer than {_MAX_DESCRIPTION} characters."
            )
        description = description or None
    return Scope(name=name, subnet=str(network), description=description)

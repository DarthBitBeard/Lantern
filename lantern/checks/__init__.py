"""Static checks over what a scan already collected.

The registry is a fixed literal. A config file can disable a check by
id and cannot add one. Nothing here loads plugins, discovers files, or
runs user code, and nothing here touches the network.
"""

from __future__ import annotations

from dataclasses import dataclass

from ..ports import SEVERITY_RANK
from .port_rules import port_rule_dicts

# Historical port findings omit these. A reader treats a missing check_id
# as port-rules and a missing confidence as "port".
_PORT_CHECK_ID = "port-rules"
_PORT_CONFIDENCE = "port"


@dataclass(frozen=True)
class Finding:
    """One check result. ``as_dict`` is what a scan stores."""

    port: int
    service: str
    severity: str
    title: str
    fix: str
    check_id: str = _PORT_CHECK_ID
    confidence: str = _PORT_CONFIDENCE
    id: str | None = None
    refs: tuple[str, ...] = ()
    evidence: str | None = None

    def as_dict(self) -> dict:
        """The stored JSON object.

        A port-rules finding keeps the five keys ``findings_for_ports``
        has always written. Extra keys appear only when a check sets them,
        so existing findings stay byte-identical.
        """
        item = {
            "port": self.port,
            "service": self.service,
            "severity": self.severity,
            "title": self.title,
            "fix": self.fix,
        }
        if self.check_id != _PORT_CHECK_ID:
            item["check_id"] = self.check_id
        if self.confidence != _PORT_CONFIDENCE:
            item["confidence"] = self.confidence
        if self.id is not None:
            item["id"] = self.id
        if self.refs:
            item["refs"] = list(self.refs)
        if self.evidence:
            item["evidence"] = self.evidence
        return item


@dataclass(frozen=True)
class Observation:
    """What one device showed the scanner. Checks only read this.

    ``open_ports`` is the port numbers that answered. ``fingerprints``
    is one dict per parsed banner, each with a ``port`` key. The dicts
    are the scanner's own records; a check must not mutate them.
    """

    open_ports: tuple[int, ...]
    fingerprints: tuple[dict, ...] = ()


def _port_rules(obs: Observation, dataset: object) -> list[Finding]:
    """Port findings. ``dataset`` is unused; port rules take no data file."""
    del dataset
    found = []
    for item in port_rule_dicts(obs.open_ports):
        found.append(
            Finding(
                port=item["port"],
                service=item["service"],
                severity=item["severity"],
                title=item["title"],
                fix=item["fix"],
                check_id=_PORT_CHECK_ID,
                confidence=_PORT_CONFIDENCE,
            )
        )
    return found


# Fixed literal. Do not build this from entry points, directories, or imports
# of anything the user can drop in beside the program.
REGISTRY: dict[str, object] = {
    "port-rules": _port_rules,
}


def known_check_ids() -> tuple[str, ...]:
    """Check ids in registry order."""
    return tuple(REGISTRY)


def unknown_check_message(names: list[str]) -> str:
    """Name the rejected ids and every id that is valid."""
    shown = ", ".join(repr(name) for name in names)
    valid = ", ".join(REGISTRY)
    noun = "check" if len(names) == 1 else "checks"
    return f"Unknown {noun} {shown}. Valid checks: {valid}."


def validate_disabled(disabled: frozenset[str]) -> None:
    """Reject an id that is not in the registry. The scan does not start."""
    unknown = [name for name in disabled if name not in REGISTRY]
    if unknown:
        raise ValueError(unknown_check_message(sorted(unknown)))


def run_checks(obs: Observation, dataset: object, disabled: frozenset[str]) -> list[dict]:
    """Run every check that is not disabled. No network I/O.

    Findings are ordered by severity, the same way port rules always were.
    Within one severity the registry order is kept, and each check keeps
    the order it returned. An unknown id raises ``ValueError``.
    """
    disabled = frozenset(disabled)
    validate_disabled(disabled)
    found: list[Finding] = []
    for check_id, fn in REGISTRY.items():
        if check_id in disabled:
            continue
        found.extend(fn(obs, dataset))
    found.sort(key=lambda item: SEVERITY_RANK.get(item.severity, 9))
    return [item.as_dict() for item in found]


def describe_checks(disabled: frozenset[str]) -> str:
    """Text for ``lantern checks``. One line per check, then the dataset.

    There is no dataset in this version, so the status is ``missing``.
    """
    disabled = frozenset(disabled)
    validate_disabled(disabled)
    width = max(len(check_id) for check_id in REGISTRY)
    lines = []
    for check_id in REGISTRY:
        state = "disabled" if check_id in disabled else "enabled"
        lines.append(f"{check_id:<{width}}  {state}")
    lines.append("dataset status: missing")
    return "\n".join(lines)

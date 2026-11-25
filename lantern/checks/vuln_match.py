"""Match banner fingerprints against an in-memory vulnerability dataset.

No file is opened here and nothing is fetched. A missing or invalid dataset
produces no findings. The wording on every finding is fixed: a banner is not
proof, and a distro may already have fixed the issue.
"""

from __future__ import annotations

from ..vulndata import Dataset, version_in_range

BANNER_SENTENCE = (
    "Based on the service banner only; coverage is limited and distro backports may already fix this."
)


def vuln_match_findings(obs, dataset) -> list:
    """Findings for fingerprints whose product and version sit in a range."""
    from . import Finding

    if not isinstance(dataset, Dataset) or dataset.status != "ok":
        return []
    found = []
    seen: set[tuple] = set()
    for raw in obs.fingerprints:
        if not isinstance(raw, dict) or raw.get("parse_status") != "ok":
            continue
        product = raw.get("product")
        version = raw.get("version")
        service = raw.get("service")
        port = raw.get("port")
        if not isinstance(product, str) or not isinstance(version, str) or not isinstance(service, str):
            continue
        if isinstance(port, bool) or not isinstance(port, int):
            continue
        for entry in dataset.entries:
            if not _same(service, entry["service"]) or not _product_matches(product, entry):
                continue
            if not any(_in_range(version, item, version_in_range) for item in entry["ranges"]):
                continue
            key = (port, entry["id"])
            if key in seen:
                continue
            seen.add(key)
            evidence = f"{product} {version} on port {port}"
            found.append(
                Finding(
                    port=port,
                    service=service,
                    severity=entry["severity"],
                    title=entry["summary"],
                    fix=entry["fix"],
                    check_id="vuln-match",
                    confidence="banner",
                    id=entry["id"],
                    refs=tuple(item["id"] for item in entry["refs"]),
                    evidence=evidence[:160],
                    note=BANNER_SENTENCE,
                )
            )
    return found


def _same(left: str, right: str) -> bool:
    return left.casefold() == right.casefold()


def _product_matches(product: str, entry: dict) -> bool:
    names = [entry["product"], *entry["aliases"]]
    folded = product.casefold()
    return any(folded == name.casefold() for name in names)


def _in_range(version: str, item: dict, version_in_range) -> bool:
    if "fixed" in item:
        return version_in_range(version, item["introduced"], fixed=item["fixed"])
    return version_in_range(version, item["introduced"], last_affected=item["last_affected"])

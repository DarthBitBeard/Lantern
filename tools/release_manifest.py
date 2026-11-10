"""Write SHA256SUMS and a CycloneDX SBOM for files already built.

Nothing here is published. The workflows upload the two files as artifacts.
Runtime dependencies: none. The SBOM lists Lantern, the bundled vendor
table, and the pinned build tools.
"""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def checksum_lines(paths: list[Path]) -> str:
    lines = [f"{sha256(path)}  {path.name}" for path in paths]
    return "\n".join(lines) + "\n"


def _continued(text: str) -> list[str]:
    lines = []
    pending = ""
    for raw in text.splitlines():
        stripped = raw.strip()
        if not stripped or stripped.startswith("#"):
            continue
        if stripped.endswith("\\"):
            pending += stripped[:-1].strip() + " "
            continue
        lines.append((pending + stripped).strip())
        pending = ""
    if pending:
        lines.append(pending.strip())
    return lines


def build_requirements(text: str) -> list[tuple[str, str]]:
    found = []
    for line in _continued(text):
        body = line.split("#", 1)[0].split(";", 1)[0].strip()
        if "==" not in body:
            continue
        name, version = body.split("==", 1)
        name = name.strip()
        version = version.split()[0].strip()
        if name and version:
            found.append((name, version))
    return found


def lantern_version() -> str:
    sys.path.insert(0, str(ROOT))
    from lantern import __version__

    return __version__


def sbom(paths: list[Path], requirements: list[tuple[str, str]], version: str) -> dict:
    components = [
        {
            "type": "application",
            "name": "lantern",
            "version": version,
            "purl": f"pkg:pypi/lantern@{version}",
        },
        {
            "type": "data",
            "name": "oui.tsv.gz",
            "version": version,
            "description": "Bundled IEEE MAC vendor table. No network lookup.",
        },
    ]
    for name, req_version in requirements:
        components.append({
            "type": "library",
            "name": name,
            "version": req_version,
            "scope": "optional",
            "description": "Build tool only. Lantern has no runtime dependencies.",
            "purl": f"pkg:pypi/{name}@{req_version}",
        })
    for path in paths:
        components.append({
            "type": "file",
            "name": path.name,
            "hashes": [{"alg": "SHA-256", "content": sha256(path)}],
        })
    return {
        "bomFormat": "CycloneDX",
        "specVersion": "1.5",
        "version": 1,
        "metadata": {
            "component": {
                "type": "application",
                "name": "lantern",
                "version": version,
            },
        },
        "components": components,
    }


def write_manifest(paths: list[Path], out_dir: Path, requirements_text: str, version: str) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    sums = out_dir / "SHA256SUMS"
    sums.write_text(checksum_lines(paths), encoding="utf-8")
    document = out_dir / "lantern-sbom.cdx.json"
    document.write_text(
        json.dumps(sbom(paths, build_requirements(requirements_text), version), indent=2) + "\n",
        encoding="utf-8",
    )
    return sums, document


def check_manifest(out_dir: Path) -> None:
    """Raise if SHA256SUMS does not match the files beside it."""
    for line in (out_dir / "SHA256SUMS").read_text(encoding="utf-8").splitlines():
        digest, name = line.split("  ", 1)
        got = sha256(out_dir / name)
        if got != digest:
            raise ValueError(f"checksum mismatch for {name}")


def main(argv: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(description="Write SHA256SUMS and a CycloneDX SBOM.")
    parser.add_argument("--out", type=Path, required=True)
    parser.add_argument("--check", action="store_true", help="Verify SHA256SUMS in --out.")
    parser.add_argument("files", nargs="*", type=Path)
    args = parser.parse_args(argv)
    if args.check:
        try:
            check_manifest(args.out)
        except (OSError, ValueError) as exc:
            print(str(exc), file=sys.stderr)
            return 1
        return 0
    if not args.files:
        print("name the built files", file=sys.stderr)
        return 1
    missing = [path for path in args.files if not path.is_file()]
    if missing:
        print("missing files: " + ", ".join(str(path) for path in missing), file=sys.stderr)
        return 1
    requirements = (ROOT / ".github" / "requirements-build.txt").read_text(encoding="utf-8")
    write_manifest(args.files, args.out, requirements, lantern_version())
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

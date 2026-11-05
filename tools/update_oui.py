"""Rebuild lantern/data/oui.tsv.gz from the IEEE Registration Authority public listing.

Maintainer tool, not part of the package. Lantern never downloads this data
at runtime; the built file ships with each release.

    python tools/update_oui.py                 # download from IEEE, then build
    python tools/update_oui.py --from DIR      # build from oui.csv, mam.csv, oui36.csv in DIR

IEEE does not assert copyright in the public listing and does not restrict
its distribution, and encourages users to obtain it from IEEE directly, which
is what this script does. The output keeps only the assignment and the
organization name (no addresses), one `PREFIX<TAB>Name` line per assignment,
sorted, gzip-compressed with a fixed timestamp so rebuilds are reproducible.
"""

from __future__ import annotations

import argparse
import csv
import datetime
import gzip
import io
import sys
import urllib.request
from pathlib import Path

SOURCES = {
    # Registry: (URL, expected hex length of the assignment)
    "oui.csv": ("https://standards-oui.ieee.org/oui/oui.csv", 6),        # MA-L
    "mam.csv": ("https://standards-oui.ieee.org/oui28/mam.csv", 7),      # MA-M
    "oui36.csv": ("https://standards-oui.ieee.org/oui36/oui36.csv", 9),  # MA-S
}
OUT = Path(__file__).resolve().parent.parent / "lantern" / "data" / "oui.tsv.gz"
MAX_DOWNLOAD = 32 * 1024 * 1024
HEX = set("0123456789ABCDEF")


def fetch(url: str) -> bytes:
    req = urllib.request.Request(url, headers={"User-Agent": "lantern-oui-update"})
    with urllib.request.urlopen(req, timeout=120) as resp:
        data = resp.read(MAX_DOWNLOAD + 1)
    if len(data) > MAX_DOWNLOAD:
        raise SystemExit(f"{url} is larger than {MAX_DOWNLOAD} bytes; refusing.")
    return data


def clean(name: str) -> str:
    # One line, no tabs, no control characters, bounded length.
    name = "".join(ch if ch.isprintable() else " " for ch in name)
    return " ".join(name.split())[:120]


def parse(raw: bytes, length: int, label: str) -> dict[str, str]:
    text = raw.decode("utf-8-sig")
    rows = csv.DictReader(io.StringIO(text))
    found: dict[str, str] = {}
    for row in rows:
        prefix = (row.get("Assignment") or "").strip().upper()
        name = clean(row.get("Organization Name") or "")
        if len(prefix) != length or not set(prefix) <= HEX or not name:
            continue
        found[prefix] = name
    if len(found) < 100:
        raise SystemExit(f"{label}: only {len(found)} usable rows; the format may have changed.")
    return found


def build(sources: dict[str, bytes]) -> bytes:
    table: dict[str, str] = {}
    for filename, (_url, length) in SOURCES.items():
        table.update(parse(sources[filename], length, filename))
    stamp = datetime.date.today().isoformat()
    lines = [f"# IEEE Registration Authority public listing (MA-L, MA-M, MA-S), fetched {stamp}"]
    lines += [f"{prefix}\t{name}" for prefix, name in sorted(table.items())]
    body = ("\n".join(lines) + "\n").encode("utf-8")
    out = io.BytesIO()
    with gzip.GzipFile(fileobj=out, mode="wb", compresslevel=9, mtime=0, filename="") as gz:
        gz.write(body)
    return out.getvalue()


def main(argv=None) -> int:
    parser = argparse.ArgumentParser(description=__doc__.splitlines()[0])
    parser.add_argument("--from", dest="source_dir", help="Build from CSVs already in this directory.")
    parser.add_argument("--output", default=str(OUT))
    args = parser.parse_args(argv)
    sources = {}
    for filename, (url, _length) in SOURCES.items():
        if args.source_dir:
            sources[filename] = (Path(args.source_dir) / filename).read_bytes()
        else:
            print(f"Downloading {url}", file=sys.stderr)
            sources[filename] = fetch(url)
    data = build(sources)
    Path(args.output).write_bytes(data)
    count = gzip.decompress(data).count(b"\n") - 1
    print(f"Wrote {args.output}: {count} prefixes, {len(data)} bytes.", file=sys.stderr)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())

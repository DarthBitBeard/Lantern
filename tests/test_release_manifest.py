"""Checksum manifest and CycloneDX SBOM. No network and no publishing."""

import hashlib
import json
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
TOOL = ROOT / "tools" / "release_manifest.py"


class ReleaseManifestTests(unittest.TestCase):
    def test_checksums_and_sbom_describe_the_built_files(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            wheel = folder / "lantern-1.4.0-py3-none-any.whl"
            sdist = folder / "lantern-1.4.0.tar.gz"
            wheel.write_bytes(b"wheel-bytes")
            sdist.write_bytes(b"sdist-bytes")
            out = folder / "manifest"
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--out", str(out), str(wheel), str(sdist)],
                cwd=ROOT, check=False, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            sums = (out / "SHA256SUMS").read_text(encoding="utf-8")
            self.assertIn(hashlib.sha256(b"wheel-bytes").hexdigest() + "  " + wheel.name, sums)
            self.assertIn(hashlib.sha256(b"sdist-bytes").hexdigest() + "  " + sdist.name, sums)
            (out / wheel.name).write_bytes(wheel.read_bytes())
            (out / sdist.name).write_bytes(sdist.read_bytes())
            checked = subprocess.run(
                [sys.executable, str(TOOL), "--out", str(out), "--check"],
                cwd=ROOT, check=False, capture_output=True, text=True,
            )
            self.assertEqual(checked.returncode, 0, checked.stderr)
            document = json.loads((out / "lantern-sbom.cdx.json").read_text(encoding="utf-8"))
            self.assertEqual(document["bomFormat"], "CycloneDX")
            self.assertEqual(document["specVersion"], "1.5")
            names = {item["name"] for item in document["components"]}
            self.assertIn("lantern", names)
            self.assertIn("oui.tsv.gz", names)
            self.assertIn("setuptools", names)
            self.assertTrue(all("version" in item or "hashes" in item for item in document["components"]))

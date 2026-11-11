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

    def test_check_fails_when_the_checksum_file_is_missing_or_empty(self):
        with tempfile.TemporaryDirectory() as tmp:
            out = Path(tmp)
            missing = subprocess.run(
                [sys.executable, str(TOOL), "--out", str(out), "--check"],
                cwd=ROOT, check=False, capture_output=True, text=True,
            )
            self.assertNotEqual(missing.returncode, 0, missing.stdout)
            self.assertIn("missing", missing.stderr)
            (out / "SHA256SUMS").write_text("\n", encoding="utf-8")
            empty = subprocess.run(
                [sys.executable, str(TOOL), "--out", str(out), "--check"],
                cwd=ROOT, check=False, capture_output=True, text=True,
            )
            self.assertNotEqual(empty.returncode, 0, empty.stdout)
            self.assertIn("empty", empty.stderr)

    def test_check_fails_when_the_hashed_file_is_not_beside_the_sums(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            built = folder / "elsewhere"
            built.mkdir()
            artifact = built / "lantern.exe"
            artifact.write_bytes(b"exe-bytes")
            out = folder / "manifest"
            proc = subprocess.run(
                [sys.executable, str(TOOL), "--out", str(out), str(artifact)],
                cwd=ROOT, check=False, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            checked = subprocess.run(
                [sys.executable, str(TOOL), "--out", str(out), "--check"],
                cwd=ROOT, check=False, capture_output=True, text=True,
            )
            self.assertNotEqual(checked.returncode, 0, checked.stdout)
            self.assertIn("lantern.exe", checked.stderr)

    def test_windows_sbom_names_pyinstaller_and_the_bundled_python(self):
        with tempfile.TemporaryDirectory() as tmp:
            folder = Path(tmp)
            exe = folder / "lantern.exe"
            exe.write_bytes(b"exe-bytes")
            out = folder / "manifest"
            proc = subprocess.run(
                [
                    sys.executable, str(TOOL), "--out", str(out),
                    "--python-runtime", "3.12.10",
                    "--requirements", str(ROOT / ".github" / "requirements-pyinstaller.txt"),
                    str(exe),
                ],
                cwd=ROOT, check=False, capture_output=True, text=True,
            )
            self.assertEqual(proc.returncode, 0, proc.stderr)
            document = json.loads((out / "lantern-sbom.cdx.json").read_text(encoding="utf-8"))
            by_name = {item["name"]: item for item in document["components"]}
            self.assertEqual(by_name["pyinstaller"]["version"], "6.22.3")
            self.assertEqual(by_name["python"]["version"], "3.12.10")
            self.assertIn("bundled", by_name["python"]["description"].lower())

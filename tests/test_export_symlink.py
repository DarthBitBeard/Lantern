"""Export paths: the last directory may not be a link. Ancestor links may.

Local directories only. Nothing is scanned.
"""

import os
import shutil
import stat
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lantern.v1 import ExportPathError, write_export_file


class ExportSymlinkTests(unittest.TestCase):
    def setUp(self):
        self.root = Path(tempfile.mkdtemp())
        self.addCleanup(shutil.rmtree, self.root, True)

    def test_an_ancestor_link_is_accepted(self):
        real = self.root / "real"
        real.mkdir()
        via = self.root / "via"
        via.symlink_to(real, target_is_directory=True)
        child = via / "child"
        child.mkdir()
        written = write_export_file(str(child / "out.json"), b"ok", force=False)
        self.assertEqual(Path(written).read_bytes(), b"ok")
        self.assertEqual((real / "child" / "out.json").read_bytes(), b"ok")

    def test_the_final_directory_symlink_is_refused(self):
        target = self.root / "target"
        target.mkdir()
        linked = self.root / "linked"
        linked.symlink_to(target, target_is_directory=True)
        with self.assertRaises(ExportPathError) as caught:
            write_export_file(str(linked / "out.json"), b"x", force=False)
        self.assertIn("directory itself", str(caught.exception))
        self.assertFalse((target / "out.json").exists())

    def test_a_symlinked_or_dangling_output_is_refused_with_and_without_force(self):
        folder = self.root / "folder"
        folder.mkdir()
        (folder / "real.json").write_bytes(b"old")
        linked = folder / "linked.json"
        linked.symlink_to(folder / "real.json")
        dangling = folder / "dangling.json"
        dangling.symlink_to(folder / "missing.json")
        for path in (linked, dangling):
            for force in (False, True):
                with self.assertRaises(ExportPathError) as caught:
                    write_export_file(str(path), b"new", force=force)
                self.assertIn("output file", str(caught.exception))
        self.assertEqual((folder / "real.json").read_bytes(), b"old")
        self.assertTrue(dangling.is_symlink())

    def test_force_replaces_a_regular_file(self):
        folder = self.root / "folder"
        folder.mkdir()
        dest = folder / "out.json"
        dest.write_bytes(b"old")
        write_export_file(str(dest), b"new", force=True)
        self.assertEqual(dest.read_bytes(), b"new")
        self.assertEqual(stat.S_IMODE(dest.stat().st_mode) & 0o777, 0o600)

    def test_swapping_the_directory_after_the_check_is_refused(self):
        if not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("O_NOFOLLOW is POSIX-only")
        slot = self.root / "slot"
        slot.mkdir()
        decoy = self.root / "decoy"
        decoy.mkdir()
        swapped = {"done": False}
        real_lstat = os.lstat

        def lstat(path, *args, **kwargs):
            info = real_lstat(path, *args, **kwargs)
            if not swapped["done"] and Path(path) == slot:
                swapped["done"] = True
                os.rename(slot, self.root / "slot-real")
                os.symlink(decoy, slot, target_is_directory=True)
            return info

        with mock.patch("lantern.v1.os.lstat", lstat):
            with self.assertRaises(ExportPathError) as caught:
                write_export_file(str(slot / "out.json"), b"{}", force=False)
        self.assertIn("directory itself", str(caught.exception))
        self.assertFalse((decoy / "out.json").exists())

    def test_windows_reparse_and_case_are_best_effort(self):
        if os.name != "nt":
            self.skipTest("Windows reparse points and 8.3 names")
        folder = self.root / "Folder"
        folder.mkdir()
        dest = folder / "out.json"
        write_export_file(str(dest), b"ok", force=False)
        other_case = Path(str(dest).swapcase()) if str(dest) != str(dest).swapcase() else dest
        write_export_file(str(other_case), b"case", force=True)


if __name__ == "__main__":
    unittest.main()

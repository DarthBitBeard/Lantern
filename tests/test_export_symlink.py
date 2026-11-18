"""Export paths: the last directory may not be a link. Ancestor links may.

Local directories only. Nothing is scanned.
"""

import os
import shutil
import signal
import stat
import subprocess
import tempfile
import unittest
from pathlib import Path
from unittest import mock

from lantern.v1 import ExportInterrupted, ExportPathError, write_export_file


def _short_path(path: Path) -> str | None:
    """Windows 8.3 name, or None when short names are disabled."""
    if os.name != "nt":
        return None
    import ctypes
    buffer = ctypes.create_unicode_buffer(32768)
    length = ctypes.windll.kernel32.GetShortPathNameW(str(path), buffer, len(buffer))
    if not length or length >= len(buffer):
        return None
    short = buffer.value
    if short.casefold() == str(path).casefold():
        return None
    return short


class _OpenPatch:
    """Replace os.open without making the dir_fd support check fail.

    ``os.open in os.supports_dir_fd`` is how the export chooses the
    descriptor path. A bare patch is a different object, so the check
    would take the mkstemp fallback and the test would not see the open.
    """

    def __init__(self, opener):
        self._opener = opener
        self._patches = (
            mock.patch("lantern.v1.os.supports_dir_fd", frozenset({opener})),
            mock.patch("lantern.v1.os.open", opener),
        )

    def __enter__(self):
        for patch in self._patches:
            patch.start()
        return self._opener

    def __exit__(self, *exc):
        for patch in reversed(self._patches):
            patch.stop()
        return False


def _make_junction(link: Path, target: Path) -> None:
    completed = subprocess.run(
        ["cmd", "/c", "mklink", "/J", str(link), str(target)],
        capture_output=True, text=True, check=False,
    )
    if completed.returncode != 0 or not link.exists():
        raise unittest.SkipTest(completed.stderr.strip() or "mklink /J failed")


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

    def test_a_tmp_style_ancestor_link_is_accepted_and_the_link_itself_is_refused(self):
        # macOS /tmp is a symlink to /private/tmp. A file in a real directory
        # under that link is allowed. A file whose parent is the link itself
        # is refused. This tree is the same shape, under the test root.
        private = self.root / "private"
        private.mkdir()
        real_tmp = private / "tmp"
        real_tmp.mkdir()
        tmp_link = self.root / "tmp"
        tmp_link.symlink_to(real_tmp, target_is_directory=True)
        child = tmp_link / "child"
        child.mkdir()
        written = write_export_file(str(child / "out.json"), b"ok", force=False)
        self.assertEqual(Path(written).read_bytes(), b"ok")
        self.assertEqual((real_tmp / "child" / "out.json").read_bytes(), b"ok")
        with self.assertRaises(ExportPathError) as caught:
            write_export_file(str(tmp_link / "direct.json"), b"no", force=False)
        self.assertIn("directory itself", str(caught.exception))
        self.assertFalse((real_tmp / "direct.json").exists())
        readme = Path(__file__).resolve().parents[1].joinpath("README.md").read_text(encoding="utf-8")
        self.assertIn("/private/tmp", readme)
        self.assertIn("export directory itself", readme)

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
        if os.name != "nt":
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

    def test_a_final_directory_symlink_is_refused_before_it_is_opened(self):
        target = self.root / "target"
        target.mkdir()
        linked = self.root / "linked"
        linked.symlink_to(target, target_is_directory=True)

        def opener(*_args, **_kwargs):
            raise AssertionError("directory was opened")

        with mock.patch("lantern.v1.os.open", opener):
            with self.assertRaises(ExportPathError) as caught:
                write_export_file(str(linked / "out.json"), b"x", force=False)
        self.assertIn("directory itself", str(caught.exception))
        self.assertFalse((target / "out.json").exists())

    def test_cleanup_does_not_follow_a_directory_swapped_during_the_write(self):
        if os.open not in getattr(os, "supports_dir_fd", ()):
            self.skipTest("dir_fd is required to clean up the opened directory")
        slot = self.root / "slot"
        slot.mkdir()
        decoy = self.root / "decoy"
        decoy.mkdir()
        (decoy / "out.json").write_bytes(b"keep")
        swapped = {"done": False}

        def write(fd, data):
            if not swapped["done"]:
                swapped["done"] = True
                os.rename(slot, self.root / "slot-real")
                os.symlink(decoy, slot, target_is_directory=True)
                raise KeyboardInterrupt
            return os.write(fd, data)

        with mock.patch("lantern.v1.os.write", write):
            with self.assertRaises(KeyboardInterrupt):
                write_export_file(str(slot / "out.json"), b"new", force=False)
        self.assertEqual((decoy / "out.json").read_bytes(), b"keep")
        self.assertFalse((self.root / "slot-real" / "out.json").exists())

    def test_an_interrupt_inside_temp_open_removes_the_new_file(self):
        if os.open not in getattr(os, "supports_dir_fd", ()):
            self.skipTest("dir_fd is required for the POSIX temp file")
        folder = self.root / "folder"
        folder.mkdir()
        dest = folder / "out.json"
        dest.write_bytes(b"old")
        real_open = os.open

        def opener(path, flags, mode=0o777, *, dir_fd=None):
            fd = real_open(path, flags, mode, dir_fd=dir_fd)
            if isinstance(path, str) and path.startswith(".lantern-export-"):
                os.close(fd)
                raise ExportInterrupted(signal.SIGINT)
            return fd

        with _OpenPatch(opener):
            with self.assertRaises(SystemExit) as caught:
                write_export_file(str(dest), b"new", force=True)
        self.assertEqual(caught.exception.code, 130)
        self.assertEqual(list(folder.glob(".lantern-export-*")), [])
        self.assertEqual(dest.read_bytes(), b"old")

    def test_replace_stays_on_the_opened_directory_after_a_swap(self):
        if os.open not in getattr(os, "supports_dir_fd", ()):
            self.skipTest("dir_fd is required for the POSIX replace")
        slot = self.root / "slot"
        slot.mkdir()
        decoy = self.root / "decoy"
        decoy.mkdir()
        (decoy / "out.json").write_bytes(b"keep")
        dest = slot / "out.json"
        dest.write_bytes(b"old")
        real_replace = os.replace

        def replace(src, dst, *args, **kwargs):
            self.assertIsNotNone(kwargs.get("src_dir_fd"))
            self.assertIsNotNone(kwargs.get("dst_dir_fd"))
            if not getattr(replace, "swapped", False):
                replace.swapped = True
                os.rename(slot, self.root / "slot-real")
                os.symlink(decoy, slot, target_is_directory=True)
            return real_replace(src, dst, *args, **kwargs)

        with mock.patch("lantern.v1.os.replace", replace):
            write_export_file(str(dest), b"new", force=True)
        self.assertEqual((self.root / "slot-real" / "out.json").read_bytes(), b"new")
        self.assertEqual((decoy / "out.json").read_bytes(), b"keep")

    def test_the_temp_file_is_created_through_the_directory_fd(self):
        if os.open not in getattr(os, "supports_dir_fd", ()) or not hasattr(os, "O_NOFOLLOW"):
            self.skipTest("POSIX dir_fd and O_NOFOLLOW")
        folder = self.root / "folder"
        folder.mkdir()
        (folder / "out.json").write_bytes(b"old")
        secret = self.root / "secret"
        planted = folder / ".lantern-export-fixed"
        planted.symlink_to(secret)
        real_open = os.open
        seen = []

        def opener(path, flags, mode=0o777, *, dir_fd=None):
            if isinstance(path, str) and path.startswith(".lantern-export-"):
                seen.append(flags)
                self.assertIsNotNone(dir_fd)
                self.assertTrue(flags & os.O_NOFOLLOW)
                self.assertTrue(flags & os.O_EXCL)
            return real_open(path, flags, mode, dir_fd=dir_fd)

        with mock.patch("lantern.v1.secrets.token_hex", return_value="fixed"):
            with mock.patch("lantern.v1.tempfile.mkstemp", side_effect=AssertionError("mkstemp")):
                with _OpenPatch(opener):
                    with self.assertRaises(ExportPathError):
                        write_export_file(str(folder / "out.json"), b"new", force=True)
        self.assertTrue(seen)
        self.assertFalse(secret.exists())
        self.assertEqual((folder / "out.json").read_bytes(), b"old")

    def test_windows_reparse_and_case_are_best_effort(self):
        if os.name != "nt":
            self.skipTest("Windows reparse points and 8.3 names")
        folder = self.root / "Folder"
        folder.mkdir()
        dest = folder / "out.json"
        write_export_file(str(dest), b"ok", force=False)
        other_case = Path(str(dest).swapcase()) if str(dest) != str(dest).swapcase() else dest
        write_export_file(str(other_case), b"case", force=True)
        self.assertEqual(dest.read_bytes(), b"case")

        short = _short_path(folder)
        if short is not None:
            write_export_file(str(Path(short) / "out.json"), b"short", force=True)
            self.assertEqual(dest.read_bytes(), b"short")

        target = self.root / "junction-target"
        target.mkdir()
        junction = self.root / "junction"
        _make_junction(junction, target)
        with self.assertRaises(ExportPathError) as caught:
            write_export_file(str(junction / "out.json"), b"no", force=False)
        self.assertIn("directory itself", str(caught.exception))
        self.assertFalse((target / "out.json").exists())

        real = self.root / "real-parent"
        real.mkdir()
        ancestor = self.root / "ancestor-junction"
        _make_junction(ancestor, real)
        child = ancestor / "child"
        child.mkdir()
        write_export_file(str(child / "out.json"), b"ok", force=False)
        self.assertEqual((real / "child" / "out.json").read_bytes(), b"ok")


if __name__ == "__main__":
    unittest.main()

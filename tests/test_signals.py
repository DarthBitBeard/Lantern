"""Ctrl-C, the export signal window, and SIGTERM for the dashboard.

Localhost and fake data only. SIGINT and SIGTERM to a subprocess are skipped
on Windows, where those signals do not interrupt a child the same way.
"""

import io
import os
import select
import shutil
import signal
import socket
import subprocess
import sys
import tempfile
import textwrap
import time
import unittest
from pathlib import Path
from unittest import mock

from lantern import cli, v1
from lantern.store import connect, save_scan

ROOT = Path(__file__).resolve().parent.parent


def _device():
    return {
        "ip": "10.9.0.5", "mac": "aa:bb:cc:dd:ee:10", "hostname": "box",
        "label": None, "open_ports": [], "findings": [],
    }


class InterruptTests(unittest.TestCase):
    def setUp(self):
        if os.name == "nt":
            self.skipTest("SIGINT to a subprocess is not used on Windows")
        self.tmp = tempfile.TemporaryDirectory()
        self.db = str(Path(self.tmp.name) / "t.db")
        conn = connect(self.db)
        save_scan(conn, "10.9.0.0/24", [_device()])
        conn.close()

    def tearDown(self):
        self.tmp.cleanup()

    def _interrupt(self, code: str):
        ready_r, ready_w = os.pipe()
        proc = subprocess.Popen(
            [sys.executable, "-c", code],
            cwd=ROOT,
            pass_fds=(ready_w,),
            env={**os.environ, "LANTERN_DB": self.db, "LANTERN_READY": str(ready_w)},
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
        )
        os.close(ready_w)
        try:
            if not select.select([ready_r], [], [], 5)[0]:
                proc.kill()
                proc.wait(timeout=5)
                self.fail("child was not ready")
            os.read(ready_r, 1)
            os.kill(proc.pid, signal.SIGINT)
            try:
                proc.wait(timeout=5)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=5)
                self.fail("process did not exit after SIGINT")
        finally:
            os.close(ready_r)
        err = proc.stderr.read().decode()
        self.assertEqual(proc.returncode, 130, err)
        self.assertNotIn("Traceback", err)
        self.assertIn("interrupted", err)
        proc.stdout.close()
        proc.stderr.close()
        again = connect(self.db)
        again.close()

    def test_sigint_during_scan_demo_exits_130(self):
        self._interrupt(textwrap.dedent("""
            import os, time
            from lantern import cli
            def pause(*args, **kwargs):
                os.write(int(os.environ["LANTERN_READY"]), b"1")
                time.sleep(30)
            import lantern.cli as cli_mod
            cli_mod.scan_subnet = pause
            raise SystemExit(cli.main(["--db", os.environ["LANTERN_DB"], "scan", "--demo"]))
        """))

    def test_sigint_during_report_exits_130(self):
        self._interrupt(textwrap.dedent("""
            import os, time
            from lantern import cli
            def pause(*args, **kwargs):
                os.write(int(os.environ["LANTERN_READY"]), b"1")
                time.sleep(30)
            import lantern.cli as cli_mod
            cli_mod.load_scan_with_diff = pause
            raise SystemExit(cli.main(["--db", os.environ["LANTERN_DB"], "report"]))
        """))

    def test_sigint_during_export_exits_130(self):
        self._interrupt(textwrap.dedent("""
            import os, time
            from lantern import cli
            def pause(*args, **kwargs):
                os.write(int(os.environ["LANTERN_READY"]), b"1")
                time.sleep(30)
            import lantern.v1 as v1
            v1.render_export = pause
            raise SystemExit(cli.main([
                "--db", os.environ["LANTERN_DB"], "export", "--what", "devices",
            ]))
        """))


def _real_tempdir():
    """A private directory. An ancestor may be a symlink; the last component is not."""
    return tempfile.mkdtemp()


class ExportWindowTests(unittest.TestCase):
    def test_interrupt_during_create_removes_the_new_file(self):
        tmp = _real_tempdir()
        self.addCleanup(shutil.rmtree, tmp, True)
        dest = Path(tmp) / "out.json"
        real = os.open

        def boom(path, flags, *args, **kwargs):
            fd = real(path, flags, *args, **kwargs)
            if flags & os.O_CREAT:
                os.close(fd)
                raise KeyboardInterrupt
            return fd

        with mock.patch("lantern.v1.os.open", boom):
            with self.assertRaises(KeyboardInterrupt):
                v1.write_export_file(str(dest), b"{}", force=False)
        self.assertFalse(dest.exists())
        self.assertEqual(list(Path(tmp).glob(".lantern-export-*")), [])

    def test_interrupt_during_mkstemp_removes_only_that_temp_file(self):
        tmp = _real_tempdir()
        self.addCleanup(shutil.rmtree, tmp, True)
        dest = Path(tmp) / "out.json"
        dest.write_bytes(b"old")
        other = Path(tmp) / ".lantern-export-keep"
        other.write_bytes(b"keep")

        def boom(_fd, _payload):
            raise KeyboardInterrupt

        with mock.patch("lantern.v1._write_fd", boom):
            with self.assertRaises(KeyboardInterrupt):
                v1.write_export_file(str(dest), b"new", force=True)
        self.assertEqual(dest.read_bytes(), b"old")
        self.assertEqual(other.read_bytes(), b"keep")
        self.assertEqual(list(Path(tmp).glob(".lantern-export-*")), [other])

    def test_sigint_in_the_create_window_is_delivered_after_the_path_is_recorded(self):
        """A real SIGINT while the new file exists, in a one-thread child.

        The signal has to stay pending until the path is recorded. Removing
        the mask delivers it inside ``os.open``, and recording the path
        after the unblock leaves the file behind.
        """
        if not hasattr(signal, "pthread_sigmask"):
            self.skipTest("pthread_sigmask is POSIX-only")
        tmp = _real_tempdir()
        self.addCleanup(shutil.rmtree, tmp, True)
        code = textwrap.dedent("""
            import os, signal, sys
            from pathlib import Path
            from lantern import v1

            dest = Path(sys.argv[1]) / "out.json"
            real = os.open
            saw = {}

            def opening(path, flags, *args, **kwargs):
                fd = real(path, flags, *args, **kwargs)
                if flags & os.O_CREAT:
                    held = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                    saw["blocked"] = signal.SIGINT in held
                    os.kill(os.getpid(), signal.SIGINT)
                    saw["pending"] = True
                return fd

            v1.os.open = opening
            try:
                v1.write_export_file(str(dest), b"{}", force=False)
                print("code=none")
            except SystemExit as exc:
                print(f"code={exc.code}")
            print(f"blocked={saw.get('blocked')}")
            print(f"pending={saw.get('pending')}")
            print(f"exists={dest.exists()}")
            print(f"temps={len(list(Path(sys.argv[1]).glob('.lantern-export-*')))}")
        """)
        proc = subprocess.run(
            [sys.executable, "-c", code, tmp],
            cwd=ROOT, check=False, capture_output=True, text=True, timeout=10,
        )
        out = proc.stdout
        self.assertEqual(proc.returncode, 0, proc.stderr + out)
        self.assertIn("code=130", out)
        self.assertIn("blocked=True", out)
        self.assertIn("pending=True", out)
        self.assertIn("exists=False", out)
        self.assertIn("temps=0", out)

    def test_sigint_in_the_temp_window_is_delivered_after_that_name_is_recorded(self):
        if not hasattr(signal, "pthread_sigmask"):
            self.skipTest("pthread_sigmask is POSIX-only")
        tmp = _real_tempdir()
        self.addCleanup(shutil.rmtree, tmp, True)
        code = textwrap.dedent("""
            import os, signal, sys, tempfile
            from pathlib import Path
            from lantern import v1

            folder = Path(sys.argv[1])
            dest = folder / "out.json"
            dest.write_bytes(b"old")
            real = os.open
            saw = {}

            def opening(path, flags, *args, **kwargs):
                fd = real(path, flags, *args, **kwargs)
                if os.path.basename(str(path)).startswith(".lantern-export-"):
                    held = signal.pthread_sigmask(signal.SIG_BLOCK, set())
                    saw["blocked"] = signal.SIGINT in held
                    os.kill(os.getpid(), signal.SIGINT)
                    saw["pending"] = True
                return fd

            v1.os.open = opening
            try:
                v1.write_export_file(str(dest), b"new", force=True)
                print("code=none")
            except SystemExit as exc:
                print(f"code={exc.code}")
            temps = [path.name for path in folder.glob(".lantern-export-*")]
            print(f"blocked={saw.get('blocked')}")
            print(f"pending={saw.get('pending')}")
            print(f"old={dest.read_bytes() == b'old'}")
            print(f"temps={temps}")
        """)
        proc = subprocess.run(
            [sys.executable, "-c", code, tmp],
            cwd=ROOT, check=False, capture_output=True, text=True, timeout=10,
        )
        out = proc.stdout
        self.assertEqual(proc.returncode, 0, proc.stderr + out)
        self.assertIn("code=130", out)
        self.assertIn("blocked=True", out)
        self.assertIn("pending=True", out)
        self.assertIn("old=True", out)
        self.assertIn("temps=[]", out)

    def test_export_interrupted_during_create_removes_the_new_file(self):
        tmp = _real_tempdir()
        self.addCleanup(shutil.rmtree, tmp, True)
        dest = Path(tmp) / "out.json"
        real = os.open

        def boom(path, flags, *args, **kwargs):
            fd = real(path, flags, *args, **kwargs)
            if flags & os.O_CREAT:
                os.close(fd)
                raise v1.ExportInterrupted(signal.SIGINT)
            return fd

        with mock.patch("lantern.v1.os.open", boom):
            with self.assertRaises(SystemExit) as caught:
                v1.write_export_file(str(dest), b"{}", force=False)
        self.assertEqual(caught.exception.code, 130)
        self.assertFalse(dest.exists())

    def test_a_mask_the_caller_held_is_still_held(self):
        if not hasattr(signal, "pthread_sigmask"):
            self.skipTest("pthread_sigmask is POSIX-only")
        tmp = _real_tempdir()
        self.addCleanup(shutil.rmtree, tmp, True)
        dest = Path(tmp) / "out.json"
        previous = signal.pthread_sigmask(signal.SIG_BLOCK, {signal.SIGINT})
        try:
            v1.write_export_file(str(dest), b"{}", force=False)
            current = signal.pthread_sigmask(signal.SIG_BLOCK, [])
            self.assertIn(signal.SIGINT, current)
        finally:
            signal.pthread_sigmask(signal.SIG_SETMASK, previous)

    def test_signal_mask_is_restored(self):
        if not hasattr(signal, "pthread_sigmask"):
            self.skipTest("pthread_sigmask is POSIX-only")
        tmp = _real_tempdir()
        self.addCleanup(shutil.rmtree, tmp, True)
        dest = Path(tmp) / "out.json"
        before = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        v1.write_export_file(str(dest), b"{}", force=False)
        after = signal.pthread_sigmask(signal.SIG_BLOCK, [])
        self.assertEqual(before, after)


class ConnectInterruptTests(unittest.TestCase):
    def test_ctrl_c_during_connect_exits_130(self):
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "t.db")
            err = io.StringIO()
            with mock.patch("lantern.cli.connect", side_effect=KeyboardInterrupt), \
                    mock.patch("sys.stderr", err):
                code = cli.main(["--db", db, "history"])
        self.assertEqual(code, 130)
        self.assertIn("interrupted", err.getvalue())
        self.assertNotIn("Traceback", err.getvalue())


class WebTermTests(unittest.TestCase):
    def test_sigterm_stops_the_dashboard_and_releases_the_port(self):
        if os.name == "nt":
            self.skipTest("SIGTERM to a subprocess is not used on Windows")
        with tempfile.TemporaryDirectory() as tmp:
            db = str(Path(tmp) / "t.db")
            token = Path(tmp) / "token"
            token.write_text("a" * 32, encoding="utf-8")
            os.chmod(token, 0o600)
            probe = socket.socket()
            probe.bind(("127.0.0.1", 0))
            chosen = probe.getsockname()[1]
            probe.close()
            proc = subprocess.Popen(
                [sys.executable, "-m", "lantern", "--db", db, "web", "--port", str(chosen)],
                cwd=ROOT,
                env={**os.environ, "LANTERN_API_TOKEN_FILE": str(token)},
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                text=True,
            )
            port = None
            deadline = time.monotonic() + 5
            lines = []
            while time.monotonic() < deadline and port is None:
                line = proc.stdout.readline()
                if not line:
                    break
                lines.append(line)
                if "127.0.0.1:" in line:
                    port = int(line.split("127.0.0.1:")[1].split("/")[0])
            self.assertIsNotNone(port, "".join(lines))
            os.kill(proc.pid, signal.SIGTERM)
            try:
                proc.wait(timeout=3)
            except subprocess.TimeoutExpired:
                proc.kill()
                proc.wait(timeout=3)
                self.fail("web did not exit after SIGTERM")
            self.assertEqual(proc.returncode, 0, "".join(lines))
            proc.stdout.close()
            sock = socket.socket()
            try:
                sock.bind(("127.0.0.1", port))
            finally:
                sock.close()

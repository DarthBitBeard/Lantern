"""The test runner must not report success when something was hidden."""

import subprocess
import sys
import tempfile
import textwrap
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
RUNNER = ROOT / "tests" / "run_tests.py"


def _run(directory: Path) -> subprocess.CompletedProcess:
    return subprocess.run(
        [sys.executable, str(RUNNER), str(directory)],
        cwd=ROOT, check=False, capture_output=True, text=True, timeout=60,
    )


class RunnerTests(unittest.TestCase):
    def test_a_leaked_connection_fails_the_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "test_leak.py").write_text(textwrap.dedent("""
                import sqlite3
                import unittest

                class LeakTests(unittest.TestCase):
                    def test_leaks_a_connection(self):
                        # SQLite warns about this on 3.13. The file warns on
                        # every supported Python, through the same hook.
                        self.conn = sqlite3.connect(":memory:")
                        self.handle = open(__file__, "rb")
            """), encoding="utf-8")
            proc = _run(Path(tmp))
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)

    def test_a_thread_exception_fails_the_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "test_thread.py").write_text(textwrap.dedent("""
                import threading
                import unittest

                class ThreadTests(unittest.TestCase):
                    def test_a_thread_raises(self):
                        def boom():
                            raise RuntimeError("boom")
                        thread = threading.Thread(target=boom)
                        thread.start()
                        thread.join()
            """), encoding="utf-8")
            proc = _run(Path(tmp))
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("boom", proc.stderr)

    def test_a_windows_socket_error_in_a_thread_fails_the_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "test_socket.py").write_text(textwrap.dedent("""
                import threading
                import unittest

                class SocketTests(unittest.TestCase):
                    def test_serve_forever_raises_winerror_10038(self):
                        def serve_forever():
                            err = OSError(10038, "socket operation on non-socket")
                            err.winerror = 10038
                            raise err
                        thread = threading.Thread(target=serve_forever)
                        thread.start()
                        thread.join()
            """), encoding="utf-8")
            proc = _run(Path(tmp))
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("10038", proc.stderr)

    def test_zero_tests_fails_the_run(self):
        with tempfile.TemporaryDirectory() as tmp:
            Path(tmp, "notes.py").write_text("x = 1\n", encoding="utf-8")
            proc = _run(Path(tmp))
        self.assertNotEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        self.assertIn("no tests discovered", proc.stderr)

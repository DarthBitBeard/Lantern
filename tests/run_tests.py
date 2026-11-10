"""Run all Lantern tests offline. Usage: python3 tests/run_tests.py

Discovers every tests/test_*.py (unittest), then smoke-tests the CLI
demo in a fresh process against a temporary database.

A run is a failure when a test fails, when no tests were discovered,
when a thread raises, or when an unraisable exception is reported
(including an unclosed database). ResourceWarning is an error here so
a leaked connection cannot pass quietly.
"""

import gc
import sys
import tempfile
import threading
import traceback
import unittest
import warnings
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent
_PROBLEMS: list[str] = []


def _remember(kind: str, text: str) -> None:
    _PROBLEMS.append(f"{kind}: {text}")


def _unraisable(unraisable) -> None:
    err = unraisable.exc_value
    _remember("unraisable", f"{unraisable.err_msg or 'exception'}: {err!r}")


def _thread_exception(args) -> None:
    # Closing a test server's socket on Windows wakes serve_forever's select
    # with WSAENOTSOCK (10038). The server has already stopped; the exception
    # is the selector noticing. Every other thread exception still fails the run.
    if isinstance(args.exc_value, OSError) and getattr(args.exc_value, "winerror", None) == 10038:
        frames = "".join(traceback.format_tb(args.exc_traceback))
        if "serve_forever" in frames:
            return
    text = "".join(traceback.format_exception(args.exc_type, args.exc_value, args.exc_traceback))
    _remember("thread", text.rstrip())


def main(argv: list[str] | None = None) -> None:
    args = list(sys.argv[1:] if argv is None else argv)
    custom = bool(args)
    tests_dir = Path(args[0]) if args else ROOT / "tests"
    sys.path.insert(0, str(ROOT))
    warnings.simplefilter("error", ResourceWarning)
    sys.unraisablehook = _unraisable
    threading.excepthook = _thread_exception
    _PROBLEMS.clear()

    suite = unittest.defaultTestLoader.discover(str(tests_dir))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    gc.collect()
    failed = not result.wasSuccessful() or result.testsRun == 0 or bool(_PROBLEMS)
    if result.testsRun == 0:
        print("no tests discovered", file=sys.stderr)
    for problem in _PROBLEMS:
        print(problem, file=sys.stderr)
    if failed:
        raise SystemExit(1)
    if custom:
        # A self-test points at a temporary directory and does not run the demo.
        print("all tests passed")
        return

    with tempfile.TemporaryDirectory() as tmp:
        import subprocess

        proc = subprocess.run(
            [sys.executable, "-m", "lantern", "demo", "--db", str(Path(tmp) / "lantern.db")],
            cwd=ROOT, check=False, capture_output=True, text=True,
        )
    print(proc.stdout, end="")
    if proc.returncode != 0:
        print(proc.stderr, end="", file=sys.stderr)
        raise SystemExit(proc.returncode)
    print("all tests passed")


if __name__ == "__main__":
    main()

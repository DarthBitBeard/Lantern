"""Run all Lantern tests offline. Usage: python3 tests/run_tests.py

Discovers every tests/test_*.py (unittest), then smoke-tests the CLI
demo in a fresh process against a temporary database.
"""

import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    sys.path.insert(0, str(ROOT))
    suite = unittest.defaultTestLoader.discover(str(ROOT / "tests"))
    result = unittest.TextTestRunner(verbosity=1).run(suite)
    if not result.wasSuccessful():
        raise SystemExit(1)

    with tempfile.TemporaryDirectory() as tmp:
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

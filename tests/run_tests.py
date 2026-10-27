"""Run all Lantern tests offline. Usage: python3 tests/run_tests.py"""

import subprocess
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parent.parent


def main():
    # Risk and safety tests: import and run the plain functions.
    sys.path.insert(0, str(ROOT))
    sys.path.insert(0, str(ROOT / "tests"))
    from test_risks import (  # noqa: E402
        test_public_subnet_refused,
        test_telnet_is_critical,
        test_too_large_subnet_refused,
    )

    test_telnet_is_critical()
    test_public_subnet_refused()
    test_too_large_subnet_refused()
    print("risk tests passed")

    # Web dashboard tests: separate process, temporary database.
    result = subprocess.run(
        [sys.executable, str(ROOT / "tests" / "test_web.py")],
        check=False, capture_output=True, text=True,
    )
    print(result.stdout, end="")
    if result.returncode != 0:
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(result.returncode)

    # CLI demo smoke test, temporary database.
    result = subprocess.run(
        [sys.executable, "-m", "lantern", "demo", "--db", "/tmp/lantern-ci-test.db"],
        cwd=ROOT, check=False, capture_output=True, text=True,
    )
    print(result.stdout, end="")
    if result.returncode != 0:
        print(result.stderr, end="", file=sys.stderr)
        raise SystemExit(result.returncode)
    print("all tests passed")


if __name__ == "__main__":
    main()

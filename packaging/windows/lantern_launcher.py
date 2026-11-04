"""Entry point that PyInstaller freezes into lantern.exe. Same as `python -m lantern`."""

import sys

from lantern.cli import main

if __name__ == "__main__":
    sys.exit(main())

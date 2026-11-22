"""Entry point that PyInstaller freezes into lantern.exe and lantern-tray.exe.

lantern.exe is the console program, the same as `python -m lantern`.

lantern-tray.exe is the same code built without a console window. It runs
the dashboard from the system tray (`lantern web --tray`). With no console
there is nowhere to print an error, so a failed start is shown in a message
box instead of vanishing.
"""

import io
import os
import sys

from lantern.cli import main

TRAY_EXE = "lantern-tray"


def _is_tray_build() -> bool:
    name = os.path.splitext(os.path.basename(sys.executable))[0].lower()
    return name == TRAY_EXE


def _default_db() -> str:
    base = os.environ.get("LOCALAPPDATA") or os.path.expanduser("~")
    return os.path.join(base, "Lantern", "lantern.db")


def _show_error(text: str) -> None:
    try:
        import ctypes

        ctypes.windll.user32.MessageBoxW(None, text, "Lantern", 0x10)  # MB_ICONERROR
    except Exception:
        pass


def run_tray() -> int:
    # A windowed program has no stdout or stderr. Give print() something to
    # write to, and keep what was written so a failure can be shown.
    captured = io.StringIO()
    sys.stdout = captured
    sys.stderr = captured
    argv = sys.argv[1:] or ["web", "--tray", "--open", "--db", _default_db()]
    code = main(argv)
    if code:
        message = captured.getvalue().strip().splitlines()
        detail = message[-1] if message else "Lantern stopped unexpectedly."
        _show_error(f"Lantern could not start.\n\n{detail}")
    return code


if __name__ == "__main__":
    sys.exit(run_tray() if _is_tray_build() else main())

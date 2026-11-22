# PyInstaller spec for the installer's one-folder build.
#
# One analysis, two programs in one folder, so they share `_internal`:
#   lantern.exe       console program (the command line)
#   lantern-tray.exe  same code, no console window: runs the dashboard from
#                     the system tray (see lantern_launcher.py)
#
# Build (from the repository root):
#   python -m PyInstaller --noconfirm --clean --distpath build/dir \
#     --workpath build/pyi-onedir packaging/windows/lantern.spec

import os

from PyInstaller.utils.hooks import collect_data_files

HERE = SPECPATH  # noqa: F821 - provided by PyInstaller
ICON = os.path.join(HERE, "lantern.ico")

a = Analysis(  # noqa: F821
    [os.path.join(HERE, "lantern_launcher.py")],
    pathex=[os.path.abspath(os.path.join(HERE, "..", ".."))],
    datas=collect_data_files("lantern"),
)
pyz = PYZ(a.pure)  # noqa: F821

console = EXE(  # noqa: F821
    pyz, a.scripts, [], exclude_binaries=True,
    name="lantern", console=True, icon=ICON,
)
tray = EXE(  # noqa: F821
    pyz, a.scripts, [], exclude_binaries=True,
    name="lantern-tray", console=False, icon=ICON,
)
coll = COLLECT(  # noqa: F821
    console, tray, a.binaries, a.datas,
    name="lantern",
)

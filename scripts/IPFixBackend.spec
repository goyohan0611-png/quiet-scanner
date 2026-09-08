# -*- mode: python ; coding: utf-8 -*-
#
# Builds must go through this file.
#     python -m PyInstaller --noconfirm --clean ^
#         --distpath dist --workpath build scripts/IPFixBackend.spec
#
#  Always pass the output locations (--distpath·--workpath) as well. Without them
#  PyInstaller drops dist next to the spec (scripts/), build_electron.bat goes
#  looking for dist at the root, and dies with "vendor database was not bundled".
#
# Hand electron-backend.py straight to PyInstaller and it overwrites this file and
# empties datas. Then the vendor DB and the device book never make it into the exe,
# and on site every vendor comes out as "Unknown".

import os

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['scapy.layers.all']
hiddenimports += collect_submodules('scapy')

# Paths resolve against **the directory this spec file lives in**, not the directory
# you called it from (CWD) — assuming otherwise and writing them relative to the root
# once killed a build hunting for scripts/src/... . Pin the root via SPECPATH, absolute.
ROOT = os.path.abspath(os.path.join(SPECPATH, os.pardir))

def at(*parts):
    return os.path.join(ROOT, *parts)

datas = [
    (at('src', 'oui.dat.gz'), '.'),        # IEEE vendor registry, 58,471 entries
    (at('src', 'device-book.json'), '.'),  # MAC prefix -> device type
]

a = Analysis(
    [at('src', 'electron-backend.py')],
    # electron-backend.py imports IPFixStudio. Both live in src/, so point the
    # search path there.
    pathex=[at('src')],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # Electron draws the UI. Drop tkinter and the heavy numeric libraries.
    excludes=['torch', 'matplotlib', 'pygame', 'tkinter', 'PIL', 'numpy', 'pandas'],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name='IPFixBackend',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    console=True,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)
coll = COLLECT(
    exe,
    a.binaries,
    a.datas,
    strip=False,
    upx=True,
    upx_exclude=[],
    name='IPFixBackend',
)

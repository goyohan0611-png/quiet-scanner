# -*- mode: python ; coding: utf-8 -*-
#
# 이 파일을 반드시 거쳐서 빌드해야 한다.
#     python -m PyInstaller --noconfirm --clean ^
#         --distpath dist --workpath build scripts/IPFixBackend.spec
#
#  출력 자리(--distpath·--workpath)를 반드시 같이 넘길 것. 안 그러면 PyInstaller
#  가 spec 옆(scripts/)에 dist 를 만들고, build_electron.bat 은 뿌리의 dist 를
#  찾다가 "vendor database was not bundled" 로 죽는다.
#
# electron-backend.py 를 PyInstaller 에 직접 넘기면 이 파일이 새로 덮어써지고
# datas 가 비워진다. 그러면 제조사 DB 와 장비 사전이 exe 에 안 들어가고,
# 현장에서 제조사가 전부 "미상" 으로 나온다.

import os

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['scapy.layers.all']
hiddenimports += collect_submodules('scapy')

# 경로는 **이 spec 파일이 있는 자리**를 기준으로 읽힌다. 부른 자리(CWD)가
# 아니다 — 그렇게 알고 뿌리 기준으로 적었다가 scripts/src/... 를 찾으며
# 빌드가 죽은 적이 있다. SPECPATH 로 뿌리를 잡아 절대 경로로 못박는다.
ROOT = os.path.abspath(os.path.join(SPECPATH, os.pardir))

def at(*parts):
    return os.path.join(ROOT, *parts)

datas = [
    (at('src', 'oui.dat.gz'), '.'),        # IEEE 제조사 등록부 58,471개
    (at('src', 'device-book.json'), '.'),  # MAC 앞자리 -> 장비 종류
]

a = Analysis(
    [at('src', 'electron-backend.py')],
    # electron-backend.py 가 IPFixStudio 를 import 한다. 둘 다 src/ 에 있으니
    # 그 자리를 찾을 곳으로 넣어 준다.
    pathex=[at('src')],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    # 화면은 일렉트론이 그린다. tkinter 와 무거운 계산 라이브러리는 뺀다.
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

# -*- mode: python ; coding: utf-8 -*-
#
# 이 파일을 반드시 거쳐서 빌드해야 한다.
#     python -m PyInstaller --noconfirm --clean scripts/IPFixBackend.spec
#     (반드시 프로젝트 뿌리에서 부를 것 — 아래 경로가 뿌리 기준이다)
#
# electron-backend.py 를 PyInstaller 에 직접 넘기면 이 파일이 새로 덮어써지고
# datas 가 비워진다. 그러면 제조사 DB 와 장비 사전이 exe 에 안 들어가고,
# 현장에서 제조사가 전부 "미상" 으로 나온다.

from PyInstaller.utils.hooks import collect_submodules

hiddenimports = ['scapy.layers.all']
hiddenimports += collect_submodules('scapy')

# 경로는 이 파일이 아니라 **PyInstaller 를 부른 자리**를 기준으로 읽힌다.
# build_electron.bat 이 프로젝트 뿌리에서 부르므로 뿌리 기준으로 적는다.
datas = [
    ('src/oui.dat.gz', '.'),        # IEEE 제조사 등록부 58,471개
    ('src/장비사전.json', '.'),      # MAC 앞자리 -> 장비 종류
]

a = Analysis(
    ['src/electron-backend.py'],
    pathex=[],
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

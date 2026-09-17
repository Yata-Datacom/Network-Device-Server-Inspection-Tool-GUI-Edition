# -*- mode: python ; coding: utf-8 -*-
# Network Inspection System V3 - For Yata (个人版：巡检 + 流量测试)
# 基于 net_inspect_gui.py 的独立 exe 打包配置（onefile, 无控制台窗口）

a = Analysis(
    ['net_inspect_gui.py'],
    pathex=[],
    binaries=[],
    datas=[],
    hiddenimports=[],
    hookspath=[],
    hooksconfig={},
    runtime_hooks=[],
    excludes=[],
    noarchive=False,
    optimize=0,
)
pyz = PYZ(a.pure)

exe = EXE(
    pyz,
    a.scripts,
    a.binaries,
    a.datas,
    [],
    name='巡检Network Inspection System V3 - For Yata',
    icon='app_icon.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=True,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

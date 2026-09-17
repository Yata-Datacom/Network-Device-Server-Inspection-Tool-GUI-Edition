# -*- mode: python ; coding: utf-8 -*-
# Network Inspection System V5 - For Yata（个人版：巡检 + 流量/安全/主动探测 + 环路告警）
# 入口：net_inspect_gui_v5.py（巡检工具 + 环路告警页签，onefile / 无控制台窗口）

a = Analysis(
    ['net_inspect_gui_v5.py'],
    pathex=['.'],
    binaries=[],
    datas=[],                       # rules.yaml 由程序运行首日自动释放到 exe 同目录
    hiddenimports=['yaml', 'openpyxl'],   # 这两处是函数内延迟 import，显式声明最稳
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
    name='巡检Network Inspection System V5 - For Yata',
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

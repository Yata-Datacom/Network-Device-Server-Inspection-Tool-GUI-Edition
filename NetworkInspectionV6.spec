# -*- mode: python ; coding: utf-8 -*-
# Network Inspection Studio 6.1 — NADT-style V6 shell over the V5 engine

a = Analysis(
    ['net_inspect_v6.py'],
    pathex=['v5'],
    binaries=[],
    datas=[('rules.yaml', '.')],
    hiddenimports=[
        'net_inspect_gui_v5', 'netinspect_secrets',
        'ring_panel', 'ring_rules', 'ring_parsers', 'ring_analyze', 'ring_events',
    ],
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
    name='Network Inspection Studio 6.1',
    icon='app_icon.ico',
    debug=False,
    bootloader_ignore_signals=False,
    strip=False,
    upx=False,
    upx_exclude=[],
    runtime_tmpdir=None,
    console=False,
    disable_windowed_traceback=False,
    argv_emulation=False,
    target_arch=None,
    codesign_identity=None,
    entitlements_file=None,
)

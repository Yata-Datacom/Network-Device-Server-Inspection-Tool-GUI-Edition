"""GUI 冒烟：实例化三个版本，打印标题栏文字（能抓 NameError / 标题写错）。"""
import importlib
import os
import sys
import tkinter as tk

repo = sys.argv[1]
for mod, sub in (("net_inspect_gui", ""), ("net_inspect_gui_v5", "v5"), ("net_inspect_gui_v4", "v4")):
    sys.path.insert(0, os.path.join(repo, sub) if sub else repo)
    m = importlib.import_module(mod)
    root = tk.Tk()
    root.withdraw()
    app = m.NetworkInspectGUI(root)
    print(f"   {mod}: v{m.__version__} | 标题: {root.title()}")
    root.destroy()
    sys.modules.pop(mod, None)

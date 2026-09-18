#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Ring Alert 页签冒烟测试：隐藏窗口实例化 → 双视图切换 → 故障卡渲染（无需真设备）。"""
import os
import sys
import tkinter as tk

V5 = sys.argv[1] if len(sys.argv) > 1 else os.path.join(
    os.path.dirname(os.path.abspath(__file__)), "..", "v5")
sys.path.insert(0, V5)

root = tk.Tk()
root.withdraw()

import ring_panel as RPAN
from tkinter import ttk


def shown(w) -> bool:
    """控件是否处于 pack 布局中（ScrolledText 是复合控件，winfo_manager 不可靠）。"""
    try:
        w.pack_info()
        return True
    except Exception:
        return False

nb = ttk.Notebook(root)
panel = RPAN.RingAlertPanel(nb, None)          # app=None → 用内置兜底路径
nb.pack()

ok = []
ok.append(("panel 构建", panel is not None))
ok.append(("故障卡控件存在", hasattr(panel, "fault_text")))
ok.append(("视图变量默认=故障", panel.view_mode.get() == "fault"))
ok.append(("故障卡默认可见", shown(panel.fault_text)))
ok.append(("明细表已收起", not shown(panel.tree)))

faults = [
    {"id": "F1", "kind": "loop", "title": "二层环路（网络里有一根线接成了圈）", "severity": "high",
     "confidence": "high", "score": 80, "device": "10.21.11.193", "first": True,
     "symptoms": ["涉及端口 3 个：GE1/0/1、GE1/0/2、GE1/0/3", "广播量最高约 7244 pps"],
     "cause": "同一个 MAC 同时出现在这些端口上 → 这些端口之间被线路环接了。",
     "steps": ["先拔掉 **GE1/0/2** 的网线，等 1 分钟看广播量有没有降下来", "顺着这根线找另一端"],
     "alerts": [{"rule_id": "D13"}, {"rule_id": "D4"}]},
    {"id": "F2", "kind": "mild", "title": "终端广播异常（大概率不是环路）", "severity": "low",
     "confidence": "low", "score": 10, "device": "多处（轻微）",
     "symptoms": ["共 5 处轻微超标"], "cause": "终端在猛发广播。", "steps": ["先观察"], "alerts": []},
]
panel._render_faults(faults)
txt = panel.fault_text.get("1.0", tk.END)
ok.append(("故障卡含设备名", "10.21.11.193" in txt))
ok.append(("故障卡含处理步骤", "拔掉" in txt and "GE1/0/2" in txt))
ok.append(("故障卡含术语小抄", "术语小抄" in txt))
ok.append(("已插入标题", "先处理这个" in txt))

panel.view_mode.set("table"); panel._switch_view()
ok.append(("切到明细：表显示", shown(panel.tree)))
ok.append(("切到明细：卡收起", not shown(panel.fault_text)))
panel.view_mode.set("fault"); panel._switch_view()
ok.append(("切回故障：卡显示", shown(panel.fault_text)))

# 空结果不崩
panel._render_faults([])
ok.append(("空故障不崩", "未发现故障级问题" in panel.fault_text.get("1.0", tk.END)))

for name, good in ok:
    print(("  ✓ " if good else "  ✗ ") + name)
print("结果:", "全部通过 ✓" if all(g for _, g in ok) else "有失败 ✗")
root.destroy()

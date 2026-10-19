"""
Network Inspection Studio 6.0
=============================
A modern, NADT-style shell around the proven V5 inspection engine.

- Left rail workspaces: Overview / Single / Batch / Backup / Traffic / Security /
  Probes / Ring Alert / Profiles
- Dark navy header, page titles, summary cards and a compact status bar
- All SSH, report, backup and ring-detection logic is reused from
  ``v5/net_inspect_gui_v5.py``; this module only replaces the UI shell.
"""

from __future__ import annotations

import json
import os
import sys
import tkinter as tk
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

import netinspect_secrets as vault

__version__ = "6.2.0"

BASE_DIR = os.path.dirname(os.path.abspath(sys.executable if getattr(sys, "frozen", False) else __file__))
V5_DIR = os.path.join(BASE_DIR, "v5")
if V5_DIR not in sys.path:
    sys.path.insert(0, V5_DIR)

import net_inspect_gui_v5 as base  # noqa: E402
from net_inspect_gui_v5 import (  # noqa: E402
    ActiveTestPanel,
    NetworkInspectGUI,
    RingAlertPanel,
    SecurityTestPanel,
    TrafficTestPanel,
    setup_app_style,
)

# ── palette ──────────────────────────────────────────────────────────────
NAVY = "#0b1f3a"
NAVY2 = "#12294a"
NAVY3 = "#1b355a"
BG = "#f1f5f9"
PANEL = "#ffffff"
FG = "#0f172a"
MUTED = "#64748b"
LINE = "#dbe3ef"
ACCENT = "#2563eb"
ACCENT2 = "#1d4ed8"
GREEN = "#16a34a"
AMBER = "#d97706"
RED = "#dc2626"

NAV_ITEMS = [
    ("dashboard", "总览", "Overview", None),
    ("single", "单机巡检", "Single host", "巡检"),
    ("batch", "批量巡检", "Batch", "巡检"),
    ("backup", "配置备份", "Backup", "巡检"),
    ("testing", "测试中心", "Tests", "诊断"),
    ("traffic", "流量测试", "Traffic", "诊断"),
    ("security", "安全核查", "Security", "诊断"),
    ("active", "主动探测", "Probes", "诊断"),
    ("ring", "环路告警", "Ring alert", "诊断"),
    ("profiles", "连接档案", "Profiles", "配置"),
]


class NavItem(tk.Frame):
    """自绘导航项，选中时左侧出现蓝色强调条。"""

    def __init__(self, parent, title: str, sub: str, command):
        super().__init__(parent, bg=NAVY, cursor="hand2")
        self.command = command
        self._active = False
        self.bar = tk.Frame(self, bg=NAVY, width=4)
        self.bar.pack(side=tk.LEFT, fill=tk.Y)
        box = tk.Frame(self, bg=NAVY)
        box.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(12, 8), pady=6)
        self.title = tk.Label(box, text=title, bg=NAVY, fg="#e2e8f0",
                              font=("Microsoft YaHei UI", 10, "bold"), anchor="w")
        self.title.pack(fill=tk.X)
        self.sub = tk.Label(box, text=sub, bg=NAVY, fg="#64748b",
                            font=("Microsoft YaHei UI", 8), anchor="w")
        self.sub.pack(fill=tk.X)
        for widget in (self, box, self.title, self.sub):
            widget.bind("<Button-1>", lambda _e: self.command())
            widget.bind("<Enter>", lambda _e: self._hover(True))
            widget.bind("<Leave>", lambda _e: self._hover(False))

    def _hover(self, on: bool):
        if self._active:
            return
        bg = "#162b49" if on else NAVY
        for widget in (self, self.bar) + tuple(self.winfo_children()):
            try:
                widget.configure(bg=bg)
            except tk.TclError:
                pass
        for child in self.winfo_children():
            for sub in child.winfo_children():
                try:
                    sub.configure(bg=bg)
                except tk.TclError:
                    pass

    def set_active(self, active: bool):
        self._active = active
        bg = "#172554" if active else NAVY
        self.bar.configure(bg=ACCENT if active else NAVY)
        self.configure(bg=bg)
        for child in self.winfo_children():
            try:
                child.configure(bg=bg)
            except tk.TclError:
                pass
            for sub in child.winfo_children():
                try:
                    sub.configure(bg=bg)
                except tk.TclError:
                    pass
        self.title.configure(fg="white" if active else "#e2e8f0")
        self.sub.configure(fg="#93c5fd" if active else "#64748b")


class InspectionStudio(NetworkInspectGUI):
    """V6 UI shell. All inspection work is delegated to the V5 engine."""

    def __init__(self, root: tk.Tk):
        self.base_dir = BASE_DIR
        self._prepare_data_dirs()
        super().__init__(root)
        self.root.title(f"Network Inspection Studio {__version__} — 网络巡检工作台")
        self.root.geometry("1440x900")
        self.root.minsize(1180, 740)
        self._show_page("dashboard")

    def _prepare_data_dirs(self) -> None:
        """Keep user data next to the V6 launcher, not inside the legacy v5/ folder."""
        for name, value in (
            ("BACKUP_DIR", os.path.join(BASE_DIR, "backups")),
            ("REPORT_DIR", os.path.join(BASE_DIR, "reports")),
            ("PROFILES_FILE", os.path.join(BASE_DIR, "profiles.json")),
            ("PRESETS_FILE", os.path.join(BASE_DIR, "presets.json")),
        ):
            setattr(base, name, value)
        os.makedirs(base.BACKUP_DIR, exist_ok=True)
        os.makedirs(base.REPORT_DIR, exist_ok=True)

    # ── encrypted profiles (DPAPI) ─────────────────────────────────────
    def _load_profiles(self) -> list:
        path = base.PROFILES_FILE
        if not os.path.exists(path):
            return []
        try:
            with open(path, "r", encoding="utf-8") as fh:
                profiles = json.load(fh).get("profiles", [])
        except (OSError, ValueError):
            return []
        migrate = False
        for profile in profiles:
            token = str(profile.get("password", ""))
            if token and vault.protection_kind(token) == "raw":
                migrate = True
            profile["password"] = vault.unprotect(token)
        if migrate:
            self._write_profiles(profiles)
        return profiles

    def _save_profiles(self) -> None:
        self._write_profiles(self.profiles)

    def _write_profiles(self, profiles: list) -> None:
        path = base.PROFILES_FILE
        os.makedirs(os.path.dirname(path), exist_ok=True)
        payload = []
        for profile in profiles:
            item = dict(profile)
            item["password"] = vault.protect(str(item.get("password", "")))
            payload.append(item)
        tmp = path + ".tmp"
        with open(tmp, "w", encoding="utf-8") as fh:
            json.dump({"profiles": payload}, fh, indent=2, ensure_ascii=False)
            fh.write("\n")
        os.replace(tmp, path)

    # ── top-level shell ────────────────────────────────────────────────
    def _setup_ui(self) -> None:
        setup_app_style(self.root)
        self.root.configure(bg=BG)
        self._build_header()
        self._build_statusbar()

        body = ttk.Frame(self.root)
        body.pack(fill=tk.BOTH, expand=True)
        self.pages: dict[str, tuple[ttk.Frame, ttk.Frame]] = {}
        self.nav: dict[str, NavItem] = {}
        self._build_rail(body)

        self.content = ttk.Frame(body)
        self.content.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        self.content.grid_rowconfigure(0, weight=1)
        self.content.grid_columnconfigure(0, weight=1)

        self._build_pages()
        self._translate_widgets(self.content)
        for idx, key in enumerate(("dashboard", "single", "batch", "backup",
                                   "testing", "traffic", "security", "active", "ring"), 1):
            self.root.bind_all(f"<Control-Key-{idx}>",
                               lambda _e, k=key: self._show_page(k))
        self.root.bind_all("<Control-Key-0>", lambda _e: self._show_page("profiles"))

    def _build_header(self) -> None:
        header = tk.Frame(self.root, bg=NAVY, height=66)
        header.pack(fill=tk.X)
        header.pack_propagate(False)

        brand = tk.Frame(header, bg=NAVY)
        brand.pack(side=tk.LEFT, padx=(18, 0), pady=10)
        logo = tk.Canvas(brand, width=38, height=38, bg=NAVY,
                         highlightthickness=0, bd=0)
        logo.pack(side=tk.LEFT, padx=(0, 11))
        logo.create_oval(3, 3, 35, 35, fill="#1d4ed8", outline="")
        for x1, y1, x2, y2 in ((19, 8, 8, 19), (19, 8, 30, 19),
                               (8, 19, 8, 30), (30, 19, 30, 30),
                               (8, 30, 19, 30), (30, 30, 19, 30)):
            logo.create_line(x1, y1, x2, y2, fill="#7dd3fc", width=2)
        for x, y in ((19, 8), (8, 19), (30, 19), (8, 30), (30, 30), (19, 30)):
            logo.create_oval(x - 3, y - 3, x + 3, y + 3, fill="#34d399", outline=NAVY)

        titles = tk.Frame(brand, bg=NAVY)
        titles.pack(side=tk.LEFT)
        tk.Label(titles, text="NET INSPECT", bg=NAVY, fg="white",
                 font=("Microsoft YaHei UI", 15, "bold")).pack(anchor="w")
        tk.Label(titles, text="网络巡检工作台  ·  Network Inspection Studio",
                 bg=NAVY, fg="#94a3b8", font=("Microsoft YaHei UI", 8)).pack(anchor="w")

        chips = tk.Frame(header, bg=NAVY)
        chips.pack(side=tk.RIGHT, padx=(0, 18))
        self.chip_profiles = tk.Label(chips, text="档案 0", bg=NAVY2, fg="#e2e8f0",
                                      font=("Microsoft YaHei UI", 8, "bold"),
                                      padx=10, pady=4)
        self.chip_profiles.pack(side=tk.RIGHT, padx=(6, 0))
        self.chip_reports = tk.Label(chips, text="报告 0", bg=NAVY2, fg="#e2e8f0",
                                     font=("Microsoft YaHei UI", 8, "bold"),
                                     padx=10, pady=4)
        self.chip_reports.pack(side=tk.RIGHT, padx=(6, 0))
        tk.Label(chips, text=f"v{__version__}", bg="#172554", fg="#93c5fd",
                 font=("Microsoft YaHei UI", 8, "bold"), padx=10, pady=4).pack(side=tk.RIGHT)

    def _build_rail(self, parent) -> None:
        rail = tk.Frame(parent, bg=NAVY, width=196)
        rail.pack(side=tk.LEFT, fill=tk.Y)
        rail.pack_propagate(False)
        tk.Label(rail, text="工作区 / WORKSPACES", bg=NAVY, fg="#475569",
                 font=("Microsoft YaHei UI", 7), anchor="w").pack(
            fill="x", padx=16, pady=(12, 4))
        last_section = None
        for key, title, sub, section in NAV_ITEMS:
            if section and section != last_section:
                tk.Label(rail, text=section, bg=NAVY, fg="#475569",
                         font=("Microsoft YaHei UI", 7), anchor="w").pack(
                    fill="x", padx=16, pady=(7, 1))
                last_section = section
            item = NavItem(rail, title, sub, lambda k=key: self._show_page(k))
            item.pack(fill="x", padx=8, pady=0)
            self.nav[key] = item
        tk.Frame(rail, bg=NAVY).pack(fill=tk.BOTH, expand=True)
        tk.Label(rail, text="V6 shell · V5 engine", bg=NAVY, fg="#475569",
                 font=("Microsoft YaHei UI", 7)).pack(pady=10)

    def _build_statusbar(self) -> None:
        bar = tk.Frame(self.root, bg=PANEL, highlightthickness=1,
                       highlightbackground=LINE, height=30)
        bar.pack(fill=tk.X, side=tk.BOTTOM)
        bar.pack_propagate(False)
        self.status_var = tk.StringVar(value="就绪 · 选择工作区开始")
        tk.Label(bar, text="●", bg=PANEL, fg=GREEN,
                 font=("Microsoft YaHei UI", 8), padx=12).pack(side=tk.LEFT)
        tk.Label(bar, textvariable=self.status_var, bg=PANEL, fg=FG,
                 font=("Microsoft YaHei UI", 9), anchor="w").pack(
            side=tk.LEFT, fill=tk.X, expand=True)
        tk.Label(bar, text="Ctrl+1…9 / 0 切换  ·  Esc 停止  ·  Ctrl+Enter 启动当前页",
                 bg=PANEL, fg=MUTED, font=("Microsoft YaHei UI", 8),
                 padx=12).pack(side=tk.RIGHT)

    # ── pages ─────────────────────────────────────────────────────────
    def _page(self, key: str, title: str, subtitle: str, hint: str = "") -> ttk.Frame:
        page = ttk.Frame(self.content)
        page.grid(row=0, column=0, sticky="nsew")
        head = tk.Frame(page, bg=BG)
        head.pack(fill=tk.X, padx=14, pady=(12, 2))
        tk.Frame(head, bg=ACCENT, width=4, height=38).pack(
            side=tk.LEFT, padx=(0, 11), pady=2)
        box = tk.Frame(head, bg=BG)
        box.pack(side=tk.LEFT)
        tk.Label(box, text=title, bg=BG, fg=FG,
                 font=("Microsoft YaHei UI", 17, "bold"), anchor="w").pack(anchor="w")
        tk.Label(box, text=subtitle, bg=BG, fg=MUTED,
                 font=("Microsoft YaHei UI", 9), anchor="w").pack(anchor="w")
        if hint:
            tk.Label(head, text=hint, bg=BG, fg=MUTED,
                     font=("Microsoft YaHei UI", 8)).pack(side=tk.RIGHT, padx=4)
        ttk.Separator(page, orient=tk.HORIZONTAL).pack(fill=tk.X, padx=12, pady=(8, 0))
        body = ttk.Frame(page)
        body.pack(fill=tk.BOTH, expand=True)
        self.pages[key] = (page, body)
        return body

    def _build_pages(self) -> None:
        dash = self._page("dashboard", "总览", "巡检工作台 · 设备、报告与快速入口",
                          "Ctrl+1…9 / 0 切换  ·  Esc 停止")
        self._build_dashboard(dash)

        body = self._page("single", "单机巡检", "连接单台设备，执行可编辑命令集",
                          "Ctrl+Enter 开始  ·  Esc 停止")
        self.tab_single = body
        self._build_single_tab()

        body = self._page("batch", "批量巡检", "并行巡检多台设备，异常自动标红",
                          "选择设备后开始  ·  Esc 停止")
        self.tab_batch = body
        self._build_batch_tab()

        body = self._page("backup", "配置备份", "批量备份 running-config / current-configuration",
                          "输出到 backups/")
        self.tab_backup = body
        self._build_backup_tab()

        body = self._page("testing", "测试中心", "连通性测试 · 配置基线 · 上线前自检",
                          "ICMP / TCP 22 / SSH / 配置基线")
        from netinspect_tests import TestCenter
        self.tab_testing = TestCenter(body, self)
        self.tab_testing.pack(fill=tk.BOTH, expand=True)

        body = self._page("traffic", "流量测试", "UDP / ICMP / TCP / TCP-SYN 与接收端",
                          "V5 engine")
        self.tab_traffic = TrafficTestPanel(body)
        self.tab_traffic.pack(fill=tk.BOTH, expand=True)

        body = self._page("security", "安全核查", "DHCP snooping / DAI / DNS / 端口隔离 / 端口安全",
                          "只读核查")
        self.tab_security = SecurityTestPanel(body, self)
        self.tab_security.pack(fill=tk.BOTH, expand=True)

        body = self._page("active", "主动探测", "ICMP / DNS / DHCP / ARP / VLAN 故障定位",
                          "只读探测")
        self.tab_active = ActiveTestPanel(body)
        self.tab_active.pack(fill=tk.BOTH, expand=True)

        body = self._page("ring", "环路告警", "两轮采样差分 · 故障视图 · 光衰/温度/电源",
                          "V5 ring engine")
        if RingAlertPanel is not None:
            self.tab_ring = RingAlertPanel(body, self)
            self.tab_ring.pack(fill=tk.BOTH, expand=True)
        else:
            ttk.Label(body, text="RingAlertPanel 未加载",
                      foreground=RED).pack(padx=20, pady=20)

        body = self._page("profiles", "连接档案", "常用连接、命令预设与凭据",
                          "profiles.json / presets.json")
        self.tab_profiles = body
        self._build_profiles_tab()

    def _show_page(self, key: str) -> None:
        if key not in self.pages:
            return
        page, _body = self.pages[key]
        page.tkraise()
        self.current_page = key
        for name, item in self.nav.items():
            item.set_active(name == key)
        if key == "dashboard":
            self._refresh_dashboard()
        if key in ("profiles",):
            try:
                self._refresh_profile_list()
            except Exception:
                pass

    def _handle_ctrl_enter(self) -> None:
        action = {
            "single": self._start_single,
            "batch": self._start_batch_selected,
            "backup": self._start_backup,
        }.get(getattr(self, "current_page", ""))
        if action:
            action()

    # ── lightweight UI translation layer ──────────────────────────────
    ZH_MAP = {
        "Connection": "连接信息",
        "Commands (editable)": "命令集（可编辑）",
        "Output": "输出",
        "Load Profile:": "加载档案：",
        "Device Type:": "设备类型：",
        "IP Address:": "IP 地址：",
        "Port:": "端口：",
        "Username:": "用户名：",
        "Password": "密码",
        "Anomaly Detection": "异常检测",
        "Compact Output": "紧凑输出",
        "Quick Inspection": "快速巡检",
        "Pre-check (ping)": "Ping 预检",
        "Stop": "停止",
        "Start Inspection": "开始巡检",
        "IP Intel": "IP 情报",
        "Reset to Default": "恢复默认",
        "Presets:": "预设：",
        "Load": "加载",
        "Save": "保存",
        "Del": "删除",
        "Search:": "搜索：",
        "Target Configuration": "目标配置",
        "Target IP:": "目标 IP：",
        "Protocol:": "协议：",
        "Detected Gateways:": "检测到的网关：",
        "Detect": "检测",
        "Built-in TCP Receiver (for TCP testing)": "内置 TCP 接收端（TCP 测试用）",
        "Listen Port:": "监听端口：",
        "Start Server": "启动接收端",
        "Stop Server": "停止接收端",
        "Stopped": "已停止",
        "Traffic Parameters": "流量参数",
        "Concurrency (threads):": "并发（线程）：",
        "Packet Size (bytes):": "包大小（字节）：",
        "Rate (pkt/s/thread):": "速率（包/秒/线程）：",
        "Real-time Statistics": "实时统计",
        "Total Packets:": "总包数：",
        "Total Bytes:": "总字节：",
        "Elapsed:": "耗时：",
        "Log": "日志",
        "Start": "开始",
        "Idle": "空闲",
        "Target Device": "目标设备",
        "User:": "用户：",
        "Pass:": "口令：",
        "Type:": "类型：",
        "Start Security Test": "开始安全核查",
        "Export Report": "导出报告",
        "Saved Profiles": "已保存档案",
        "Add / Edit Profile": "新增 / 编辑档案",
        "Name:": "名称：",
        "Host:": "主机：",
        "Delete": "删除",
        "Clear Form": "清空表单",
        "Name": "名称",
        "IP / Host": "IP / 主机",
        "Type": "类型",
        "Username": "用户名",
        "Profile": "档案",
        "Status": "状态",
        "Progress": "进度",
        "Device": "设备",
        "Result": "结果",
        "Device List File": "设备清单文件",
        "Device List": "设备清单",
        "Devices": "设备列表",
        "Run": "开始巡检",
        "Browse...": "浏览…",
        "Export CSV": "导出 CSV",
        "Export HTML": "导出 HTML",
        "Parallel:": "并发：",
        "Backup Selected": "备份选中设备",
        "Backup Log": "备份日志",
        "Backup Dir:": "备份目录：",
        "IP Address": "IP 地址",
        "Commands": "命令",
        "Password:": "密码：",
        "Probe Targets (带新机器到现场，通信正常时主动探测)":
            "探测目标（带新机器到现场，通信正常时主动探测）",
        "Probe DHCP (发现私接路由器抢答)": "DHCP 探测（发现私接路由器抢答）",
        "Probe DNS (重定向对比)": "DNS 探测（重定向对比）",
        "Probe ARP (冲突/欺骗)": "ARP 探测（冲突/欺骗）",
        "Probe VLAN (跨 VLAN 连通)": "VLAN 探测（跨 VLAN 连通）",
    }

    def _translate_widgets(self, parent) -> None:
        for widget in parent.winfo_children():
            try:
                cls = widget.winfo_class()
                if cls in ("Label", "Button", "Checkbutton", "Radiobutton", "Labelframe"):
                    text = widget.cget("text")
                    if text in self.ZH_MAP:
                        widget.configure(text=self.ZH_MAP[text])
                elif cls == "TLabel" or cls == "TButton" or cls == "TCheckbutton" or cls == "TLabelframe":
                    text = widget.cget("text")
                    if text in self.ZH_MAP:
                        widget.configure(text=self.ZH_MAP[text])
                elif cls == "TNotebook":
                    for tab_id in widget.tabs():
                        text = widget.tab(tab_id, "text")
                        if text in self.ZH_MAP:
                            widget.tab(tab_id, text=self.ZH_MAP[text])
                elif cls == "Treeview":
                    for col in widget["columns"]:
                        text = widget.heading(col, "text")
                        if text in self.ZH_MAP:
                            widget.heading(col, text=self.ZH_MAP[text])
            except tk.TclError:
                pass
            self._translate_widgets(widget)

    # ── dashboard ─────────────────────────────────────────────────────
    def _build_dashboard(self, body: ttk.Frame) -> None:
        hero = tk.Frame(body, bg=PANEL, highlightthickness=1, highlightbackground=LINE)
        hero.pack(fill=tk.X, padx=14, pady=(12, 8))
        tk.Frame(hero, bg=ACCENT, width=5).pack(side=tk.LEFT, fill=tk.Y)
        inner = tk.Frame(hero, bg=PANEL)
        inner.pack(fill=tk.X, padx=18, pady=14)
        tk.Label(inner, text="今天要巡检什么？", bg=PANEL, fg=FG,
                 font=("Microsoft YaHei UI", 14, "bold")).pack(anchor="w")
        tk.Label(inner, text="从连接档案开始，或直接跑一台设备；结果会进入报告目录。",
                 bg=PANEL, fg=MUTED, font=("Microsoft YaHei UI", 9)).pack(
            anchor="w", pady=(2, 10))
        actions = tk.Frame(inner, bg=PANEL)
        actions.pack(anchor="w")
        for text, key, style in (("一键巡检", "quick", "GreenAccent.TButton"),
                                 ("单机巡检", "single", "Accent.TButton"),
                                 ("批量巡检", "batch", "TButton"),
                                 ("配置备份", "backup", "TButton"),
                                 ("测试中心", "testing", "TButton"),
                                 ("环路告警", "ring", "TButton")):
            ttk.Button(actions, text=text, style=style,
                       command=(self.quick_inspect if key == "quick"
                                else lambda k=key: self._show_page(k))).pack(
                side=tk.LEFT, padx=(0, 8))

        stats = tk.Frame(body, bg=BG)
        stats.pack(fill=tk.X, padx=14)
        self.stat_labels = {}
        for key, title in (("profiles", "连接档案"), ("reports", "最近报告"),
                           ("backups", "配置备份"), ("presets", "命令预设")):
            card = tk.Frame(stats, bg=PANEL, highlightthickness=1,
                            highlightbackground=LINE)
            card.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 8))
            tk.Label(card, text=title, bg=PANEL, fg=MUTED,
                     font=("Microsoft YaHei UI", 8)).pack(anchor="w", padx=14, pady=(10, 0))
            value = tk.Label(card, text="0", bg=PANEL, fg=FG,
                             font=("Microsoft YaHei UI", 20, "bold"))
            value.pack(anchor="w", padx=14, pady=(0, 10))
            self.stat_labels[key] = value

        lower = tk.Frame(body, bg=BG)
        lower.pack(fill=tk.BOTH, expand=True, padx=14, pady=(10, 12))
        recent = tk.LabelFrame(lower, text="最近报告 / Recent reports",
                               padx=8, pady=8)
        recent.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(0, 8))
        rbar = tk.Frame(recent, bg=BG)
        rbar.pack(fill=tk.X, pady=(0, 4))
        ttk.Button(rbar, text="打开报告目录", style="TButton",
                   command=lambda: self._open_dir(base.REPORT_DIR)).pack(side=tk.LEFT)
        ttk.Button(rbar, text="刷新", style="TButton",
                   command=self._refresh_dashboard).pack(side=tk.LEFT, padx=(4, 0))
        self.recent_list = tk.Listbox(recent, height=8, borderwidth=0,
                                      highlightthickness=1, highlightbackground=LINE,
                                      font=("Consolas", 8), activestyle="none")
        self.recent_list.pack(fill=tk.BOTH, expand=True)
        self.recent_list.bind("<Double-1>", lambda _e: self._open_selected_report())

        flow = tk.LabelFrame(lower, text="推荐流程 / Workflow", padx=12, pady=12)
        flow.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        for n, text in enumerate(("1. 连接档案 / 设备清单",
                                  "2. 批量巡检或单机巡检",
                                  "3. 异常跳转 + 报告导出",
                                  "4. 环路告警 / 配置备份"), 1):
            tk.Label(flow, text=text, bg=BG, fg=FG,
                     font=("Microsoft YaHei UI", 9), anchor="w").pack(
                fill=tk.X, pady=3)

    def _open_dir(self, path: str) -> None:
        try:
            os.makedirs(path, exist_ok=True)
            os.startfile(path)
        except OSError as exc:
            messagebox.showerror("打开失败", str(exc))

    def _open_selected_report(self) -> None:
        selection = self.recent_list.curselection()
        if not selection:
            return
        name = self.recent_list.get(selection[0])
        if not name or name.startswith("（"):
            return
        target = Path(base.REPORT_DIR) / name
        if target.is_file():
            try:
                os.startfile(str(target))
            except OSError as exc:
                messagebox.showerror("打开失败", str(exc))

    def quick_inspect(self) -> None:
        """One-click batch inspection for the current device list."""
        path = self.batch_filepath.get().strip()
        if not path or not os.path.exists(path):
            path = filedialog.askopenfilename(
                title="选择设备清单（CSV / Excel / txt）",
                filetypes=[("设备清单", "*.txt *.csv *.xlsx *.xlsm"), ("所有文件", "*.*")])
            if not path:
                return
            self.batch_filepath.set(path)
        try:
            self._load_devices()
        except Exception as exc:
            messagebox.showerror("加载失败", str(exc))
            return
        children = self.device_tree.get_children()
        if not children:
            messagebox.showwarning("没有设备", "设备清单为空或解析失败。")
            return
        self.device_tree.selection_set(children)
        self._show_page("batch")
        self._start_batch_selected()

    def _refresh_dashboard(self) -> None:
        reports = []
        try:
            reports = sorted(Path(base.REPORT_DIR).glob("*"),
                             key=lambda p: p.stat().st_mtime, reverse=True)
            reports = [p.name for p in reports if p.is_file()][:20]
        except OSError:
            pass
        backups = 0
        try:
            backups = sum(1 for p in Path(base.BACKUP_DIR).rglob("*") if p.is_file())
        except OSError:
            pass
        values = {
            "profiles": len(self.profiles),
            "presets": len(self.presets),
            "reports": len(reports),
            "backups": backups,
        }
        for key, label in self.stat_labels.items():
            label.configure(text=str(values.get(key, 0)))
        self.chip_profiles.configure(text=f"档案 {len(self.profiles)}")
        self.chip_reports.configure(text=f"报告 {values['reports']}")
        self.recent_list.delete(0, tk.END)
        for name in reports:
            self.recent_list.insert(tk.END, name)
        if not reports:
            self.recent_list.insert(tk.END, "（暂无报告）")


def main() -> None:
    root = tk.Tk()
    InspectionStudio(root)
    root.mainloop()


if __name__ == "__main__":
    main()

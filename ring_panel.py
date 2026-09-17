#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ring_panel.py —— 「环路告警」页签（巡检工具的新页签，V4/V5 共用）

这个页签把「环路 / 异常告警」功能接进巡检工具，提供两种用法：

A. **在线两轮采样**（主力）：自己连设备，同一批命令跑两轮（默认间隔 30 分钟），
   两轮结果做差分 → 判 MAC 漂移 / CRC 增长 / 广播速率 / 链路震荡 / TC 增量。
   * 环路与"正在恶化"的硬件问题，**必须看变化量**，单看一次快照看不出；
   * 间隔是第一命门：程序按实际耗时记录，界面上也会显示（不是配置值）。

B. **离线分析报告**：拿巡检工具导出的报告 CSV（1 份或 2 份）直接分析，
   适合"同事只拿到报告"或事后复盘。

设计要点
--------
* **能力自适应**：检测项勾选框由 `ring_analyze.available_rules()` 动态生成 ——
  阉割版（V4）的 `ring_rules.py` 里没有 D8/D9，界面自然就少两项，**界面代码不分叉**。
* **不依赖宿主 GUI 的内部实现**：设备文件解析 / SSH 执行都内置一份兜底，
  有 `app._parse_device_file` / `app._ssh_connect` / `app._run_commands_via_shell`
  时优先用宿主的（保持与巡检工具一致的行为和友好报错）。
* **线程模型**：worker 线程只算，经 `queue` 回主线程渲染（与巡检工具同一套路）。
* 解析失败/命令不支持**不误报**：记进「检测能力提示」，照实告诉用户缺什么。

用法（宿主 GUI 里挂页签）::

    from ring_panel import RingAlertPanel
    self.tab_ring = RingAlertPanel(notebook, self)
    notebook.add(self.tab_ring, text="Ring Alert")
"""

from __future__ import annotations

import os
import queue
import threading
import tkinter as tk
from tkinter import filedialog, messagebox, ttk
from tkinter.scrolledtext import ScrolledText

import ring_analyze as RA
import ring_parsers as RP
import ring_rules as RR

# ── 各厂商的"环路/健康"命令集（按《环路检测-规则清单》§1）────────────────
# 说明：解析器目前只完整实现华为；其他厂商的命令可以先跑起来（结果会被记入
# "检测能力提示"），等拿到真实输出再补解析（见 README 的扩展说明）。
RING_COMMANDS = {
    "huawei": [
        "display stp", "display stp brief", "display mac-address",
        "display interface brief", "display interface",
        "display device", "display logbuffer", "display alarm active",
        "display transceiver diagnosis interface", "display temperature all",
    ],
    "h3c": [
        "display stp", "display mac-address", "display interface brief",
        "display interface", "display device", "display logbuffer",
        "display alarm", "display transceiver diagnosis interface",
    ],
    "ruijie": [
        "show spanning-tree", "show mac-address-table", "show interfaces status",
        "show interfaces", "show version", "show logging", "show transceiver",
    ],
    "cisco": [
        "show spanning-tree", "show mac address-table", "show interfaces status",
        "show interfaces", "show inventory", "show logging", "show environment",
    ],
    "linux": [],
}

SEV_TAG = {"high": "ring_high", "medium": "ring_med", "low": "ring_low"}


class RingAlertPanel(ttk.Frame):
    """环路告警页签。构造参数 `app` 为宿主 GUI（可为 None，此时用内置兜底实现）。"""

    def __init__(self, parent, app=None, **kw) -> None:
        super().__init__(parent, **kw)
        self.app = app
        self.result: dict | None = None
        self._alerts: list[dict] = []
        self._q: "queue.Queue[tuple]" = queue.Queue()
        self._stop = threading.Event()
        self._busy = False
        self._last_export_dir: str | None = None
        self._rules = RP.load_rules()
        self._rules_meta = RA.available_rules()
        self._build()
        self.after(150, self._poll)

    # ══════════════════════════════════════════════════════════════
    # 界面
    # ══════════════════════════════════════════════════════════════

    def _build(self) -> None:
        # ── A. 在线两轮采样 ──────────────────────────────────────
        on = ttk.LabelFrame(self, text="A. 在线两轮采样（工具自己连设备跑两轮，做差分）", padding=10)
        on.pack(fill=tk.X, padx=10, pady=(10, 6))

        ttk.Label(on, text="设备文件：").grid(row=0, column=0, sticky="e")
        self.dev_var = tk.StringVar(value="")
        ttk.Entry(on, textvariable=self.dev_var).grid(row=0, column=1, columnspan=3,
                                                     sticky="ew", pady=3)
        ttk.Button(on, text="浏览…", width=9, command=self._pick_devices).grid(row=0, column=4, padx=5)
        ttk.Label(on, text="（支持 txt / xlsx；留空则用巡检工具批量页当前的设备文件）",
                  foreground="#8a97a5").grid(row=0, column=5, sticky="w")

        ttk.Label(on, text="两轮间隔(分钟)：").grid(row=1, column=0, sticky="e")
        self.gap_var = tk.StringVar(value="30")
        ttk.Entry(on, textvariable=self.gap_var, width=8).grid(row=1, column=1, sticky="w")
        ttk.Label(on, text="并发设备数：").grid(row=1, column=2, sticky="e", padx=(12, 0))
        self.workers_var = tk.StringVar(value="8")
        ttk.Entry(on, textvariable=self.workers_var, width=6).grid(row=1, column=3, sticky="w")
        ttk.Label(on, text="建议 15~60 分钟；间隔越长越能看出缓慢劣化，但排查要等",
                  foreground="#8a97a5").grid(row=1, column=4, columnspan=2, sticky="w", padx=6)

        ttk.Label(on, text="采样命令：").grid(row=2, column=0, sticky="ne", pady=(6, 0))
        self.cmd_text = ScrolledText(on, height=6, font=("Consolas", 9))
        self.cmd_text.grid(row=2, column=1, columnspan=5, sticky="ew", pady=(6, 0))
        self._load_default_commands()

        rowb = ttk.Frame(on)
        rowb.grid(row=3, column=0, columnspan=6, sticky="w", pady=(8, 0))
        self.btn_run2 = ttk.Button(rowb, text="开始两轮采样分析", style="Accent.TButton",
                                   command=self._start_online)
        self.btn_run2.pack(side=tk.LEFT)
        self.btn_stop2 = ttk.Button(rowb, text="停止", style="Danger.TButton",
                                    command=self._stop_work, state=tk.DISABLED)
        self.btn_stop2.pack(side=tk.LEFT, padx=5)
        ttk.Button(rowb, text="恢复默认命令", command=self._load_default_commands).pack(side=tk.LEFT, padx=8)
        on.columnconfigure(1, weight=1)

        # ── B. 离线分析 ──────────────────────────────────────────
        off = ttk.LabelFrame(self, text="B. 离线分析报告（拿巡检导出的 CSV 分析，适合事后复盘）", padding=10)
        off.pack(fill=tk.X, padx=10, pady=(0, 6))
        self.r1_var, self.r2_var = tk.StringVar(), tk.StringVar()
        ttk.Label(off, text="第 1 期报告：").grid(row=0, column=0, sticky="e")
        ttk.Entry(off, textvariable=self.r1_var).grid(row=0, column=1, sticky="ew", pady=2)
        ttk.Button(off, text="浏览…", width=9,
                   command=lambda: self._pick_report(self.r1_var)).grid(row=0, column=2, padx=5)
        ttk.Label(off, text="第 2 期报告：").grid(row=1, column=0, sticky="e")
        ttk.Entry(off, textvariable=self.r2_var).grid(row=1, column=1, sticky="ew", pady=2)
        ttk.Button(off, text="浏览…", width=9,
                   command=lambda: self._pick_report(self.r2_var)).grid(row=1, column=2, padx=5)
        rb = ttk.Frame(off)
        rb.grid(row=2, column=0, columnspan=3, sticky="w", pady=(6, 0))
        self.btn_run_off = ttk.Button(rb, text="分析这两份报告", command=self._start_offline)
        self.btn_run_off.pack(side=tk.LEFT)
        ttk.Label(rb, text="（只给第 1 期也行：出关键字/绝对值类结果，看不出“正在变化”）",
                  foreground="#8a97a5").pack(side=tk.LEFT, padx=6)
        off.columnconfigure(1, weight=1)

        # ── 检测项 ──────────────────────────────────────────────
        rl = ttk.LabelFrame(self, text="检测项（改完 rules.yaml 可点下面「重新加载规则」生效）", padding=8)
        rl.pack(fill=tk.X, padx=10, pady=(0, 6))
        self.rule_vars: dict[str, tk.BooleanVar] = {}
        defaults = set(RA.default_enabled(self._rules_meta))
        base_ids = [r for r, c in self._rules_meta.items() if c.get("scope") == "single"]
        deep_ids = [r for r, c in self._rules_meta.items() if c.get("scope") == "cross"]
        for col, (title, ids) in enumerate((("基础检测", base_ids), ("深度检测（完整版独有）", deep_ids))):
            f = ttk.LabelFrame(rl, text=title, padding=5)
            f.grid(row=0, column=col, sticky="nw", padx=(0, 12))
            if not ids:
                ttk.Label(f, text="（本版本不含）", foreground="#8a97a5").grid(row=0, column=0)
            for i, rid in enumerate(ids):
                v = tk.BooleanVar(value=rid in defaults)
                self.rule_vars[rid] = v
                ttk.Checkbutton(f, text=f"{rid} {self._rules_meta[rid].get('name', '')}",
                                variable=v).grid(row=i // 2, column=i % 2, sticky="w", padx=(0, 12))
        ttk.Label(rl, text="设备角色档：").grid(row=1, column=0, sticky="e", pady=(6, 0))
        self.cls_var = tk.StringVar(value="aggregation")
        ttk.Combobox(rl, textvariable=self.cls_var, width=13, state="readonly",
                     values=["core", "aggregation", "access"]).grid(row=1, column=1, sticky="w")
        ttk.Button(rl, text="打开规则表", command=self._open_rules).grid(row=1, column=2, padx=6)
        ttk.Button(rl, text="重新加载规则", command=self._reload_rules).grid(row=1, column=3)

        # ── 结果 ────────────────────────────────────────────────
        res = ttk.LabelFrame(self, text="告警列表（双击看完整证据）", padding=8)
        res.pack(fill=tk.BOTH, expand=True, padx=10, pady=(0, 6))
        fb = ttk.Frame(res)
        fb.pack(fill=tk.X, pady=(0, 6))
        self.summary_var = tk.StringVar(value="尚未分析")
        ttk.Label(fb, textvariable=self.summary_var, foreground="#1f4e79",
                  font=("Microsoft YaHei UI", 9, "bold")).pack(side=tk.LEFT)
        ttk.Button(fb, text="⚠ 上一异常", width=11, command=lambda: self._jump(-1)).pack(side=tk.RIGHT, padx=(4, 0))
        ttk.Button(fb, text="⚠ 下一异常", width=11, command=lambda: self._jump(1)).pack(side=tk.RIGHT, padx=(4, 0))
        ttk.Label(fb, text="级别：").pack(side=tk.LEFT, padx=(14, 2))
        self.fsev = tk.StringVar(value="全部")
        cb = ttk.Combobox(fb, textvariable=self.fsev, width=7, state="readonly",
                          values=["全部", "高危", "一般", "提示"])
        cb.pack(side=tk.LEFT)
        cb.bind("<<ComboboxSelected>>", lambda _e: self._apply_filter())
        ttk.Label(fb, text="搜索：").pack(side=tk.LEFT, padx=(10, 2))
        self.fkw = tk.StringVar()
        en = ttk.Entry(fb, textvariable=self.fkw, width=22)
        en.pack(side=tk.LEFT)
        en.bind("<Return>", lambda _e: self._apply_filter())
        ttk.Button(fb, text="筛选", width=6, command=self._apply_filter).pack(side=tk.LEFT, padx=4)
        ttk.Button(fb, text="导出 HTML", command=lambda: self._export("html")).pack(side=tk.LEFT, padx=(10, 2))
        ttk.Button(fb, text="导出 CSV", command=lambda: self._export("csv")).pack(side=tk.LEFT)

        cols = ("sev", "sig", "dev", "intf", "ev")
        self.tree = ttk.Treeview(res, columns=cols, show="headings", height=10)
        for c, t, w in (("sev", "级别", 58), ("sig", "信号", 165), ("dev", "设备", 125),
                        ("intf", "接口", 145), ("ev", "证据（截断，双击看全文）", 600)):
            self.tree.heading(c, text=t)
            self.tree.column(c, width=w, anchor="center" if c == "sev" else "w")
        vs = ttk.Scrollbar(res, orient=tk.VERTICAL, command=self.tree.yview)
        self.tree.configure(yscrollcommand=vs.set)
        self.tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        vs.pack(side=tk.RIGHT, fill=tk.Y)
        self.tree.tag_configure("ring_high", foreground="#b91c1c", background="#ffebee")
        self.tree.tag_configure("ring_med", foreground="#b45309", background="#fff7ed")
        self.tree.tag_configure("ring_low", foreground="#8a6d00", background="#fffdf0")
        self.tree.bind("<Double-1>", lambda _e: self._detail())

        # ── 进度 / 状态 ─────────────────────────────────────────
        bar = ttk.Frame(self)
        bar.pack(fill=tk.X, padx=10, pady=(0, 8))
        self.prog = ttk.Progressbar(bar, mode="determinate", length=220)
        self.prog.pack(side=tk.RIGHT)
        self.status_var = tk.StringVar(value=f"规则表：{RP.default_rules_path()}"
                                            f"（{len(self._rules.get('signals') or {})} 组关键字符号）")
        ttk.Label(bar, textvariable=self.status_var, foreground="#5b6b7c").pack(side=tk.LEFT)

    def _load_default_commands(self) -> None:
        cmds = RING_COMMANDS.get("huawei", [])
        self.cmd_text.config(state=tk.NORMAL)
        self.cmd_text.delete("1.0", tk.END)
        self.cmd_text.insert("1.0", "\n".join(cmds))
        self.cmd_text.config(state=tk.NORMAL)

    def _commands(self) -> list[str]:
        raw = self.cmd_text.get("1.0", tk.END)
        return [l.strip() for l in raw.splitlines() if l.strip()]

    # ══════════════════════════════════════════════════════════════
    # 设备文件 / SSH（优先用宿主 GUI 的实现，保证行为一致）
    # ══════════════════════════════════════════════════════════════

    def _pick_devices(self) -> None:
        p = filedialog.askopenfilename(
            title="选择设备清单",
            filetypes=[("设备清单", "*.txt *.xlsx *.xlsm"), ("所有文件", "*.*")])
        if p:
            self.dev_var.set(p)

    def _pick_report(self, var: tk.StringVar) -> None:
        p = filedialog.askopenfilename(title="选择巡检报告 CSV",
                                       filetypes=[("报告 CSV", "*.csv"), ("所有文件", "*.*")])
        if p:
            var.set(p)

    def _device_file(self) -> str:
        """取设备文件：本页签填了就用它，否则借批量页的当前文件。"""
        p = self.dev_var.get().strip()
        if p:
            return p
        for attr in ("batch_filepath", "devices_file", "_devices_file"):
            v = getattr(self.app, attr, None)
            if v is not None:
                v = v.get() if hasattr(v, "get") else v
                if v:
                    return str(v)
        for name in ("devices.xlsx", "devices.txt"):
            if os.path.exists(os.path.join(RP.app_dir(), name)):
                return os.path.join(RP.app_dir(), name)
        return ""

    def _parse_devices(self, path: str):
        """解析设备清单 → [(host, devtype, user, pwd)]；优先用宿主的解析器（支持 xlsx）。"""
        fn = getattr(self.app, "_parse_device_file", None)
        if callable(fn):
            try:
                devices, errs = fn(path)
                if errs:
                    self._put("warn", f"设备文件有 {len(errs)} 行无法识别（前 3 条）："
                                      + "；".join(str(e[2]) for e in errs[:3]))
                return [(d[0], d[1], d[2], d[3]) for d in devices]
            except Exception as e:
                self._put("warn", f"宿主解析器失败({e})，改用内置解析")
        return self._parse_devices_builtin(path)

    @staticmethod
    def _parse_devices_builtin(path: str):
        """内置兜底解析：txt `IP:user:pwd:type:"cmd,cmd"` 与 xlsx 五列（IP/用户名/密码/类型/命令）。"""
        out = []
        if path.lower().endswith((".xlsx", ".xlsm")):
            try:
                from openpyxl import load_workbook
                wb = load_workbook(path, read_only=True, data_only=True)
                ws = wb.active
                for i, row in enumerate(ws.iter_rows(values_only=True)):
                    if i == 0:
                        continue
                    if not row or not row[0]:
                        continue
                    out.append((str(row[0]).strip(), str(row[3] or "cisco").strip().lower(),
                                str(row[1] or ""), str(row[2] or "")))
                wb.close()
            except Exception as e:
                raise RuntimeError(f"读取 Excel 设备表失败：{e}（需 openpyxl）")
            return out
        with open(path, encoding="utf-8", errors="replace") as f:
            for line in f:
                line = line.strip()
                if not line or line.startswith("#"):
                    continue
                parts = line.split(":")
                if len(parts) < 2:
                    continue
                host, user = parts[0].strip(), parts[1].strip()
                pwd = parts[2].strip() if len(parts) > 2 else ""
                devtype = parts[3].strip().lower() if len(parts) > 3 else "cisco"
                out.append((host, devtype, user, pwd))
        return out

    def _ssh_run(self, host: str, user: str, pwd: str, devtype: str,
                 cmds: list[str], timeout: int = 20) -> dict:
        """连一台设备把命令跑完，返回 `{命令: 输出}`。异常不回抛，记进 "_error"。"""
        if self.app is not None and hasattr(self.app, "_ssh_connect"):
            ssh = self.app._ssh_connect(host, user, pwd, timeout=timeout)
        else:                                    # 内置兜底（独立运行时用）
            import paramiko
            ssh = paramiko.SSHClient()
            ssh.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            ssh.connect(hostname=host, username=user, password=pwd,
                        timeout=timeout, banner_timeout=timeout, auth_timeout=timeout,
                        look_for_keys=False, allow_agent=False)
        outs: dict[str, str] = {}
        try:
            disable_page = "screen-length 0 temporary" if devtype in ("huawei", "h3c") else (
                "terminal length 0" if devtype in ("cisco", "ruijie") else "")
            for cmd in cmds:
                if self._stop.is_set():
                    break
                fn = getattr(self.app, "_run_commands_via_shell", None)
                if callable(fn):
                    outs[cmd] = fn(ssh, [cmd], disable_page=disable_page)[0] if disable_page \
                        else fn(ssh, [cmd])[0]
                else:
                    outs[cmd] = self._exec_cmd(ssh, cmd, disable_page)
        finally:
            try:
                ssh.close()
            except Exception:
                pass
        return outs

    @staticmethod
    def _exec_cmd(ssh, cmd: str, disable_page: str = "") -> str:
        """内置命令执行：开交互 shell、关分页、发命令、读到提示符。"""
        import time as _t
        chan = ssh.invoke_shell(width=512, height=1000)
        buf = ""

        def drain(seconds: float) -> str:
            nonlocal buf
            end = _t.time() + seconds
            got = ""
            while _t.time() < end:
                if chan.recv_ready():
                    got += chan.recv(65536).decode("utf-8", "replace")
                    end = _t.time() + 0.6
                else:
                    _t.sleep(0.15)
            buf += got
            return got

        drain(1.5)
        if disable_page:
            chan.send(disable_page + "\n")
            drain(1.2)
        buf = ""
        chan.send(cmd + "\n")
        drain(4.0)
        try:
            chan.close()
        except Exception:
            pass
        return buf

    # ══════════════════════════════════════════════════════════════
    # 线程/队列
    # ══════════════════════════════════════════════════════════════

    def _put(self, kind: str, *payload) -> None:
        self._q.put((kind, *payload))

    def _poll(self) -> None:
        try:
            while True:
                m = self._q.get_nowait()
                k = m[0]
                if k == "progress":
                    _, txt, cur, tot = m
                    self.prog.config(maximum=max(tot, 1), value=cur)
                    self.status_var.set(f"{txt}（{cur}/{tot}）")
                elif k == "done":
                    self.result = m[1]
                    self._finish()
                elif k == "error":
                    self._fail(m[1], m[2] if len(m) > 2 else "")
                elif k in ("info", "warn"):
                    self.status_var.set(str(m[1]))
        except queue.Empty:
            pass
        self.after(150, self._poll)

    def _set_busy(self, busy: bool) -> None:
        self._busy = busy
        state_idle = tk.DISABLED if busy else tk.NORMAL
        self.btn_run2.config(state=state_idle)
        self.btn_run_off.config(state=state_idle)
        self.btn_stop2.config(state=tk.NORMAL if busy else tk.DISABLED)

    def _stop_work(self) -> None:
        self._stop.set()
        self.status_var.set("已请求停止（本轮结束即停）")

    def _enabled_ids(self) -> list[str] | None:
        ids = [r for r, v in self.rule_vars.items() if v.get()]
        if not ids:
            messagebox.showwarning("提示", "至少要勾选一个检测项。", parent=self)
            return None
        return ids

    # ══════════════════════════════════════════════════════════════
    # A. 在线两轮采样
    # ══════════════════════════════════════════════════════════════

    def _start_online(self) -> None:
        if self._busy:
            return
        dev_file = self._device_file()
        if not dev_file or not os.path.exists(dev_file):
            messagebox.showwarning("提示", "请先指定设备文件（txt 或 xlsx）。", parent=self)
            return
        cmds = self._commands()
        if not cmds:
            messagebox.showwarning("提示", "采样命令不能为空。", parent=self)
            return
        ids = self._enabled_ids()
        if ids is None:
            return
        try:
            gap_min = float(self.gap_var.get().strip())
            workers = max(1, int(self.workers_var.get().strip()))
        except ValueError:
            messagebox.showwarning("提示", "两轮间隔/并发数必须是数字。", parent=self)
            return
        if gap_min < 0:
            messagebox.showwarning("提示", "间隔不能为负。", parent=self)
            return
        if gap_min > 0 and not messagebox.askyesno(
                "确认", f"将连设备跑两轮巡检，两轮之间等待 {gap_min:g} 分钟（期间可随时停止）。\n\n"
                        "⚠ 巡检会登录设备执行只读查询命令，请确认已获得授权。\n\n继续吗？", parent=self):
            return
        self._stop.clear()
        self.result = None
        self._alerts = []
        self._render([])
        self._set_busy(True)
        self.summary_var.set("两轮采样中…")
        threading.Thread(target=self._work_online, args=(dev_file, cmds, ids, gap_min, workers),
                         daemon=True).start()

    def _work_online(self, dev_file: str, cmds: list[str], ids: list[str],
                     gap_min: float, workers: int) -> None:
        try:
            devices = self._parse_devices(dev_file)
            if not devices:
                self._put("error", "设备文件里没有可用设备", ""); return
            total = len(devices)
            self._put("progress", f"第 1 轮采样（{total} 台）", 0, total * 2)

            class_dev = self.cls_var.get()
            r1_raw: dict[str, dict] = {}

            def one(d):
                host, devtype, user, pwd = d
                try:
                    return host, self._ssh_run(host, user, pwd, devtype, cmds), None
                except Exception as e:
                    return host, {}, str(e)

            from concurrent.futures import ThreadPoolExecutor, as_completed
            done = 0
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = [ex.submit(one, d) for d in devices]
                for fu in as_completed(futs):
                    host, outs, err = fu.result()
                    done += 1
                    if err:
                        self._put("warn", f"{host} 第 1 轮失败：{err[:120]}")
                    r1_raw[host] = outs
                    self._put("progress", "第 1 轮采样", done, total * 2)
                    if self._stop.is_set():
                        break

            if self._stop.is_set():
                self._put("error", "操作已停止", ""); return

            if gap_min > 0:
                import time as _t
                wait_s = gap_min * 60
                t0 = _t.time()
                while _t.time() - t0 < wait_s:
                    if self._stop.is_set():
                        self._put("error", "操作已停止", ""); return
                    left = int(wait_s - (_t.time() - t0))
                    self._put("progress", f"等待第 2 轮（剩余 {left // 60} 分 {left % 60} 秒）",
                              total, total * 2)
                    _t.sleep(2)

            self._put("progress", "第 2 轮采样", total, total * 2)
            r2_raw: dict[str, dict] = {}
            import time as _t
            t_round1_start = _t.time()
            done = 0
            with ThreadPoolExecutor(max_workers=workers) as ex:
                futs = [ex.submit(one, d) for d in devices]
                for fu in as_completed(futs):
                    host, outs, err = fu.result()
                    done += 1
                    if err:
                        self._put("warn", f"{host} 第 2 轮失败：{err[:120]}")
                    r2_raw[host] = outs
                    self._put("progress", "第 2 轮采样", total + done, total * 2)
                    if self._stop.is_set():
                        break

            # 采样窗口：用两轮的开始时刻差（比"配置的间隔"更真实）
            interval = max(1.0, gap_min * 60) if gap_min > 0 else max(1.0, _t.time() - t_round1_start)
            self._put("progress", "解析并判定…", total * 2, total * 2)
            s1, s2 = {}, {}
            for host in r1_raw:
                t = next((d[1] for d in devices if d[0] == host), "huawei")
                s1[host] = RP.parse_device_sample(r1_raw.get(host, {}), device=host, vendor=t,
                                                 ts=0.0, device_class=class_dev)
                s2[host] = RP.parse_device_sample(r2_raw.get(host, {}), device=host, vendor=t,
                                                 ts=interval, device_class=class_dev)

            res = RA.analyze_samples(s1, s2, rules=self._rules, enabled=ids,
                                     device_class=class_dev, interval_seconds=interval,
                                     progress=lambda m, c, t: self._put("progress", m, c, t))
            self._put("done", res)
        except Exception as e:
            import traceback
            self._put("error", str(e), traceback.format_exc())

    # ══════════════════════════════════════════════════════════════
    # B. 离线分析
    # ══════════════════════════════════════════════════════════════

    def _start_offline(self) -> None:
        if self._busy:
            return
        r1, r2 = self.r1_var.get().strip(), self.r2_var.get().strip()
        if not r1 or not os.path.exists(r1):
            messagebox.showwarning("提示", "请选择第 1 期报告 CSV。", parent=self)
            return
        if r2 and not os.path.exists(r2):
            messagebox.showwarning("提示", "第 2 期报告不存在。", parent=self)
            return
        ids = self._enabled_ids()
        if ids is None:
            return
        self._stop.clear()
        self.result = None
        self._alerts = []
        self._render([])
        self._set_busy(True)
        self.summary_var.set("分析中…")
        threading.Thread(target=self._work_offline,
                         args=(r1, r2 or None, ids, self.cls_var.get()), daemon=True).start()

    def _work_offline(self, r1: str, r2: str | None, ids: list[str], cls: str) -> None:
        try:
            res = RA.analyze_reports(r1, r2, rules=self._rules, enabled=ids, device_class=cls,
                                     progress=lambda m, c, t: self._put("progress", m, c, t))
            self._put("done", res)
        except Exception as e:
            import traceback
            self._put("error", str(e), traceback.format_exc())

    # ══════════════════════════════════════════════════════════════
    # 渲染 / 跳转 / 详情 / 导出
    # ══════════════════════════════════════════════════════════════

    def _finish(self) -> None:
        self._set_busy(False)
        self.prog.config(value=self.prog["maximum"])
        self._apply_filter()
        s = (self.result or {}).get("summary", {})
        mode = "两轮差分" if s.get("two_round") else "单轮快照"
        self.summary_var.set(
            f"{mode} ｜ 设备 {s.get('devices', 0)} 台（{s.get('devices_with_alerts', 0)} 台有告警）"
            f" ｜ 高危 {s.get('high', 0)} / 一般 {s.get('medium', 0)} / 提示 {s.get('low', 0)}"
            f" ｜ 间隔 {s.get('interval_text', '—')}")
        warns = (self.result or {}).get("warnings") or []
        self.status_var.set(f"完成：共 {s.get('total', 0)} 条告警"
                            + ("；提示：" + "；".join(warns) if warns else ""))
        if not s.get("total"):
            messagebox.showinfo("结果", "未发现告警。\n\n单轮时看不出增长类问题"
                                        "（MAC 漂移 / CRC 增长 / 广播速率），需要两轮对比。",
                                parent=self)

    def _fail(self, msg: str, tb: str) -> None:
        self._set_busy(False)
        self.status_var.set("失败：" + msg[:160])
        messagebox.showerror("出错", f"{msg}\n\n{tb[-600:]}", parent=self)

    def _apply_filter(self) -> None:
        if not self.result:
            return
        want, kw = self.fsev.get(), self.fkw.get().strip().lower()
        rows = []
        for a in self.result.get("alerts", []):
            if want != "全部" and RA.SEVERITY_CN.get(a.get("severity")) != want:
                continue
            blob = f"{a.get('signal','')}{a.get('device','')}{a.get('interface','')}{a.get('evidence','')}".lower()
            if kw and kw not in blob:
                continue
            rows.append(a)
        self._render(rows)

    def _render(self, rows: list[dict]) -> None:
        self._alerts = rows
        self.tree.delete(*self.tree.get_children())
        for a in rows:
            ev = str(a.get("evidence", ""))
            self.tree.insert("", tk.END, values=(
                RA.SEVERITY_CN.get(a.get("severity"), ""), a.get("signal", ""),
                a.get("device", ""), a.get("interface", ""),
                ev[:150] + ("…" if len(ev) > 150 else "")),
                tags=(SEV_TAG.get(a.get("severity"), ""),))
        if rows:
            self.tree.selection_set(self.tree.get_children()[0])

    def _jump(self, direction: int) -> None:
        kids = self.tree.get_children()
        if not kids:
            self.status_var.set("没有可跳转的告警行")
            return
        cur = self.tree.selection()
        idx = kids.index(cur[0]) if cur and cur[0] in kids else (-1 if direction > 0 else 0)
        idx = (idx + direction) % len(kids)
        self.tree.selection_set(kids[idx]); self.tree.focus(kids[idx]); self.tree.see(kids[idx])
        self.status_var.set(f"第 {idx + 1} / {len(kids)} 条：{self.tree.item(kids[idx], 'values')[1]}")

    def _detail(self) -> None:
        sel = self.tree.selection()
        if not sel:
            return
        a = self._alerts[self.tree.get_children().index(sel[0])]
        w = tk.Toplevel(self)
        w.title(f"告警详情 - {a.get('signal','')} @ {a.get('device','')}")
        w.geometry("820x520")
        head = (f"级别：{RA.SEVERITY_CN.get(a.get('severity'), '')}"
                f"（置信度 {a.get('confidence','?')}）\n"
                f"信号：{a.get('signal','')}    规则：{a.get('rule_id','')}\n"
                f"设备：{a.get('device','')}    接口：{a.get('interface','') or '—'}\n"
                f"增量：{a.get('delta')}    阈值：{a.get('threshold')}")
        ttk.Label(w, text=head, justify="left", font=("Microsoft YaHei UI", 9, "bold"),
                  foreground="#1f4e79").pack(anchor="w", padx=12, pady=(12, 6))
        ttk.Label(w, text="原始证据：").pack(anchor="w", padx=12)
        t1 = ScrolledText(w, height=11, font=("Consolas", 9))
        t1.pack(fill=tk.BOTH, expand=True, padx=12, pady=(2, 6))
        t1.insert("1.0", str(a.get("evidence", ""))); t1.config(state=tk.DISABLED)
        ttk.Label(w, text="建议动作：").pack(anchor="w", padx=12)
        t2 = ScrolledText(w, height=6, font=("Microsoft YaHei UI", 9))
        t2.pack(fill=tk.BOTH, expand=True, padx=12, pady=(2, 6))
        t2.insert("1.0", str(a.get("advice", ""))); t2.config(state=tk.DISABLED)

        def cp() -> None:
            self.clipboard_clear()
            self.clipboard_append(f"{head}\n\n证据：\n{a.get('evidence','')}\n\n建议：\n{a.get('advice','')}")
            self.status_var.set("已复制该条告警到剪贴板")
        ttk.Button(w, text="复制到剪贴板", command=cp).pack(pady=(0, 10))

    def _export(self, kind: str) -> None:
        if not self.result:
            messagebox.showwarning("提示", "请先跑一次分析。", parent=self)
            return
        ts = RA.datetime.now().strftime("%Y%m%d_%H%M%S")
        base = self._last_export_dir or os.path.join(RP.app_dir(), "reports")
        os.makedirs(base, exist_ok=True)
        if kind == "html":
            fp = filedialog.asksaveasfilename(
                title="导出 HTML 报告", defaultextension=".html",
                filetypes=[("HTML 文件", "*.html"), ("所有文件", "*.*")],
                initialdir=base, initialfile=f"环路告警报告_{ts}.html")
            if not fp:
                return
            RA.alerts_to_html(self.result, fp, tool_name="环路 / 异常告警")
        else:
            fp = filedialog.asksaveasfilename(
                title="导出 CSV 清单", defaultextension=".csv",
                filetypes=[("CSV 文件", "*.csv"), ("所有文件", "*.*")],
                initialdir=base, initialfile=f"环路告警清单_{ts}.csv")
            if not fp:
                return
            RA.alerts_to_csv(self.result, fp)
        self._last_export_dir = os.path.dirname(fp)
        self.status_var.set(f"已导出：{fp}")
        if messagebox.askyesno("导出完成", f"已保存到：\n{fp}\n\n现在打开吗？", parent=self):
            try:
                os.startfile(fp)          # noqa: S606
            except Exception as e:
                messagebox.showerror("打开失败", str(e), parent=self)

    def _open_rules(self) -> None:
        p = RP.default_rules_path()
        if not os.path.exists(p):
            self._reload_rules()
        try:
            os.startfile(p)               # noqa: S606
            self.status_var.set(f"已打开规则表：{p}（改完点「重新加载规则」）")
        except Exception as e:
            messagebox.showerror("打开失败", f"{p}\n{e}", parent=self)

    def _reload_rules(self) -> None:
        self._rules = RP.load_rules()
        w = self._rules.get("_warnings") or []
        self.status_var.set("规则表已重新加载" + ("；" + "；".join(w) if w else ""))

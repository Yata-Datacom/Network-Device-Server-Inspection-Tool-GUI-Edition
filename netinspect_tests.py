"""Test center: connectivity probes and configuration-baseline checks.

This module is intentionally self-contained and reuses the V5 engine helpers
through the running application instance (device parsing, SSH connect, command
execution). It never writes credentials or config bodies to the public repo;
baselines live in the ignored ``baselines/`` folder.
"""

from __future__ import annotations

import csv
import difflib
import hashlib
import os
import queue
import socket
import threading
import time
import tkinter as tk
from datetime import datetime
from pathlib import Path
from tkinter import filedialog, messagebox, ttk

CONFIG_COMMANDS = {
    "huawei": "display current-configuration",
    "h3c": "display current-configuration",
    "ruijie": "show running-config",
    "cisco": "show running-config",
}
SMOKE_COMMANDS = {
    "huawei": "display version",
    "h3c": "display version",
    "ruijie": "show version",
    "cisco": "show version",
    "linux": "uname -a",
}
INSECURE_NAMES = str.maketrans({"/": "_", "\\": "_", ":": "_", "*": "_", "?": "_", " ": "_"})


def tcp_check(host: str, port: int = 22, timeout: float = 2.5) -> tuple[bool, str]:
    started = time.perf_counter()
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True, f"{(time.perf_counter() - started) * 1000:.0f} ms"
    except OSError as exc:
        return False, str(exc)[:80]


def baseline_name(host: str) -> str:
    return str(host).translate(INSECURE_NAMES) + ".cfg"


def baseline_compare(old: str, new: str) -> tuple[str, int, int]:
    if not old:
        return "新基线", len(new.splitlines()), 0
    if old == new:
        return "一致", 0, 0
    added = deleted = 0
    for line in difflib.unified_diff(old.splitlines(), new.splitlines(), lineterm="", n=0):
        if line.startswith("+") and not line.startswith("+++"):
            added += 1
        elif line.startswith("-") and not line.startswith("---"):
            deleted += 1
    return "已变更", added, deleted


def config_hash(text: str) -> str:
    return hashlib.sha256(text.encode("utf-8", errors="replace")).hexdigest()


class TestCenter(ttk.Frame):
    def __init__(self, parent, app):
        super().__init__(parent)
        self.app = app
        self.base_dir = app.base_dir
        self.report_dir = Path(getattr(app, "base_report_dir", os.path.join(self.base_dir, "reports")))
        self.baseline_dir = Path(self.base_dir) / "baselines"
        self.baseline_dir.mkdir(parents=True, exist_ok=True)
        self.devices: list[tuple] = []
        self.running = False
        self.current_configs: dict[str, str] = {}
        self._queue: queue.Queue = queue.Queue()
        self._build()

    # ── layout ────────────────────────────────────────────────────────
    def _build(self) -> None:
        source = ttk.LabelFrame(self, text="设备清单 / Device list", padding=10)
        source.pack(fill=tk.X, padx=10, pady=(8, 4))
        self.file_var = tk.StringVar(value=self.app.batch_filepath.get() if hasattr(self.app, "batch_filepath") else "")
        ttk.Label(source, text="文件：").pack(side=tk.LEFT)
        ttk.Entry(source, textvariable=self.file_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=4)
        ttk.Button(source, text="浏览…", style="TButton", command=self._browse).pack(side=tk.LEFT)
        ttk.Button(source, text="加载", style="TButton", command=self.load_devices).pack(side=tk.LEFT, padx=(4, 0))
        self.count_var = tk.StringVar(value="未加载设备")
        ttk.Label(source, textvariable=self.count_var, foreground="#64748b").pack(side=tk.LEFT, padx=10)
        self.smoke_var = tk.BooleanVar(value=True)
        ttk.Checkbutton(source, text="SSH 后执行冒烟命令", variable=self.smoke_var).pack(side=tk.LEFT, padx=8)

        nb = ttk.Notebook(self)
        nb.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 8))

        conn = ttk.Frame(nb)
        nb.add(conn, text="连通性测试")
        self._build_connectivity(conn)

        base = ttk.Frame(nb)
        nb.add(base, text="配置基线")
        self._build_baseline(base)

    def _build_connectivity(self, parent) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill=tk.X, padx=6, pady=6)
        ttk.Button(bar, text="开始测试", style="Accent.TButton",
                   command=self.run_connectivity).pack(side=tk.LEFT)
        ttk.Button(bar, text="停止", style="Danger.TButton",
                   command=self.stop).pack(side=tk.LEFT, padx=(4, 0))
        ttk.Button(bar, text="导出 CSV", style="TButton",
                   command=self.export_connectivity).pack(side=tk.LEFT, padx=(8, 0))
        self.conn_status = tk.StringVar(value="就绪 · 测试 ICMP / TCP 22 / SSH 登录")
        ttk.Label(bar, textvariable=self.conn_status, foreground="#64748b").pack(side=tk.LEFT, padx=12)

        cols = ("host", "type", "ping", "tcp", "ssh", "ms", "result", "detail")
        self.conn_tree = ttk.Treeview(parent, columns=cols, show="headings", height=12)
        for col, title, width in (
            ("host", "IP / 主机", 150), ("type", "类型", 80), ("ping", "Ping", 60),
            ("tcp", "TCP 22", 60), ("ssh", "SSH 登录", 80), ("ms", "耗时", 70),
            ("result", "结果", 90), ("detail", "证据 / 错误", 380),
        ):
            self.conn_tree.heading(col, text=title)
            self.conn_tree.column(col, width=width, anchor="w", stretch=(col == "detail"))
        vsb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.conn_tree.yview)
        self.conn_tree.configure(yscrollcommand=vsb.set)
        self.conn_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(6, 0), pady=(0, 6))
        vsb.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 6), pady=(0, 6))
        self.conn_tree.tag_configure("ok", foreground="#15803d")
        self.conn_tree.tag_configure("bad", foreground="#b91c1c")
        self.conn_tree.tag_configure("warn", foreground="#b45309")

    def _build_baseline(self, parent) -> None:
        bar = ttk.Frame(parent)
        bar.pack(fill=tk.X, padx=6, pady=6)
        ttk.Button(bar, text="检查配置变更", style="Accent.TButton",
                   command=self.run_baseline).pack(side=tk.LEFT)
        ttk.Button(bar, text="保存为基线", style="TButton",
                   command=self.save_baselines).pack(side=tk.LEFT, padx=(6, 0))
        ttk.Button(bar, text="停止", style="Danger.TButton",
                   command=self.stop).pack(side=tk.LEFT, padx=(4, 0))
        self.base_status = tk.StringVar(value="就绪 · 对比当前配置与 baselines/")
        ttk.Label(bar, textvariable=self.base_status, foreground="#64748b").pack(side=tk.LEFT, padx=12)

        cols = ("host", "type", "status", "added", "deleted", "baseline", "detail")
        self.base_tree = ttk.Treeview(parent, columns=cols, show="headings", height=12)
        for col, title, width in (
            ("host", "IP / 主机", 150), ("type", "类型", 80), ("status", "结果", 90),
            ("added", "新增行", 70), ("deleted", "删除行", 70),
            ("baseline", "基线时间", 140), ("detail", "说明", 380),
        ):
            self.base_tree.heading(col, text=title)
            self.base_tree.column(col, width=width, anchor="w", stretch=(col == "detail"))
        vsb = ttk.Scrollbar(parent, orient=tk.VERTICAL, command=self.base_tree.yview)
        self.base_tree.configure(yscrollcommand=vsb.set)
        self.base_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True, padx=(6, 0), pady=(0, 6))
        vsb.pack(side=tk.RIGHT, fill=tk.Y, padx=(0, 6), pady=(0, 6))
        self.base_tree.tag_configure("same", foreground="#15803d")
        self.base_tree.tag_configure("changed", foreground="#b45309")
        self.base_tree.tag_configure("new", foreground="#1d4ed8")
        self.base_tree.tag_configure("bad", foreground="#b91c1c")

    # ── data ──────────────────────────────────────────────────────────
    def _browse(self) -> None:
        path = filedialog.askopenfilename(
            title="选择设备清单",
            filetypes=[("设备清单", "*.txt *.csv *.xlsx *.xlsm"), ("所有文件", "*.*")])
        if path:
            self.file_var.set(path)
            self.load_devices()

    def load_devices(self) -> list[tuple]:
        path = self.file_var.get().strip()
        if not path or not os.path.exists(path):
            messagebox.showwarning("提示", "请先选择设备清单文件。")
            return []
        if path.lower().endswith((".xlsx", ".xlsm")):
            devices, errors = self.app._parse_device_excel(path)
        else:
            devices, errors = self.app._parse_device_file(path)
        self.devices = devices
        self.count_var.set(f"已加载 {len(devices)} 台" + (f" · {len(errors)} 行忽略" if errors else ""))
        self.conn_tree.delete(*self.conn_tree.get_children())
        self.base_tree.delete(*self.base_tree.get_children())
        for device in devices:
            host, devtype, user, _pwd = device[0], device[1], device[2], device[3]
            self.conn_tree.insert("", tk.END, iid=host, values=(host, devtype, "…", "…", "…", "", "待测", user))
            self.base_tree.insert("", tk.END, iid=host, values=(host, devtype, "待检查", "", "", "", ""))
        return devices

    # ── connectivity ──────────────────────────────────────────────────
    def run_connectivity(self) -> None:
        if self.running:
            return
        devices = self.load_devices() or self.devices
        if not devices:
            return
        self.running = True
        self.app.stop_event.clear()
        self.conn_status.set(f"测试中 · {len(devices)} 台")
        for device in devices:
            host = device[0]
            if self.conn_tree.exists(host):
                self.conn_tree.item(host, values=(host, device[1], "…", "…", "…", "", "测试中", ""))
        threading.Thread(target=self._conn_worker, args=(list(devices),), daemon=True).start()
        self.after(100, self._poll_conn)

    def _conn_worker(self, devices) -> None:
        for device in devices:
            if self.app.stop_event.is_set():
                break
            host, devtype, user, pwd = device[0], device[1], device[2], device[3]
            started = time.perf_counter()
            # use the module-level ICMP helper imported by the V5 engine
            import net_inspect_gui_v5 as base
            ping_ok, rtts, _err = base.icmp_ping(host, count=1, timeout=1.5)
            ping_text = f"{rtts[0]:.0f}ms" if rtts else ("通" if ping_ok else "不通")
            tcp_ok, tcp_info = tcp_check(host, 22)
            ssh_text = "未测"
            detail = tcp_info
            if tcp_ok:
                client = None
                try:
                    client = self.app._create_ssh_client()
                    self.app._ssh_connect(client, host, 22, user, pwd, timeout=6)
                    ssh_text = "成功"
                    if self.smoke_var.get():
                        cmd = SMOKE_COMMANDS.get(str(devtype).lower(), SMOKE_COMMANDS["huawei"])
                        out = self.app._run_commands_via_shell(client, devtype, {"smoke": cmd}, timeout=8)
                        text = out.get("smoke", "").strip()
                        detail = next((ln.strip() for ln in text.splitlines() if ln.strip()), "命令无输出")[:160]
                except Exception as exc:
                    ssh_text = "失败"
                    detail = base._friendly_conn_error(exc)[:160]
                finally:
                    if client:
                        try:
                            client.close()
                        except Exception:
                            pass
            elapsed = f"{(time.perf_counter() - started):.1f}s"
            if ping_ok and tcp_ok and ssh_text == "成功":
                result = "通过"
            elif tcp_ok and ssh_text == "失败":
                result = "SSH 失败"
            elif ping_ok:
                result = "端口不通"
            else:
                result = "不可达"
            self._queue.put(("conn", {
                "host": host, "type": devtype, "ping": ping_text, "tcp": "通" if tcp_ok else "不通",
                "ssh": ssh_text, "ms": elapsed, "result": result, "detail": detail,
            }))
        self._queue.put(("conn_done", None))

    def _poll_conn(self) -> None:
        while True:
            try:
                kind, data = self._queue.get_nowait()
            except queue.Empty:
                break
            if kind == "conn" and self.conn_tree.exists(data["host"]):
                tag = "ok" if data["result"] == "通过" else ("warn" if data["result"] in ("SSH 失败", "端口不通") else "bad")
                self.conn_tree.item(data["host"], tags=(tag,), values=(
                    data["host"], data["type"], data["ping"], data["tcp"], data["ssh"],
                    data["ms"], data["result"], data["detail"]))
            elif kind == "conn_done":
                self.running = False
                self.conn_status.set("测试完成")
                return
        if self.running:
            self.after(100, self._poll_conn)

    def export_connectivity(self) -> None:
        rows = [self.conn_tree.item(iid, "values") for iid in self.conn_tree.get_children()]
        if not rows:
            messagebox.showinfo("提示", "没有可导出的结果。")
            return
        self.report_dir.mkdir(parents=True, exist_ok=True)
        path = self.report_dir / f"connectivity_{datetime.now():%Y%m%d_%H%M%S}.csv"
        with path.open("w", newline="", encoding="utf-8-sig") as fh:
            writer = csv.writer(fh)
            writer.writerow(["host", "type", "ping", "tcp22", "ssh", "elapsed", "result", "detail"])
            writer.writerows(rows)
        self.conn_status.set(f"已导出 {path.name}")

    # ── configuration baseline ────────────────────────────────────────
    def run_baseline(self) -> None:
        if self.running:
            return
        devices = self.load_devices() or self.devices
        if not devices:
            return
        self.running = True
        self.app.stop_event.clear()
        self.current_configs.clear()
        self.base_status.set(f"检查中 · {len(devices)} 台")
        threading.Thread(target=self._baseline_worker, args=(list(devices),), daemon=True).start()
        self.after(100, self._poll_baseline)

    def _baseline_worker(self, devices) -> None:
        import net_inspect_gui_v5 as base
        for device in devices:
            if self.app.stop_event.is_set():
                break
            host, devtype, user, pwd = device[0], device[1], device[2], device[3]
            devtype_norm = base.normalize_devtype(devtype)
            if devtype_norm not in CONFIG_COMMANDS:
                self._queue.put(("base", {"host": host, "type": devtype, "status": "跳过",
                                          "added": "", "deleted": "", "baseline": "",
                                          "detail": "该类型不做配置基线", "tag": "warn"}))
                continue
            client = None
            try:
                client = self.app._create_ssh_client()
                self.app._ssh_connect(client, host, 22, user, pwd, timeout=8)
                out = self.app._run_commands_via_shell(
                    client, devtype, {"config": CONFIG_COMMANDS[devtype_norm]}, timeout=20)
                config = out.get("config", "").strip()
                self.current_configs[host] = config
                path = self.baseline_dir / baseline_name(host)
                old = path.read_text(encoding="utf-8", errors="replace") if path.exists() else ""
                status, added, deleted = baseline_compare(old, config)
                tag = {"一致": "same", "已变更": "changed", "新基线": "new"}.get(status, "bad")
                stamp = datetime.fromtimestamp(path.stat().st_mtime).strftime("%Y-%m-%d %H:%M") if path.exists() else ""
                self._queue.put(("base", {"host": host, "type": devtype, "status": status,
                                          "added": added, "deleted": deleted, "baseline": stamp,
                                          "detail": f"sha256 {config_hash(config)[:12]}", "tag": tag}))
            except Exception as exc:
                self._queue.put(("base", {"host": host, "type": devtype, "status": "失败",
                                          "added": "", "deleted": "", "baseline": "",
                                          "detail": base._friendly_conn_error(exc)[:160], "tag": "bad"}))
            finally:
                if client:
                    try:
                        client.close()
                    except Exception:
                        pass
        self._queue.put(("base_done", None))

    def _poll_baseline(self) -> None:
        while True:
            try:
                kind, data = self._queue.get_nowait()
            except queue.Empty:
                break
            if kind == "base" and self.base_tree.exists(data["host"]):
                self.base_tree.item(data["host"], tags=(data.get("tag", ""),), values=(
                    data["host"], data["type"], data["status"], data["added"],
                    data["deleted"], data["baseline"], data["detail"]))
            elif kind == "base_done":
                self.running = False
                self.base_status.set(f"检查完成 · 已缓存 {len(self.current_configs)} 台当前配置")
                return
        if self.running:
            self.after(100, self._poll_baseline)

    def save_baselines(self) -> None:
        if not self.current_configs:
            messagebox.showinfo("提示", "请先检查配置，再保存基线。")
            return
        for host, config in self.current_configs.items():
            if not config:
                continue
            (self.baseline_dir / baseline_name(host)).write_text(config, encoding="utf-8")
        self.base_status.set(f"已保存 {len(self.current_configs)} 份基线到 {self.baseline_dir}")
        self.run_baseline()

    def stop(self) -> None:
        self.app.stop_event.set()
        self.conn_status.set("停止中…")
        self.base_status.set("停止中…")

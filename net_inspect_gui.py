"""
网络设备/服务器巡检工具 — GUI 版
Network Device / Server Inspection Tool — GUI Edition
======================================================

功能 Features:
  1. 单机巡检     Single Host    — SSH 连接单台设备，执行可编辑的命令集
  2. 批量巡检     Batch          — 并行多线程 + 异常检测 + HTML/CSV 报告导出
  3. 配置备份     Config Backup  — 备份 running-config / current-configuration
  4. 连接信息管理 Profiles       — profiles.json 保存常用连接
  5. 异常检测     Anomaly Detect — CPU / 内存 / 磁盘超阈值自动标红告警
  6. 紧凑输出     Compact Output — 仅保留关键指标行（CPU%、内存% 等）
  7. 简短巡检     Quick Inspect  — 仅执行 cpu/mem/alarm/device/stack 核心命令
  8. 运行状态栏   Status Column  — 批量巡检设备列表实时显示 Running/OK/FAILED

依赖 Dependencies:
  pip install paramiko
  可选 Optional: pip install openpyxl  (Excel 导出 / Excel export)

运行 Run: 双击"启动巡检工具.bat" 或 python net_inspect_gui.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import os
import re
import json
import csv
import time
import subprocess
import platform
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import paramiko


# ═══════════════════════════════════════════════════════════════
# 全局路径常量 / Global Path Constants
# ═══════════════════════════════════════════════════════════════

SCRIPT_DIR   = os.path.dirname(os.path.abspath(__file__))  # 脚本所在目录 / script directory
PROFILES_FILE = os.path.join(SCRIPT_DIR, "profiles.json")   # 连接信息文件 / saved connections
PRESETS_FILE  = os.path.join(SCRIPT_DIR, "presets.json")    # 巡检预设方案 / inspection presets
BACKUP_DIR    = os.path.join(SCRIPT_DIR, "backups")          # 配置备份目录 / config backups
REPORT_DIR   = os.path.join(SCRIPT_DIR, "reports")          # 报告导出目录 / exported reports

os.makedirs(BACKUP_DIR, exist_ok=True)
os.makedirs(REPORT_DIR, exist_ok=True)


# ═══════════════════════════════════════════════════════════════
# 设备类型元数据 / Device Type Metadata
# ═══════════════════════════════════════════════════════════════

# 下拉框显示的设备类型标签列表 / Combobox label list
DEVTYPE_LABELS = ["Linux Server", "Cisco Device", "Huawei Device"]

# 标签 → 内部 key: "Cisco Device" → "cisco" / UI label → internal key
DEVTYPE_MAP = {v: k for k, v in zip(["linux", "cisco", "huawei"], DEVTYPE_LABELS)}

# 内部 key → 标签: "cisco" → "Cisco Device" / internal key → UI label
DEVTYPE_LABEL_OF = {k: v for v, k in DEVTYPE_MAP.items()}


# ═══════════════════════════════════════════════════════════════
# 各设备类型禁用分页的命令 / Paging Disable Commands per Type
# ═══════════════════════════════════════════════════════════════

DISABLE_PAGING = {
    "linux":  None,                            # Linux 不需要 / not needed
    "cisco":  "terminal length 0",            # Cisco IOS
    "huawei": "screen-length 0 temporary",    # Huawei VRP
}


# ═══════════════════════════════════════════════════════════════
# 完整巡检命令集 / Full Inspection Command Sets
# 键 = 设备类型, 值 = {标题: Shell命令} / key=type, value={title: shell_cmd}
# ═══════════════════════════════════════════════════════════════

DEFAULT_COMMANDS = {
    "linux": {
        "Hostname":        "hostnamectl --static",
        "OS Release":      "cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2",
        "Kernel":          "uname -r",
        "Uptime":          "uptime -p",
        "CPU Info":        "lscpu | grep 'Model name' | sed 's/Model name:[[:space:]]*//'",
        "CPU Cores":       "nproc",
        "CPU Load":        "uptime | awk -F'load average:' '{print $2}'",
        "Memory":          "free -h | awk 'NR==2{printf \"total: %s  used: %s  free: %s  available: %s\", $2,$3,$4,$7}'",
        "Swap":            "free -h | awk 'NR==3{printf \"total: %s  used: %s  free: %s\", $2,$3,$4}'",
        "Disk Usage":      "df -h --total | awk '/^total/{printf \"total: %s  used: %s  avail: %s  use%%: %s\", $2,$3,$4,$5}'",
        "Top 10 by CPU":   "ps -eo pid,pcpu,pmem,user,comm --sort=-pcpu --no-headers | head -10",
        "Top 10 by Memory":"ps -eo pid,pcpu,pmem,user,comm --sort=-pmem --no-headers | head -10",
    },
    "cisco": {
        "Show Version":             "show version",
        "Show Running Config":      "show running-config",
        "Show IP Interface Brief":  "show ip interface brief",
        "Show Interfaces Status":   "show interfaces status",
        "Show VLAN Brief":          "show vlan brief",
        "Show MAC Address Table":   "show mac address-table",
        "Show CPU Usage":           "show processes cpu sorted | exclude 0.00%",
        "Show Memory":              "show memory statistics",
        "Show Logging (last 20)":   "show logging | tail 20",
        "Show Environment":         "show environment",
    },
    "huawei": {
        "Display Version":          "display version",
        "Display Current Config":   "display current-configuration",
        "Display IP Interface Brief":"display ip interface brief",
        "Display Interface Brief":  "display interface brief",
        "Display VLAN":             "display vlan",
        "Display MAC Address":      "display mac-address",
        "Display CPU Usage":        "display cpu-usage",
        "Display Memory":           "display memory-usage",
        "Display Logbuffer":        "display logbuffer",
        "Display Environment":      "display environment",
    },
}


# ═══════════════════════════════════════════════════════════════
# 配置备份命令（Linux 不备份）/ Backup Commands (Linux excluded)
# ═══════════════════════════════════════════════════════════════

BACKUP_COMMANDS = {
    "cisco":  "show running-config",
    "huawei": "display current-configuration",
    "linux":  None,
}


# ═══════════════════════════════════════════════════════════════
# 简短巡检命令集 / Quick Inspection Command Set
# 仅执行 cpu / mem / alarm / device / stack 核心命令
# ═══════════════════════════════════════════════════════════════

QUICK_COMMANDS = {
    "linux": {
        "CPU Load":       "uptime | awk -F'load average:' '{print $2}'",
        "CPU Cores":      "nproc",
        "Memory":         "free -h | awk 'NR==2{printf \"total: %s  used: %s  free: %s  available: %s\", $2,$3,$4,$7}'",
        "Disk Usage":     "df -h --total | awk '/^total/{printf \"total: %s  used: %s  avail: %s  use%%: %s\", $2,$3,$4,$5}'",
        "Top 5 by CPU":   "ps -eo pid,pcpu,pmem,comm --sort=-pcpu --no-headers | head -5",
    },
    "cisco": {
        "CPU":            "show processes cpu sorted | exclude 0.00%",
        "Memory":         "show memory statistics",
        "Alarm":          "show logging | include ERR|CRIT",
        "Device":         "show inventory",
        "Stack":          "show switch",
    },
    "huawei": {
        "CPU":            "display cpu-usage",
        "Memory":         "display memory-usage",
        "Alarm Active":   "display alarm active",
        "Device":         "display device",
        "CSS Status":     "display css status",
        "Stack":          "display stack",
    },
}


# ═══════════════════════════════════════════════════════════════
# 异常检测规则 / Anomaly Detection Rules
# 键 = 设备类型 / key = device type
# 值 = [{metric, pattern, threshold, compare, unit, desc, severity}]
# compare 支持 ">" 和 "<" / supports greater-than and less-than
# ═══════════════════════════════════════════════════════════════

ANOMALY_RULES = {
    "linux": [
        {
            "metric":    "CPU Load (5min)",       # 5分钟平均负载 / 5-min load avg
            "pattern":   r"load average:\s*([\d.]+),\s*[\d.]+,\s*[\d.]+",
            "threshold": 4.0, "compare": ">", "unit": "",
            "desc":      "5分钟负载过高 / high 5-min load",
            "severity":  "warning",
        },
        {
            "metric":    "Disk Usage",            # 磁盘使用率 / disk usage
            "pattern":   r"(\d+)%\s+/",
            "threshold": 80, "compare": ">", "unit": "%",
            "desc":      "磁盘使用率超过 80% / disk usage > 80%",
            "severity":  "critical",
        },
    ],
    "cisco": [
        {
            "metric":    "CPU Usage",
            "pattern":   r"CPU utilization.*?(\d+)%",
            "threshold": 80, "compare": ">", "unit": "%",
            "desc":      "CPU 利用率超过 80% / CPU utilization > 80%",
            "severity":  "critical",
        },
        {
            "metric":    "CPU 5sec",              # 5秒 CPU 利用率 / 5-sec CPU
            "pattern":   r"five seconds?:\s*(\d+)%",
            "threshold": 80, "compare": ">", "unit": "%",
            "desc":      "5秒 CPU 利用率超过 80% / 5-sec CPU > 80%",
            "severity":  "critical",
        },
    ],
    "huawei": [
        {
            "metric":    "CPU Usage",
            "pattern":   r"CPU (?:usage|Usage).*?(\d+)%",
            "threshold": 80, "compare": ">", "unit": "%",
            "desc":      "CPU 利用率超过 80% / CPU utilization > 80%",
            "severity":  "critical",
        },
        {
            "metric":    "Memory Usage",
            "pattern":   r"[Mm]emory.*?(?:usage|Usage|using).*?(\d+)%",
            "threshold": 80, "compare": ">", "unit": "%",
            "desc":      "内存利用率超过 80% / memory usage > 80%",
            "severity":  "critical",
        },
    ],
}


# ═══════════════════════════════════════════════════════════════
# 紧凑输出过滤规则 / Compact Output Filter Rules
# 键 = 设备类型 → 命令标题 → [保留行的正则列表]
# 值为 None = 不过滤（完整保留）/ no filtering, keep all
# 未匹配的命令标题 = 保留全输出 / unknown title → keep all
# ═══════════════════════════════════════════════════════════════

OUTPUT_FILTERS = {
    "cisco": {
        "Show Version": [
            r"Cisco.*Software.*Version", r"uptime is",
            r"System image file is", r"bytes of (memory|RAM)",
        ],
        "Show Running Config": None,   # 配置文件不压缩 / don't compress configs
        "Show IP Interface Brief":     [r"^\S+\s+\d", r"Interface\s+IP-Address"],
        "Show Interfaces Status":      [r"^\S+\s+\S+\s+(connected|notconnect|err)", r"Port\s+Name"],
        "Show VLAN Brief":             [r"^\d+\s+\S", r"VLAN\s+Name"],
        "Show MAC Address Table":      [r"^\S+\s+\d+\s+\S{4}", r"Mac Address"],
        "Show CPU Usage":              [r"CPU utilization.*\d+%"],
        "Show Memory":                 [r"Processor.*\d+", r"Total.*\d+", r"Used.*\d+", r"Free.*\d+"],
        "Show Logging (last 20)":      [r"%\S+"],
        "Show Environment":            [r"Temperature", r"Fan", r"Power", r"\d+\s*C"],
        # ── 简短巡检标题兼容 / quick-inspect title compat ──
        "CPU":    [r"CPU utilization.*\d+%"],
        "Memory": [r"Processor.*\d+", r"Total.*\d+", r"Used.*\d+", r"Free.*\d+"],
        "Alarm":  [r"%\S+"],
        "Device": [r"Cisco.*Software.*Version", r"uptime is", r"bytes of (memory|RAM)"],
        "Stack":  [r"\d+\s+\S+\s+\S+\s+\S+", r"Switch\s+#", r"Role", r"State"],
    },
    "huawei": {
        "Display Version":        [r"VRP.*software.*[Vv]ersion", r"Huawei.*[Vv]ersion", r"uptime is"],
        "Display Current Config": None,
        "Display IP Interface Brief": [r"^\S+\s+\d", r"Interface\s+IP"],
        "Display Interface Brief":    [r"^\S+\s+(up|down)", r"Interface\s+PHY"],
        "Display VLAN":               [r"^\d+\s+\S", r"VLAN\s+ID"],
        "Display MAC Address":        [r"^\S+\s+\S{4}", r"MAC\s+Address"],
        "Display CPU Usage":   [r"CPU Usage\s*:\s*\d+%", r"CPU Using Percentage\s*:?\s*\d+%", r"System CPU.*:\s*\d+%"],
        "Display Memory":      [r"Memory Using Percentage\s*:?\s*(Is:?\s*)?\d+%"],
        "Display Logbuffer":   [r"%\S+", r"Error|Warning|Critical"],
        "Display Environment": [r"Temperature", r"FAN", r"\d+\s*C"],
        # ── 简短巡检标题兼容 / quick-inspect title compat ──
        "CPU":          [r"CPU Usage\s*:\s*\d+%", r"CPU Using Percentage\s*:?\s*\d+%", r"System CPU.*:\s*\d+%"],
        "Memory":       [r"Memory Using Percentage\s*:?\s*(Is:?\s*)?\d+%"],
        "Alarm Active": [r"\d{4}-\d{2}-\d{2}", r"Critical|Major|Minor|Warning", r"Sequence"],
        "Device":       [r"VRP.*software.*[Vv]ersion", r"Huawei.*[Vv]ersion", r"uptime is", r"Slot\s+\d+"],
        "CSS Status":   [r"CSS\s+[Ss]tatus", r"[Ee]nable", r"[Mm]ember", r"Master", r"Priority"],
        "Stack":        [r"[Ss]tack\s+[Ss]tatus", r"[Mm]ember", r"Role", r"Priority"],
    },
    "linux": {
        "Hostname":          None,
        "OS Release":        [r"PRETTY_NAME"],
        "Kernel":            None,
        "Uptime":            None,
        "CPU Info":          [r"Model name"],
        "CPU Cores":         None,
        "CPU Load":          None,
        "Memory":            [r"Mem:", r"Swap:"],
        "Swap":              [r"Swap:"],
        "Disk Usage":        [r"^total"],
        "Top 10 by CPU":     [r"^\s*\d+\s+\d+\.\d+"],
        "Top 10 by Memory":  [r"^\s*\d+\s+\d+\.\d+"],
        "Top 5 by CPU":      [r"^\s*\d+\s+\d+\.\d+"],   # 简短巡检兼容 / quick compat
    },
}


# ═══════════════════════════════════════════════════════════════
# 模块级辅助函数 / Module-level Helper Functions
# ═══════════════════════════════════════════════════════════════

def detect_anomalies(devtype: str, command_title: str, output: str) -> list:
    """
    在命令输出中检测异常指标 / Scan command output for anomaly indicators.

    :param devtype:       设备类型 (linux/cisco/huawei) / device type
    :param command_title: 命令标题（用于记录异常来源）/ command title for traceability
    :param output:        命令的 stdout 文本 / command output text
    :return: 告警字典列表，每项含 metric/value/threshold/desc/severity 字段
    """
    alerts = []
    rules = ANOMALY_RULES.get(devtype, [])
    for rule in rules:
        # 用正则提取候选数值 / extract candidate values via regex
        matches = re.findall(rule["pattern"], output, re.IGNORECASE)
        for value_str in matches:
            try:
                value = float(value_str)
            except ValueError:
                continue
            # 根据 compare 方向判断是否触发 / compare direction: > or <
            triggered = (value > rule["threshold"]) if rule["compare"] == ">" else (value < rule["threshold"])
            if triggered:
                alerts.append({
                    "metric":    rule["metric"],
                    "value":     value,
                    "threshold": rule["threshold"],
                    "unit":      rule["unit"],
                    "desc":      rule["desc"],
                    "severity":  rule["severity"],
                    "source":    command_title,
                })
    return alerts


def generate_html_report(results: list, filepath: str) -> str:
    """生成 HTML 巡检报告 / Generate HTML inspection report."""
    now = datetime.now().strftime("%Y-%m-%d %H:%M:%S")
    summary_rows = ""
    detail_blocks = ""

    for host, devtype, status, cmds_output, alerts_list in results:
        anomaly_count = len(alerts_list)
        status_color = "#4caf50" if status == "OK" else "#f44336"
        anomaly_badge = (
            f'<span style="color:#fff;background:#ff9800;padding:2px 6px;border-radius:3px;font-size:12px">'
            f'{anomaly_count} alerts</span>' if anomaly_count else ""
        )
        type_badge = f'<span style="color:#666;font-size:12px">[{devtype.upper()}]</span>'

        summary_rows += (
            f"<tr><td>{host}</td><td>{type_badge}</td>"
            f'<td style="color:{status_color};font-weight:bold">{status}</td>'
            f"<td>{anomaly_badge}</td></tr>"
        )

        detail_blocks += f'<h3>{host} {type_badge}</h3>'
        if alerts_list:
            detail_blocks += '<div style="background:#fff3e0;padding:10px;margin:5px 0;border-left:4px solid #ff9800">'
            detail_blocks += "<strong>⚠ Anomalies Detected:</strong><ul>"
            for a in alerts_list:
                detail_blocks += (
                    f'<li><b>{a["metric"]}</b>: {a["value"]}{a["unit"]} '
                    f'(threshold {a["threshold"]}{a["unit"]}) — {a["desc"]}</li>'
                )
            detail_blocks += "</ul></div>"
        for title, output in cmds_output:
            escaped = output.replace("&", "&amp;").replace("<", "&lt;").replace(">", "&gt;")
            detail_blocks += f"<h4>{title}</h4><pre>{escaped}</pre>"

    html = f"""<!DOCTYPE html>
<html lang="zh">
<head>
<meta charset="utf-8"><title>Network Inspection Report</title>
<style>
 body {{ font-family:'Segoe UI',Arial,sans-serif; margin:20px; background:#f5f5f5; }}
 .container {{ max-width:1200px; margin:0 auto; background:#fff; padding:30px; border-radius:8px; box-shadow:0 2px 10px rgba(0,0,0,.1); }}
 h1 {{ color:#333; border-bottom:3px solid #2196f3; padding-bottom:10px; }}
 h2 {{ color:#555; margin-top:30px; }} h3 {{ color:#2196f3; margin-top:25px; }}
 h4 {{ color:#666; margin:15px 0 5px; font-size:14px; }}
 table {{ border-collapse:collapse; width:100%; margin:10px 0; }}
 th {{ background:#2196f3; color:#fff; padding:10px; text-align:left; }}
 td {{ padding:8px 10px; border-bottom:1px solid #e0e0e0; }} tr:hover {{ background:#f0f8ff; }}
 pre {{ background:#263238; color:#aed581; padding:12px; border-radius:4px; overflow-x:auto; font-size:12px; line-height:1.5; }}
 .footer {{ margin-top:30px; color:#999; font-size:12px; text-align:center; }}
</style></head><body><div class="container">
<h1>Network Inspection Report</h1>
<p style="color:#888">Generated: {now}</p>
<h2>Summary</h2>
<table><tr><th>Device</th><th>Type</th><th>Status</th><th>Anomalies</th></tr>
{summary_rows}</table>
<h2>Detailed Results</h2>
{detail_blocks}
<div class="footer">Generated by Network Inspection Tool</div>
</div></body></html>"""
    with open(filepath, "w", encoding="utf-8") as f:
        f.write(html)
    return filepath


def generate_csv_report(results: list, filepath: str) -> str:
    """生成 CSV 巡检报告（UTF-8 BOM，Excel 可直接打开）/ CSV report with BOM for Excel."""
    with open(filepath, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Device", "Type", "Status", "Anomalies", "Command", "Output"])
        for host, devtype, status, cmds_output, alerts_list in results:
            anomaly_text = "; ".join(f'{a["metric"]}={a["value"]}{a["unit"]}' for a in alerts_list)
            for title, output in cmds_output:
                writer.writerow([host, devtype, status, anomaly_text, title, output])
    return filepath


def generate_excel_report(results: list, filepath: str) -> str:
    """生成 Excel 巡检报告（依赖 openpyxl）/ Excel report (requires openpyxl)."""
    try:
        from openpyxl import Workbook
        from openpyxl.styles import Font, PatternFill
    except ImportError:
        raise ImportError("openpyxl not installed. Run: pip install openpyxl")

    wb = Workbook(); ws = wb.active; ws.title = "Summary"
    hf = Font(bold=True, color="FFFFFF", size=11)
    hfill = PatternFill(start_color="2196F3", end_color="2196F3", fill_type="solid")
    wfill = PatternFill(start_color="FFF3E0", end_color="FFF3E0", fill_type="solid")

    ws.append(["Device", "Type", "Status", "Anomalies"])
    for cell in ws[1]:
        cell.font = hf; cell.fill = hfill

    for host, devtype, status, cmds_output, alerts_list in results:
        anomaly_text = "; ".join(f'{a["metric"]}={a["value"]}{a["unit"]}' for a in alerts_list)
        row = ws.max_row + 1
        ws.append([host, devtype.upper(), status, anomaly_text])
        if alerts_list:
            for cell in ws[row]:
                cell.fill = wfill

    ws2 = wb.create_sheet("Details")
    ws2.append(["Device", "Command", "Output"])
    for cell in ws2[1]:
        cell.font = hf; cell.fill = hfill
    for host, devtype, status, cmds_output, alerts_list in results:
        for title, output in cmds_output:
            ws2.append([host, title, output])

    ws.column_dimensions["A"].width  = 18
    ws.column_dimensions["B"].width  = 10
    ws.column_dimensions["C"].width  = 12
    ws.column_dimensions["D"].width  = 50
    ws2.column_dimensions["A"].width = 18
    ws2.column_dimensions["B"].width = 30
    ws2.column_dimensions["C"].width = 80
    wb.save(filepath)
    return filepath


# ═══════════════════════════════════════════════════════════════
# 主 GUI 类 / Main GUI Class
# ═══════════════════════════════════════════════════════════════

class NetworkInspectGUI:
    """
    网络巡检工具主窗口 / Main inspection tool window.

    四个标签页 / Four tabs:
      - Single Host    : 单机巡检 / single device inspection
      - Batch Inspection: 并行批量巡检 + 异常检测 + 报告导出 / parallel batch
      - Config Backup  : 网络设备配置备份 / running-config backup
      - Profiles       : 连接信息增删改查 / connection profile CRUD
    """

    # ────────── 队列消息格式 / Queue Message Protocol ──────────
    # 三元组 (target, msg_type, data) / three-tuple
    #   target  : "single" | "batch" | "backup"  → 路由到哪个输出区 / output routing
    #   msg_type: "output" | "error" | "alert" | "result" | "summary"
    #             | "status" | "device_status" | "progress" | "done"
    #   data    : str (output/error/summary) | dict (alert) |
    #             tuple (result/device_status) | int (progress) | None (done)

    def __init__(self, root: tk.Tk) -> None:
        self.root = root
        self.root.title("Network Inspection Tool")
        self.root.geometry("1000x800")
        self.root.minsize(800, 600)

        # 线程间通信队列 / inter-thread message queue (worker → UI)
        self.result_queue: queue.Queue = queue.Queue()
        # 共享停止标志 / shared stop flag (single/batch/backup)
        self.stop_event = threading.Event()
        self.running = False

        self.last_results: list = []       # 最近一次批量巡检结果 / cached for export
        self.anomaly_store: dict = {}      # 异常结果缓存（预留）/ anomaly cache (reserved)
        self.profiles: list = self._load_profiles()
        self.presets: list = self._load_presets()
        self._device_row: dict = {}        # host → treeview iid 映射

        # 全局键盘快捷键 / global keyboard shortcuts
        self.root.bind_all("<Escape>", lambda e: self._stop_all())  # Esc → 停止 / stop
        self.root.bind_all("<Control-Return>", lambda e: self._handle_ctrl_enter())  # Ctrl+Enter → 启动批量
        # pre-check 开关 / ping reachability toggle
        self.precheck_var = tk.BooleanVar(value=True)

        self._setup_ui()
        self._poll_queue()                 # 启动每 100ms 的队列轮询 / start 100ms poll

    # ═══════════════════════════════════════════════════════════
    # Profiles 持久化 / Profiles Persistence (profiles.json)
    # ═══════════════════════════════════════════════════════════

    def _load_profiles(self) -> list:
        """从 profiles.json 读取已保存的连接信息 / Load saved connections."""
        if not os.path.exists(PROFILES_FILE):
            return []
        try:
            with open(PROFILES_FILE, "r", encoding="utf-8") as f:
                return json.load(f).get("profiles", [])
        except Exception:
            return []

    def _save_profiles(self) -> None:
        """将 profiles 列表写回 profiles.json / Persist profiles to JSON."""
        with open(PROFILES_FILE, "w", encoding="utf-8") as f:
            json.dump({"profiles": self.profiles}, f, indent=2, ensure_ascii=False)

    # ═══════════════════════════════════════════════════════════
    # Presets 持久化 / Presets Persistence (presets.json)
    # ═══════════════════════════════════════════════════════════

    def _load_presets(self) -> list:
        """从 presets.json 读入巡检预设方案 / Load inspection presets."""
        if not os.path.exists(PRESETS_FILE):
            return []
        try:
            with open(PRESETS_FILE, "r", encoding="utf-8") as f:
                return json.load(f).get("presets", [])
        except Exception:
            return []

    def _save_presets(self) -> None:
        """将 presets 写回 presets.json / Persist presets to JSON."""
        with open(PRESETS_FILE, "w", encoding="utf-8") as f:
            json.dump({"presets": self.presets}, f, indent=2, ensure_ascii=False)

    # ═══════════════════════════════════════════════════════════
    # 顶层 UI：Notebook + 4 标签页 + 状态栏 / Top-level Layout
    # ═══════════════════════════════════════════════════════════

    def _setup_ui(self) -> None:
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tab_single   = ttk.Frame(notebook); notebook.add(self.tab_single,   text="Single Host")
        self.tab_batch    = ttk.Frame(notebook); notebook.add(self.tab_batch,    text="Batch Inspection")
        self.tab_backup   = ttk.Frame(notebook); notebook.add(self.tab_backup,   text="Config Backup")
        self.tab_profiles = ttk.Frame(notebook); notebook.add(self.tab_profiles, text="Profiles")

        self._build_single_tab()
        self._build_batch_tab()
        self._build_backup_tab()
        self._build_profiles_tab()

        # 底部状态栏 / bottom status bar
        self.status_var = tk.StringVar(value="Ready")
        ttk.Label(self.root, textvariable=self.status_var,
                  relief=tk.SUNKEN, anchor=tk.W, padding=(5, 2)
                 ).pack(fill=tk.X, side=tk.BOTTOM)

    # ═══════════════════════════════════════════════════════════
    # 标签页 1 — Single Host (单机巡检 / single device)
    # ═══════════════════════════════════════════════════════════

    def _build_single_tab(self) -> None:
        """构建单机巡检标签页 / Build single-host inspection tab."""
        input_frame = ttk.LabelFrame(self.tab_single, text="Connection", padding=10)
        input_frame.pack(fill=tk.X, padx=10, pady=(10, 5))

        # ── Profile 快速加载下拉框 / profile quick-load dropdown ──
        pf = ttk.Frame(input_frame); pf.pack(fill=tk.X, pady=(0, 5))
        ttk.Label(pf, text="Load Profile:", width=14).pack(side=tk.LEFT)
        self.profile_combo = ttk.Combobox(
            pf, values=[p.get("name","") for p in self.profiles], state="readonly", width=24
        )
        self.profile_combo.pack(side=tk.LEFT, padx=(0, 10))
        self.profile_combo.bind("<<ComboboxSelected>>", self._on_profile_selected)

        # ── 行1 Row1: Device Type + IP + Port ──
        r1 = ttk.Frame(input_frame); r1.pack(fill=tk.X, pady=2)
        ttk.Label(r1, text="Device Type:", width=14).pack(side=tk.LEFT)
        self.single_devtype = ttk.Combobox(r1, values=DEVTYPE_LABELS, state="readonly", width=16)
        self.single_devtype.current(0); self.single_devtype.pack(side=tk.LEFT, padx=(0, 10))
        self.single_devtype.bind("<<ComboboxSelected>>", self._on_devtype_changed)

        ttk.Label(r1, text="IP Address:", width=12).pack(side=tk.LEFT)
        self.single_host = ttk.Entry(r1)
        self.single_host.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        ttk.Label(r1, text="Port:", width=6).pack(side=tk.LEFT)
        self.single_port = ttk.Entry(r1, width=8)
        self.single_port.insert(0, "22"); self.single_port.pack(side=tk.LEFT)
        # 在输入框中按回车启动巡检 / Enter key starts inspection
        for w in (self.single_host, self.single_port):
            w.bind("<Return>", lambda e: self._start_single())

        # ── 行2 Row2: Username + Password ──
        r2 = ttk.Frame(input_frame); r2.pack(fill=tk.X, pady=2)
        ttk.Label(r2, text="Username:", width=14).pack(side=tk.LEFT)
        self.single_user = ttk.Entry(r2)
        self.single_user.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0, 10))
        ttk.Label(r2, text="Password:", width=8).pack(side=tk.LEFT)
        self.single_pwd = ttk.Entry(r2, show="*")
        self.single_pwd.pack(side=tk.LEFT, fill=tk.X, expand=True)
        # 用户名/密码框按回车也启动巡检
        for w in (self.single_user, self.single_pwd):
            w.bind("<Return>", lambda e: self._start_single())

        # ── 行3 Row3: 选项复选框 + Start/Stop 按钮 / option checkboxes + buttons ──
        r3 = ttk.Frame(input_frame); r3.pack(fill=tk.X, pady=(5, 0))
        self.anomaly_toggle_single = tk.BooleanVar(value=True)
        ttk.Checkbutton(r3, text="Anomaly Detection", variable=self.anomaly_toggle_single).pack(side=tk.LEFT, padx=(0,5))
        self.compact_toggle_single = tk.BooleanVar(value=True)
        ttk.Checkbutton(r3, text="Compact Output", variable=self.compact_toggle_single).pack(side=tk.LEFT, padx=(0,5))
        self.quick_toggle_single = tk.BooleanVar(value=False)
        ttk.Checkbutton(r3, text="Quick Inspection", variable=self.quick_toggle_single,
                        command=self._on_quick_single_toggle).pack(side=tk.LEFT, padx=(0,5))
        ttk.Checkbutton(r3, text="Pre-check (ping)", variable=self.precheck_var).pack(side=tk.LEFT, padx=(0,5))

        self.btn_single = ttk.Button(r3, text="Start Inspection", command=self._start_single)
        self.btn_single.pack(side=tk.RIGHT, padx=(5, 0))
        self.btn_single_stop = ttk.Button(r3, text="Stop", command=self._stop_all, state=tk.DISABLED)
        self.btn_single_stop.pack(side=tk.RIGHT)

        # ── 命令编辑区 / editable commands area ──
        cmd_frame = ttk.LabelFrame(self.tab_single, text="Commands (editable)", padding=5)
        cmd_frame.pack(fill=tk.X, padx=10, pady=5)
        br = ttk.Frame(cmd_frame); br.pack(fill=tk.X)
        ttk.Button(br, text="Reset to Default", command=self._reset_single_commands).pack(side=tk.LEFT, padx=(0, 10))

        # 预设方案选择 / preset selector
        ttk.Label(br, text="Presets:", font=("", 8)).pack(side=tk.LEFT)
        self.preset_combo = ttk.Combobox(br, values=[], state="readonly", width=14, font=("", 8))
        self.preset_combo.pack(side=tk.LEFT, padx=(3, 3))
        self._refresh_preset_combo()
        ttk.Button(br, text="Load", command=self._load_preset).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(br, text="Save", command=self._save_preset).pack(side=tk.LEFT, padx=(0, 2))
        ttk.Button(br, text="Del", command=self._delete_preset).pack(side=tk.LEFT)

        self.cmd_count_var = tk.StringVar(value="")
        ttk.Label(br, textvariable=self.cmd_count_var, foreground="gray").pack(side=tk.RIGHT)

        self.single_cmds_text = tk.Text(cmd_frame, height=6, font=("Consolas", 9), wrap=tk.NONE, undo=True)
        sy = ttk.Scrollbar(cmd_frame, orient=tk.VERTICAL,   command=self.single_cmds_text.yview)
        sx = ttk.Scrollbar(cmd_frame, orient=tk.HORIZONTAL, command=self.single_cmds_text.xview)
        self.single_cmds_text.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.single_cmds_text.pack(fill=tk.X, expand=True)
        sy.pack(side=tk.RIGHT, fill=tk.Y); sx.pack(side=tk.BOTTOM, fill=tk.X)
        ttk.Label(cmd_frame, text="Format: Title::command  (one per line)",
                  foreground="gray", font=("", 8)).pack(anchor=tk.W)
        self._load_default_commands("linux")

        # ── 输出区 / output area ──
        out_frame = ttk.LabelFrame(self.tab_single, text="Output", padding=5)
        out_frame.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5, 10))

        # 搜索栏 / search bar
        search_row = ttk.Frame(out_frame)
        search_row.pack(fill=tk.X, pady=(0, 3))
        ttk.Label(search_row, text="Search:", font=("", 8)).pack(side=tk.LEFT)
        self.single_search_entry = ttk.Entry(search_row, width=20, font=("", 9))
        self.single_search_entry.pack(side=tk.LEFT, padx=(3, 5))
        self.single_search_entry.bind("<Return>", lambda e: self._search_find(
            self.single_output, self.single_search_entry, self.single_search_label, True))
        self.single_search_entry.bind("<KeyRelease>", lambda e: self._search_highlight(
            self.single_output, self.single_search_entry, self.single_search_label))
        ttk.Button(search_row, text="↑", width=2, command=lambda: self._search_find(
            self.single_output, self.single_search_entry, self.single_search_label, False)).pack(side=tk.LEFT)
        ttk.Button(search_row, text="↓", width=2, command=lambda: self._search_find(
            self.single_output, self.single_search_entry, self.single_search_label, True)).pack(side=tk.LEFT, padx=(1, 5))
        self.single_search_label = ttk.Label(search_row, text="", font=("", 8), foreground="gray")
        self.single_search_label.pack(side=tk.LEFT)

        self.single_output = scrolledtext.ScrolledText(
            out_frame, wrap=tk.WORD, font=("Consolas", 10), state=tk.DISABLED
        )
        self.single_output.pack(fill=tk.BOTH, expand=True)
        # 颜色标签: 严重 critical=红 red、警告 warning=橙 orange、搜索 match=黄 yellow
        self.single_output.tag_config("critical", foreground="#d32f2f", background="#ffebee")
        self.single_output.tag_config("warning",  foreground="#e65100", background="#fff3e0")
        self.single_output.tag_config("search_match", background="#ffff00")
        self.single_output.tag_config("search_current", background="#ff9632")

    # ────────── 设备类型切换 & 命令加载 / type switch & command loading ──────────

    def _on_devtype_changed(self, event=None) -> None:
        """设备类型下拉框变更时重新加载对应命令集 / Reload commands on type change."""
        devtype = DEVTYPE_MAP.get(self.single_devtype.get(), "linux")
        self._load_commands_for_current_mode(devtype)
        self._set_status(f"Switched to {self.single_devtype.get()} — commands reloaded")

    def _on_quick_single_toggle(self) -> None:
        """简短巡检复选框切换：ON 锁定编辑并加载简短命令 / Toggle quick mode."""
        devtype = DEVTYPE_MAP.get(self.single_devtype.get(), "linux")
        if self.quick_toggle_single.get():
            self._load_quick_commands(devtype)
            self.single_cmds_text.config(state=tk.DISABLED, bg="#f0f0f0")
            self._set_status("Quick Inspection mode ON — limited commands")
        else:
            self._load_default_commands(devtype)
            self.single_cmds_text.config(state=tk.NORMAL, bg="white")
            self._set_status("Quick Inspection mode OFF")

    def _load_commands_for_current_mode(self, devtype: str) -> None:
        """根据当前 Quick 开关状态加载对应命令集 / Load commands based on Quick toggle."""
        if self.quick_toggle_single.get():
            self._load_quick_commands(devtype)
        else:
            self._load_default_commands(devtype)

    def _load_quick_commands(self, devtype: str) -> None:
        """将 QUICK_COMMANDS 写入文本框并锁定编辑 / Load quick set & lock editing."""
        self._write_commands_to_text(QUICK_COMMANDS.get(devtype, {}))
        self.single_cmds_text.config(state=tk.DISABLED)

    def _load_default_commands(self, devtype: str) -> None:
        """将 DEFAULT_COMMANDS 写入文本框 / Load default full command set."""
        self._write_commands_to_text(DEFAULT_COMMANDS.get(devtype, {}))

    def _write_commands_to_text(self, cmds: dict) -> None:
        """把 {标题:命令} 字典写入文本框（格式 title::cmd）/ Write command dict to text area."""
        lines = [f"{t}::{c}" for t, c in cmds.items()]
        self.single_cmds_text.config(state=tk.NORMAL)
        self.single_cmds_text.delete("1.0", tk.END)
        self.single_cmds_text.insert("1.0", "\n".join(lines))
        self._update_cmd_count()

    def _parse_commands_from_text(self) -> dict:
        """从文本框解析 {标题: 命令} 字典，跳过空行和 # 注释 / Parse text area to cmd dict."""
        cmds = {}
        for line in self.single_cmds_text.get("1.0", tk.END).splitlines():
            line = line.strip()
            if not line or line.startswith("#"):
                continue
            if "::" in line:
                title, cmd = line.split("::", 1)
                title, cmd = title.strip(), cmd.strip()
                if title and cmd:
                    cmds[title] = cmd
        return cmds

    def _reset_single_commands(self) -> None:
        """恢复当前设备类型的默认/简短命令集 / Reset commands to defaults (or quick)."""
        devtype = DEVTYPE_MAP.get(self.single_devtype.get(), "linux")
        self._load_commands_for_current_mode(devtype)

    def _update_cmd_count(self) -> None:
        """更新命令计数标签 / Update command count label."""
        self.cmd_count_var.set(f"{len(self._parse_commands_from_text())} command(s)")

    # ────────── Profile 快速加载 / Profile Quick Load ──────────

    def _on_profile_selected(self, event=None) -> None:
        """选择 Profile 后自动填入 IP/端口/用户/密码/设备类型 / Auto-fill form from profile."""
        name = self.profile_combo.get()
        for p in self.profiles:
            if p.get("name") != name:
                continue
            self.single_host.delete(0, tk.END);  self.single_host.insert(0, p.get("host",""))
            self.single_port.delete(0, tk.END);  self.single_port.insert(0, str(p.get("port",22)))
            self.single_user.delete(0, tk.END);  self.single_user.insert(0, p.get("user",""))
            self.single_pwd.delete(0, tk.END);   self.single_pwd.insert(0, p.get("password",""))
            devtype = p.get("devtype", "linux")
            self.single_devtype.set(DEVTYPE_LABEL_OF.get(devtype, "Linux Server"))
            self._load_commands_for_current_mode(devtype)
            self._set_status(f"Profile loaded: {name}")
            return

    # ═══════════════════════════════════════════════════════════
    # 标签页 2 — Batch Inspection (批量巡检 / parallel batch)
    # ═══════════════════════════════════════════════════════════

    def _build_batch_tab(self) -> None:
        """构建批量巡检标签页 / Build batch inspection tab."""
        # ── 设备文件选择 / device file selection ──
        ff = ttk.LabelFrame(self.tab_batch, text="Device List File", padding=10)
        ff.pack(fill=tk.X, padx=10, pady=(10, 5))
        ttk.Label(ff,
            text='Format: IP:user:password:[linux|cisco|huawei]:"cmd1,cmd2,..."  (type optional, default cisco)',
            foreground="gray", font=("", 8)
        ).pack(anchor=tk.W, pady=(0,5))
        row = ttk.Frame(ff); row.pack(fill=tk.X)
        self.batch_filepath = tk.StringVar(value="devices.txt")
        ttk.Entry(row, textvariable=self.batch_filepath).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(row, text="Browse...", command=self._browse_file).pack(side=tk.LEFT, padx=(5,0))
        ttk.Button(row, text="Load", command=self._load_devices).pack(side=tk.LEFT, padx=(5,0))

        # ── 设备列表树 / device list treeview ──
        lf = ttk.LabelFrame(self.tab_batch, text="Devices", padding=5)
        lf.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        cols = ("host", "type", "user", "status", "commands")
        self.device_tree = ttk.Treeview(lf, columns=cols, show="headings", selectmode="extended")
        for col, txt in zip(cols, ["IP Address","Type","Username","Status","Commands"]):
            self.device_tree.heading(col, text=txt)
        self.device_tree.column("host",     width=140, anchor=tk.W)
        self.device_tree.column("type",     width=70,  anchor=tk.CENTER)
        self.device_tree.column("user",     width=100, anchor=tk.W)
        self.device_tree.column("status",   width=80,  anchor=tk.CENTER)
        self.device_tree.column("commands", width=300, anchor=tk.W)
        sy = ttk.Scrollbar(lf, orient=tk.VERTICAL,   command=self.device_tree.yview)
        sx = ttk.Scrollbar(lf, orient=tk.HORIZONTAL, command=self.device_tree.xview)
        self.device_tree.configure(yscrollcommand=sy.set, xscrollcommand=sx.set)
        self.device_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sy.pack(side=tk.RIGHT, fill=tk.Y); sx.pack(side=tk.BOTTOM, fill=tk.X)

        # ── 操作按钮行 / action buttons row ──
        bf = ttk.Frame(self.tab_batch); bf.pack(fill=tk.X, padx=10, pady=(0,5))
        self.btn_batch_all = ttk.Button(bf, text="Inspect Selected", command=self._start_batch_selected)
        self.btn_batch_all.pack(side=tk.LEFT, padx=(0,5))
        self.btn_batch_stop = ttk.Button(bf, text="Stop", command=self._stop_all, state=tk.DISABLED)
        self.btn_batch_stop.pack(side=tk.LEFT, padx=(0,10))

        ttk.Label(bf, text="Parallel:", foreground="gray").pack(side=tk.LEFT)
        self.concurrency_var = tk.IntVar(value=3)
        ttk.Spinbox(bf, from_=1, to=10, textvariable=self.concurrency_var, width=4).pack(side=tk.LEFT, padx=(5,10))

        self.anomaly_toggle_batch = tk.BooleanVar(value=True)
        ttk.Checkbutton(bf, text="Anomaly Detection", variable=self.anomaly_toggle_batch).pack(side=tk.LEFT, padx=(0,5))
        self.compact_toggle_batch = tk.BooleanVar(value=True)
        ttk.Checkbutton(bf, text="Compact Output", variable=self.compact_toggle_batch).pack(side=tk.LEFT, padx=(0,5))
        self.quick_toggle_batch = tk.BooleanVar(value=False)
        ttk.Checkbutton(bf, text="Quick Inspection", variable=self.quick_toggle_batch).pack(side=tk.LEFT, padx=(0,10))

        # 导出按钮（巡检完成后启用）/ export buttons (enabled after inspection)
        self.btn_export_html = ttk.Button(bf, text="Export HTML", command=self._export_html, state=tk.DISABLED)
        self.btn_export_html.pack(side=tk.RIGHT, padx=(5,0))
        self.btn_export_csv  = ttk.Button(bf, text="Export CSV",  command=self._export_csv,  state=tk.DISABLED)
        self.btn_export_csv.pack(side=tk.RIGHT, padx=(5,0))

        self.batch_progress = ttk.Progressbar(bf, mode="determinate", length=150)
        self.batch_progress.pack(side=tk.RIGHT, padx=(10,0))
        self.progress_label = ttk.Label(bf, text="")
        self.progress_label.pack(side=tk.RIGHT, padx=(5,0))

        # ── 输出区 / output area ──
        of = ttk.LabelFrame(self.tab_batch, text="Output", padding=5)
        of.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5,10))

        # 搜索栏 / search bar
        srow = ttk.Frame(of); srow.pack(fill=tk.X, pady=(0,3))
        ttk.Label(srow, text="Search:", font=("",8)).pack(side=tk.LEFT)
        self.batch_search_entry = ttk.Entry(srow, width=20, font=("",9))
        self.batch_search_entry.pack(side=tk.LEFT, padx=(3,5))
        self.batch_search_entry.bind("<Return>", lambda e: self._search_find(
            self.batch_output, self.batch_search_entry, self.batch_search_label, True))
        self.batch_search_entry.bind("<KeyRelease>", lambda e: self._search_highlight(
            self.batch_output, self.batch_search_entry, self.batch_search_label))
        ttk.Button(srow, text="↑", width=2, command=lambda: self._search_find(
            self.batch_output, self.batch_search_entry, self.batch_search_label, False)).pack(side=tk.LEFT)
        ttk.Button(srow, text="↓", width=2, command=lambda: self._search_find(
            self.batch_output, self.batch_search_entry, self.batch_search_label, True)).pack(side=tk.LEFT, padx=(1,5))
        self.batch_search_label = ttk.Label(srow, text="", font=("",8), foreground="gray")
        self.batch_search_label.pack(side=tk.LEFT)

        self.batch_output = scrolledtext.ScrolledText(
            of, wrap=tk.WORD, font=("Consolas",10), state=tk.DISABLED
        )
        self.batch_output.pack(fill=tk.BOTH, expand=True)
        self.batch_output.tag_config("critical", foreground="#d32f2f", background="#ffebee")
        self.batch_output.tag_config("warning",  foreground="#e65100", background="#fff3e0")
        self.batch_output.tag_config("success",  foreground="#2e7d32")
        self.batch_output.tag_config("search_match", background="#ffff00")
        self.batch_output.tag_config("search_current", background="#ff9632")

    # ═══════════════════════════════════════════════════════════
    # 标签页 3 — Config Backup (配置备份 / running-config backup)
    # ═══════════════════════════════════════════════════════════

    def _build_backup_tab(self) -> None:
        """构建配置备份标签页 / Build config backup tab."""
        ff = ttk.LabelFrame(self.tab_backup, text="Device List", padding=10)
        ff.pack(fill=tk.X, padx=10, pady=(10,5))
        row = ttk.Frame(ff); row.pack(fill=tk.X)
        self.backup_filepath = tk.StringVar(value="devices.txt")
        ttk.Entry(row, textvariable=self.backup_filepath).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(row, text="Browse...", command=self._browse_backup_file).pack(side=tk.LEFT, padx=(5,0))
        ttk.Button(row, text="Load", command=self._load_backup_devices).pack(side=tk.LEFT, padx=(5,0))

        dr = ttk.Frame(ff); dr.pack(fill=tk.X, pady=(5,0))
        ttk.Label(dr, text="Backup Dir:").pack(side=tk.LEFT)
        self.backup_dir_var = tk.StringVar(value=BACKUP_DIR)
        ttk.Entry(dr, textvariable=self.backup_dir_var).pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(5,0))
        ttk.Button(dr, text="...", width=3, command=self._choose_backup_dir).pack(side=tk.LEFT, padx=(5,0))

        lf = ttk.LabelFrame(self.tab_backup, text="Devices", padding=5)
        lf.pack(fill=tk.BOTH, expand=True, padx=10, pady=5)
        cols = ("host","type","user")
        self.backup_tree = ttk.Treeview(lf, columns=cols, show="headings", selectmode="extended")
        for col, txt in zip(cols, ["IP Address","Type","Username"]):
            self.backup_tree.heading(col, text=txt)
        self.backup_tree.column("host", width=160, anchor=tk.W)
        self.backup_tree.column("type", width=80,  anchor=tk.CENTER)
        self.backup_tree.column("user", width=120, anchor=tk.W)
        sy = ttk.Scrollbar(lf, orient=tk.VERTICAL, command=self.backup_tree.yview)
        self.backup_tree.configure(yscrollcommand=sy.set)
        self.backup_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sy.pack(side=tk.RIGHT, fill=tk.Y)

        bf = ttk.Frame(self.tab_backup); bf.pack(fill=tk.X, padx=10, pady=(0,5))
        self.btn_backup_sel = ttk.Button(bf, text="Backup Selected", command=self._start_backup)
        self.btn_backup_sel.pack(side=tk.LEFT, padx=(0,5))
        self.btn_backup_stop = ttk.Button(bf, text="Stop", command=self._stop_all, state=tk.DISABLED)
        self.btn_backup_stop.pack(side=tk.LEFT)
        self.backup_progress = ttk.Progressbar(bf, mode="determinate", length=150)
        self.backup_progress.pack(side=tk.RIGHT, padx=(10,0))
        self.backup_prog_label = ttk.Label(bf, text="")
        self.backup_prog_label.pack(side=tk.RIGHT, padx=(5,0))

        of = ttk.LabelFrame(self.tab_backup, text="Backup Log", padding=5)
        of.pack(fill=tk.BOTH, expand=True, padx=10, pady=(5,10))
        self.backup_output = scrolledtext.ScrolledText(
            of, wrap=tk.WORD, font=("Consolas",10), state=tk.DISABLED
        )
        self.backup_output.pack(fill=tk.BOTH, expand=True)

    def _browse_backup_file(self) -> None:   # 选择设备文件 / select device file
        path = filedialog.askopenfilename(title="Select device list file",
                                          filetypes=[("Text files","*.txt"),("All files","*.*")],
                                          initialfile="devices.txt")
        if path:
            self.backup_filepath.set(path); self._load_backup_devices()

    def _choose_backup_dir(self) -> None:    # 选择备份目录 / select backup dir
        path = filedialog.askdirectory(title="Select backup directory")
        if path:
            self.backup_dir_var.set(path)

    def _load_backup_devices(self) -> None:
        """加载设备列表到备份树视图（过滤 Linux）/ Load devices into backup treeview (excl. Linux)."""
        for item in self.backup_tree.get_children():
            self.backup_tree.delete(item)
        devices, _ = self._parse_device_file(self.backup_filepath.get())
        for host, devtype, user, pwd, cmds in devices:
            if devtype != "linux":
                self.backup_tree.insert("", tk.END,
                    values=(host, devtype.upper(), user),
                    tags=(f"{host}|{devtype}|{user}|{pwd}",))

    # ═══════════════════════════════════════════════════════════
    # 标签页 4 — Profiles (连接信息管理 / connection profile CRUD)
    # ═══════════════════════════════════════════════════════════

    def _build_profiles_tab(self) -> None:
        """构建 Profiles 管理标签页 / Build profiles management tab."""
        lf = ttk.LabelFrame(self.tab_profiles, text="Saved Profiles", padding=5)
        lf.pack(fill=tk.BOTH, expand=True, padx=10, pady=(10,5))
        cols = ("name","host","type","user")
        self.profile_tree = ttk.Treeview(lf, columns=cols, show="headings", selectmode="browse")
        for col, txt in zip(cols, ["Name","IP / Host","Type","Username"]):
            self.profile_tree.heading(col, text=txt)
        self.profile_tree.column("name", width=150, anchor=tk.W)
        self.profile_tree.column("host", width=150, anchor=tk.W)
        self.profile_tree.column("type", width=100, anchor=tk.CENTER)
        self.profile_tree.column("user", width=120, anchor=tk.W)
        sy = ttk.Scrollbar(lf, orient=tk.VERTICAL, command=self.profile_tree.yview)
        self.profile_tree.configure(yscrollcommand=sy.set)
        self.profile_tree.pack(side=tk.LEFT, fill=tk.BOTH, expand=True)
        sy.pack(side=tk.RIGHT, fill=tk.Y)
        self._refresh_profile_list()

        # 编辑表单 / edit form
        ff = ttk.LabelFrame(self.tab_profiles, text="Add / Edit Profile", padding=10)
        ff.pack(fill=tk.X, padx=10, pady=5)
        r1 = ttk.Frame(ff); r1.pack(fill=tk.X, pady=2)
        ttk.Label(r1, text="Name:", width=10).pack(side=tk.LEFT)
        self.prof_name = ttk.Entry(r1)
        self.prof_name.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,10))
        ttk.Label(r1, text="Type:", width=8).pack(side=tk.LEFT)
        self.prof_type = ttk.Combobox(r1, values=DEVTYPE_LABELS, state="readonly", width=16)
        self.prof_type.current(0); self.prof_type.pack(side=tk.LEFT)

        r2 = ttk.Frame(ff); r2.pack(fill=tk.X, pady=2)
        ttk.Label(r2, text="Host:", width=10).pack(side=tk.LEFT)
        self.prof_host = ttk.Entry(r2)
        self.prof_host.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,10))
        ttk.Label(r2, text="Port:", width=8).pack(side=tk.LEFT)
        self.prof_port = ttk.Entry(r2, width=8)
        self.prof_port.insert(0,"22"); self.prof_port.pack(side=tk.LEFT)

        r3 = ttk.Frame(ff); r3.pack(fill=tk.X, pady=2)
        ttk.Label(r3, text="User:", width=10).pack(side=tk.LEFT)
        self.prof_user = ttk.Entry(r3)
        self.prof_user.pack(side=tk.LEFT, fill=tk.X, expand=True, padx=(0,10))
        ttk.Label(r3, text="Password:", width=8).pack(side=tk.LEFT)
        self.prof_password = ttk.Entry(r3, show="*")
        self.prof_password.pack(side=tk.LEFT, fill=tk.X, expand=True)

        br = ttk.Frame(ff); br.pack(fill=tk.X, pady=(8,0))
        ttk.Button(br, text="Save", command=self._save_profile).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(br, text="Delete", command=self._delete_profile).pack(side=tk.LEFT, padx=(0,5))
        ttk.Button(br, text="Clear Form", command=self._clear_profile_form).pack(side=tk.LEFT)

        self.profile_tree.bind("<<TreeviewSelect>>", self._on_profile_tree_select)

    def _refresh_profile_list(self) -> None:
        """刷新 Profile 列表树视图 / Refresh profile treeview."""
        for item in self.profile_tree.get_children():
            self.profile_tree.delete(item)
        for p in self.profiles:
            self.profile_tree.insert("", tk.END, values=(
                p.get("name",""), p.get("host",""), p.get("devtype","linux").upper(), p.get("user","")
            ))

    def _on_profile_tree_select(self, event=None) -> None:
        """选中列表中的 Profile 后回填编辑表单 / Fill edit form from selected profile."""
        sel = self.profile_tree.selection()
        if not sel: return
        name = self.profile_tree.item(sel[0],"values")[0]
        for p in self.profiles:
            if p.get("name") == name:
                self.prof_name.delete(0,tk.END);    self.prof_name.insert(0,p.get("name",""))
                self.prof_host.delete(0,tk.END);    self.prof_host.insert(0,p.get("host",""))
                self.prof_port.delete(0,tk.END);    self.prof_port.insert(0,str(p.get("port",22)))
                self.prof_user.delete(0,tk.END);    self.prof_user.insert(0,p.get("user",""))
                self.prof_password.delete(0,tk.END);self.prof_password.insert(0,p.get("password",""))
                self.prof_type.set(DEVTYPE_LABEL_OF.get(p.get("devtype","linux"),"Linux Server"))
                return

    def _save_profile(self) -> None:
        """保存当前表单为 Profile / Save current form as a profile."""
        name = self.prof_name.get().strip(); host = self.prof_host.get().strip()
        if not name or not host:
            messagebox.showwarning("Warning","Name and Host are required."); return
        try:
            port = int(self.prof_port.get().strip() or "22")
        except ValueError:
            messagebox.showwarning("Warning","Port must be a number."); return
        devtype = DEVTYPE_MAP.get(self.prof_type.get(),"linux")
        profile = {"name":name,"host":host,"port":port,
                   "user":self.prof_user.get().strip(),
                   "password":self.prof_password.get(),"devtype":devtype}
        for i,p in enumerate(self.profiles):
            if p.get("name") == name:
                self.profiles[i] = profile; break
        else:
            self.profiles.append(profile)
        self._save_profiles(); self._refresh_profile_list()
        self._refresh_profile_combo(); self._set_status(f"Profile saved: {name}")

    def _delete_profile(self) -> None:
        """删除选中的 Profile / Delete selected profile."""
        sel = self.profile_tree.selection()
        if not sel:
            messagebox.showwarning("Warning","Select a profile to delete."); return
        name = self.profile_tree.item(sel[0],"values")[0]
        self.profiles = [p for p in self.profiles if p.get("name") != name]
        self._save_profiles(); self._refresh_profile_list()
        self._refresh_profile_combo(); self._clear_profile_form()
        self._set_status(f"Profile deleted: {name}")

    def _clear_profile_form(self) -> None:
        """清空 Profile 编辑表单 / Clear profile edit form."""
        for w in (self.prof_name, self.prof_host, self.prof_user, self.prof_password):
            w.delete(0,tk.END)
        self.prof_port.delete(0,tk.END); self.prof_port.insert(0,"22")
        self.prof_type.current(0)

    def _refresh_profile_combo(self) -> None:
        """刷新 Single Host 标签页的 Profile 下拉框列表 / Refresh profile combobox."""
        self.profile_combo["values"] = [p.get("name","") for p in self.profiles]

    # ═══════════════════════════════════════════════════════════
    # 预设方案管理 / Preset Management
    # ═══════════════════════════════════════════════════════════

    def _refresh_preset_combo(self) -> None:
        """刷新预设方案下拉框 / Refresh preset combobox."""
        self.preset_combo["values"] = [p.get("name","") for p in self.presets]

    def _load_preset(self) -> None:
        """加载选中的预设方案到命令文本框和设备类型 / Load selected preset."""
        name = self.preset_combo.get()
        for p in self.presets:
            if p.get("name") == name:
                devtype = p.get("devtype", "linux")
                self.single_devtype.set(DEVTYPE_LABEL_OF.get(devtype, "Linux Server"))
                # 关闭 Quick 模式，允许编辑 / disable quick mode to allow editing
                self.quick_toggle_single.set(False)
                self.single_cmds_text.config(state=tk.NORMAL, bg="white")
                self._write_commands_to_text(p.get("cmds", {}))
                self._set_status(f"Preset loaded: {name}")
                return
        messagebox.showwarning("Warning", "No preset selected.")

    def _save_preset(self) -> None:
        """将当前命令集保存为新预设方案 / Save current commands as a preset."""
        from tkinter import simpledialog
        name = simpledialog.askstring("Save Preset", "Preset name:", parent=self.root)
        if not name:
            return
        name = name.strip()
        cmds = self._parse_commands_from_text()
        if not cmds:
            messagebox.showwarning("Warning", "No commands to save."); return
        devtype = DEVTYPE_MAP.get(self.single_devtype.get(), "linux")
        preset = {"name": name, "devtype": devtype, "cmds": cmds}
        # 同名覆盖 / overwrite same name
        for i, p in enumerate(self.presets):
            if p.get("name") == name:
                self.presets[i] = preset; break
        else:
            self.presets.append(preset)
        self._save_presets()
        self._refresh_preset_combo()
        self.preset_combo.set(name)
        self._set_status(f"Preset saved: {name}")

    def _delete_preset(self) -> None:
        """删除选中的预设方案 / Delete selected preset."""
        name = self.preset_combo.get()
        if not name:
            messagebox.showwarning("Warning", "No preset selected."); return
        if not messagebox.askyesno("Delete Preset", f"Delete preset '{name}'?"):
            return
        self.presets = [p for p in self.presets if p.get("name") != name]
        self._save_presets()
        self._refresh_preset_combo()
        self.preset_combo.set("")
        self._set_status(f"Preset deleted: {name}")

    # ═══════════════════════════════════════════════════════════
    # 文件选择 & 设备解析 / File Selection & Device Parsing
    # ═══════════════════════════════════════════════════════════

    def _browse_file(self) -> None:
        """浏览并加载设备列表文件 / Browse and load device list file."""
        path = filedialog.askopenfilename(title="Select device list file",
                                          filetypes=[("Text files","*.txt"),("All files","*.*")],
                                          initialfile="devices.txt")
        if path:
            self.batch_filepath.set(path); self._load_devices()

    def _load_devices(self) -> None:
        """解析设备文件并填充 batch 树视图，同时建立 host→iid 映射 / Load & populate tree."""
        for item in self.device_tree.get_children():
            self.device_tree.delete(item)
        self._device_row.clear()
        devices, errors = self._parse_device_file(self.batch_filepath.get())
        for host, devtype, user, pwd, cmds in devices:
            iid = self.device_tree.insert("", tk.END,
                values=(host, devtype.upper(), user, "---", ", ".join(cmds)),
                tags=(f"{host}|{devtype}|{user}|{pwd}|{','.join(cmds)}",))
            self._device_row[host] = iid
        status = f"Loaded {len(devices)} device(s)"
        if errors: status += f" | {errors} parse error(s)"
        self._set_status(status)

    def _parse_device_file(self, filepath: str) -> tuple:
        """
        解析设备列表文件 / Parse device list file.

        支持格式 / Supported formats:
          带类型: IP:user:password:linux|cisco|huawei:"cmd1,cmd2"
          无类型: IP:user:password:"cmd1,cmd2"                  → 默认 cisco / defaults to cisco

        :return: (设备列表 [(host,devtype,user,pwd,[cmds])], 错误行数 / error count)
        """
        devices, errors = [], 0
        if not os.path.exists(filepath):
            return devices, errors
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                pat_with_type = re.compile(r'^([^:]+):([^:]+):([^:]+):(linux|cisco|huawei):"([^"]*)"$')
                pat_no_type   = re.compile(r'^([^:]+):([^:]+):([^:]+):"([^"]*)"$')
                for line in f:
                    line = line.strip()
                    if not line or line.startswith("#"):  # 跳过空行和注释 / skip blanks & comments
                        continue
                    m = pat_with_type.match(line)
                    if m:
                        host, user, pwd, devtype, cmds_str = m.groups()
                    else:
                        m = pat_no_type.match(line)
                        if m:
                            host, user, pwd, cmds_str = m.groups()
                            devtype = "cisco"           # 无类型时默认思科 / default cisco
                        else:
                            errors += 1; continue
                    cmds = [c.strip() for c in cmds_str.split(",") if c.strip()]
                    if cmds:
                        devices.append((host, devtype, user, pwd, cmds))
                    else:
                        errors += 1
        except Exception as e:
            messagebox.showerror("Error", f"Cannot open file:\n{e}")
        return devices, errors

    # ═══════════════════════════════════════════════════════════
    # 单机巡检 / Single Host Inspection
    # ═══════════════════════════════════════════════════════════

    def _start_single(self) -> None:
        """
        验证输入并启动单机巡检后台线程 / Validate & launch single-host worker thread.

        关键设计: 所有 tk 变量在主线程中读取后传给工作线程，
        避免跨线程访问 tk 对象 (tk 非线程安全)。
        Key: read all tk vars in main thread before passing to worker.
        """
        host = self.single_host.get().strip()
        user = self.single_user.get().strip()
        if not host or not user:
            messagebox.showwarning("Warning","IP address and username are required."); return
        try:
            port = int(self.single_port.get().strip() or "22")
        except ValueError:
            messagebox.showwarning("Warning","Port must be a number."); return
        cmds = self._parse_commands_from_text()
        if not cmds:
            messagebox.showwarning("Warning","No commands to execute."); return

        # 在主线程读 tk 变量 / read tk vars on main thread
        devtype         = DEVTYPE_MAP.get(self.single_devtype.get(), "linux")
        anomaly_enabled = self.anomaly_toggle_single.get()
        compact_enabled = self.compact_toggle_single.get()
        precheck_enabled = self.precheck_var.get()

        self.btn_single.config(state=tk.DISABLED)
        self.btn_single_stop.config(state=tk.NORMAL)
        self._clear_output(self.single_output)
        self._set_status(f"Connecting to {host}:{port} ({DEVTYPE_LABEL_OF.get(devtype,devtype)})...")

        self.stop_event.clear(); self.running = True
        threading.Thread(
            target=self._single_worker,
            args=(host, port, user, pwd, devtype, cmds, anomaly_enabled, compact_enabled, precheck_enabled),
            daemon=True
        ).start()

    def _single_worker(self, host, port, user, pwd, devtype, cmds, anomaly_enabled, compact_enabled, precheck_enabled=False):
        """
        单机巡检工作线程（后台运行）/ Single-host worker (runs on background thread).

        流程 / Flow:
          1. ping 预检（可选）/ optional pre-check
          2. SSH 连接 / connect
          3. 按设备类型选择执行方式 / branch by type:
             cisco/huawei → invoke_shell() 交互通道
             linux         → exec_command()  独立通道
          4. 可选 compact 过滤 / optional compact filter
          5. 可选 anomaly 检测 / optional anomaly detection
          6. 结果通过 queue 发回 UI 线程 / send results back via queue
        """
        Q = self.result_queue

        # ── ping 预检 / reachability pre-check ──
        if precheck_enabled:
            Q.put(("single","status",f"Pinging {host}..."))
            if not self._ping_host(host):
                Q.put(("single","error",f"Host unreachable (ping failed): {host}"))
                Q.put(("single","done",None)); return
            Q.put(("single","status",f"Ping OK — connecting to {host}..."))

        client = self._create_ssh_client()
        try:
            client.connect(host, port=port, username=user, password=pwd, timeout=10)
        except Exception as e:
            Q.put(("single","error",f"Connection failed: {e}"))
            Q.put(("single","done",None)); return

        Q.put(("single","output",
              f"{'='*60}\n  Inspection Report — {host}:{port} [{devtype.upper()}]\n{'='*60}\n"))
        Q.put(("single","status",f"Running on {host}..."))
        all_alerts = []

        if devtype in ("cisco","huawei"):
            # ── 网络设备 / network device: invoke_shell ──
            results = self._run_commands_via_shell(client, devtype, cmds)
            for title, output in results.items():
                if self.stop_event.is_set(): break
                if compact_enabled: output = self._filter_output(devtype, title, output)
                Q.put(("single","output",f"\n[{title}]\n{output}\n"))
                if anomaly_enabled:
                    for a in detect_anomalies(devtype, title, output):
                        Q.put(("single","alert",a)); all_alerts.append(a)
        else:
            # ── Linux: exec_command ──
            self._send_paging_disable(client, devtype)
            for title, cmd in cmds.items():
                if self.stop_event.is_set(): break
                try:
                    stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
                    output = stdout.read().decode(errors="replace").strip()
                    err    = stderr.read().decode(errors="replace").strip()
                    if compact_enabled: output = self._filter_output(devtype, title, output)
                    if output: Q.put(("single","output",f"\n[{title}]\n{output}\n"))
                    if err:    Q.put(("single","output",f"\n[{title} STDERR]\n{err}\n"))
                    if anomaly_enabled:
                        for a in detect_anomalies(devtype, title, output):
                            Q.put(("single","alert",a)); all_alerts.append(a)
                except Exception as e:
                    Q.put(("single","output",f"\n[{title}] Error: {e}\n"))

        client.close()
        if all_alerts:
            Q.put(("single","summary",f"\n⚠ {len(all_alerts)} anomaly(s) detected:\n"))
            for a in all_alerts:
                Q.put(("single","output",
                       f"  - [{a['severity'].upper()}] {a['desc']}: {a['value']}{a['unit']} "
                       f"(threshold {a['threshold']}{a['unit']})\n"))
        Q.put(("single","done",None))

    # ═══════════════════════════════════════════════════════════
    # 批量巡检 — 并行 ThreadPoolExecutor / Batch — Parallel
    # ═══════════════════════════════════════════════════════════

    def _get_selected_devices(self) -> list:
        """从树视图获取选中的设备列表（未选则全部）/ Get selected (or all) devices."""
        selected = self.device_tree.selection() or self.device_tree.get_children()
        devices = []
        for item in selected:
            tags = self.device_tree.item(item,"tags")
            if tags:
                parts = tags[0].split("|",4)
                if len(parts)==5:
                    host, devtype, user, pwd, cmds_str = parts
                    cmds = [c.strip() for c in cmds_str.split(",") if c.strip()]
                    devices.append((host,devtype,user,pwd,cmds))
        return devices

    def _start_batch_selected(self) -> None:
        """启动批量巡检 / Start batch inspection."""
        devices = self._get_selected_devices()
        if not devices:
            messagebox.showwarning("Warning","No devices to inspect."); return
        self.last_results = []
        self._clear_output(self.batch_output)

        # 重置所有设备状态为 "---" / reset all statuses
        for iid in self._device_row.values():
            if self.device_tree.exists(iid):
                vals = list(self.device_tree.item(iid,"values"))
                if len(vals)>=4: vals[3]="---"
                self.device_tree.item(iid,values=vals)

        self.btn_batch_all.config(state=tk.DISABLED)
        self.btn_batch_stop.config(state=tk.NORMAL)
        self.btn_export_html.config(state=tk.DISABLED)
        self.btn_export_csv.config(state=tk.DISABLED)
        self.stop_event.clear(); self.running = True

        self.batch_progress["maximum"] = len(devices)
        self.batch_progress["value"] = 0
        self.progress_label.config(text=f"0 / {len(devices)}")

        # 在主线程读 tk 变量 / read tk vars on main thread
        max_workers     = self.concurrency_var.get()
        anomaly_enabled = self.anomaly_toggle_batch.get()
        compact_enabled = self.compact_toggle_batch.get()
        quick_enabled   = self.quick_toggle_batch.get()
        precheck_enabled = self.precheck_var.get()

        self._set_status(f"Inspecting {len(devices)} device(s) in parallel (workers={max_workers})...")
        threading.Thread(
            target=self._batch_worker_parallel,
            args=(devices, max_workers, anomaly_enabled, compact_enabled, quick_enabled, precheck_enabled),
            daemon=True
        ).start()

    def _batch_worker_parallel(self, devices, max_workers, anomaly_enabled, compact_enabled, quick_enabled, precheck_enabled=False):
        """
        批量巡检工作线程 / Batch worker thread.

        使用 ThreadPoolExecutor 并行执行，结果通过 queue 发回 UI。
        Uses ThreadPoolExecutor for parallel execution; results go via queue.
        """
        Q = self.result_queue
        Q.put(("batch","output",f"{'='*60}\n  Network Device Inspection Report\n{'='*60}\n"))

        for dev in devices:
            Q.put(("batch","device_status",(dev[0],"Running...")))  # 标为运行中 / mark running

        completed = 0
        with ThreadPoolExecutor(max_workers=max_workers) as executor:
            future_map = {
                executor.submit(self._inspect_one_device, dev,
                                anomaly_enabled, compact_enabled, quick_enabled, precheck_enabled): dev
                for dev in devices
            }
            for future in as_completed(future_map):
                if self.stop_event.is_set():
                    for f in future_map: f.cancel()
                    Q.put(("batch","output","\n[!] Inspection stopped by user.\n"))
                    break
                try:
                    result = future.result()            # (host,devtype,status,cmds_output,alerts)
                    self.last_results.append(result)
                    host, devtype, status, cmds_output, alerts = result
                    Q.put(("batch","result",result))
                    Q.put(("batch","device_status",(host,status)))
                except Exception as e:
                    dev = future_map[future]
                    Q.put(("batch","output",f"\n  [ERROR] {dev[0]}: {e}\n"))
                    Q.put(("batch","device_status",(dev[0],"ERROR")))
                completed += 1
                Q.put(("batch","progress",completed))

        Q.put(("batch","done",None))

    def _inspect_one_device(self, device, anomaly_enabled, compact_enabled=False, quick_enabled=False, precheck_enabled=False):
        """
        对单台设备执行巡检（由 ThreadPoolExecutor 子线程调用）/ Inspect one device (called by pool).

        :return: (host, devtype, status, cmds_output, alerts_list)
                 status: "OK" | "FAILED" | "WARNING" | "UNREACHABLE"
        """
        host, devtype, user, pwd, cmds = device
        status = "OK"; cmds_output = []; all_alerts = []

        # ── ping 预检 / reachability pre-check ──
        if precheck_enabled and not self._ping_host(host):
            return (host, devtype, "UNREACHABLE", [(f"Ping", "Host unreachable")], [])

        # 简短巡检：用 QUICK_COMMANDS 覆盖设备文件命令 / quick mode override
        if quick_enabled:
            quick_cmds = QUICK_COMMANDS.get(devtype,{})
            if quick_cmds: cmds = list(quick_cmds.values())
        cmd_dict = {cmd: cmd for cmd in cmds}
        if quick_enabled:
            quick_cmds = QUICK_COMMANDS.get(devtype,{})
            if quick_cmds: cmd_dict = quick_cmds   # 使用友好短标题 / friendly short titles

        client = self._create_ssh_client()
        try:
            client.connect(host, username=user, password=pwd,
                           timeout=10, look_for_keys=False, allow_agent=False)
        except Exception as e:
            return (host, devtype, "FAILED", [(f"Connection",str(e))], [])

        # 分支执行 / branch by device type
        if devtype in ("cisco","huawei"):
            results = self._run_commands_via_shell(client, devtype, cmd_dict)
        else:
            results = self._exec_commands_linux(client, devtype, cmd_dict)

        for title, output in results.items():
            if self.stop_event.is_set(): break
            if compact_enabled: output = self._filter_output(devtype, title, output)
            cmds_output.append((title,output))
            if anomaly_enabled:
                all_alerts.extend(detect_anomalies(devtype, title, output))

        client.close()
        if all_alerts: status = "WARNING"
        return (host, devtype, status, cmds_output, all_alerts)

    def _exec_commands_linux(self, client, devtype, cmd_dict):
        """
        通过 exec_command 在 Linux 上执行命令（每命令独立通道）。
        Execute commands on Linux via exec_command (each cmd = separate channel).

        :return: {title: output} 字典
        """
        results = {}
        self._send_paging_disable(client, devtype)
        for title, cmd in cmd_dict.items():
            if self.stop_event.is_set(): break
            try:
                stdin, stdout, stderr = client.exec_command(cmd, timeout=30)
                output = stdout.read().decode(errors="replace").strip()
                err    = stderr.read().decode(errors="replace").strip()
                results[title] = output
                if err: results[title] += f"\n[STDERR] {err}"
            except Exception as e:
                results[title] = f"[ERROR] {e}"
        return results

    # ═══════════════════════════════════════════════════════════
    # 键盘快捷键 / Keyboard Shortcuts
    # ═══════════════════════════════════════════════════════════

    def _handle_ctrl_enter(self) -> None:
        """Ctrl+Enter: 根据当前活跃标签页启动对应巡检 / Start inspection on active tab."""
        notebook = self.root.nametowidget(
            self.root.winfo_children()[0] if self.root.winfo_children() else None
        )
        try:
            notebook = [c for c in self.root.winfo_children() if isinstance(c, ttk.Notebook)][0]
            idx = notebook.index(notebook.select())
            if idx == 0:
                self._start_single()
            elif idx == 1:
                self._start_batch_selected()
            elif idx == 2:
                self._start_backup()
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════
    # 停止 / Stop
    # ═══════════════════════════════════════════════════════════

    def _stop_all(self) -> None:
        """停止所有正在执行的巡检（单机/批量/备份共用 stop_event）/ Stop all running ops."""
        self.stop_event.set()
        self._set_status("Stopping...")

    # ═══════════════════════════════════════════════════════════
    # 配置备份 / Config Backup
    # ═══════════════════════════════════════════════════════════

    def _start_backup(self) -> None:
        """启动配置备份线程 / Launch backup worker thread."""
        selected = self.backup_tree.selection() or self.backup_tree.get_children()
        devices = []
        for item in selected:
            tags = self.backup_tree.item(item,"tags")
            if tags:
                parts = tags[0].split("|",3)
                if len(parts)==4: devices.append(parts)
        if not devices:
            messagebox.showwarning("Warning","No devices to backup."); return

        self.btn_backup_sel.config(state=tk.DISABLED)
        self.btn_backup_stop.config(state=tk.NORMAL)
        self._clear_output(self.backup_output)
        self.stop_event.clear()
        self.backup_progress["maximum"] = len(devices)
        self.backup_progress["value"] = 0
        self.backup_prog_label.config(text=f"0 / {len(devices)}")
        self._set_status(f"Backing up {len(devices)} device(s)...")

        threading.Thread(target=self._backup_worker,
                         args=(devices, self.backup_dir_var.get()), daemon=True).start()

    def _backup_worker(self, devices, backup_dir):
        """配置备份工作线程 / Backup worker thread."""
        Q = self.result_queue; completed = 0
        for host, devtype, user, pwd in devices:
            if self.stop_event.is_set():
                Q.put(("backup","output","\n[!] Backup stopped by user.\n")); break
            backup_cmd = BACKUP_COMMANDS.get(devtype)
            if not backup_cmd:
                Q.put(("backup","output",f"  {host} [{devtype.upper()}] — No backup command, skipping\n"))
                completed+=1; Q.put(("backup","progress",completed)); continue

            client = self._create_ssh_client()
            try:
                client.connect(host, username=user, password=pwd,
                               timeout=10, look_for_keys=False, allow_agent=False)
            except Exception as e:
                Q.put(("backup","output",f"  {host} [FAILED] Connection error: {e}\n"))
                completed+=1; Q.put(("backup","progress",completed)); continue

            result = self._run_commands_via_shell(client, devtype, {"backup":backup_cmd}, timeout=60)
            config = result.get("backup","").strip()
            client.close()

            # 保存: backups/<类型>/<IP>/<IP>_<时间戳>.cfg
            dev_dir = os.path.join(backup_dir, devtype, host)
            os.makedirs(dev_dir, exist_ok=True)
            ts = datetime.now().strftime("%Y%m%d_%H%M%S")
            fp = os.path.join(dev_dir, f"{host}_{ts}.cfg")
            with open(fp,"w",encoding="utf-8") as f: f.write(config)

            Q.put(("backup","output",
                  f"  {host} [{devtype.upper()}] ✓ Saved: {fp} ({len(config)} chars)\n"))
            completed+=1; Q.put(("backup","progress",completed))
        Q.put(("backup","done",None))

    # ═══════════════════════════════════════════════════════════
    # SSH 工具方法 / SSH Utility Methods
    # ═══════════════════════════════════════════════════════════

    @staticmethod
    def _ping_host(host: str, timeout: int = 2) -> bool:
        """
        ping 预检: 发送 1 个 ICMP 包, timeout 秒内响应则返回 True。
        Ping reachability check: 1 packet, returns True if host responds.
        """
        system = platform.system().lower()
        if system == "windows":
            cmd = ["ping", "-n", "1", "-w", str(timeout * 1000), host]
        else:
            cmd = ["ping", "-c", "1", "-W", str(timeout), host]
        try:
            result = subprocess.run(cmd, capture_output=True, timeout=timeout + 1)
            return result.returncode == 0
        except Exception:
            return False

    @staticmethod
    def _create_ssh_client() -> paramiko.SSHClient:
        """创建并配置 SSH 客户端 (AutoAddPolicy) / Create pre-configured SSH client."""
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return c

    @staticmethod
    def _filter_output(devtype: str, title: str, output: str) -> str:
        """
        紧凑模式过滤器 / Compact-mode output filter.

        根据 OUTPUT_FILTERS 规则只保留匹配正则的行。
        无规则 / 无匹配 → 返回原输出（兜底策略）。
        When no rule matches, return full output as fallback.
        """
        rules = OUTPUT_FILTERS.get(devtype,{})
        if title not in rules: return output
        patterns = rules[title]
        if patterns is None: return output          # None = 显式不过滤 / explicit no-filter
        kept = [line for line in output.splitlines()
                if line.strip() and any(re.search(p,line,re.IGNORECASE) for p in patterns)]
        return "\n".join(kept) if kept else output  # 无匹配行时返回原输出 / no match → original

    def _run_commands_via_shell(self, client, devtype, cmds, timeout=30):
        """
        通过 invoke_shell() 交互式 SSH 通道执行多条命令（Cisco/Huawei）。

        轮询机制: 每次 send 后，循环读 channel 直到无新数据 ≥ 3 秒
        (no_data_count * 150ms > 20) 或超时，视为该命令输出结束。

        Uses interactive shell channel: after each send, polls recv_ready()
        until 3s of silence or timeout, treating that as end-of-output.
        """
        results = {}
        try:
            channel = client.invoke_shell(width=200, height=100)
            time.sleep(1.5)                                  # 等待设备就绪 / wait for device
            if channel.recv_ready(): channel.recv(65535)     # 清空 banner / clear banner

            # 先发送禁用分页命令 / send paging-disable first
            paging_cmd = DISABLE_PAGING.get(devtype)
            if paging_cmd:
                channel.send(paging_cmd+'\n')
                time.sleep(0.6)
                if channel.recv_ready(): channel.recv(65535)

            for title, cmd in cmds.items():
                if self.stop_event.is_set(): break
                channel.send(cmd+'\n')
                time.sleep(0.4)

                output = ''
                deadline = time.time() + timeout
                no_data_count = 0
                while time.time() < deadline:
                    if channel.recv_ready():
                        output += channel.recv(65535).decode('utf-8', errors='replace')
                        no_data_count = 0
                    else:
                        time.sleep(0.15)
                        no_data_count += 1
                        if output.strip() and no_data_count > 20:  # ≈3s 无数据→命令结束
                            break
                results[title] = output.strip()
            channel.close()
        except Exception as e:
            for title in cmds:
                if title not in results:
                    results[title] = f"[ERROR] {e}"
        return results

    def _send_paging_disable(self, client, devtype):
        """Linux 设备的分页禁用（网络设备已在 invoke_shell 中处理）。"""
        if devtype != "linux": return
        paging_cmd = DISABLE_PAGING.get(devtype)
        if not paging_cmd: return
        try:
            stdin, stdout, stderr = client.exec_command(paging_cmd, timeout=5)
            stdout.read()
        except Exception:
            pass

    # ═══════════════════════════════════════════════════════════
    # 报告导出 / Report Export
    # ═══════════════════════════════════════════════════════════

    def _export_html(self) -> None:
        """导出最近一次批量巡检结果为 HTML / Export latest results as HTML."""
        if not self.last_results:
            messagebox.showwarning("Warning","No inspection results to export."); return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fp = os.path.join(REPORT_DIR, f"report_{ts}.html")
        try:
            generate_html_report(self.last_results, fp)
            self._set_status(f"HTML report saved: {fp}")
            messagebox.showinfo("Export",f"HTML report saved:\n{fp}")
        except Exception as e:
            messagebox.showerror("Export Error",str(e))

    def _export_csv(self) -> None:
        """导出最近一次批量巡检结果为 CSV / Export latest results as CSV."""
        if not self.last_results:
            messagebox.showwarning("Warning","No inspection results to export."); return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        fp = os.path.join(REPORT_DIR, f"report_{ts}.csv")
        try:
            generate_csv_report(self.last_results, fp)
            self._set_status(f"CSV report saved: {fp}")
            messagebox.showinfo("Export",f"CSV report saved:\n{fp}")
        except Exception as e:
            messagebox.showerror("Export Error",str(e))

    # ═══════════════════════════════════════════════════════════
    # 队列轮询 — 线程安全地刷新 UI / Queue Poll (thread-safe UI update)
    # ═══════════════════════════════════════════════════════════

    def _poll_queue(self) -> None:
        """
        每 100ms 检查 result_queue，将后台线程输出刷新到对应标签页。
        Polls queue every 100ms to flush worker output into the correct tab.

        消息格式 / Message format: (target, msg_type, data)
          target="single"|"batch"|"backup" → 路由目标 / routing target
        """
        try:
            while True:
                target, msg_type, data = self.result_queue.get_nowait()

                # 路由目标输出区 / route to correct output widget
                out = {"single": self.single_output,
                       "batch":  self.batch_output,
                       "backup": self.backup_output}.get(target, self.single_output)

                if msg_type == "output":
                    self._append_output(out, data)

                elif msg_type == "section":
                    pass  # 预留 / reserved

                elif msg_type == "status":
                    self._set_status(data)

                elif msg_type == "device_status":
                    # 更新批量巡检树视图 Status 列 / update batch tree status column
                    dev_host, dev_status = data
                    iid = self._device_row.get(dev_host)
                    if iid and self.device_tree.exists(iid):
                        vals = list(self.device_tree.item(iid,"values"))
                        if len(vals)>=4: vals[3]=dev_status
                        self.device_tree.item(iid,values=vals)

                elif msg_type == "alert":
                    # 异常告警：颜色高亮 / anomaly alert with color highlight
                    sev = data.get("severity","warning")
                    tag = "critical" if sev=="critical" else "warning"
                    self._append_output(out,
                        f"  [{sev.upper()}] {data['desc']}: {data['value']}{data.get('unit','')} "
                        f"(> {data['threshold']})\n", tag)

                elif msg_type == "result":
                    # 批量巡检单设备结果 / single-device batch result
                    host, devtype, status, cmds_output, alerts = data
                    self._append_output(out,
                        f"\n{'─'*60}\n  Device: {host} [{devtype.upper()}]", "success")
                    if alerts:
                        self._append_output(out, f"\n  ⚠ {len(alerts)} anomaly(s):")
                        for a in alerts:
                            tag = "critical" if a.get("severity")=="critical" else "warning"
                            self._append_output(out,
                                f"\n    [{a.get('severity','warning').upper()}] "
                                f"{a['desc']}: {a['value']}{a.get('unit','')}", tag)
                    self._append_output(out,"\n")
                    for title, output_text in cmds_output:
                        self._append_output(out, f"\n--- [{title}] ---\n{output_text}\n")

                elif msg_type == "summary":
                    self._append_output(out, data, "warning")

                elif msg_type == "error":
                    self._append_output(out, f"\n[ERROR] {data}\n", "critical")

                elif msg_type == "progress":
                    if target == "batch":
                        self.batch_progress["value"] = data
                        self.progress_label.config(text=f"{int(data)}/{int(self.batch_progress['maximum'])}")
                    elif target == "backup":
                        self.backup_progress["value"] = data
                        self.backup_prog_label.config(text=f"{int(data)}/{int(self.backup_progress['maximum'])}")

                elif msg_type == "done":
                    # 巡检完成：恢复按钮状态 / enable buttons on completion
                    self.running = False
                    self.btn_single.config(state=tk.NORMAL)
                    self.btn_single_stop.config(state=tk.DISABLED)
                    self.btn_batch_all.config(state=tk.NORMAL)
                    self.btn_batch_stop.config(state=tk.DISABLED)
                    self.btn_backup_sel.config(state=tk.NORMAL)
                    self.btn_backup_stop.config(state=tk.DISABLED)
                    if target=="batch" and self.last_results:
                        self.btn_export_html.config(state=tk.NORMAL)
                        self.btn_export_csv.config(state=tk.NORMAL)
                    self._set_status("Ready")
                    self._append_output(out, f"\n{'='*60}\n  Complete.\n{'='*60}\n", "success")

        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)   # 100ms 后再查 / re-check in 100ms

    # ═══════════════════════════════════════════════════════════
    # 辅助方法 / Utility Methods
    # ═══════════════════════════════════════════════════════════

    def _append_output(self, widget, text, tag=None):
        """
        向 ScrolledText 追加文本，可选颜色标签。
        Append text to ScrolledText with optional color tag.
        由 _poll_queue 在主线程调用，保证线程安全。
        Called on main thread via _poll_queue → thread-safe.
        """
        widget.config(state=tk.NORMAL)
        widget.insert(tk.END, text, tag) if tag else widget.insert(tk.END, text)
        widget.see(tk.END)
        widget.config(state=tk.DISABLED)

    def _clear_output(self, widget):
        """清空 ScrolledText 内容 / Clear all text in output area."""
        widget.config(state=tk.NORMAL)
        widget.delete("1.0", tk.END)
        widget.config(state=tk.DISABLED)

    def _set_status(self, text):
        """更新底部状态栏 / Update bottom status bar."""
        self.status_var.set(text)

    # ═══════════════════════════════════════════════════════════
    # 输出区关键词搜索 / Output Area Keyword Search
    # ═══════════════════════════════════════════════════════════

    def _search_highlight(self, output, entry, label):
        """清除旧高亮后重新标记所有匹配 / Re-highlight all matches."""
        text = entry.get().strip()
        # 清除旧标记 / clear old tags
        output.tag_remove("search_match", "1.0", tk.END)
        output.tag_remove("search_current", "1.0", tk.END)
        if not text:
            label.config(text="")
            return

        count = 0; pos = "1.0"
        while True:
            pos = output.search(text, pos, tk.END, nocase=True)
            if not pos: break
            end = f"{pos}+{len(text)}c"
            output.tag_add("search_match", pos, end)
            pos = end; count += 1

        label.config(text=f"{count} match(es)" if count else "no match")
        # 重置当前位置 / reset search cursor
        setattr(output, "_search_pos", "1.0")

    def _search_find(self, output, entry, label, forward=True):
        """跳转到下一个/上一个匹配并高亮当前项 / Jump to next/prev match."""
        text = entry.get().strip()
        if not text:
            return
        last = getattr(output, "_search_pos", "1.0")
        if forward:
            pos = output.search(text, last, tk.END, nocase=True)
            if not pos:  # wrap to top
                pos = output.search(text, "1.0", tk.END, nocase=True)
        else:
            pos = output.search(text, last, "1.0", nocase=True, backwards=True)
            if not pos:  # wrap to bottom
                pos = output.search(text, tk.END, "1.0", nocase=True, backwards=True)

        if not pos:
            return
        end = f"{pos}+{len(text)}c"
        # 高亮当前项 / highlight current match
        output.tag_remove("search_current", "1.0", tk.END)
        output.tag_add("search_current", pos, end)
        output.see(pos)
        if forward:
            setattr(output, "_search_pos", end)         # 继续向后找 / move past current
        else:
            setattr(output, "_search_pos", pos)          # 停在当前 / stay at current


# ═══════════════════════════════════════════════════════════════
# 程序入口 / Entry Point
# ═══════════════════════════════════════════════════════════════

if __name__ == "__main__":
    root = tk.Tk()
    app = NetworkInspectGUI(root)
    root.mainloop()

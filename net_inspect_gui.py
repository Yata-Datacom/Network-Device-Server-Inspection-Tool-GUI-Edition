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
  9. 流量测试     Traffic Test  — 内置 UDP/TCP/TCP-SYN 压测 + TCP 接收端（V3 新增）

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
import socket
import random
import struct
from dataclasses import dataclass, field
from typing import List, Tuple
from datetime import datetime
from concurrent.futures import ThreadPoolExecutor, as_completed

import paramiko

# ── 老设备 SSH 兼容（2026-09-01 修复）──
# paramiko 3.x 默认从偏好列表移除了 ssh-rsa（host key）和 group1/group14-sha1（kex），
# 华为 VRP5 / H3C Comware V5 等老设备只提供 ssh-rsa host key + sha1 组 kex，
# 直接协商报 "Incompatible ssh peer (no acceptable host key)"。
# 把老算法加回偏好列表——协商取交集，不影响现代设备正常用 rsa-sha2/ecdh。
try:
    from paramiko.transport import Transport as _ParamikoTransport
    _PT_ADD = {
        "_preferred_keys": ("ssh-rsa",),
        "_preferred_kex": ("diffie-hellman-group14-sha1", "diffie-hellman-group1-sha1"),
    }
    for _attr, _add in _PT_ADD.items():
        _cur = getattr(_ParamikoTransport, _attr, ())
        if _add and any(x not in _cur for x in _add):
            setattr(_ParamikoTransport, _attr, tuple(_cur) + _add)
except Exception:
    pass


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
DEVTYPE_LABELS = ["Linux Server", "Cisco Device", "Huawei Device", "H3C Device", "Ruijie Device"]

# 标签 → 内部 key: "Cisco Device" → "cisco" / UI label → internal key
DEVTYPE_MAP = {v: k for k, v in zip(["linux", "cisco", "huawei", "h3c", "ruijie"], DEVTYPE_LABELS)}

# 内部 key → 标签: "cisco" → "Cisco Device" / internal key → UI label
DEVTYPE_LABEL_OF = {k: v for v, k in DEVTYPE_MAP.items()}

# 设备类型别名（大小写不敏感 + 中文/常见缩写）→ 内部 key / type aliases
TYPE_ALIASES = {
    "linux": "linux", "lin": "linux", "linux服务器": "linux", "服务器": "linux",
    "cisco": "cisco", "ios": "cisco", "思科": "cisco",
    "huawei": "huawei", "vrp": "huawei", "华为": "huawei",
    "h3c": "h3c", "comware": "h3c", "华三": "h3c",
    "ruijie": "ruijie", "锐捷": "ruijie",
}


def normalize_devtype(raw: str):
    """设备类型别名归一化：大小写不敏感 + 中文/常见缩写 → 内部 key；未知返回 None。"""
    return TYPE_ALIASES.get((raw or "").strip().lower())


# ═══════════════════════════════════════════════════════════════
# 各设备类型禁用分页的命令 / Paging Disable Commands per Type
# ═══════════════════════════════════════════════════════════════

DISABLE_PAGING = {
    "linux":  None,                            # Linux 不需要 / not needed
    "cisco":  "terminal length 0",            # Cisco IOS
    "huawei": "screen-length 0 temporary",    # Huawei VRP
    "h3c":    "screen-length disable",        # H3C Comware V7（V5 用 screen-length 0 temporary）
    "ruijie": "terminal length 0",            # Ruijie（思科风格）
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
    # H3C Comware V7：命令与华为 VRP 高度相似（display 系列）
    "h3c": {
        "Display Version":          "display version",
        "Display Current Config":   "display current-configuration",
        "Display IP Interface Brief":"display ip interface brief",
        "Display Interface Brief":  "display interface brief",
        "Display VLAN":             "display vlan",
        "Display MAC Address":      "display mac-address",
        "Display CPU Usage":        "display cpu-usage",
        "Display Memory":           "display memory",
        "Display Logbuffer":        "display logbuffer",
        "Display Environment":      "display environment",
    },
    # Ruijie（锐捷）：命令为思科风格（show 系列）
    "ruijie": {
        "Show Version":             "show version",
        "Show Running Config":      "show running-config",
        "Show IP Interface Brief":  "show ip interface brief",
        "Show Interfaces Status":   "show interfaces status",
        "Show VLAN Brief":          "show vlan brief",
        "Show MAC Address Table":   "show mac address-table",
        "Show CPU Usage":           "show cpu",
        "Show Memory":              "show memory",
        "Show Logging (last 20)":   "show logging | tail 20",
        "Show Environment":         "show environment",
    },
}


# ═══════════════════════════════════════════════════════════════
# 配置备份命令（Linux 不备份）/ Backup Commands (Linux excluded)
# ═══════════════════════════════════════════════════════════════

BACKUP_COMMANDS = {
    "cisco":  "show running-config",
    "huawei": "display current-configuration",
    "h3c":    "display current-configuration",
    "ruijie": "show running-config",
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
    "h3c": {
        "CPU":            "display cpu-usage",
        "Memory":         "display memory",
        "Alarm Active":   "display alarm active",
        "Device":         "display device",
        "Stack":          "display irf",           # H3C 堆叠 = IRF
    },
    "ruijie": {
        "CPU":            "show cpu",
        "Memory":         "show memory",
        "Alarm":          "show logging | include ERR|CRIT",
        "Device":         "show version",
        "Stack":          "show vsu",              # 锐捷堆叠 = VSU
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
    # H3C Comware：CPU/内存输出格式与华为类似
    "h3c": [
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
    # Ruijie：思科风格输出
    "ruijie": [
        {
            "metric":    "CPU Usage",
            "pattern":   r"CPU utilization.*?(\d+)%",
            "threshold": 80, "compare": ">", "unit": "%",
            "desc":      "CPU 利用率超过 80% / CPU utilization > 80%",
            "severity":  "critical",
        },
        {
            "metric":    "CPU 5sec",
            "pattern":   r"five seconds?:?\s*(\d+)%",
            "threshold": 80, "compare": ">", "unit": "%",
            "desc":      "5秒 CPU 利用率超过 80% / 5-sec CPU > 80%",
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
    # H3C Comware：标题与华为一致，输出格式类似（V7 显示 "Comware Software"）
    "h3c": {
        "Display Version":        [r"Comware.*[Ss]oftware", r"VRP.*[Vv]ersion", r"uptime is", r"H3C.*[Vv]ersion"],
        "Display Current Config": None,
        "Display IP Interface Brief": [r"^\S+\s+\d", r"Interface\s+IP"],
        "Display Interface Brief":    [r"^\S+\s+(up|down)", r"Interface\s+PHY"],
        "Display VLAN":               [r"^\d+\s+\S", r"VLAN\s+ID"],
        "Display MAC Address":        [r"^\S+\s+\S{4}", r"MAC\s+Address"],
        "Display CPU Usage":   [r"CPU Usage\s*:\s*\d+%", r"CPU Using Percentage\s*:?\s*\d+%", r"System CPU.*:\s*\d+%"],
        "Display Memory":      [r"Memory Using Percentage\s*:?\s*(Is:?\s*)?\d+%", r"Memory\s+Usage\s*:\s*\d+%"],
        "Display Logbuffer":   [r"%\S+", r"Error|Warning|Critical"],
        "Display Environment": [r"Temperature", r"FAN", r"\d+\s*C"],
        # ── 简短巡检标题兼容 / quick-inspect title compat ──
        "CPU":          [r"CPU Usage\s*:\s*\d+%", r"CPU Using Percentage\s*:?\s*\d+%", r"System CPU.*:\s*\d+%"],
        "Memory":       [r"Memory Using Percentage\s*:?\s*(Is:?\s*)?\d+%", r"Memory\s+Usage\s*:\s*\d+%"],
        "Alarm Active": [r"\d{4}-\d{2}-\d{2}", r"Critical|Major|Minor|Warning", r"Sequence"],
        "Device":       [r"Comware.*[Ss]oftware", r"H3C.*[Vv]ersion", r"uptime is", r"Slot\s+\d+"],
        "Stack":        [r"[Ii][Rr][Ff]", r"[Mm]ember", r"Role", r"Priority"],
    },
    # Ruijie：标题与思科一致，输出思科风格
    "ruijie": {
        "Show Version": [r"Ruijie.*[Ss]oftware", r"System.*Version", r"uptime is"],
        "Show Running Config": None,
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
        "Device": [r"Ruijie.*[Ss]oftware", r"System.*Version", r"uptime is"],
        "Stack":  [r"[Vv][Ss][Uu]", r"[Mm]ember", r"Role", r"State"],
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


def count_flagged_lines(command_title: str, output: str):
    """
    统计命令输出中被标红的告警/异常行数（无视大小写）。

    Count flagged lines (case-insensitive) for a command section:
      - Alarm / Logbuffer:  Critical / Major / Minor / Warning
      - Device:             Unregistered / NotSupply / Abnormal

    :param command_title: 命令标题 / command title
    :param output:        命令输出文本 / command output text
    :return: (crit, major, minor, dev_bad) 四元组计数
    """
    t = (command_title or "").lower()
    crit = major = minor = dev_bad = 0
    if "alarm" in t or "logbuffer" in t:
        for line in output.splitlines():
            if re.search(r"\bCritical\b", line, re.I):
                crit += 1
            elif re.search(r"\bMajor\b", line, re.I):
                major += 1
            elif re.search(r"\b(Minor|Warning)\b", line, re.I):
                minor += 1
    elif "device" in t:
        for line in output.splitlines():
            if re.search(r"\b(Unregistered|NotSupply|Abnormal)\b", line, re.I):
                dev_bad += 1
    return crit, major, minor, dev_bad


def flagged_lines(command_title: str, output: str) -> list:
    """返回被标红/标黄的异常行明细 [(line, sev)]，sev∈{critical,major,minor,device}。

    与 count_flagged_lines 同一套关键字/大小写规则，但返回具体行文本，
    供批量汇总展示匹配行（2026-09-01 加）。
    """
    t = (command_title or "").lower()
    hits: list = []
    if "alarm" in t or "logbuffer" in t:
        for line in output.splitlines():
            ls = line.strip()
            if not ls:
                continue
            if re.search(r"\bCritical\b", ls, re.I):
                hits.append((ls, "critical"))
            elif re.search(r"\bMajor\b", ls, re.I):
                hits.append((ls, "major"))
            elif re.search(r"\b(Minor|Warning)\b", ls, re.I):
                hits.append((ls, "minor"))
    elif "device" in t:
        for line in output.splitlines():
            ls = line.strip()
            if not ls:
                continue
            if re.search(r"\b(Unregistered|NotSupply|Abnormal)\b", ls, re.I):
                hits.append((ls, "device"))
    return hits


# ═══════════════════════════════════════════════════════════════
# 攻击日志检测引擎 / Attack Log Detection (V3.1, ported from intelmcp)
# 纯本地正则规则，不联网 —— 巡检 logbuffer/auth/access 日志时自动识别攻击
# ═══════════════════════════════════════════════════════════════

_ATTACK_RULES: list = [
    {"id": "R001", "name": "SQL 注入尝试", "severity": "high", "target": "web",
     "pattern": re.compile(r"(\%27|'|--\s|\bunion\b.*\bselect\b|/\*.*\*/|(?:;|--)\s*(?:drop|delete|update|insert)\s)", re.I)},
    {"id": "R002", "name": "XSS 尝试", "severity": "medium", "target": "web",
     "pattern": re.compile(r"(<script[^>]*>|javascript:|onerror\s*=|onload\s*=|%3cscript%3e)", re.I)},
    {"id": "R003", "name": "路径穿越", "severity": "high", "target": "web",
     "pattern": re.compile(r"(\.\./|\.\.\\|%2e%2e%2f|/etc/passwd|/windows/win\.ini|c:\\windows)", re.I)},
    {"id": "R004", "name": "命令注入尝试", "severity": "critical", "target": "web",
     "pattern": re.compile(r"(\|\s*(id|whoami|cat|curl|wget|nc)\b|;\s*(id|whoami)\b|`\w+`|\$\()", re.I)},
    {"id": "R005", "name": "扫描器指纹", "severity": "medium", "target": "web",
     "pattern": re.compile(r"(sqlmap|nikto|nmap|nessus|acunetix|wpscan|gobuster|dirsearch|masscan)", re.I)},
    {"id": "R006", "name": "WebShell 上传/危险函数", "severity": "critical", "target": "web",
     "pattern": re.compile(r"(\.(php|jsp|asp|aspx|sh)(\.\w+)?\s*$|eval\(|base64_decode\(|shell_exec\(|assert\()", re.I)},
    {"id": "R007", "name": "异常 User-Agent", "severity": "low", "target": "web",
     "pattern": re.compile(r"^(curl/|wget|python-requests|libwww|jakarta commons-httpclient|go-http-client)", re.I)},
    {"id": "R008", "name": "SSH 认证失败", "severity": "high", "target": "ssh",
     "pattern": re.compile(r"(failed password|failed to login|invalid user|authentication failure|connection closed by authenticating user)", re.I)},
    {"id": "R009", "name": "SSH 登录成功", "severity": "info", "target": "ssh",
     "pattern": re.compile(r"(accepted (publickey|password)|session opened for user)", re.I)},
    {"id": "R010", "name": "设备安全事件", "severity": "high", "target": "all",
     "pattern": re.compile(r"(%\S*SEC/\d+|attack detected|intrusion detection|brute-force)", re.I)},
]


def _looks_like_log(text: str, title: str | None = None) -> bool:
    """判断文本是否像日志（避免对普通配置输出误报攻击）。"""
    t = (title or "").lower()
    if any(k in t for k in ("logbuffer", "log", "auth", "secure", "access", "journal", "syslog")):
        return True
    sample = text[:3000]
    if re.search(r"^\w{3}\s+\d{1,2}\s+\d{2}:\d{2}:\d{2}", sample, re.M):   # syslog: Aug 31 10:00:00
        return True
    if re.search(r"\[\d{2}/\w{3}/\d{4}:", sample):                         # web: [24/Aug/2026:
        return True
    if re.search(r"\bsshd\[\d+\]", sample):                                # sshd[12345]:
        return True
    if re.search(r"%\S+SEC/\d+", sample):                                  # 华为 %SEC/ 安全日志
        return True
    return False


_WEB_METHOD_RE = re.compile(r"\b(?:GET|POST|PUT|DELETE|HEAD|OPTIONS|PATCH)\b")
_SSH_HINT_RE = re.compile(r"\b(?:sshd|failed|login|password|authenticat|user)\b")


def _line_log_type(line: str) -> str:
    """粗略判断日志行类型（web / ssh / other），用于规则门控避免误报。"""
    if _WEB_METHOD_RE.search(line):
        return "web"
    if _SSH_HINT_RE.search(line):
        return "ssh"
    return "other"


def attack_scan(text: str) -> dict:
    """扫描日志文本中的攻击特征。返回 {line_hits, agg_alerts, counts}。"""
    from collections import Counter, defaultdict
    lines = text.splitlines()
    ip_re = re.compile(r"\b(?:\d{1,3}\.){3}\d{1,3}\b")
    line_hits = []
    for idx, line in enumerate(lines):
        if not line.strip():
            continue
        if re.match(r"^\s*[-═=·]{2,}", line):          # 跳过区块分隔线（如 --- [Device] ---）
            continue
        m = ip_re.search(line)
        ip = m.group(0) if m else None
        ltype = _line_log_type(line)
        for r in _ATTACK_RULES:
            if r["target"] not in ("all", ltype):
                continue
            if r["pattern"].search(line):
                line_hits.append({"line_idx": idx, "rule": r["id"], "attack": r["name"],
                                  "severity": r["severity"], "ip": ip,
                                  "line": line.strip()[:200]})
                break  # 每行只记最高优先级命中

    # 聚合：同 IP 同规则计数 → 行为告警
    per_ip_rule: dict = defaultdict(Counter)
    for h in line_hits:
        if h["ip"]:
            per_ip_rule[h["ip"]][h["rule"]] += 1
    agg_alerts = []
    for ip, c in per_ip_rule.items():
        for rule, cnt in c.items():
            if rule == "R008" and cnt >= 8:
                agg_alerts.append({"attack": "SSH 暴力破解(疑似)", "severity": "critical", "ip": ip, "count": cnt})
            elif rule == "R010" and cnt >= 3:
                agg_alerts.append({"attack": "设备安全事件(疑似)", "severity": "high", "ip": ip, "count": cnt})

    # Web 状态码聚合：401/403 撞库、404 目录扫描
    per_ip_status: dict = defaultdict(Counter)
    for line in lines:
        m = ip_re.search(line)
        if not m:
            continue
        for s in re.findall(r"\b(401|403|404)\b", line):
            per_ip_status[m.group(0)][s] += 1
    for ip, st in per_ip_status.items():
        c401 = st.get("401", 0) + st.get("403", 0)
        c404 = st.get("404", 0)
        if c401 >= 15:
            agg_alerts.append({"attack": "Web 暴力破解/撞库(疑似)", "severity": "high", "ip": ip, "count": c401})
        if c404 >= 30:
            agg_alerts.append({"attack": "目录扫描(疑似)", "severity": "medium", "ip": ip, "count": c404})

    counts = Counter(h["severity"] for h in line_hits)
    return {"line_hits": line_hits, "agg_alerts": agg_alerts, "counts": dict(counts)}


def ip_intel_lookup(ip: str) -> dict:
    """IP 被动情报查询（ip-api 免费接口，纯 stdlib，无 Key）。

    返回 dict：status=success 时含 country/regionName/city/isp/org/as/
    lat/lon/proxy/hosting/mobile；失败时含 error 字段。
    """
    import ipaddress as _ipa
    import json as _json
    import urllib.request as _ur
    import urllib.error as _ue
    ip = (ip or "").strip()
    if not ip:
        return {"error": "IP 为空"}
    try:
        obj = _ipa.ip_address(ip)
        if obj.is_private or obj.is_loopback or obj.is_link_local or obj.is_multicast or obj.is_reserved:
            return {"error": f"{ip} 是内网/保留地址，无需查询"}
    except ValueError:
        return {"error": f"无效 IP: {ip}"}
    url = (f"http://ip-api.com/json/{ip}"
           "?fields=status,message,country,regionName,city,isp,org,as,asname,lat,lon,proxy,hosting,mobile,query")
    try:
        req = _ur.Request(url, headers={"User-Agent": "NIS-V3.1/1.0"})
        with _ur.urlopen(req, timeout=10) as resp:
            data = _json.loads(resp.read().decode("utf-8", "replace"))
    except Exception as e:
        return {"error": f"查询失败: {e}（检查网络）"}
    if data.get("status") != "success":
        return {"error": data.get("message", "查询失败")}
    return data


def format_ip_intel(data: dict) -> str:
    """把 ip_intel_lookup 结果格式化为可读文本。"""
    if "error" in data:
        return f"❌ {data['error']}"
    flags = []
    if data.get("proxy"):
        flags.append("🕶 代理")
    if data.get("hosting"):
        flags.append("☁ 云主机/托管")
    if data.get("mobile"):
        flags.append("📱 移动网络")
    lines = [
        f"📍 {data.get('query', '')}",
        f"   国家: {data.get('country', '-')}  地区: {data.get('regionName', '-')}  城市: {data.get('city', '-')}",
        f"   ISP: {data.get('isp', '-')}",
        f"   Org: {data.get('org', '-')}",
        f"   ASN: {data.get('as', '-')}",
        f"   坐标: {data.get('lat', '-')}, {data.get('lon', '-')}",
        f"   特征: {', '.join(flags) if flags else '普通'}",
    ]
    return "\n".join(lines)


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


def setup_app_style(root: tk.Tk) -> None:
    """
    应用「现代清爽蓝」主题（零依赖，基于 ttk clam）。

    Apply a modern clean-blue theme using the built-in clam base — no
    third-party theme package required. Styles every ttk widget class,
    plus Accent.TButton / Danger.TButton for primary & stop actions.
    """
    # ── 调色板 / palette ──
    BG     = "#f3f5f9"    # 窗口背景 / window background
    PANEL  = "#ffffff"    # 面板背景 / panel background
    FG     = "#1f2937"    # 主文字 / main text
    MUTED  = "#64748b"    # 次要文字 / muted text
    ACCENT = "#2563eb"    # 主色蓝 / primary blue
    ACCENT2= "#3b82f6"    # 亮蓝(悬停) / lighter blue (hover)
    ACCENTD= "#1e40af"    # 深蓝(按下/标题) / darker blue
    LINE   = "#d7dde8"    # 边框线 / border line
    HEADER = "#eef2f9"    # 表头背景 / table header bg
    ROW_SEL= "#dbeafe"    # 选中行 / selected row
    DANGER = "#dc2626"    # 危险红 / danger red
    FONT   = ("Microsoft YaHei UI", 9)
    FONT_B = ("Microsoft YaHei UI", 9, "bold")
    FONT_H = ("Microsoft YaHei UI", 10, "bold")

    style = ttk.Style(root)
    try:
        style.theme_use("clam")
    except tk.TclError:
        pass

    root.configure(bg=BG)

    # 全局默认 / global defaults
    style.configure(".", background=BG, foreground=FG, bordercolor=LINE,
                    lightcolor=BG, darkcolor=BG, focuscolor=ACCENT)
    style.configure("TFrame", background=BG)
    style.configure("TLabel", background=BG, foreground=FG, font=FONT)
    style.configure("TLabelframe", background=BG, bordercolor=LINE,
                    relief="solid", borderwidth=1)
    style.configure("TLabelframe.Label", background=BG, foreground=ACCENTD,
                    font=FONT_H)

    # 按钮 / buttons
    style.configure("TButton", background="#e8edf5", foreground=FG,
                    borderwidth=0, focusthickness=0, padding=(12, 7), font=FONT)
    style.map("TButton",
              background=[("pressed", ACCENTD), ("active", "#dbe6f8")],
              foreground=[("pressed", "white")])
    style.configure("Accent.TButton", background=ACCENT, foreground="white",
                    padding=(14, 8), font=FONT_B)
    style.map("Accent.TButton",
              background=[("pressed", ACCENTD), ("active", ACCENT2)],
              foreground=[("pressed", "white"), ("disabled", "#bfdbfe")])
    style.configure("Danger.TButton", background=DANGER, foreground="white",
                    padding=(12, 7), font=FONT_B)
    style.map("Danger.TButton",
              background=[("pressed", "#991b1b"), ("active", "#ef4444")],
              foreground=[("disabled", "#fecaca")])

    # 输入框 / entries & comboboxes
    style.configure("TEntry", fieldbackground="white", foreground=FG,
                    bordercolor=LINE, padding=4, insertcolor=ACCENT)
    style.configure("TCombobox", fieldbackground="white", foreground=FG,
                    bordercolor=LINE, padding=4, arrowcolor=ACCENT)
    style.map("TCombobox", fieldbackground=[("readonly", "white")])

    # 复选框 / checkbuttons
    style.configure("TCheckbutton", background=BG, foreground=FG, font=FONT,
                    focuscolor=ACCENT)
    style.map("TCheckbutton",
              background=[("active", BG)],
              foreground=[("disabled", MUTED)])

    # 笔记本标签页 / notebook tabs
    style.configure("TNotebook", background=BG, borderwidth=0)
    style.configure("TNotebook.Tab", background="#e2e8f0", foreground=MUTED,
                    padding=(16, 8), borderwidth=0, font=FONT)
    style.map("TNotebook.Tab",
              background=[("selected", PANEL)],
              foreground=[("selected", ACCENT)],
              font=[("selected", FONT_H)])

    # 树形表 / treeview
    style.configure("Treeview", background="white", fieldbackground="white",
                    foreground=FG, rowheight=28, borderwidth=0, font=FONT)
    style.configure("Treeview.Heading", background=HEADER, foreground="#334155",
                    padding=(8, 6), relief="flat", font=FONT_B)
    style.map("Treeview.Heading", background=[("active", "#e2e8f0")])
    style.map("Treeview",
              background=[("selected", ROW_SEL)],
              foreground=[("selected", FG)])

    # 进度条 / progress bars
    style.configure("Horizontal.TProgressbar", background=ACCENT,
                    troughcolor="#e2e8f0", borderwidth=0, thickness=8)
    style.configure("Vertical.TProgressbar", background=ACCENT,
                    troughcolor="#e2e8f0", borderwidth=0, thickness=8)

    # 滚动条 / scrollbars
    style.configure("Vertical.TScrollbar", background="#cbd5e1", troughcolor=BG,
                    borderwidth=0, arrowsize=12)
    style.configure("Horizontal.TScrollbar", background="#cbd5e1", troughcolor=BG,
                    borderwidth=0, arrowsize=12)
    style.map("Vertical.TScrollbar", background=[("active", "#94a3b8")])
    style.map("Horizontal.TScrollbar", background=[("active", "#94a3b8")])

    # 流量测试页绿色强调按钮 / traffic-test green accent button
    style.configure("GreenAccent.TButton", background="#16a34a", foreground="white",
                    padding=(14, 8), font=FONT_B)
    style.map("GreenAccent.TButton",
              background=[("pressed", "#15803d"), ("active", "#4ade80")],
              foreground=[("pressed", "white"), ("disabled", "#bbf7d0")])


# ═══════════════════════════════════════════════════════════════
# 流量测试核心 / Traffic Test Core (merged from test_A → V3)
# ═══════════════════════════════════════════════════════════════

def detect_gateways() -> List[Tuple[str, str]]:
    cmd = (
        "Get-NetRoute -DestinationPrefix '0.0.0.0/0' | "
        "ForEach-Object { '{0}|{1}' -f $_.NextHop, $_.InterfaceAlias }"
    )
    try:
        proc = subprocess.run(
            ["powershell", "-NoProfile", "-Command", cmd],
            capture_output=True, text=True, timeout=10,
            creationflags=subprocess.CREATE_NO_WINDOW
        )
    except FileNotFoundError:
        return []
    except subprocess.TimeoutExpired:
        return []

    results: List[Tuple[str, str]] = []
    seen = set()
    for line in proc.stdout.strip().splitlines():
        line = line.strip()
        if not line or '|' not in line:
            continue
        parts = line.split('|', 1)
        if len(parts) != 2:
            continue
        gw_ip, iface = parts[0].strip(), parts[1].strip()
        key = gw_ip
        if key in seen:
            continue
        seen.add(key)
        display = f"{gw_ip}  ({iface})"
        results.append((display, gw_ip))
    return results


def parse_ports(port_str: str) -> Tuple[List[int], str]:
    """Parse port string into list of ports.
    Formats:
      '8080'             -> [8080], desc='single port 8080'
      '80,443,8080'      -> [80, 443, 8080], desc='3 ports'
      '100-1000'         -> [100..1000], desc='range 100-1000 (901 ports)'
      '100-1000:50'      -> 50 random ports from 100-1000, desc='50 ports from 100-1000'
    Returns (list_of_ports, description_string).
    """
    raw = port_str.strip()
    if not raw:
        return [], "empty"

    if ':' in raw and '-' in raw:
        range_part, count_part = raw.rsplit(':', 1)
        parts = range_part.split('-', 1)
        try:
            lo, hi = int(parts[0]), int(parts[1])
            cnt = int(count_part)
        except ValueError:
            return [], f"invalid: {raw}"
        if lo < 1 or hi > 65535 or lo > hi:
            return [], f"invalid range: {raw}"
        cnt = min(cnt, hi - lo + 1)
        ports = sorted(random.sample(range(lo, hi + 1), cnt))
        return ports, f"{cnt} ports from {lo}-{hi}"

    if '-' in raw:
        parts = raw.split('-', 1)
        try:
            lo, hi = int(parts[0]), int(parts[1])
        except ValueError:
            return [], f"invalid: {raw}"
        if lo < 1 or hi > 65535 or lo > hi:
            return [], f"invalid range: {raw}"
        ports = list(range(lo, hi + 1))
        return ports, f"range {lo}-{hi} ({len(ports)} ports)"

    if ',' in raw:
        ports = []
        for part in raw.split(','):
            part = part.strip()
            if not part:
                continue
            try:
                p = int(part)
            except ValueError:
                return [], f"invalid port: {part}"
            if p < 1 or p > 65535:
                return [], f"invalid port: {p}"
            ports.append(p)
        return sorted(set(ports)), f"{len(ports)} port(s)"

    try:
        p = int(raw)
        if p < 1 or p > 65535:
            return [], f"invalid port: {p}"
        return [p], f"single port {p}"
    except ValueError:
        return [], f"invalid: {raw}"


@dataclass
class Stats:
    total_packets: int = 0
    total_bytes: int = 0
    prev_packets: int = 0
    prev_bytes: int = 0
    current_pps: float = 0.0
    current_bps: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, packet_size: int, count: int = 1):
        with self.lock:
            self.total_packets += count
            self.total_bytes += count * packet_size

    def snapshot(self) -> tuple:
        with self.lock:
            now_packets = self.total_packets
            now_bytes = self.total_bytes
            pps = self.current_pps
            bps = self.current_bps
        return pps, bps, now_packets, now_bytes

    def tick(self, interval: float):
        with self.lock:
            dp = self.total_packets - self.prev_packets
            db = self.total_bytes - self.prev_bytes
            self.current_pps = dp / interval if interval > 0 else 0.0
            self.current_bps = db / interval if interval > 0 else 0.0
            self.prev_packets = self.total_packets
            self.prev_bytes = self.total_bytes


class TCPServer:
    def __init__(self, port: int, log_callback=None):
        self.port = port
        self.log = log_callback or (lambda msg: None)
        self.stats = Stats()
        self.running = False
        self.server_sock: socket.socket | None = None
        self.server_thread: threading.Thread | None = None
        self.client_threads: List[threading.Thread] = []

    def start(self):
        if self.running:
            return
        self.running = True
        self.server_sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.server_sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.server_sock.settimeout(0.5)
        try:
            self.server_sock.bind(("0.0.0.0", self.port))
            self.server_sock.listen(100)
        except OSError as e:
            self.log(f"TCP server bind failed: {e}")
            self.running = False
            return

        self.server_thread = threading.Thread(target=self._accept_loop, daemon=True)
        self.server_thread.start()
        self.log(f"TCP server listening on 0.0.0.0:{self.port}")

    def stop(self):
        self.running = False
        if self.server_sock:
            try:
                self.server_sock.close()
            except Exception:
                pass
            self.server_sock = None
        for t in list(self.client_threads):
            t.join(timeout=1)
        self.client_threads.clear()
        self.log(f"TCP server stopped. Rx: {self.stats.total_packets:,} pkts, "
                 f"{self._fmt(self.stats.total_bytes)}")

    def _accept_loop(self):
        while self.running:
            try:
                client, addr = self.server_sock.accept()
            except (socket.timeout, OSError):
                if not self.running:
                    break
                continue
            t = threading.Thread(target=self._recv_worker, args=(client, addr), daemon=True)
            t.start()
            self.client_threads.append(t)
            self.client_threads = [t for t in self.client_threads if t.is_alive()]

    def _recv_worker(self, sock: socket.socket, addr):
        sock.settimeout(1)
        try:
            while self.running:
                try:
                    data = sock.recv(65536)
                except socket.timeout:
                    continue
                except OSError:
                    break
                if not data:
                    break
                self.stats.add(len(data))
        finally:
            try:
                sock.close()
            except Exception:
                pass

    @staticmethod
    def _fmt(b: int) -> str:
        if b < 1024:
            return f"{b} B"
        elif b < 1024 ** 2:
            return f"{b / 1024:.1f} KB"
        elif b < 1024 ** 3:
            return f"{b / 1024 ** 2:.1f} MB"
        else:
            return f"{b / 1024 ** 3:.2f} GB"


def _icmp_checksum(data: bytes) -> int:
    """ICMP 校验和 / ICMP header checksum (RFC 792)."""
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


class TrafficGenerator:
    def __init__(self, target_ip: str, target_port_str: str, protocol: str,
                 concurrency: int, packet_size: int, rate: int,
                 log_callback=None):
        self.target_ip = target_ip
        self.target_port_str = target_port_str
        self.target_ports, self.port_desc = parse_ports(target_port_str)
        self.protocol = protocol.upper()
        self.concurrency = concurrency
        self.packet_size = packet_size
        self.rate = rate
        self.log = log_callback or (lambda msg: None)
        self.stats = Stats()
        self.running = False
        self.threads: List[threading.Thread] = []
        self.payload = self._generate_payload()
        self._tcp_connect_error_logged = 0

    def _pick_port(self) -> int:
        return random.choice(self.target_ports)

    def _generate_payload(self) -> bytes:
        return bytes(random.getrandbits(8) for _ in range(self.packet_size))

    def _udp_worker(self, thread_id: int):
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536 * 8)

        interval = 1.0 / self.rate if self.rate > 0 else 0.0
        last_time = time.perf_counter()
        accumulated = 0.0

        while self.running:
            target = (self.target_ip, self._pick_port())
            now = time.perf_counter()
            elapsed = now - last_time
            last_time = now
            accumulated += elapsed

            if self.rate > 0:
                to_send = int(accumulated * self.rate)
                if to_send > 1000:
                    to_send = 1000
                if to_send > 0:
                    accumulated -= to_send / self.rate
            else:
                to_send = 1000
                accumulated = 0.0

            for _ in range(to_send):
                try:
                    sock.sendto(self.payload, target)
                    self.stats.add(self.packet_size)
                except Exception:
                    pass

            if self.rate > 0:
                sleep_time = interval - (time.perf_counter() - last_time)
                if sleep_time > 0:
                    time.sleep(min(sleep_time, 0.1))
            else:
                time.sleep(0.001)

        sock.close()

    def _tcp_worker(self, thread_id: int):
        while self.running:
            sock = None
            port = self._pick_port()
            try:
                sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                sock.setsockopt(socket.IPPROTO_TCP, socket.TCP_NODELAY, 1)
                sock.setsockopt(socket.SOL_SOCKET, socket.SO_SNDBUF, 65536 * 8)
                sock.settimeout(5)
                sock.connect((self.target_ip, port))

                interval = 1.0 / self.rate if self.rate > 0 else 0.0
                last_time = time.perf_counter()
                accumulated = 0.0

                while self.running:
                    now = time.perf_counter()
                    elapsed = now - last_time
                    last_time = now
                    accumulated += elapsed

                    if self.rate > 0:
                        to_send = int(accumulated * self.rate)
                        if to_send > 1000:
                            to_send = 1000
                        if to_send > 0:
                            accumulated -= to_send / self.rate
                    else:
                        to_send = 1000
                        accumulated = 0.0

                    for _ in range(to_send):
                        try:
                            sock.sendall(self.payload)
                            self.stats.add(self.packet_size)
                        except (BrokenPipeError, ConnectionResetError, OSError):
                            raise

                    if self.rate > 0:
                        sleep_time = interval - (time.perf_counter() - last_time)
                        if sleep_time > 0:
                            time.sleep(min(sleep_time, 0.1))
                    else:
                        time.sleep(0.001)

            except (ConnectionRefusedError, ConnectionAbortedError):
                if self._tcp_connect_error_logged < 3:
                    self.log(f"TCP connect to {self.target_ip}:{port} refused "
                             f"(thread #{thread_id}) - is a TCP server listening?")
                    self._tcp_connect_error_logged += 1
            except socket.timeout:
                if self._tcp_connect_error_logged < 3:
                    self.log(f"TCP connect to {self.target_ip}:{port} timed out "
                             f"(thread #{thread_id})")
                    self._tcp_connect_error_logged += 1
            except (BrokenPipeError, ConnectionResetError):
                pass
            except OSError as e:
                if self._tcp_connect_error_logged < 1:
                    self.log(f"TCP connect error: {e} (thread #{thread_id})")
                    self._tcp_connect_error_logged += 1
            except Exception:
                pass
            finally:
                if sock:
                    try:
                        sock.close()
                    except Exception:
                        pass
                if self.running:
                    time.sleep(0.5)

    def _tcp_syn_worker(self, thread_id: int):
        interval = 1.0 / self.rate if self.rate > 0 else 0.0
        last_time = time.perf_counter()
        accumulated = 0.0

        while self.running:
            port = self._pick_port()
            now = time.perf_counter()
            elapsed = now - last_time
            last_time = now
            accumulated += elapsed

            if self.rate > 0:
                to_send = int(accumulated * self.rate)
                if to_send > 500:
                    to_send = 500
                if to_send > 0:
                    accumulated -= to_send / self.rate
            else:
                to_send = 500
                accumulated = 0.0

            if to_send <= 0:
                time.sleep(0.001)
                continue

            socks = []
            for _ in range(to_send):
                try:
                    s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
                    s.setblocking(False)
                    s.connect((self.target_ip, port))
                except BlockingIOError:
                    pass
                except Exception:
                    try:
                        s.close()
                    except Exception:
                        pass
                    continue
                socks.append(s)

            sent = len(socks)
            if sent > 0:
                self.stats.add(1, count=sent)

            for s in socks:
                try:
                    s.close()
                except Exception:
                    pass

            if self.rate > 0:
                sleep_time = interval - (time.perf_counter() - last_time)
                if sleep_time > 0:
                    time.sleep(min(sleep_time, 0.1))
            else:
                time.sleep(0.001)

    def _icmp_worker(self, thread_id: int):
        """ICMP echo flood（raw socket，Windows 需要管理员权限）。

        ICMP echo request 手工组包：type=8 code=0 + 校验和(RFC 792)，
        目标无需监听服务（同 UDP）。无权限时友好提示并停止，不崩溃。
        """
        try:
            sock = socket.socket(socket.AF_INET, socket.SOCK_RAW, socket.IPPROTO_ICMP)
        except PermissionError:
            self.log("ICMP 需要管理员权限（raw socket）— 请右键以管理员身份运行本程序")
            self.running = False
            return
        except OSError as e:
            self.log(f"ICMP socket 创建失败: {e}")
            self.running = False
            return

        ident = (os.getpid() & 0xFFFF) ^ (thread_id & 0xFFFF)
        seq = 0
        interval = 1.0 / self.rate if self.rate > 0 else 0.0
        last_time = time.perf_counter()
        accumulated = 0.0

        while self.running:
            now = time.perf_counter()
            elapsed = now - last_time
            last_time = now
            accumulated += elapsed

            if self.rate > 0:
                to_send = int(accumulated * self.rate)
                if to_send > 500:
                    to_send = 500
                if to_send > 0:
                    accumulated -= to_send / self.rate
            else:
                to_send = 500
                accumulated = 0.0

            for _ in range(to_send):
                seq = (seq + 1) & 0xFFFF
                pkt = struct.pack("!BBHHH", 8, 0, 0, ident, seq) + self.payload
                csum = _icmp_checksum(pkt)
                pkt = struct.pack("!BBHHH", 8, 0, csum, ident, seq) + self.payload
                try:
                    sock.sendto(pkt, (self.target_ip, 0))
                    self.stats.add(self.packet_size)
                except PermissionError:
                    self.log("ICMP 发送被拒绝 — 需要管理员权限")
                    self.running = False
                    break
                except OSError:
                    pass

            if self.rate > 0:
                sleep_time = interval - (time.perf_counter() - last_time)
                if sleep_time > 0:
                    time.sleep(min(sleep_time, 0.1))
            else:
                time.sleep(0.001)

        sock.close()

    def start(self):
        if self.running:
            return
        self.running = True
        self.threads.clear()
        if self.protocol == 'UDP':
            worker = self._udp_worker
        elif self.protocol == 'ICMP':
            worker = self._icmp_worker
        elif self.protocol == 'TCP SYN':
            worker = self._tcp_syn_worker
        else:
            worker = self._tcp_worker
        for i in range(self.concurrency):
            t = threading.Thread(target=worker, args=(i,), daemon=True)
            t.start()
            self.threads.append(t)

    def stop(self):
        self.running = False
        for t in self.threads:
            t.join(timeout=2)


# ═══════════════════════════════════════════════════════════════
# 安全配置核查（V3.2 Security Test）——只查配置不发起攻击，合法合规
# ═══════════════════════════════════════════════════════════════

# 核查项定义：label(界面名) + 各厂商查询命令（title: cmd）
SECURITY_CHECKS = {
    "dhcp_snooping": {
        "label": "DHCP Snooping（防私接路由器抢答）",
        "cmds": {
            "huawei": [("DHCP Snooping", "display dhcp snooping"),
                       ("绑定表 user-bind", "display dhcp snooping user-bind")],
            "cisco": [("DHCP Snooping", "show ip dhcp snooping"),
                      ("绑定表", "show ip dhcp snooping binding")],
            "h3c": [("DHCP Snooping", "display dhcp snooping"),
                    ("绑定表", "display dhcp snooping user-bind")],
            "ruijie": [("DHCP Snooping", "show dhcp snooping"),
                       ("绑定表", "show dhcp snooping binding")],
        },
    },
    "dai": {
        "label": "DAI ARP 攻击防护（防 ARP 欺骗）",
        "cmds": {
            "huawei": [("ARP DHCP-Snooping", "display arp dhcp-snooping"),
                       ("ARP 防攻击", "display arp anti-attack")],
            "cisco": [("ARP Inspection", "show ip arp inspection")],
            "h3c": [("ARP Detection", "display arp detection")],
            "ruijie": [("ARP Check", "show arp-check")],
        },
    },
    "dns": {
        "label": "DNS 防重定向（DHCP 池 DNS 下发）",
        "cmds": {
            "huawei": [("DHCP 地址池", "display ip pool")],
            "cisco": [("name-server", "show running-config | include ip name-server"),
                      ("DHCP 池", "show running-config | include dns-server")],
            "h3c": [("DHCP 地址池", "display ip pool")],
            "ruijie": [("DHCP 池", "show running-config | include dns-server"),
                       ("name-server", "show running-config | include ip name-server")],
        },
    },
    "vlan_isolate": {
        "label": "跨 VLAN 访问控制（端口隔离 / ACL）",
        "cmds": {
            "huawei": [("端口隔离", "display port-isolate"),
                       ("ACL", "display acl all"),
                       ("Trunk", "display interface trunk")],
            "cisco": [("VLAN", "show vlan brief"),
                      ("Trunk", "show interfaces trunk")],
            "h3c": [("端口隔离", "display port-isolate"),
                    ("ACL", "display acl all"),
                    ("Trunk", "display interface trunk")],
            "ruijie": [("VLAN", "show vlan"),
                       ("Trunk", "show interfaces trunk")],
        },
    },
    "port_security": {
        "label": "端口安全（MAC 学习限制）",
        "cmds": {
            "huawei": [("MAC 限速", "display mac-address limit"),
                       ("端口安全", "display port-security")],
            "cisco": [("Port Security", "show port-security")],
            "h3c": [("端口安全", "display port-security"),
                    ("MAC 限速", "display mac-address limit")],
            "ruijie": [("Port Security", "show port-security")],
        },
    },
}

SECURITY_ORDER = ["dhcp_snooping", "dai", "dns", "vlan_isolate", "port_security"]

# 修复建议（中文，按核查项）
SECURITY_ADVICE = {
    "dhcp_snooping": (
        "交换机需开启 DHCP Snooping 并把合法上联口设为 trusted，否则私接路由器会抢答 DHCP，"
        "终端拿不到正确地址：\n"
        "  [HUAWEI] dhcp snooping enable\n"
        "  [HUAWEI] interface GigabitEthernet0/0/1\n"
        "  [HUAWEI-GigabitEthernet0/0/1] dhcp snooping trusted\n"
        "  （思科: ip dhcp snooping vlan X + ip dhcp snooping trust）"),
    "dai": (
        "需开启 ARP 攻击防护（DAI），防 ARP 欺骗/中间人：\n"
        "  [HUAWEI] arp dhcp-snooping detect enable\n"
        "  [HUAWEI] arp anti-attack check user-bind enable\n"
        "  （思科: ip arp inspection vlan X）"),
    "dns": (
        "DHCP 地址池应显式下发正确的 DNS 服务器，防止私接路由器把 DNS 重定向到恶意地址：\n"
        "  [HUAWEI] ip pool vlan1\n"
        "  [HUAWEI-ip-pool-vlan1] dns-server 114.114.114.114 223.5.5.5"),
    "vlan_isolate": (
        "跨 VLAN 访问应有控制：同一交换机不同 VLAN 建议端口隔离，VLAN 间路由建议 ACL 限定：\n"
        "  [HUAWEI] port-isolate enable group 1\n"
        "  [HUAWEI] interface vlanif10 / traffic-filter inbound acl 3000"),
    "port_security": (
        "建议开启端口安全限制单端口 MAC 学习数，防 MAC 泛洪/私接设备：\n"
        "  [HUAWEI] port-security enable\n"
        "  [HUAWEI] port-security max-mac-num 5"),
}


def _text_has(text: str, *patterns) -> bool:
    """大小写无关的多关键字命中（华为 VRP 输出中英文机型差异大）。"""
    low = text.lower()
    return any(p.lower() in low for p in patterns)


def judge_security_item(devtype: str, item: str, outputs: dict) -> tuple:
    """判定一个核查项 → (status, detail_lines, advice)。

    status: ok(绿) / warn(黄) / fail(红) / na(灰-设备不支持或无法判断)
    outputs: {title: output_text}
    """
    joined = "\n".join(outputs.values())
    low = joined.lower()

    if item == "dhcp_snooping":
        # 开启状态（全局）→ fail 条件优先（明确 Disabled）
        if _text_has(joined, "disabled", "未使能", "disable"):
            return "fail", _head_lines(outputs, 6), SECURITY_ADVICE["dhcp_snooping"]
        if _text_has(joined, "enabled", "使能", "enable"):
            # 看绑定表是否有条目
            bind = outputs.get("绑定表") or outputs.get("绑定表 user-bind") or ""
            if bind and _text_has(bind, "no user bind", "no entry", "0 entries", "无绑定", "未学习到"):
                return "warn", _head_lines(outputs, 6), "DHCP Snooping 已开启，但暂无绑定表条目（设备未上线或未学习到）"
            if bind and bind.strip():
                n = sum(1 for l in bind.splitlines() if l.strip() and not l.startswith("---"))
                if n > 1:
                    return "ok", _head_lines(outputs, 8), "DHCP Snooping 已开启且存在绑定表，可防私接路由器抢答"
            return "ok", _head_lines(outputs, 6), "DHCP Snooping 已开启"
        if not joined.strip():
            return "na", ["（无输出，设备可能不支持该命令）"], SECURITY_ADVICE["dhcp_snooping"]
        return "fail", _head_lines(outputs, 6), SECURITY_ADVICE["dhcp_snooping"]

    if item == "dai":
        if _text_has(joined, "disabled", "未使能", "not enabled", "no entry", "没有"):
            return "fail", _head_lines(outputs, 6), SECURITY_ADVICE["dai"]
        if _text_has(joined, "enabled", "使能", "enable", "total", "learned", "检测到", "攻击", "anti-attack"):
            if _text_has(joined, "disabled", "未使能"):
                return "fail", _head_lines(outputs, 6), SECURITY_ADVICE["dai"]
            return "ok", _head_lines(outputs, 6), "ARP 攻击防护已开启"
        if not joined.strip():
            return "na", ["（无输出，设备可能不支持该命令）"], SECURITY_ADVICE["dai"]
        return "warn", _head_lines(outputs, 6), SECURITY_ADVICE["dai"]

    if item == "dns":
        if _text_has(joined, "dns-server", "name-server", "dns server", "dns-server-ip"):
            return "ok", _head_lines(outputs, 6), "DHCP 池已下发 DNS 服务器地址，防 DNS 重定向"
        if not joined.strip():
            return "na", ["（无输出，设备可能不做 DHCP/DNS 下发）"], SECURITY_ADVICE["dns"]
        return "warn", _head_lines(outputs, 6), SECURITY_ADVICE["dns"]

    if item == "vlan_isolate":
        if _text_has(joined, "isolate", "隔离", "isolation"):
            return "ok", _head_lines(outputs, 6), "已配置端口隔离（跨 VLAN 同机互访受限）"
        if _text_has(joined, "acl", "traffic-filter"):
            if _text_has(joined, "rule", "acl number"):
                return "ok", _head_lines(outputs, 6), "存在 ACL，可对跨 VLAN 访问做控制"
        if _text_has(joined, "trunk", "trunking", "trunk mode"):
            return "warn", _head_lines(outputs, 6), "存在 Trunk 口，请确认 VLAN 放行范围，防 VLAN Hopping"
        return "warn", _head_lines(outputs, 6), SECURITY_ADVICE["vlan_isolate"]

    if item == "port_security":
        if _text_has(joined, "disabled", "未使能", "no limit", "maximum mac addresses : 0", "max secure addr.*0"):
            return "warn", _head_lines(outputs, 6), SECURITY_ADVICE["port_security"]
        if _text_has(joined, "enable", "使能", "limit", "max-mac", "max secure", "安全"):
            if _text_has(joined, "disabled", "未使能"):
                return "warn", _head_lines(outputs, 6), SECURITY_ADVICE["port_security"]
            return "ok", _head_lines(outputs, 6), "端口安全/MAC 学习限制已配置"
        if not joined.strip():
            return "na", ["（无输出，设备可能不支持该命令）"], SECURITY_ADVICE["port_security"]
        return "warn", _head_lines(outputs, 6), SECURITY_ADVICE["port_security"]

    return "na", ["未知核查项"], ""


def _head_lines(outputs: dict, max_total: int = 6) -> list:
    """把多命令输出压成前 max_total 行摘要（每命令标题 + 前几行）。"""
    lines = []
    for title, text in outputs.items():
        if lines:
            lines.append(f"── [{title}] ──")
        body = [l for l in text.splitlines() if l.strip()]
        lines.extend(body[: max(1, max_total // max(1, len(outputs)))])
        if len(body) > max(1, max_total // max(1, len(outputs))):
            lines.append(f"... 共 {len(body)} 行")
    return lines[: max_total + 8]


class SecurityTestPanel(ttk.Frame):
    """安全配置核查标签页 / Security audit panel (V3.2)."""

    def __init__(self, master: tk.Widget, app) -> None:
        super().__init__(master)
        self._app = app
        self.stop_event = threading.Event()
        self.result_queue = queue.Queue()
        self._build_ui()
        self.after(100, self._poll_queue)

    def destroy(self) -> None:
        self.stop_event.set()
        super().destroy()

    # ── UI ──
    def _build_ui(self):
        main = ttk.Frame(self, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        cfg = ttk.LabelFrame(main, text="Target Device", padding=8)
        cfg.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(cfg, text="IP:").grid(row=0, column=0, sticky=tk.W)
        self.sec_host = tk.StringVar(value="")
        ttk.Entry(cfg, textvariable=self.sec_host, width=18).grid(row=0, column=1, padx=4)
        ttk.Label(cfg, text="User:").grid(row=0, column=2, sticky=tk.W, padx=(12, 0))
        self.sec_user = tk.StringVar(value="admin")
        ttk.Entry(cfg, textvariable=self.sec_user, width=12).grid(row=0, column=3, padx=4)
        ttk.Label(cfg, text="Pass:").grid(row=0, column=4, sticky=tk.W, padx=(12, 0))
        self.sec_pwd = tk.StringVar(value="")
        ttk.Entry(cfg, textvariable=self.sec_pwd, width=14, show="*").grid(row=0, column=5, padx=4)
        ttk.Label(cfg, text="Type:").grid(row=0, column=6, sticky=tk.W, padx=(12, 0))
        self.sec_devtype = tk.StringVar(value="huawei")
        ttk.Combobox(cfg, textvariable=self.sec_devtype, state="readonly", width=10,
                     values=["huawei", "cisco", "h3c", "ruijie", "linux"]).grid(row=0, column=7, padx=4)
        ttk.Label(cfg, text="Port:").grid(row=0, column=8, sticky=tk.W, padx=(12, 0))
        self.sec_port = tk.StringVar(value="22")
        ttk.Entry(cfg, textvariable=self.sec_port, width=6).grid(row=0, column=9, padx=4)

        checks = ttk.LabelFrame(main, text="Security Checks（只查询配置，不发起攻击）", padding=8)
        checks.pack(fill=tk.X, pady=(0, 8))
        self.sec_check_vars = {}
        for i, key in enumerate(SECURITY_ORDER):
            var = tk.BooleanVar(value=True)
            self.sec_check_vars[key] = var
            ttk.Checkbutton(checks, text=SECURITY_CHECKS[key]["label"], variable=var).grid(
                row=i // 2, column=(i % 2) * 2, sticky=tk.W, padx=(0, 16), pady=2)
        btns = ttk.Frame(checks)
        btns.grid(row=3, column=0, columnspan=4, sticky=tk.W, pady=(6, 0))
        self.sec_start_btn = ttk.Button(btns, text="Start Security Test", style="GreenAccent.TButton",
                                        command=self._on_start)
        self.sec_start_btn.pack(side=tk.LEFT, padx=(0, 8))
        self.sec_stop_btn = ttk.Button(btns, text="Stop", style="Danger.TButton",
                                       command=self._on_stop, state=tk.DISABLED)
        self.sec_stop_btn.pack(side=tk.LEFT, padx=(0, 8))
        ttk.Button(btns, text="Export Report", command=self._on_export).pack(side=tk.LEFT)
        self.sec_status = ttk.Label(checks, text="", foreground="#2563eb")
        self.sec_status.grid(row=3, column=2, columnspan=2, sticky=tk.E)

        self.sec_output = scrolledtext.ScrolledText(main, height=22, font=("Consolas", 9),
                                                    state=tk.DISABLED, bg="#fbfdfb")
        self.sec_output.pack(fill=tk.BOTH, expand=True)
        for tag, fg, bg in (("ok", "#15803d", "#dcfce7"), ("warn", "#b45309", "#fef3c7"),
                            ("fail", "#b91c1c", "#fee2e2"), ("na", "#475569", "#f1f5f9"),
                            ("title", "#1e3a8a", "#e0e7ff"), ("advice", "#1f2937", "#f8fafc")):
            self.sec_output.tag_configure(tag, foreground=fg, background=bg)

    def _log(self, text, tag=None):
        self.sec_output.config(state=tk.NORMAL)
        self.sec_output.insert(tk.END, text + "\n", tag)
        self.sec_output.see(tk.END)
        self.sec_output.config(state=tk.DISABLED)

    def _set_busy(self, busy: bool):
        self.sec_start_btn.config(state=tk.DISABLED if busy else tk.NORMAL)
        self.sec_stop_btn.config(state=tk.NORMAL if busy else tk.DISABLED)

    # ── 控制 ──
    def _on_start(self):
        host = self.sec_host.get().strip()
        if not host:
            tk.messagebox.showwarning("提示", "请填写设备 IP")
            return
        try:
            port = int(self.sec_port.get().strip() or "22")
        except ValueError:
            tk.messagebox.showwarning("提示", "端口格式错误")
            return
        checked = [k for k, v in self.sec_check_vars.items() if v.get()]
        if not checked:
            tk.messagebox.showwarning("提示", "请至少勾选一个核查项")
            return
        self.stop_event.clear()
        self.sec_output.config(state=tk.NORMAL)
        self.sec_output.delete("1.0", tk.END)
        self.sec_output.config(state=tk.DISABLED)
        self._set_busy(True)
        self.sec_status.config(text="Running...")
        threading.Thread(target=self._worker,
                         args=(host, port, self.sec_user.get().strip(), self.sec_pwd.get(),
                               normalize_devtype(self.sec_devtype.get()) or "huawei", checked),
                         daemon=True).start()

    def _on_stop(self):
        self.stop_event.set()
        self.sec_status.config(text="Stopping...")

    def _on_export(self):
        content = self.sec_output.get("1.0", tk.END).strip()
        if not content:
            tk.messagebox.showinfo("提示", "没有可导出的结果")
            return
        import datetime
        path = tk.filedialog.asksaveasfilename(
            title="导出安全核查报告", defaultextension=".txt",
            initialfile=f"security_test_{self.sec_host.get().strip()}_{datetime.datetime.now():%Y%m%d_%H%M}.txt",
            filetypes=[("Text", "*.txt")])
        if not path:
            return
        with open(path, "w", encoding="utf-8-sig", newline="") as f:
            f.write(content)
        self.sec_status.config(text=f"已导出: {path}")

    # ── worker ──
    def _worker(self, host, port, user, pwd, devtype, checked):
        try:
            import paramiko
            client = paramiko.SSHClient()
            client.set_missing_host_key_policy(paramiko.AutoAddPolicy())
            self._app._ssh_connect(client, host, port, user, pwd)
            self.result_queue.put(("sys", f"== {host} ({devtype}) 安全配置核查 =="))
            for key in SECURITY_ORDER:
                if key not in checked or self.stop_event.is_set():
                    continue
                spec = SECURITY_CHECKS[key]
                cmds = spec["cmds"].get(devtype)
                if not cmds:
                    self.result_queue.put(("sys", f"⚠ [{spec['label']}] 此设备类型暂不支持"))
                    continue
                cmds_dict = {t: c for t, c in cmds}
                try:
                    outputs = self._app._run_commands_via_shell(client, devtype, cmds_dict, timeout=25)
                except Exception as e:
                    self.result_queue.put(("sys", f"✗ [{spec['label']}] 命令执行失败: {e}"))
                    continue
                status, detail, advice = judge_security_item(devtype, key, outputs)
                self.result_queue.put(("item", (spec["label"], status, detail, advice)))
            client.close()
            self.result_queue.put(("sys", "== 核查完成 =="))
        except Exception as e:
            self.result_queue.put(("sys", f"✗ 连接失败: {self._app._friendly_conn_error(e)}"))
        finally:
            self.result_queue.put(("done", None))

    def _poll_queue(self):
        try:
            while True:
                kind, data = self.result_queue.get_nowait()
                if kind == "sys":
                    self._log(str(data), "title")
                elif kind == "item":
                    label, status, detail, advice = data
                    mark = {"ok": "✅", "warn": "⚠️", "fail": "❌", "na": "➖"}.get(status, "❓")
                    self._log(f"\n{mark} {label}  →  {status.upper()}", status if status != "na" else "na")
                    for line in detail:
                        self._log("    " + line, "na")
                    self._log("    建议: " + advice.replace("\n", "\n    "), "advice")
                elif kind == "done":
                    self._set_busy(False)
                    self.sec_status.config(text="Done")
        except queue.Empty:
            pass
        try:
            self.after(100, self._poll_queue)
        except Exception:
            pass


# ═══════════════════════════════════════════════════════════════
# 主动探测引擎（V3.3 Active Test）——标准协议故障定位，合法合规
# 场景：带新机器去现场，间歇性故障在通信正常时主动探测定位
# ═══════════════════════════════════════════════════════════════

# 隐藏子进程窗口（Windows 控制台程序，如 arp -a）
_NO_WINDOW = subprocess.CREATE_NO_WINDOW if os.name == "nt" else 0


def _local_mac() -> bytes:
    """本机 MAC（探测用 chaddr），失败返回 6 字节 0。"""
    try:
        out = subprocess.run(["getmac", "/fo", "csv", "/nh"], capture_output=True,
                             text=True, encoding="gbk", errors="replace",
                             timeout=5, creationflags=_NO_WINDOW).stdout or ""
        m = re.search(r"([0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2}-[0-9a-f]{2})",
                      out, re.I)
        if m:
            return bytes.fromhex(m.group(1).replace("-", ""))
    except Exception:
        pass
    return b"\x00\x00\x00\x00\x00\x00"


def icmp_ping(host: str, count: int = 4, timeout: float = 2.0) -> tuple:
    """标准 ping（系统命令，无管理员要求）→ (reachable, rtt_list, err)。

    主动探测用系统 ping 更可靠（raw socket 需要管理员且本机回环收不到）；
    流量压测的高压 ICMP 仍用 TrafficGenerator 的 raw socket 实现。
    """
    try:
        out = subprocess.run(
            ["ping", "-n", str(count), "-w", str(int(timeout * 1000)), host],
            capture_output=True, text=True, encoding="gbk", errors="replace",
            timeout=count * (timeout + 1) + 5,
            creationflags=_NO_WINDOW).stdout or ""
    except subprocess.TimeoutExpired:
        return False, [], "ping 命令超时"
    except OSError as e:
        return False, [], f"ping 命令失败: {e}"
    rtts = [float(m) for m in re.findall(r"(?:time|时间)[=<](\d+)ms", out, re.I)]
    if rtts:
        return True, rtts[:count], None
    low = out.lower()
    if "unreachable" in low or "无法访问" in out or "timed out" in low or "超时" in out:
        return False, [], None
    if "ttl" in low or "存活" in out or "bytes" in low:
        return True, [], None
    return False, [], None


def dns_probe(dns_server: str, domain: str = "www.baidu.com",
              expected_ip: str = "", timeout: float = 5.0) -> tuple:
    """DNS A 记录查询（UDP 53）→ (status, answers, rtt, err)。

    status: ok(有响应且匹配预期) / warn(响应但 IP 与预期不符=疑似重定向) /
            fail(无响应) / na(参数错)
    """
    try:
        socket.inet_aton(dns_server)
    except OSError:
        return "na", [], None, f"DNS 服务器 IP 格式错误: {dns_server}"
    try:
        txid = os.getpid() & 0xFFFF
        header = struct.pack("!HHHHHH", txid, 0x0100, 1, 0, 0, 0)
        qname = b"".join(bytes([len(p)]) + p.encode() for p in domain.split(".")) + b"\x00"
        question = qname + struct.pack("!HH", 1, 1)
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
        sock.settimeout(timeout)
        t0 = time.time()
        sock.sendto(header + question, (dns_server, 53))
        data, _ = sock.recvfrom(4096)
        rtt = round((time.time() - t0) * 1000, 1)
        sock.close()
        if len(data) < 12:
            return "fail", [], rtt, "DNS 响应过短"
        # 跳过 question 解析 answer 的 A 记录
        pos = 12
        for _ in range(struct.unpack("!H", data[4:6])[0]):
            while pos < len(data) and data[pos] != 0:
                pos += 1 + data[pos]
            pos += 5
        answers = []
        for _ in range(struct.unpack("!H", data[6:8])[0]):
            if pos + 12 > len(data):
                break
            if data[pos] != 0xc0:
                while pos < len(data) and data[pos] != 0:
                    pos += 1 + data[pos]
                pos += 1
            else:
                pos += 2
            _typ, _cls, _ttl, rdlen = struct.unpack("!HHIH", data[pos:pos + 10])
            pos += 10
            if _typ == 1 and rdlen == 4 and pos + 4 <= len(data):
                answers.append(socket.inet_ntoa(data[pos:pos + 4]))
            pos += rdlen
        if not answers:
            return "fail", [], rtt, "无 A 记录响应"
        if expected_ip:
            if expected_ip in answers:
                return "ok", answers, rtt, None
            return "warn", answers, rtt, f"解析到 {answers[0]}，但预期 {expected_ip} — 疑似 DNS 被重定向"
        return "ok", answers, rtt, None
    except socket.timeout:
        return "fail", [], None, f"{dns_server} 无响应（超时 {timeout}s）"
    except OSError as e:
        return "fail", [], None, f"查询失败: {e}"


def _parse_dhcp_options(raw: bytes) -> dict:
    """解析 DHCP options（从 magic cookie 后开始）→ {code: value}。"""
    opts = {}
    i = 0
    while i < len(raw):
        code = raw[i]
        if code == 0:
            i += 1
            continue
        if code == 255:
            break
        if i + 1 >= len(raw):
            break
        ln = raw[i + 1]
        if i + 2 + ln > len(raw):
            break
        val = raw[i + 2:i + 2 + ln]
        if code == 54 and ln == 4:
            opts["server_id"] = socket.inet_ntoa(val)
        elif code == 3:
            opts["router"] = socket.inet_ntoa(val[:4])
        elif code == 6:
            opts["dns"] = " ".join(socket.inet_ntoa(val[j:j + 4])
                                   for j in range(0, len(val), 4))
        elif code == 1:
            opts["subnet"] = socket.inet_ntoa(val[:4])
        elif code == 51 and ln == 4:
            opts["lease"] = struct.unpack("!I", val)[0]
        elif code == 12:
            opts["hostname"] = val.decode("utf-8", "replace")
        i += 2 + ln
    return opts


def dhcp_probe(timeout: float = 6.0) -> tuple:
    """DHCP Discover 广播 → 收集所有 Offer 响应者 → (servers, err)。

    定位：私接路由器抢答 DHCP（>1 个服务器响应 = 有非法 DHCP）。
    servers: [{ip, mac?, router, dns, subnet, lease, rtt}]
    """
    mac = _local_mac()
    xid = (os.getpid() ^ int(time.time())) & 0xFFFFFFFF
    # BOOTP header + magic cookie + options
    bootp = struct.pack("!BBBBIHHHH", 1, 1, 6, 0, xid, 0, 0x8000, 0, 0) \
        + bytes(4) + bytes(4) + bytes(4) + mac + bytes(10) \
        + bytes(64) + bytes(128) + bytes([99, 130, 83, 99])
    opts = bytes([53, 1, 1])                       # DHCP Discover
    opts += bytes([55, 7, 1, 3, 6, 15, 51, 54, 119])   # 请求参数列表
    opts += bytes([12, 7]) + b"NADT-PROBE"
    opts += bytes([255])
    pkt = bootp + opts
    try:
        sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM, socket.IPPROTO_UDP)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        sock.setsockopt(socket.SOL_SOCKET, socket.SO_BROADCAST, 1)
        sock.bind(("0.0.0.0", 68))
    except OSError as e:
        return [], f"无法绑定 UDP 68（系统 DHCP 客户端占用？）：{e}"
    servers = []
    try:
        sock.settimeout(timeout)
        t0 = time.time()
        try:
            sock.sendto(pkt, ("255.255.255.255", 67))
        except PermissionError:
            return [], "发送被拒绝 — 请以管理员身份运行"
        while time.time() - t0 < timeout:
            try:
                data, addr = sock.recvfrom(4096)
            except socket.timeout:
                break
            if len(data) < 240 or data[0] != 2:        # BOOTREPLY
                continue
            if struct.unpack("!I", data[4:8])[0] != xid:
                continue
            srv = {
                "ip": socket.inet_ntoa(data[20:24]) or addr[0],
                "yiaddr": socket.inet_ntoa(data[16:20]),
                "rtt": round((time.time() - t0) * 1000, 1),
            }
            srv.update(_parse_dhcp_options(data[240:]))
            servers.append(srv)
    finally:
        sock.close()
    return servers, None


def _arp_lookup(ip: str) -> str:
    """arp -a 查 IP 的 MAC（隐藏窗口）。"""
    try:
        out = subprocess.run(["arp", "-a", ip], capture_output=True, text=True,
                             encoding="gbk", errors="replace",
                             timeout=5, creationflags=_NO_WINDOW).stdout or ""
        m = re.search(r"([0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2}[:-][0-9a-f]{2})",
                      out, re.I)
        return m.group(1).replace("-", ":").lower() if m else ""
    except Exception:
        return ""


def arp_probe(ip: str, repeat: int = 3, timeout: float = 2.0) -> tuple:
    """ARP 探测：ping 触发 + arp 表多次采样 → (macs, status, err)。

    多次探测到不同 MAC（同一 IP） = 疑似 ARP 欺骗/重复 IP。
    status: ok(单一稳定 MAC) / warn(多个 MAC=冲突) / fail(无 MAC/不可达)
    """
    macs = []
    err = None
    for _ in range(repeat):
        reach, _, _err = icmp_ping(ip, count=1, timeout=timeout)
        if _err and "管理员" in _err:
            return [], "fail", _err
        time.sleep(0.25)
        mac = _arp_lookup(ip)
        if mac and mac not in macs:
            macs.append(mac)
    if not macs:
        return [], "fail", f"{ip} 无 ARP 条目（不可达或不同网段）"
    if len(macs) > 1:
        return macs, "warn", f"同一 IP 出现 {len(macs)} 个不同 MAC — 疑似 ARP 欺骗/重复 IP"
    return macs, "ok", None


def vlan_probe(target: str, count: int = 4, timeout: float = 2.0) -> tuple:
    """跨 VLAN 连通性探测（标准 ICMP）→ (reachable, rtts, err)。

    定位：应隔离却通（缺跨 VLAN 控制）/ 应通却不通（路由/ACL 问题）。
    """
    return icmp_ping(target, count=count, timeout=timeout)


class ActiveTestPanel(ttk.Frame):
    """主动探测标签页 / Active test panel (V3.3) — 标准协议故障定位。"""

    def __init__(self, master: tk.Widget) -> None:
        super().__init__(master)
        self.result_queue = queue.Queue()
        self._build_ui()
        self.after(100, self._poll_queue)

    def destroy(self) -> None:
        super().destroy()

    def _build_ui(self):
        main = ttk.Frame(self, padding=10)
        main.pack(fill=tk.BOTH, expand=True)

        tgt = ttk.LabelFrame(main, text="Probe Targets（带新机器到现场，通信正常时主动探测）", padding=8)
        tgt.pack(fill=tk.X, pady=(0, 8))
        ttk.Label(tgt, text="ARP 目标 IP（网关/冲突IP）:").grid(row=0, column=0, sticky=tk.W)
        self.at_arp_ip = tk.StringVar(value="")
        ttk.Entry(tgt, textvariable=self.at_arp_ip, width=16).grid(row=0, column=1, padx=4)
        ttk.Label(tgt, text="DNS 服务器 IP:").grid(row=0, column=2, sticky=tk.W, padx=(12, 0))
        self.at_dns = tk.StringVar(value="")
        ttk.Entry(tgt, textvariable=self.at_dns, width=16).grid(row=0, column=3, padx=4)
        ttk.Label(tgt, text="预期解析 IP（对比重定向）:").grid(row=0, column=4, sticky=tk.W, padx=(12, 0))
        self.at_dns_expected = tk.StringVar(value="")
        ttk.Entry(tgt, textvariable=self.at_dns_expected, width=15).grid(row=0, column=5, padx=4)
        ttk.Label(tgt, text="跨 VLAN 目标 IP:").grid(row=1, column=0, sticky=tk.W, pady=(6, 0))
        self.at_vlan_ip = tk.StringVar(value="")
        ttk.Entry(tgt, textvariable=self.at_vlan_ip, width=16).grid(row=1, column=1, padx=4, pady=(6, 0))
        ttk.Label(tgt, text="查询域名:").grid(row=1, column=2, sticky=tk.W, padx=(12, 0), pady=(6, 0))
        self.at_domain = tk.StringVar(value="www.baidu.com")
        ttk.Entry(tgt, textvariable=self.at_domain, width=16).grid(row=1, column=3, padx=4, pady=(6, 0))

        btns = ttk.Frame(main)
        btns.pack(fill=tk.X, pady=(0, 8))
        ttk.Button(btns, text="🕮 Probe DHCP（发现私接路由器抢答）", style="GreenAccent.TButton",
                   command=lambda: self._run("dhcp")).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btns, text="Probe DNS（重定向对比）", command=lambda: self._run("dns")).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btns, text="Probe ARP（冲突/欺骗）", command=lambda: self._run("arp")).pack(side=tk.LEFT, padx=(0, 6))
        ttk.Button(btns, text="Probe VLAN（跨 VLAN 连通）", command=lambda: self._run("vlan")).pack(side=tk.LEFT, padx=(0, 6))
        self.at_status = ttk.Label(btns, text="", foreground="#2563eb")
        self.at_status.pack(side=tk.LEFT, padx=(12, 0))

        self.at_output = scrolledtext.ScrolledText(main, height=24, font=("Consolas", 9),
                                                   state=tk.DISABLED, bg="#fbfdfb")
        self.at_output.pack(fill=tk.BOTH, expand=True)
        for tag, fg, bg in (("ok", "#15803d", "#dcfce7"), ("warn", "#b45309", "#fef3c7"),
                            ("fail", "#b91c1c", "#fee2e2"), ("na", "#475569", "#f1f5f9"),
                            ("title", "#1e3a8a", "#e0e7ff"), ("plain", "#1f2937", "#f8fafc")):
            self.at_output.tag_configure(tag, foreground=fg, background=bg)

    def _log(self, text, tag=None):
        self.at_output.config(state=tk.NORMAL)
        self.at_output.insert(tk.END, text + "\n", tag)
        self.at_output.see(tk.END)
        self.at_output.config(state=tk.DISABLED)

    def _run(self, kind: str):
        # 主线程取好参数（worker 线程不能碰 tkinter 变量）
        args = {
            "dns": self.at_dns.get().strip(),
            "domain": self.at_domain.get().strip(),
            "expected": self.at_dns_expected.get().strip(),
            "arp_ip": self.at_arp_ip.get().strip(),
            "vlan_ip": self.at_vlan_ip.get().strip(),
        }
        self.at_output.config(state=tk.NORMAL)
        self.at_output.delete("1.0", tk.END)
        self.at_output.config(state=tk.DISABLED)
        self.at_status.config(text=f"Probing {kind}...")
        threading.Thread(target=self._worker, args=(kind, args), daemon=True).start()

    def _worker(self, kind: str, args: dict):
        try:
            if kind == "dhcp":
                self._probe_dhcp()
            elif kind == "dns":
                self._probe_dns(args)
            elif kind == "arp":
                self._probe_arp(args)
            elif kind == "vlan":
                self._probe_vlan(args)
        except Exception as e:
            self.result_queue.put(("line", f"✗ 探测异常: {e}", "fail"))
        finally:
            self.result_queue.put(("done", None))

    def _probe_dhcp(self):
        self.result_queue.put(("line", "== DHCP 主动探测：广播 Discover，收集所有 Offer 响应者 ==", "title"))
        servers, err = dhcp_probe(timeout=6)
        if err:
            self.result_queue.put(("line", f"✗ {err}", "fail"))
            return
        if not servers:
            self.result_queue.put(("line", "➖ 6s 内无 DHCP Offer 响应（本网段可能没有 DHCP 服务器）", "na"))
            return
        for s in servers:
            self.result_queue.put(("line", f"  📡 服务器 {s.get('ip')}  分配 {s.get('yiaddr')}  响应 {s.get('rtt')}ms", "plain"))
            if s.get("router"):
                self.result_queue.put(("line", f"     网关={s.get('router')}  掩码={s.get('subnet', '-')}  DNS={s.get('dns', '-')}  租约={s.get('lease', '-')}s", "plain"))
        if len(servers) > 1:
            self.result_queue.put(("line", f"❌ 检测到 {len(servers)} 个 DHCP 服务器响应 — 存在私接路由器/非法 DHCP 抢答！", "fail"))
            self.result_queue.put(("line", "   终端获取到错误地址/间歇断网的根因大概率在此。排查：交换机开启 DHCP Snooping 并设合法上联口为 trusted。", "advice"))
        else:
            self.result_queue.put(("line", "✅ 仅 1 个 DHCP 服务器响应，无抢答", "ok"))

    def _probe_dns(self, args: dict):
        dns = args.get("dns", "")
        if not dns:
            self.result_queue.put(("line", "✗ 请填 DNS 服务器 IP", "fail"))
            return
        domain = args.get("domain") or "www.baidu.com"
        expected = args.get("expected", "")
        self.result_queue.put(("line", f"== DNS 主动探测：查询 {domain} @ {dns}（预期 {'未填' if not expected else expected}）==", "title"))
        status, answers, rtt, err = dns_probe(dns, domain, expected)
        if err:
            self.result_queue.put(("line", f"✗ {err}", "fail"))
            return
        self.result_queue.put(("line", f"  解析结果: {', '.join(answers)}  ({rtt}ms)", "plain"))
        if status == "ok":
            self.result_queue.put(("line", "✅ DNS 响应正常，与预期一致", "ok"))
        elif status == "warn":
            self.result_queue.put(("line", f"⚠️ 解析到 {answers[0]} 但预期 {expected} — 疑似 DNS 被重定向（私接路由器/劫持）！", "warn"))
            self.result_queue.put(("line", "   建议：核对 DHCP 下发的 DNS、检查出口 DNS 策略", "plain"))

    def _probe_arp(self, args: dict):
        ip = args.get("arp_ip", "")
        if not ip:
            self.result_queue.put(("line", "✗ 请填 ARP 目标 IP（网关或疑似冲突的 IP）", "fail"))
            return
        self.result_queue.put(("line", f"== ARP 主动探测：{ip} 采样 3 次（ping 触发 + arp 表）==", "title"))
        macs, status, err = arp_probe(ip, repeat=3)
        if err:
            self.result_queue.put(("line", f"✗ {err}", "fail"))
            return
        for i, m in enumerate(macs, 1):
            self.result_queue.put(("line", f"  采样 {i}: {m}", "plain"))
        if status == "ok":
            self.result_queue.put(("line", f"✅ {ip} → {macs[0]}（稳定，无 ARP 冲突）", "ok"))
        elif status == "warn":
            self.result_queue.put(("line", f"⚠️ 同一 IP 出现 {len(macs)} 个不同 MAC — 疑似 ARP 欺骗/重复 IP！", "warn"))
            self.result_queue.put(("line", "   排查：display arp 查该 IP 真实归属，DAI(arp anti-attack) 未开是主因", "plain"))

    def _probe_vlan(self, args: dict):
        ip = args.get("vlan_ip", "")
        if not ip:
            self.result_queue.put(("line", "✗ 请填跨 VLAN 目标 IP", "fail"))
            return
        self.result_queue.put(("line", f"== 跨 VLAN 主动探测：ICMP ×4 → {ip} ==", "title"))
        reach, rtts, err = vlan_probe(ip, count=4)
        if err:
            self.result_queue.put(("line", f"✗ {err}", "fail"))
            return
        if reach:
            avg = sum(rtts) / len(rtts)
            self.result_queue.put(("line", f"  RTT: {', '.join(map(str, rtts))}ms  平均 {avg:.1f}ms", "plain"))
            self.result_queue.put(("line", f"✅ 跨 VLAN 可达 — 若这两个 VLAN 本应隔离，说明缺少跨 VLAN 访问控制！", "warn"))
            self.result_queue.put(("line", "   排查：port-isolate / VLAN 间 ACL / 三层互访策略", "plain"))
        else:
            self.result_queue.put(("line", "➖ 4 次全部超时 — 不可达（若本应互通，查 VLANIF/路由/ACL）", "na"))

    def _poll_queue(self):
        try:
            while True:
                kind, *rest = self.result_queue.get_nowait()
                if kind == "line":
                    self._log(rest[0], rest[1] if len(rest) > 1 else None)
                elif kind == "done":
                    self.at_status.config(text="Done")
        except queue.Empty:
            pass
        try:
            self.after(100, self._poll_queue)
        except Exception:
            pass


class TrafficTestPanel(ttk.Frame):
    """流量测试标签页 / Traffic stress-test panel (V3, green accents)."""

    def __init__(self, master: tk.Widget) -> None:
        super().__init__(master)
        self.generator: TrafficGenerator | None = None
        self.tcp_server: TCPServer | None = None
        self.monitor_id: str | None = None
        self.start_time: float = 0.0
        self._build_ui()
        self._start_monitor()

    def destroy(self) -> None:
        if self.monitor_id:
            try:
                self.after_cancel(self.monitor_id)
            except Exception:
                pass
        if self.generator:
            self.generator.stop()
        if self.tcp_server:
            self.tcp_server.stop()
        super().destroy()

    def _build_ui(self):
        main_frame = ttk.Frame(self, padding=10)
        main_frame.pack(fill=tk.BOTH, expand=True)

        # --- Target Config ---
        target_frame = ttk.LabelFrame(main_frame, text="Target Configuration", padding=10)
        target_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(target_frame, text="Target IP:").grid(row=0, column=0, sticky=tk.W, padx=(0, 5))
        self.ip_var = tk.StringVar(value="127.0.0.1")
        ttk.Entry(target_frame, textvariable=self.ip_var, width=20).grid(row=0, column=1, sticky=tk.W, padx=5)

        ttk.Label(target_frame, text="Port:").grid(row=0, column=2, sticky=tk.W, padx=(15, 5))
        self.port_var = tk.StringVar(value="8080")
        ttk.Entry(target_frame, textvariable=self.port_var, width=14).grid(row=0, column=3, sticky=tk.W, padx=5)

        ttk.Label(target_frame, text="e.g. 8080, 80,443, 100-1000, 100-1000:50",
                  foreground="#5b7a68", font=("", 7)).grid(
            row=1, column=2, columnspan=2, sticky=tk.W, padx=(20, 0), pady=(0, 2))

        ttk.Label(target_frame, text="Protocol:").grid(row=0, column=4, sticky=tk.W, padx=(15, 5))
        self.protocol_var = tk.StringVar(value="UDP")
        proto_combo = ttk.Combobox(target_frame, textvariable=self.protocol_var,
                                   values=["UDP", "ICMP", "TCP", "TCP SYN"], state="readonly", width=8)
        proto_combo.grid(row=0, column=5, sticky=tk.W, padx=5)

        ttk.Label(target_frame, text="Detected Gateways:").grid(
            row=2, column=0, sticky=tk.W, padx=(0, 5), pady=(8, 0))
        self.gateway_var = tk.StringVar(value="")
        self.gateway_combo = ttk.Combobox(
            target_frame, textvariable=self.gateway_var,
            values=[], state="readonly", width=32)
        self.gateway_combo.grid(row=2, column=1, columnspan=2, sticky=tk.W, padx=5, pady=(8, 0))
        self.gateway_combo.bind("<<ComboboxSelected>>", self._on_gateway_selected)

        detect_btn = ttk.Button(target_frame, text="Detect", command=self._on_detect_gateways)
        detect_btn.grid(row=2, column=3, sticky=tk.W, padx=5, pady=(8, 0))

        # --- TCP Server ---
        tcp_srv_frame = ttk.LabelFrame(main_frame, text="Built-in TCP Receiver (for TCP testing)", padding=10)
        tcp_srv_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(tcp_srv_frame, text="Listen Port:").pack(side=tk.LEFT)
        self.tcp_srv_port_var = tk.IntVar(value=8080)
        ttk.Entry(tcp_srv_frame, textvariable=self.tcp_srv_port_var, width=8).pack(side=tk.LEFT, padx=5)

        self.tcp_srv_start_btn = ttk.Button(tcp_srv_frame, text="Start Server",
                                            command=self._on_start_tcp_server,
                                            style="GreenAccent.TButton")
        self.tcp_srv_start_btn.pack(side=tk.LEFT, padx=5)

        self.tcp_srv_stop_btn = ttk.Button(tcp_srv_frame, text="Stop Server",
                                           command=self._on_stop_tcp_server, state=tk.DISABLED,
                                           style="Danger.TButton")
        self.tcp_srv_stop_btn.pack(side=tk.LEFT, padx=5)

        self.tcp_srv_status_var = tk.StringVar(value="Stopped")
        ttk.Label(tcp_srv_frame, textvariable=self.tcp_srv_status_var,
                  foreground="#5b7a68").pack(side=tk.LEFT, padx=10)

        self.tcp_srv_rx_var = tk.StringVar(value="")
        ttk.Label(tcp_srv_frame, textvariable=self.tcp_srv_rx_var,
                  foreground="#15803d").pack(side=tk.RIGHT, padx=5)

        # --- Traffic Params ---
        param_frame = ttk.LabelFrame(main_frame, text="Traffic Parameters", padding=10)
        param_frame.pack(fill=tk.X, pady=(0, 10))

        ttk.Label(param_frame, text="Concurrency (threads):").grid(row=0, column=0, sticky=tk.W)
        self.concurrency_var = tk.IntVar(value=10)
        conc_scale = ttk.Scale(param_frame, from_=1, to=500, variable=self.concurrency_var,
                               orient=tk.HORIZONTAL, length=200, command=self._on_concurrency_scale)
        conc_scale.grid(row=0, column=1, sticky=tk.W, padx=5)
        self.conc_label = ttk.Label(param_frame, text="10", width=4)
        self.conc_label.grid(row=0, column=2, sticky=tk.W)
        self.concurrency_var.trace_add("write", lambda *_: self._update_conc_label())

        ttk.Label(param_frame, text="Packet Size (bytes):").grid(row=1, column=0, sticky=tk.W, pady=(10, 0))
        self.pkt_size_var = tk.IntVar(value=1024)
        size_frame = ttk.Frame(param_frame)
        size_frame.grid(row=1, column=1, columnspan=2, sticky=tk.W, pady=(10, 0), padx=5)
        ttk.Radiobutton(size_frame, text="64", variable=self.pkt_size_var, value=64).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(size_frame, text="256", variable=self.pkt_size_var, value=256).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(size_frame, text="512", variable=self.pkt_size_var, value=512).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(size_frame, text="1024", variable=self.pkt_size_var, value=1024).pack(side=tk.LEFT, padx=2)
        ttk.Radiobutton(size_frame, text="1460", variable=self.pkt_size_var, value=1460).pack(side=tk.LEFT, padx=2)
        custom_entry = ttk.Entry(param_frame, textvariable=self.pkt_size_var, width=8)
        custom_entry.grid(row=1, column=3, sticky=tk.W, pady=(10, 0), padx=5)

        ttk.Label(param_frame, text="Rate (pkt/s/thread):").grid(row=2, column=0, sticky=tk.W, pady=(10, 0))
        self.rate_var = tk.IntVar(value=1000)
        rate_scale = ttk.Scale(param_frame, from_=0, to=50000, variable=self.rate_var,
                               orient=tk.HORIZONTAL, length=200, command=self._on_rate_scale)
        rate_scale.grid(row=2, column=1, sticky=tk.W, pady=(10, 0), padx=5)
        self.rate_label = ttk.Label(param_frame, text="1000", width=8)
        self.rate_label.grid(row=2, column=2, sticky=tk.W, pady=(10, 0))
        self.rate_var.trace_add("write", lambda *_: self._update_rate_label())
        ttk.Label(param_frame, text="(0 = unlimited burst)").grid(row=2, column=3, sticky=tk.W, pady=(10, 0), padx=5)

        self.rate_warn_var = tk.StringVar(value="")
        ttk.Label(param_frame, textvariable=self.rate_warn_var,
                  foreground="#dc2626", font=("Microsoft YaHei UI", 8, "bold")).grid(
            row=3, column=0, columnspan=4, sticky=tk.W, pady=(4, 0), padx=5)

        # --- Control Buttons ---
        ctrl_frame = ttk.Frame(main_frame)
        ctrl_frame.pack(fill=tk.X, pady=(0, 10))

        self.start_btn = ttk.Button(ctrl_frame, text="Start", command=self._on_start,
                                    style="GreenAccent.TButton")
        self.start_btn.pack(side=tk.LEFT, padx=(0, 10))

        self.stop_btn = ttk.Button(ctrl_frame, text="Stop", command=self._on_stop, state=tk.DISABLED,
                                   style="Danger.TButton")
        self.stop_btn.pack(side=tk.LEFT)

        self.status_var = tk.StringVar(value="Idle")
        ttk.Label(ctrl_frame, textvariable=self.status_var, foreground="#5b7a68").pack(side=tk.LEFT, padx=20)

        # --- Stats Display ---
        stats_frame = ttk.LabelFrame(main_frame, text="Real-time Statistics", padding=10)
        stats_frame.pack(fill=tk.X, pady=(0, 10))

        row0 = ttk.Frame(stats_frame)
        row0.pack(fill=tk.X)
        ttk.Label(row0, text="PPS (packets/sec):", font=("Consolas", 11, "bold")).pack(side=tk.LEFT)
        self.pps_var = tk.StringVar(value="0")
        ttk.Label(row0, textvariable=self.pps_var, font=("Consolas", 14, "bold"),
                  foreground="#16a34a", width=20, anchor=tk.E).pack(side=tk.RIGHT)

        row0b = ttk.Frame(stats_frame)
        row0b.pack(fill=tk.X, pady=(2, 5))
        ttk.Label(row0b, text="Bandwidth (Mbps):", font=("Consolas", 11, "bold")).pack(side=tk.LEFT)
        self.bps_var = tk.StringVar(value="0")
        ttk.Label(row0b, textvariable=self.bps_var, font=("Consolas", 14, "bold"),
                  foreground="#15803d", width=20, anchor=tk.E).pack(side=tk.RIGHT)

        row1 = ttk.Frame(stats_frame)
        row1.pack(fill=tk.X)
        ttk.Label(row1, text="Total Packets:").pack(side=tk.LEFT)
        self.total_pkt_var = tk.StringVar(value="0")
        ttk.Label(row1, textvariable=self.total_pkt_var, width=20, anchor=tk.E).pack(side=tk.RIGHT)

        row2 = ttk.Frame(stats_frame)
        row2.pack(fill=tk.X, pady=(2, 0))
        ttk.Label(row2, text="Total Bytes:").pack(side=tk.LEFT)
        self.total_bytes_var = tk.StringVar(value="0")
        ttk.Label(row2, textvariable=self.total_bytes_var, width=20, anchor=tk.E).pack(side=tk.RIGHT)

        row3 = ttk.Frame(stats_frame)
        row3.pack(fill=tk.X, pady=(2, 0))
        ttk.Label(row3, text="Elapsed:").pack(side=tk.LEFT)
        self.elapsed_var = tk.StringVar(value="00:00:00")
        ttk.Label(row3, textvariable=self.elapsed_var, width=20, anchor=tk.E).pack(side=tk.RIGHT)

        # --- Log ---
        log_frame = ttk.LabelFrame(main_frame, text="Log", padding=5)
        log_frame.pack(fill=tk.BOTH, expand=True)
        self.log_area = scrolledtext.ScrolledText(log_frame, height=8, width=80,
                                                  font=("Consolas", 9), state=tk.DISABLED,
                                                  bg="#fbfdf9", fg="#1e3a2b",
                                                  insertbackground="#16a34a", relief="flat")
        self.log_area.pack(fill=tk.BOTH, expand=True)

    def _update_conc_label(self):
        self.conc_label.config(text=str(self.concurrency_var.get()))

    def _on_concurrency_scale(self, val):
        self.concurrency_var.set(int(float(val)))
        self._update_conc_label()

    def _update_rate_label(self):
        self.rate_label.config(text=str(self.rate_var.get()))
        if self.rate_var.get() == 0:
            self.rate_warn_var.set("⚠️ rate = 0 不限速全速发包！会占用大量 CPU，请勿用于环回/本机高并发测试")
        else:
            self.rate_warn_var.set("")

    def _on_rate_scale(self, val):
        self.rate_var.set(int(float(val)))
        self._update_rate_label()

    def _on_detect_gateways(self):
        gateways = detect_gateways()
        if not gateways:
            messagebox.showwarning("Detect Gateways",
                                   "No default gateways found.\n\n"
                                   "Possible causes:\n"
                                   "- No active network interfaces\n"
                                   "- PowerShell unavailable")
            self._log("Gateway detection: none found")
            return
        display_names = [g[0] for g in gateways]
        self._gateway_map = {g[0]: g[1] for g in gateways}
        self.gateway_combo["values"] = display_names
        if display_names:
            self.gateway_combo.current(0)
            self._on_gateway_selected()
        self._log(f"Gateway detection: found {len(gateways)} gateway(s)")
        for display, ip in gateways:
            self._log(f"  {display}")

    def _on_gateway_selected(self, event=None):
        selected = self.gateway_var.get()
        if hasattr(self, '_gateway_map') and selected in self._gateway_map:
            self.ip_var.set(self._gateway_map[selected])

    def _on_start(self):
        ip = self.ip_var.get().strip()
        port_str = self.port_var.get().strip()
        if not ip:
            messagebox.showerror("Error", "Target IP cannot be empty")
            return

        try:
            pkt_size = self.pkt_size_var.get()
        except tk.TclError:
            messagebox.showerror("Error", "Packet Size must be a number")
            return
        if pkt_size < 1 or pkt_size > 65535:
            messagebox.showerror("Error", "Packet Size must be between 1 and 65535")
            return

        ports, port_desc = parse_ports(port_str)
        if not ports:
            messagebox.showerror("Error", f"Invalid port spec: {port_desc}")
            return

        self.generator = TrafficGenerator(
            target_ip=ip,
            target_port_str=port_str,
            protocol=self.protocol_var.get(),
            concurrency=self.concurrency_var.get(),
            packet_size=pkt_size,
            rate=self.rate_var.get(),
            log_callback=self._log
        )

        self.generator.start()
        self.start_time = time.perf_counter()
        self.status_var.set("Running...")
        self.start_btn.config(state=tk.DISABLED)
        self.stop_btn.config(state=tk.NORMAL)
        self._log(f"Started: {self.generator.concurrency} threads, "
                  f"{self.generator.protocol} -> {ip}, "
                  f"ports={port_desc}, "
                  f"pkt_size={self.generator.packet_size}B, "
                  f"rate={self.generator.rate} pkt/s/thread")

    def _on_stop(self):
        if self.generator:
            self._log("Stopping...")
            self.generator.stop()
            elapsed = time.perf_counter() - self.start_time
            stats = self.generator.stats
            with stats.lock:
                total_pkts = stats.total_packets
                total_bytes = stats.total_bytes
            avg_pps = total_pkts / elapsed if elapsed > 0 else 0
            avg_mbps = (total_bytes * 8) / elapsed / 1e6 if elapsed > 0 else 0
            self._log(f"Stopped. Total: {total_pkts:,} packets, {self._fmt_bytes(total_bytes)}. "
                      f"Avg PPS: {avg_pps:,.0f}, Avg Mbps: {avg_mbps:.2f}")
            self.generator = None
        self.status_var.set("Idle")
        self.pps_var.set("0")
        self.bps_var.set("0")
        self.total_pkt_var.set("0")
        self.total_bytes_var.set("0")
        self.elapsed_var.set("00:00:00")
        self.start_btn.config(state=tk.NORMAL)
        self.stop_btn.config(state=tk.DISABLED)

    def _on_start_tcp_server(self):
        try:
            port = self.tcp_srv_port_var.get()
        except tk.TclError:
            messagebox.showerror("Error", "Listen Port must be a number")
            return
        if port < 1 or port > 65535:
            messagebox.showerror("Error", "Listen Port must be between 1 and 65535")
            return
        self.tcp_server = TCPServer(port, log_callback=self._log)
        self.tcp_server.start()
        if self.tcp_server.running:
            self.tcp_srv_start_btn.config(state=tk.DISABLED)
            self.tcp_srv_stop_btn.config(state=tk.NORMAL)
            self.tcp_srv_status_var.set("Listening")

    def _on_stop_tcp_server(self):
        if self.tcp_server:
            self.tcp_server.stop()
            self.tcp_server = None
        self.tcp_srv_start_btn.config(state=tk.NORMAL)
        self.tcp_srv_stop_btn.config(state=tk.DISABLED)
        self.tcp_srv_status_var.set("Stopped")
        self.tcp_srv_rx_var.set("")

    def _start_monitor(self):
        self._monitor_tick()
        self.monitor_id = self.after(500, self._start_monitor)

    def _monitor_tick(self):
        if self.generator and self.generator.running:
            elapsed = time.perf_counter() - self.start_time
            self.generator.stats.tick(0.5)
            pps, bps, total_pkts, total_bytes = self.generator.stats.snapshot()

            self.pps_var.set(f"{pps:,.0f}")
            self.bps_var.set(f"{(bps * 8) / 1e6:,.2f}")
            self.total_pkt_var.set(f"{total_pkts:,}")
            self.total_bytes_var.set(self._fmt_bytes(total_bytes))

            h = int(elapsed // 3600)
            m = int((elapsed % 3600) // 60)
            s = int(elapsed % 60)
            self.elapsed_var.set(f"{h:02d}:{m:02d}:{s:02d}")

        if self.tcp_server and self.tcp_server.running:
            s = self.tcp_server.stats
            with s.lock:
                rx_pkts = s.total_packets
                rx_bytes = s.total_bytes
            self.tcp_srv_rx_var.set(f"Rx: {rx_pkts:,} pkts, {TCPServer._fmt(rx_bytes)}")

    def _log(self, msg: str):
        self.log_area.config(state=tk.NORMAL)
        timestamp = time.strftime("%H:%M:%S")
        self.log_area.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    @staticmethod
    def _fmt_bytes(b: int) -> str:
        if b < 1024:
            return f"{b} B"
        elif b < 1024 ** 2:
            return f"{b / 1024:.1f} KB"
        elif b < 1024 ** 3:
            return f"{b / 1024 ** 2:.1f} MB"
        else:
            return f"{b / 1024 ** 3:.2f} GB"


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
        self.root.title("Network Inspection System V3 — 网络巡检工具")
        self.root.geometry("1120x860")
        self.root.minsize(800, 600)

        # 应用现代清爽蓝主题 / apply modern clean-blue theme
        setup_app_style(root)

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
        self._host_anom_level: dict = {}   # host → "high"|"mid"（异常级别）/ anomaly level

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
        self.tab_traffic  = TrafficTestPanel(notebook); notebook.add(self.tab_traffic, text="Traffic Test")
        self.tab_security = SecurityTestPanel(notebook, self); notebook.add(self.tab_security, text="Security Test")
        self.tab_active   = ActiveTestPanel(notebook);        notebook.add(self.tab_active,   text="Active Test")

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

        self.btn_ip_intel = ttk.Button(r3, text="IP Intel", command=lambda: self._open_ip_intel(self.single_host.get()))
        self.btn_ip_intel.pack(side=tk.RIGHT, padx=(5, 0))
        self.btn_single = ttk.Button(r3, text="Start Inspection", style="Accent.TButton", command=self._start_single)
        self.btn_single.pack(side=tk.RIGHT, padx=(5, 0))
        self.btn_single_stop = ttk.Button(r3, text="Stop", style="Danger.TButton", command=self._stop_all, state=tk.DISABLED)
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
        ttk.Button(search_row, text="⚠下一异常", width=11, command=lambda: self._jump_to_next_anomaly(
            self.single_output, self.single_search_label)).pack(side=tk.LEFT, padx=(1, 5))
        self.single_search_label = ttk.Label(search_row, text="", font=("", 8), foreground="gray")
        self.single_search_label.pack(side=tk.LEFT)

        self.single_output = scrolledtext.ScrolledText(
            out_frame, wrap=tk.WORD, font=("Consolas", 10), state=tk.DISABLED
        )
        self.single_output.pack(fill=tk.BOTH, expand=True)
        # 颜色标签: 严重 critical=红 red、警告 warning=橙 orange、搜索 match=黄 yellow
        self.single_output.tag_config("critical", foreground="#d32f2f", background="#ffebee")
        self.single_output.tag_config("warning",  foreground="#e65100", background="#fff3e0")
        self.single_output.tag_config("minor",    foreground="#f9a825", background="#fff9c4")
        self.single_output.tag_config("anom_cur", background="#ffb74d")
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
        # 状态行颜色: 红=高危 / 黄=一般 / 绿=健康 / 灰=FAILED
        self.device_tree.tag_configure("row_high", foreground="#dc2626")
        self.device_tree.tag_configure("row_mid",  foreground="#d97706")
        self.device_tree.tag_configure("row_ok",   foreground="#16a34a")
        self.device_tree.tag_configure("row_fail", foreground="#6b7280")

        # ── 操作按钮行 / action buttons row ──
        bf = ttk.Frame(self.tab_batch); bf.pack(fill=tk.X, padx=10, pady=(0,5))
        self.btn_batch_all = ttk.Button(bf, text="Run", width=16, style="Accent.TButton", command=self._start_batch_selected)
        self.btn_batch_all.pack(side=tk.LEFT, padx=(0, 6))
        self.btn_batch_stop = ttk.Button(bf, text="Stop", style="Danger.TButton", command=self._stop_all, state=tk.DISABLED)
        self.btn_batch_stop.pack(side=tk.LEFT, padx=(0,10))
        ttk.Button(bf, text="IP Intel", command=self._open_ip_intel).pack(side=tk.LEFT)

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
        self.btn_export_html = ttk.Button(bf, text="Export HTML", style="Accent.TButton", command=self._export_html, state=tk.DISABLED)
        self.btn_export_html.pack(side=tk.RIGHT, padx=(5,0))
        self.btn_export_csv  = ttk.Button(bf, text="Export CSV",  style="Accent.TButton", command=self._export_csv,  state=tk.DISABLED)
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
        ttk.Button(srow, text="⚠下一异常", width=11, command=lambda: self._jump_to_next_anomaly(
            self.batch_output, self.batch_search_label)).pack(side=tk.LEFT, padx=(1,5))
        self.batch_search_label = ttk.Label(srow, text="", font=("",8), foreground="gray")
        self.batch_search_label.pack(side=tk.LEFT)

        self.batch_output = scrolledtext.ScrolledText(
            of, wrap=tk.WORD, font=("Consolas",10), state=tk.DISABLED
        )
        self.batch_output.pack(fill=tk.BOTH, expand=True)
        self.batch_output.tag_config("critical", foreground="#d32f2f", background="#ffebee")
        self.batch_output.tag_config("warning",  foreground="#e65100", background="#fff3e0")
        self.batch_output.tag_config("minor",    foreground="#f9a825", background="#fff9c4")
        self.batch_output.tag_config("anom_cur", background="#ffb74d")
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
        self.btn_backup_sel = ttk.Button(bf, text="Backup Selected", style="Accent.TButton", command=self._start_backup)
        self.btn_backup_sel.pack(side=tk.LEFT, padx=(0, 6))
        self.btn_backup_stop = ttk.Button(bf, text="Stop", style="Danger.TButton", command=self._stop_all, state=tk.DISABLED)
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
        devices, error_lines = self._parse_device_file(self.batch_filepath.get())
        for host, devtype, user, pwd, cmds in devices:
            iid = self.device_tree.insert("", tk.END,
                values=(host, devtype.upper(), user, "---", ", ".join(cmds)),
                tags=(f"{host}|{devtype}|{user}|{pwd}|{','.join(cmds)}",))
            self._device_row[host] = iid
        status = f"Loaded {len(devices)} device(s)"
        if error_lines:
            status += f" | {len(error_lines)} parse error(s)"
            detail = "; ".join(f"L{n}:{reason}" for n, _, reason in error_lines[:3])
            if len(error_lines) > 3:
                detail += " …"
            status += f" ({detail})"
        self._set_status(status)

    def _parse_device_file(self, filepath: str) -> tuple:
        """
        解析设备列表文件 / Parse device list file.

        支持格式 / Supported formats:
          带类型: IP:user:password:linux|cisco|huawei:"cmd1,cmd2"
          无类型: IP:user:password:"cmd1,cmd2"                  → 默认 cisco / defaults to cisco

        :return: (设备列表 [(host,devtype,user,pwd,[cmds])], 错误行数 / error count)
        """
        devices, error_lines = [], []
        if not os.path.exists(filepath):
            return devices, error_lines
        try:
            with open(filepath, "r", encoding="utf-8") as f:
                # type 段宽松匹配（任意非冒号文本），再经 normalize_devtype 归一化/校验
                pat_with_type = re.compile(r'^([^:]+):([^:]+):([^:]+):([^:]+):"([^"]*)"$')
                pat_no_type   = re.compile(r'^([^:]+):([^:]+):([^:]+):"([^"]*)"$')
                for lineno, line in enumerate(f, 1):
                    line = line.strip()
                    if not line or line.startswith("#"):  # 跳过空行和注释 / skip blanks & comments
                        continue
                    m = pat_with_type.match(line)
                    if m:
                        host, user, pwd, type_raw, cmds_str = m.groups()
                        devtype = normalize_devtype(type_raw)
                        if devtype is None:
                            error_lines.append((lineno, line,
                                f"未知类型 {type_raw.strip()!r}（可用: linux/cisco/huawei/h3c/ruijie，"
                                "或中文别名 华为/华三/思科/锐捷）"))
                            continue
                    else:
                        m = pat_no_type.match(line)
                        if m:
                            host, user, pwd, cmds_str = m.groups()
                            devtype = "cisco"           # 无类型时默认思科 / default cisco
                        else:
                            error_lines.append((lineno, line,
                                "格式错误（应为 IP:user:pass:type:\"cmd1,cmd2\"）"))
                            continue
                    cmds = [c.strip() for c in cmds_str.split(",") if c.strip()]
                    if cmds:
                        devices.append((host, devtype, user, pwd, cmds))
                    else:
                        error_lines.append((lineno, line, "命令列表为空"))
        except Exception as e:
            messagebox.showerror("Error", f"Cannot open file:\n{e}")
        return devices, error_lines

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
        pwd  = self.single_pwd.get()          # 读取密码字段 / read password (fixed: was missing!)
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
            self._ssh_connect(client, host, port, user, pwd, timeout=10)
        except Exception as e:
            Q.put(("single", "error", f"Connection failed: {self._friendly_conn_error(e)}"))
            Q.put(("single", "done", None)); return

        Q.put(("single","output",
              f"{'='*60}\n  Inspection Report — {host}:{port} [{devtype.upper()}]\n{'='*60}\n"))
        Q.put(("single","status",f"Running on {host}..."))
        all_alerts = []

        if devtype in ("cisco", "huawei", "h3c", "ruijie"):
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
                    # 统计该设备被标红的异常行数 + 收集匹配行明细
                    # count flagged lines per device + collect matched lines (2026-09-01)
                    st = {"critical":0, "major":0, "minor":0, "device":0}
                    lines_by_sev = {"critical": [], "major": [], "minor": [], "device": []}
                    for _t, _o in cmds_output:
                        for _line, _sev in flagged_lines(_t, _o):
                            st[_sev] += 1
                            lines_by_sev[_sev].append(_line)
                    if any(st.values()):
                        st["lines"] = lines_by_sev
                        Q.put(("batch", "stats", (host, st)))
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
            self._ssh_connect(client, host, 22, user, pwd, timeout=10)
        except Exception as e:
            return (host, devtype, "FAILED", [(f"Connection", self._friendly_conn_error(e))], [])

        # 分支执行 / branch by device type
        if devtype in ("cisco", "huawei", "h3c", "ruijie"):
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
                self._ssh_connect(client, host, 22, user, pwd, timeout=10)
            except Exception as e:
                Q.put(("backup", "output", f"  {host} [FAILED] Connection error: {self._friendly_conn_error(e)}\n"))
                completed += 1; Q.put(("backup", "progress", completed)); continue

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
    def _friendly_conn_error(e: Exception) -> str:
        """把连接异常转成可操作的提示 / human-friendly connection error."""
        msg = str(e)
        low = msg.lower()
        if "timed out" in low or "timedout" in low or "timeout" in low:
            return (msg + " — 连接超时：检查 IP/端口是否正确、设备是否可达(ping)、"
                    "SSH 服务是否已启用（H3C 需配置 ssh server enable）")
        if "refused" in low:
            return (msg + " — 连接被拒绝：SSH 端口未开放（H3C 默认未开 SSH 需手动启用；"
                    "若只开 telnet 可把端口改成 23）")
        if "algorithm" in low or "compatible" in low or "agreement" in low:
            return msg + " — 加密算法不兼容（已自动重试老算法 ssh-rsa）"
        return msg

    def _ssh_connect(self, client, host, port, user, pwd, timeout=10):
        """SSH 连接，老设备算法兼容重试 / connect with legacy-algo retry.

        H3C Comware V5 / 华为 VRP5 等老设备 host key 只有 ssh-rsa（SHA-1），
        paramiko 3.x 默认只提议 rsa-sha2-* 会协商失败；第一次失败若为算法
        协商问题，禁用 rsa-sha2 回退 ssh-rsa 重试一次。
        """
        def _connect(disabled=None):
            kwargs = dict(hostname=host, port=port, username=user, password=pwd,
                          timeout=timeout, look_for_keys=False, allow_agent=False,
                          banner_timeout=timeout, auth_timeout=timeout)
            if disabled:
                kwargs["disabled_algorithms"] = disabled
            client.connect(**kwargs)
        try:
            _connect()
        except Exception as e1:
            low = str(e1).lower()
            if "algorithm" in low or "compatible" in low or "agreement" in low:
                try:
                    client.close()
                except Exception:
                    pass
                _connect({"pubkeys": ["rsa-sha2-256", "rsa-sha2-512"]})
                return
            raise

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
                    self._append_output_auto(out, data)

                elif msg_type == "section":
                    pass  # 预留 / reserved

                elif msg_type == "status":
                    self._set_status(data)

                elif msg_type == "device_status":
                    # 更新批量巡检树视图 Status 列（带红黄绿状态色）
                    dev_host, dev_status = data
                    if dev_status in ("FAILED", "ERROR", "UNREACHABLE"):
                        self._set_device_status(dev_host, "FAILED", "row_fail")
                    elif dev_status == "Running...":
                        self._set_device_status(dev_host, "Running...")
                    else:
                        level = self._host_anom_level.get(dev_host)
                        if level == "high":
                            self._set_device_status(dev_host, "CRITICAL", "row_high")
                        elif level == "mid":
                            self._set_device_status(dev_host, "WARNING", "row_mid")
                        elif dev_status == "OK":
                            self._set_device_status(dev_host, "OK", "row_ok")
                        elif dev_status == "WARNING":
                            self._set_device_status(dev_host, "WARNING", "row_mid")
                        else:
                            self._set_device_status(dev_host, dev_status, "row_ok")

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
                        self._append_output_auto(out, f"\n--- [{title}] ---\n{output_text}\n")

                elif msg_type == "summary":
                    self._append_output(out, data, "warning")

                elif msg_type == "stats":
                    # 每设备异常行数统计 / per-device flagged-line stats
                    host, st = data
                    if not hasattr(self, "_batch_stats"):
                        self._batch_stats = {}
                    self._batch_stats[host] = st
                    # 同步设备列表状态色：红=CRITICAL / 黄=WARNING
                    if st["critical"] or st["device"]:
                        self._host_anom_level[host] = "high"
                        self._set_device_status(host, "CRITICAL", "row_high")
                    elif st["major"] or st["minor"]:
                        self._host_anom_level[host] = "mid"
                        self._set_device_status(host, "WARNING", "row_mid")

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
                    # 按设备异常统计摘要（无异常的设备不显示）/ per-device anomaly summary
                    if target == "batch":
                        stats = getattr(self, "_batch_stats", None)
                        if stats:
                            self._append_output(out, "\n" + "="*60 +
                                "\n  ⚠ 按设备异常统计 / Per-device anomaly stats\n" + "="*60 + "\n", "warning")
                            sev_tag = {"critical": "critical", "major": "warning",
                                       "minor": "minor", "device": "critical"}
                            sorted_hosts = sorted(stats.items())
                            for i, (host, st) in enumerate(sorted_hosts):
                                parts = []
                                if st["critical"]: parts.append(f"Critical={st['critical']}")
                                if st["major"]:    parts.append(f"Major={st['major']}")
                                if st["minor"]:    parts.append(f"Minor/Warning={st['minor']}")
                                if st["device"]:   parts.append(f"Device异常={st['device']}")
                                tag = "critical" if (st["critical"] or st["device"]) else "warning"
                                self._append_output(out, f"  {host}: {', '.join(parts)}\n", tag)
                                # 匹配行明细（红/黄）/ flagged-line details (2026-09-01)
                                lines_by_sev = st.get("lines") or {}
                                total_lines = sum(len(lines_by_sev.get(s, [])) for s in lines_by_sev)
                                shown = 0
                                for sev in ("critical", "device", "major", "minor"):
                                    for line in lines_by_sev.get(sev, [])[:10]:
                                        self._append_output(out, f"      {line}\n", sev_tag[sev])
                                        shown += 1
                                hidden = total_lines - shown
                                if hidden > 0:
                                    self._append_output(out,
                                        f"      ... 还有 {hidden} 条未显示\n", "minor")
                                # 设备与设备之间用 ========== 分割 / separator between devices
                                if i < len(sorted_hosts) - 1:
                                    self._append_output(out, "  " + "="*10 + "\n")
                            self._batch_stats = {}
                            self._host_anom_level.clear()
                    self._append_output(out, f"\n{'='*60}\n  Complete.\n{'='*60}\n", "success")

        except queue.Empty:
            pass
        self.root.after(100, self._poll_queue)   # 100ms 后再查 / re-check in 100ms

    # ═══════════════════════════════════════════════════════════
    # 辅助方法 / Utility Methods
    # ═══════════════════════════════════════════════════════════

    def _set_device_status(self, host, text, tag=None) -> None:
        """更新设备树 Status 列文本并设置行颜色 / Update tree Status cell + row tag."""
        iid = self._device_row.get(host)
        if not iid or not self.device_tree.exists(iid):
            return
        vals = list(self.device_tree.item(iid, "values"))
        if len(vals) >= 4:
            vals[3] = text
            self.device_tree.item(iid, values=vals)
        # 替换行标签：先去掉旧的状态色，再加新的 / swap status tags on the row
        cur = list(self.device_tree.item(iid, "tags") or ())
        cur = [t for t in cur if t not in ("row_high", "row_mid", "row_ok", "row_fail")]
        if tag:
            cur.append(tag)
        self.device_tree.item(iid, tags=tuple(cur))

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

    def _append_output_auto(self, widget, text, tag=None):
        """
        自动识别命令输出中的告警关键字并按行高亮（批量模式为主）。

        Auto-highlight severity keywords per line, driven by the command
        title in the section header (e.g. "--- [Alarm Active] ---"):
          - Alarm / Logbuffer 输出:  Critical=红 critical, Major=橙 warning,
            Minor/Warning=黄 minor（无视大小写 / case-insensitive）
          - Device 输出:           Unregistered / NotSupply / Abnormal=红 critical
            （无视大小写 / case-insensitive）
        命中时在区块末尾附加一行告警统计摘要 / appends a summary line on hits.
        日志类输出（logbuffer / auth / access 等）自动叠加攻击检测 /
        log-like blocks also get attack-pattern scan (SQLi/brute/scan...).
        """
        widget.config(state=tk.NORMAL)
        title = None
        crit = major = minor = dev_bad = 0
        # 攻击预扫描 / pre-scan attack patterns on log-like blocks
        tm = re.search(r"[\[【]([^\]】]*)[\]】]", text)
        atk = (attack_scan(text) if _looks_like_log(text, tm.group(1) if tm else None)
               else {"line_hits": [], "agg_alerts": [], "counts": {}})
        atk_by_line = {h["line_idx"]: h for h in atk["line_hits"]}
        atk_high = atk_warn = 0
        for idx, line in enumerate(text.splitlines(keepends=True)):
            m = re.search(r"[\[【]([^\]】]*)[\]】]", line.strip())
            if m:
                title = m.group(1).lower()
            line_tag = None
            c, mj, mi, d = count_flagged_lines(title, line)
            if c:
                line_tag, crit = "critical", crit + c
            elif mj:
                line_tag, major = "warning", major + mj
            elif mi:
                line_tag, minor = "minor", minor + mi
            elif d:
                line_tag, dev_bad = "critical", dev_bad + d
            # 攻击命中覆盖颜色（攻击 > 关键字）/ attack hit overrides keyword color
            # info 级别（如 SSH 登录成功）仅提示不标色，避免正常登录刷屏
            a = atk_by_line.get(idx)
            if a and a["severity"] in ("critical", "high"):
                line_tag, atk_high = "critical", atk_high + 1
            elif a and a["severity"] in ("medium", "low"):
                line_tag, atk_warn = "warning", atk_warn + 1
            widget.insert(tk.END, line, line_tag or tag)
        if crit or major or minor:
            parts = []
            if crit:  parts.append(f"{crit} Critical")
            if major: parts.append(f"{major} Major")
            if minor: parts.append(f"{minor} Minor/Warning")
            widget.insert(tk.END,
                f"\n  ⚠ Alarm summary: {', '.join(parts)}\n",
                "critical" if crit else ("warning" if major else "minor"))
        elif dev_bad:
            widget.insert(tk.END,
                f"\n  ⚠ Device status: {dev_bad} flagged line(s)\n", "critical")
        if atk_high or atk_warn or atk["agg_alerts"]:
            parts = []
            if atk_high: parts.append(f"{atk_high} 高危攻击")
            if atk_warn: parts.append(f"{atk_warn} 可疑")
            for al in atk["agg_alerts"][:5]:
                icon = "🔴" if al["severity"] in ("critical", "high") else "🟡"
                parts.append(f"{icon}{al['attack']}×{al['count']}({al['ip']})")
            widget.insert(tk.END,
                f"\n  🛡 攻击检测: {', '.join(parts)}\n",
                "critical" if atk_high else "warning")
        widget.see(tk.END)
        widget.config(state=tk.DISABLED)

    def _open_ip_intel(self, initial_ip: str = "") -> None:
        """IP 被动情报查询弹窗 / IP passive-intel dialog (ip-api, no Key)."""
        win = tk.Toplevel(self.root)
        win.title("IP Intel — 被动情报查询")
        win.geometry("480x380")
        win.transient(self.root)
        win.grab_set()
        row = ttk.Frame(win, padding=10)
        row.pack(fill=tk.X)
        ttk.Label(row, text="IP:").pack(side=tk.LEFT)
        entry = ttk.Entry(row, width=22)
        entry.pack(side=tk.LEFT, padx=5)
        entry.insert(0, initial_ip or "")
        btn = ttk.Button(row, text="查询", style="Accent.TButton", command=lambda: do_query())
        btn.pack(side=tk.LEFT, padx=(5, 0))
        status = ttk.Label(win, text="查询 ip-api.com（免费，无需 Key）", foreground="#5b7a68")
        status.pack(anchor=tk.W, padx=10)
        result = scrolledtext.ScrolledText(win, height=14, font=("Consolas", 10), state=tk.DISABLED)
        result.pack(fill=tk.BOTH, expand=True, padx=10, pady=(4, 10))

        def do_query(_ev=None):
            ip = entry.get().strip()
            if not ip:
                return
            btn.config(state=tk.DISABLED)
            result.config(state=tk.NORMAL)
            result.delete("1.0", tk.END)
            result.insert(tk.END, "查询中...\n")
            result.config(state=tk.DISABLED)
            status.config(text=f"查询 {ip} ...")

            def _worker():
                data = ip_intel_lookup(ip)
                self.root.after(0, lambda: _show(data))

            threading.Thread(target=_worker, daemon=True).start()

        def _show(data):
            result.config(state=tk.NORMAL)
            result.delete("1.0", tk.END)
            result.insert(tk.END, format_ip_intel(data))
            result.config(state=tk.DISABLED)
            btn.config(state=tk.NORMAL)
            status.config(text="完成 ✓" if "error" not in data else "查询失败")

        entry.bind("<Return>", do_query)
        entry.focus_set()

    def _jump_to_next_anomaly(self, widget, label) -> None:
        """
        跳到下一个红色异常行，并临时橙色高亮它；已到最后一个时循环回第一个。

        Jump to the next red-flagged line; wraps back to the first one after
        the last. Keeps per-widget state (last jumped position) so repeated
        clicks always advance, independent of manual scrolling.
        """
        widget.tag_remove("anom_cur", "1.0", tk.END)
        ranges = list(widget.tag_ranges("critical"))
        if not ranges:
            label.config(text="无异常")
            return
        state = getattr(self, "_anom_state", None)
        if state is None:
            self._anom_state = {}
            state = self._anom_state
        key = id(widget)
        last = state.get(key)                # 上次跳到的位置 / last jumped start
        nxt = None
        if last is not None:
            for i in range(0, len(ranges), 2):
                start = ranges[i]
                if widget.compare(start, ">", last):
                    nxt = start
                    break
        if nxt is None:                      # 无记录或已到末尾 → 循环回第一个
            nxt = ranges[0]
        widget.see(nxt)
        widget.tag_add("anom_cur", nxt, widget.index(f"{nxt} lineend"))
        state[key] = nxt
        line_no = int(str(nxt).split(".")[0])
        label.config(text=f"⚠ 第 {line_no} 行")

    def _clear_output(self, widget):
        """清空 ScrolledText 内容 / Clear all text in output area."""
        state = getattr(self, "_anom_state", None)
        if state:
            state.pop(id(widget), None)      # 清空时重置跳转状态 / reset jump state
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

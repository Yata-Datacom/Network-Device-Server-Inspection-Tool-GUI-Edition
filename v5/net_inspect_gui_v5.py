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
  10. 环路告警     Ring Alert     — 环路特征 + 硬件健康告警（12 条判据，两轮差分 / 离线报告）

依赖 Dependencies:
  pip install paramiko
  可选 Optional: pip install openpyxl  (Excel 导出 / Excel export)

运行 Run: 双击"启动巡检工具.bat" 或 python net_inspect_gui_v5.py
"""

import tkinter as tk
from tkinter import ttk, scrolledtext, messagebox, filedialog
import threading
import queue
import os
import sys
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

__version__ = "5.1.2"

# ── 环路告警页签（可选模块：缺了工具照常跑）─────────────────────
try:
    from ring_panel import RingAlertPanel
except Exception:                      # noqa: BLE001
    RingAlertPanel = None


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

# 脚本所在目录：打包成 exe 后用 **exe 所在目录**，源码运行时用 .py 所在目录。
# 这一点很关键——PyInstaller 单文件模式下 __file__ 指向临时解包目录（_MEIxxxx），
# 曾导致 profiles/presets/backups/reports 全部落在 Temp，用户找不到、重启即被清理。
# Script dir: the exe's folder when frozen, else the .py's folder.
if getattr(sys, "frozen", False):
    SCRIPT_DIR = os.path.dirname(os.path.abspath(sys.executable))
else:
    SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))
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
    """设备类型别名归一化：把用户的各种写法统一成内部 key。

    输入如 "Linux Server"、"华为"、"IOS"、"h3c " 等（大小写不敏感，
    支持中文名与常见缩写），统一映射到内部 key：linux/cisco/huawei/h3c/ruijie。
    底层是查 TYPE_ALIASES 字典：先 strip() 去首尾空白，再 lower() 转小写。

    :param raw: 原始设备类型字符串；可为 None 或空串（此时安全返回 None，不报错）
    :return: 规范化后的设备类型 key（str）；别名表里查不到时返回 None，调用方需自行兜底
    :易错点: 别名表键必须全部小写，否则永远匹配不上；"服务器"/"lin" 等宽松别名
             也会命中 linux，归类时注意别误归并。
    """
    return TYPE_ALIASES.get((raw or "").strip().lower())


# ─────────────────────────────────────────────────────────────
# 【数据区说明】下方约 106~444 行是按"设备类型"组织的一组只读规则字典，
# 巡检业务代码只读它们、不改写，因此"调命令 / 调阈值 / 加设备类型"都改这里即可：
#   1. DISABLE_PAGING   —— 进入设备交互模式前要执行的"关分页"命令
#                          （Linux 为 None 表示不需要；华为/H3C/思科/锐捷各不相同）
#   2. DEFAULT_COMMANDS —— 完整巡检命令集：{设备类型: {命令标题: Shell 命令}}
#   3. BACKUP_COMMANDS  —— 配置备份命令（Linux 不备份，值为 None）
#   4. QUICK_COMMANDS   —— 简短巡检命令集：只取 cpu/mem/alarm/device/stack 等核心项
#   5. ANOMALY_RULES    —— 异常检测规则表：正则提取数值 + 阈值比较（compare 支持 > 和 <）
#   6. OUTPUT_FILTERS   —— 紧凑输出过滤规则：每个命令标题对应一组"保留行"正则，
#                          None 表示该标题输出全保留；未列出的标题同样全保留
# 学习建议：字典的键统一用设备类型内部 key（linux/cisco/huawei/h3c/ruijie），
# 新增一种设备类型时必须六个字典都补一份，漏一处对应功能就会失效。
# ─────────────────────────────────────────────────────────────
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
    在命令输出中检测异常指标（按设备类型查 ANOMALY_RULES 规则表）。

    核心流程：按 devtype 取出对应规则集；对每条规则用其 pattern 在输出里
    re.findall 提取候选数值（忽略大小写）；转 float 成功后按规则 compare
    方向与 threshold 比较，超阈值即生成一条告警。规则表把华为/思科等厂商
    输出格式差异都收敛在同一套检测流程里。

    :param devtype:       设备类型内部 key（linux/cisco/huawei/h3c/ruijie），
                          决定用哪套规则；未知类型按"无规则"处理，不误报
    :param command_title: 命令标题，仅作为告警来源标识写入 source 字段
    :param output:        命令执行返回的 stdout 原始文本
    :return: 告警字典列表，每个元素含
             metric/value/threshold/unit/desc/severity/source 七个字段；
             全部未超阈值时返回空列表 []
    :易错点: 规则 pattern 必须含捕获组 ()，否则 findall 返回的是整段匹配文本，
             float() 转不了会走 ValueError 分支被跳过；compare 只识别 ">" 与 "<"，
             其它取值会落入 "<" 分支，写规则时注意方向别写反。
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
    统计命令输出中被标红的告警/异常行数（关键词匹配，无视大小写）。

    按命令标题内容分流，分到哪套就只统计哪套关键词：
      - 标题含 alarm 或 logbuffer：逐行数 Critical / Major / Minor+Warning；
      - 标题含 device：统计 Unregistered / NotSupply / Abnormal（设备不在位/供电异常）；
      - 其它标题：三套都不统计，恒返回 (0, 0, 0, 0)。
    与 flagged_lines() 共用同一套关键词与大小写规则，这里只计数不返回行文本。

    :param command_title: 命令标题，决定按哪套关键词统计
    :param output:        命令输出文本，内部按行 splitlines() 逐行判断
    :return: (crit, major, minor, dev_bad) 四元组，分别对应
             Critical / Major / Minor·Warning / 设备异常 四类行数
    :易错点: 关键词用 \\b 单词边界 + re.I 忽略大小写，防止误匹配长词内部；
             每行命中一个级别后即短路（if / elif），不会重复累计。
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
    """返回被标红/标黄的异常行明细（行文本 + 级别），供批量汇总页直接展示。

    与 count_flagged_lines() 用同一套分流与关键词规则，但本函数返回具体命中行：
      - alarm/logbuffer 标题 → (行文本, critical/major/minor)
      - device 标题          → (行文本, "device")
    空行先被过滤，行文本为去首尾空白后的原行。

    :param command_title: 命令标题，决定关键字匹配方向
    :param output:        命令输出文本，按行逐行匹配
    :return: [(line, sev), ...] 列表；sev ∈ {critical, major, minor, device}；
             无命中时返回空列表 []
    :易错点: 每行只记录一个级别（命中 Critical 即 else-if 短路，不叠加记录）；
             本函数为 2026-09-01 新增，专供批量汇总展示"匹配行"，与计数版保持同步规则。
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
    """粗判文本是否像"日志"，避免把普通配置输出当攻击日志去扫描（误报源头之一）。

    判定依据（满足任一即判为日志）：
      1) 命令标题含 logbuffer / log / auth / secure / access / journal / syslog 等词；
      2) 正文前 3000 字符出现 syslog 时间头（如 Aug 31 10:00:00）；
      3) 出现 web 访问日志时间戳（[24/Aug/2026: 形如）；
      4) 出现 sshd[进程号] 行首标记；
      5) 出现华为 %SEC/ 安全日志格式。

    :param text:  待判断的命令输出文本
    :param title: 命令标题，可省略；命中关键词直接判 True
    :return: True=像日志，False=不像
    :易错点: 只采样前 3000 字符做正则，兼顾效率；本函数由 attack_scan() 作前置门控，
             防止对 show running-config 这类大段配置输出做无意义甚至误报的攻击扫描。
    """
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
    """粗判单条日志行属于哪一类（web / ssh / other），供攻击规则门控使用。

    由 attack_scan() 逐行调用：先看是否含 GET/POST/PUT 等 HTTP 方法词 → "web"；
    再看是否含 sshd/failed/login/password/authenticat/user 等词 → "ssh"；
    否则 → "other"。只有与攻击规则 target 匹配的行才套用该规则，
    避免"failed"出现在 web 日志里却触发 SSH 规则之类的交叉误报。

    :param line: 日志单行文本
    :return: 行类型字符串，取值 "web" / "ssh" / "other"
    :易错点: 依赖模块级预编译正则 _WEB_METHOD_RE / _SSH_HINT_RE（search 不区分大小写）；
             判断顺序固定为 web 优先、ssh 次之；英文词根 authentica 开头的
             派生词（authenticating 等）也能命中。
    """
    if _WEB_METHOD_RE.search(line):
        return "web"
    if _SSH_HINT_RE.search(line):
        return "ssh"
    return "other"


def attack_scan(text: str) -> dict:
    """在日志文本中扫描攻击特征（纯本地正则、不联网），返回三类汇总结果。

    处理流程分三步：
      ① 逐行匹配模块级 _ATTACK_RULES 规则库：先跳过空行与区段分隔线（如
         --- [Device] ---），再从行里提取 IP，按规则 target 与行类型门控后
         匹配；每行只记第一条命中（命中即 break）。
      ② 把逐行命中按 "IP × 规则" 聚合计数：SSH 认证失败(R008)≥8 次判
         SSH 暴力破解，设备安全事件(R010)≥3 次判高危事件。
      ③ 扫 HTTP 状态码：某 IP 的 401/403 合计≥15 判撞库，404≥30 判目录扫描。
    适用数据：巡检 logbuffer / auth 等日志的命令输出。

    :param text: 日志全文（多行文本，可为空）
    :return: dict，含三个键：
             line_hits  — [{line_idx, rule, attack, severity, ip, line}] 逐行命中明细
             agg_alerts — [{attack, severity, ip, count}] 聚合后的行为级告警
             counts     — {severity: 次数} 按严重级别统计的命中数
    :易错点: 行内嵌 IP 用正则提取，找不到时 ip 记 None 且不参与 IP 聚合；
             规则表顺序即优先级（每行只保留第一条命中）；web 状态码聚合
             只看 401/403/404 三类数值，与是否命中规则无关。
    """
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
    """查询 IP 的地理/运营商归属等被动情报（ip-api.com 免费接口，无 Key、纯标准库）。

    先做本地前置校验（不发网络请求）：IP 为空、格式非法、或属于内网/环回/
    链路本地/组播/保留地址时，直接返回含 error 的中文说明。只有公网地址才
    请求 http://ip-api.com/json/<ip> 并限定返回字段，10 秒超时；
    接口返回 status != success 或请求异常时同样返回 {"error": ...}。

    :param ip: 待查询的 IP 字符串
    :return: dict。查询成功（status=success）时含 country/regionName/city/isp/org/
             as/asname/lat/lon/proxy/hosting/mobile/query 等字段；
             任何失败情形统一返回 {"error": <中文错误说明>}
    :易错点: 接口走 HTTP 明文（免费额度无 HTTPS），内网环境可能被策略拦；
             函数内部阻塞式发 HTTP 请求（最长 10s），调用时应放在线程中执行；
             展示层建议配合 format_ip_intel() 使用。
    """
    import ipaddress as _ipa
    import json as _json
    import urllib.request as _ur
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
    """把 ip_intel_lookup() 返回的 dict 排版成便于阅读/展示的多行文本。

    :param data: ip_intel_lookup() 的返回值（dict）
    :return: 格式化后的字符串；若 data 含 "error" 键则直接返回 "❌ <错误信息>"，
             否则返回多行文本：IP、国家/地区/城市、ISP、Org、ASN、经纬度、
             特征标签（代理 🕶 / 云主机 ☁ / 移动网 📱，都没有则显示"普通"）
    :易错点: 字段缺失时用 data.get(k, '-') 兜底显示 '-'，避免 KeyError；
             特征标签由 proxy/hosting/mobile 三个布尔字段拼出，互不互斥可叠加。
    """
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
    """把批量巡检结果渲染成自包含的单文件 HTML 报告（CSS 内联，无外部依赖）。

    页面分两块：① 汇总表 Summary——每台设备一行，含设备/类型徽标/状态
    （OK 绿色、FAILED 红色）/异常数徽标；② 明细区 Detailed——按设备分块，
    有告警时先用橙色高亮框列出 metric/value/threshold/desc，再逐命令输出
    <pre> 代码块。命令输出在拼入 HTML 前会转义 & < >，防止破坏页面结构。

    :param results: 巡检结果列表，元素为 5 元组
                    (host, devtype, status, cmds_output, alerts_list)；
                    cmds_output 是 [(命令标题, 输出文本), ...] 列表
    :param filepath: 输出 HTML 文件的保存路径
    :return: 写入成功的 filepath（与入参相同），方便调用链直接链式使用
    :易错点: f-string 模板里 CSS 的花括号要写成 {{ }} 双重转义；
             只转义 & < > 三种字符（输出文本中出现引号不影响 HTML 结构安全）；
             文件以 encoding="utf-8" 写盘，页面已声明 <meta charset="utf-8">。
    """
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
    """生成 CSV 格式巡检报告（UTF-8 带 BOM，Excel 双击打开不乱码）。

    表头固定为 Device/Type/Status/Anomalies/Command/Output；每台设备的
    每条命令输出各占一行，Anomalies 列把该设备全部告警拼成
    "metric=value unit; metric=value unit" 的长文本。

    :param results: 巡检结果列表，结构与 generate_html_report() 相同
                    （元素为 host/devtype/status/cmds_output/alerts_list 五元组）
    :param filepath: 输出 CSV 文件的保存路径
    :return: 写入成功的 filepath（与入参相同）
    :易错点: 必须用 encoding="utf-8-sig"（BOM），否则 Excel 打开中文会乱码；
             newline="" 可避免 Windows 平台 csv 模块写出多余空行；
             命令输出里若含换行，会被 csv 自动加引号包裹，属正常转义。
    """
    with open(filepath, "w", encoding="utf-8-sig", newline="") as f:
        writer = csv.writer(f)
        writer.writerow(["Device", "Type", "Status", "Anomalies", "Command", "Output"])
        for host, devtype, status, cmds_output, alerts_list in results:
            anomaly_text = "; ".join(f'{a["metric"]}={a["value"]}{a["unit"]}' for a in alerts_list)
            for title, output in cmds_output:
                writer.writerow([host, devtype, status, anomaly_text, title, output])
    return filepath


def generate_excel_report(results: list, filepath: str) -> str:
    """生成带基础格式的 Excel 巡检报告（.xlsx，依赖可选库 openpyxl）。

    工作簿含两张工作表：Summary 放设备汇总（表头蓝底白字加粗；有告警的设备
    该行整行浅橙高亮）；Details 逐命令一行（Device/Command/Output）。最后按
    列内容长度设置 A~D 列宽后保存。openpyxl 未安装时抛 ImportError 并提示
    安装命令，供上层 try/except 后回退到 CSV/HTML 导出。

    :param results: 巡检结果列表，结构与 generate_html_report() 相同
    :param filepath: 输出 .xlsx 文件的保存路径
    :return: 写入成功的 filepath（与入参相同）
    :易错点: openpyxl 是可选依赖，函数体内部才 import（模块顶层不 import，
             避免没装 openpyxl 时整个程序起不来）；
             行号用 ws.max_row + 1 现算后回填高亮，紧跟 ws.append 之后取值。
    """
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
    为整个应用套用「现代清爽蓝」ttk 主题（零第三方依赖，基于 tkinter 内置 clam）。

    做法：先定义局部色板/字体常量（背景 #f3f5f9、主色蓝 #2563eb、危险红
    #dc2626 等）→ 尝试把主题切到 "clam"（失败则忽略，继续用默认主题）→
    给 root 设置背景色 → 再逐类配置 ttk 控件样式：全局默认 "."、Frame、
    Label、Labelframe、按钮、输入框、复选框、Notebook 标签页、Treeview、
    进度条与滚动条的颜色/字体/内边距及各状态映射（active/pressed/selected
    /disabled）。另外注册三套特色按钮：Accent.TButton（主操作蓝）、
    Danger.TButton（停止/删除红）、GreenAccent.TButton（流量测试绿色强调）。

    :param root: 应用根窗口（tk.Tk 实例）；函数会修改其背景色 bg
    :return: None（所有效果通过 ttk.Style 单例与 root 直接生效，无返回值）
    :易错点: 必须在创建任何 ttk 控件之前调用一次，样式才会全局生效；
             style.configure(".", ...) 配置的是"所有未单独定制类"的默认外观，
             具体类（如 TButton）配置会覆盖全局默认；
             色板常量是函数局部变量，仅供本函数下方配置语句引用。
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
    """探测本机默认网关列表（供流量测试页自动填充"目标网关"）。

    通过 PowerShell 查询 IPv4 默认路由（DestinationPrefix 0.0.0.0/0）的
    NextHop（网关 IP）与 InterfaceAlias（接口别名），格式化成
    "IP|接口别名" 一行一条；逐行解析并在解析中按网关 IP 去重（同网关只
    保留第一条，通常对应多网卡场景）。Windows 下执行时带
    CREATE_NO_WINDOW 标志，避免弹出黑色控制台窗口。

    :return: [(显示文本, 网关IP), ...] 列表，显示文本形如 "192.168.1.1  (WLAN)"；
             无默认路由、命令超时或系统无 powershell 时返回空列表 []
    :易错点: 依赖 Windows + powershell 环境，非 Windows 会抛 FileNotFoundError
             被捕获后返回 []；每行要求恰好含一个 '|' 分隔符，格式不对的行直接跳过。
    """
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
    """把用户输入的端口字符串解析成端口号列表 + 人类可读描述。

    支持 4 种写法（判定顺序即下方顺序，先命中先返回）：
      1. 区间随机抽样  "100-1000:50"  —— 在 [100,1000] 内随机取 50 个不重复端口
         （抽样数会自动收敛到区间宽度内），描述 "50 ports from 100-1000"；
      2. 区间展开      "100-1000"      —— 展开为 100~1000 全部整数端口；
      3. 逗号列表      "80,443,8080"   —— 逐个解析并去重排序；
      4. 单个端口      "8080"          —— 最简单的写法。
    任何解析失败或越界（端口 <1 / >65535 / lo>hi）都返回空列表 + 以
    "invalid" 开头的错误描述；空输入返回 ([], "empty")。

    :param port_str: 用户输入的端口字符串（首尾空白会被 strip，可为空串）
    :return: (ports, desc) 二元组：
             ports —— 解析出的端口号列表（整数），非法输入时为空列表 []
             desc  —— 描述文本，如 "range 100-1000 (901 ports)"；出错时
                      为 "invalid..." 错误信息
    :易错点: 区间随机抽样用 rsplit(':', 1) 从最右侧切开分号，先检查
             lo/hi/cnt 是否为整数再判范围；random.sample 要求 cnt ≤ 区间宽度，
             故先 min(cnt, hi-lo+1) 收敛；逗号列表最终 sorted(set(...)) 去重排序，
             保证结果顺序稳定、无重复端口。
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
    """线程安全的收发统计器（@dataclass）。

    维护两组数据：
    - 累计值 total_packets / total_bytes：自启动以来的总包数与总字节数；
    - 瞬时速率 current_pps / current_bps：由 tick() 按固定时间窗计算，
      snapshot() 供 UI 轮询读取，add() 由各收发线程写入。

    内部所有读写都经过 self.lock 互斥，多线程并发调用无需再加锁。
    该统计器被 TCPServer（接收侧）与 TrafficGenerator（发送侧）共用。
    """

    total_packets: int = 0
    total_bytes: int = 0
    prev_packets: int = 0
    prev_bytes: int = 0
    current_pps: float = 0.0
    current_bps: float = 0.0
    lock: threading.Lock = field(default_factory=threading.Lock)

    def add(self, packet_size: int, count: int = 1):
        """记录一次收/发包：累加包数与字节数（线程安全）。

        :param packet_size: 单个数据包负载大小（字节），累计时按 count 倍计入 total_bytes；
        :param count: 本次实际计入的包个数（默认 1）。TCP-SYN 模式下一次批量发起
                      多个半开连接时用 count 一次性入账，减少锁竞争。
        :return: 无
        """
        with self.lock:
            self.total_packets += count
            self.total_bytes += count * packet_size

    def snapshot(self) -> tuple:
        """原子读取当前统计快照，供界面定时刷新显示。

        :return: (pps, bps, total_packets, total_bytes) 四元组：
                 pps/bps 是上一轮 tick() 计算出的瞬时速率，packets/bytes 为实时累计值；
                 四个值都在锁内读取，保证互不串位。
        """
        with self.lock:
            now_packets = self.total_packets
            now_bytes = self.total_bytes
            pps = self.current_pps
            bps = self.current_bps
        return pps, bps, now_packets, now_bytes

    def tick(self, interval: float):
        """按固定时间窗计算实时速率，由定时器每个 interval 秒调用一次。

        算法：本窗口增量 = 当前累计值 - 上次累计值(prev_packets/prev_bytes)，
        再除以窗口时长即得该窗口的平均 pps/bps，随后把 prev_* 推进到当前值。
        首轮窗口内增量很小，速率会从低值逐步爬升到真实水平。

        :param interval: 窗口时长（秒）。<=0 时分母非法，速率直接置 0 防除零。
        :return: 无（结果写入 self.current_pps / self.current_bps）
        """
        with self.lock:
            dp = self.total_packets - self.prev_packets
            db = self.total_bytes - self.prev_bytes
            self.current_pps = dp / interval if interval > 0 else 0.0
            self.current_bps = db / interval if interval > 0 else 0.0
            self.prev_packets = self.total_packets
            self.prev_bytes = self.total_bytes


class TCPServer:
    """简易多线程 TCP 接收服务器（压测回环的“接收侧”）。

    在 0.0.0.0:port 上 listen，每个接入的客户端连接开一个独立守护线程
    持续 recv 并仅做字节统计（不解析业务数据），用于配合 TrafficGenerator
    验证对端收包能力/连通性。listen socket 与各客户端 socket 均设置了超时，
    保证 stop() 后各线程能及时醒来退出。SO_REUSEADDR 让端口可快速重启复用。
    """

    def __init__(self, port: int, log_callback=None):
        """初始化 TCP 服务器对象（此时尚未监听，需再调用 start()）。

        :param port: 监听端口号；
        :param log_callback: 日志回调函数 log(msg: str)，缺省为静默丢弃。
        :return: 无
        主要成员：stats(Stats 统计器)、server_sock(监听 socket)、
        server_thread(接收线程)、client_threads(存活客户端线程列表)。
        """
        self.port = port
        self.log = log_callback or (lambda msg: None)
        self.stats = Stats()
        self.running = False
        self.server_sock: socket.socket | None = None
        self.server_thread: threading.Thread | None = None
        self.client_threads: List[threading.Thread] = []

    def start(self):
        """创建监听 socket 并启动接收线程。

        流程：建 TCP socket → SO_REUSEADDR → 0.5s 超时 → bind 0.0.0.0:port
        → listen(100) → 启动 _accept_loop 守护线程。
        socket 超时设 0.5s 是为了让接收循环周期性醒来检查 self.running，
        从而能被 stop() 及时终止。若 bind 失败（如端口被占）会记日志并
        回退 running=False，不抛异常。

        :return: 无
        """
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
        """停止服务器：置 running=False 并关闭监听 socket。

        关闭监听 socket 会使阻塞在 accept() 的接收线程抛 OSError 从而退出；
        随后对每个客户端线程最多 join 1 秒（其 1s recv 超时内也会自行退出），
        最后清空线程列表并打印接收侧汇总（总包数/总字节数，字节数经 _fmt 格式化）。

        :return: 无
        """
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
        """接收循环（运行在 server_thread 中）：循环 accept 接入的连接。

        监听 socket 带 0.5s 超时：accept 抛超时/OSError 时若 running 已为
        False 即退出循环，否则继续等待——这是 stop() 能中断阻塞 accept 的关键。
        每个客户端连接开一个 _recv_worker 守护线程处理并登记到 client_threads；
        列表定期滤除已结束的线程，避免长期运行后线程对象堆积。

        :return: 无
        """
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
        """单个客户端连接的接收处理线程：只管收数据并统计字节数。

        :param sock: 已 accept 的客户端 socket（本线程负责其生命周期，退出前关闭）；
        :param addr: 客户端地址 (ip, port)，仅作标识用途。
        :return: 无
        逻辑细节：
        - socket 设 1s 超时；recv(65536) 超时则 continue，顺带让循环有机会
          检查 self.running 以便及时退出；
        - 收到空字节(b'')表示对端正常关闭(FIN)，break 结束；
          OSError 表示连接异常断开，break 结束；
        - 每次成功收包按 len(data) 计入 stats.add()——统计的是应用层净荷字节，
          不含 TCP/IP 头部；
        - 无论以何种方式退出，finally 都确保关闭 socket，防句柄泄漏。
        """
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
        """把字节数格式化为人类可读字符串（1024 进位）。

        :param b: 字节数（非负整数）；
        :return: 示例 "512 B"、"1.5 KB"、"3.2 MB"、"1.00 GB"，供日志/界面展示。
        """
        if b < 1024:
            return f"{b} B"
        elif b < 1024 ** 2:
            return f"{b / 1024:.1f} KB"
        elif b < 1024 ** 3:
            return f"{b / 1024 ** 2:.1f} MB"
        else:
            return f"{b / 1024 ** 3:.2f} GB"


def _icmp_checksum(data: bytes) -> int:
    """计算 ICMP 报文校验和（RFC 792，算法与 IP 头校验和相同：16 位反码和的取反）。

    算法步骤：
    1. 若数据长度为奇数，末尾补一个 0x00（仅参与求和，不属于真实报文）；
    2. 按网络字节序（大端）每 16 位一组求和；
    3. 把高 16 位的进位折叠回低 16 位（可能需折叠两次）；
    4. 对结果按位取反并 & 0xFFFF，得到 0~65535 的最终校验和。

    :param data: 完整 ICMP 报文（计算时其校验和字段应暂填 0，见调用处组包方式）；
    :return: 校验和整数。写入报文时需 struct.pack('!H', csum) 转大端字节序，
             回填到 ICMP 头第 3、4 字节。
    易错点：必须以大端逐 16 位相加；发送方回填后，接收方对整包重算
    校验和应得到 0x0000，这是验证校验和正确性的常用手段。
    """
    if len(data) % 2:
        data += b"\x00"
    s = 0
    for i in range(0, len(data), 2):
        s += (data[i] << 8) + data[i + 1]
    s = (s >> 16) + (s & 0xFFFF)
    s += s >> 16
    return (~s) & 0xFFFF


class TrafficGenerator:
    """流量压测发生器：按并发线程向目标持续发包（UDP/TCP/TCP-SYN/ICMP）。

    四种模式对应四个 *_worker 线程函数，由 start() 按 protocol 分发：
    - UDP     : _udp_worker     无连接 sendto，目标无需有服务在监听；
    - TCP     : _tcp_worker     反复建立真实连接并沿连接灌数据（有握手开销）；
    - TCP SYN : _tcp_syn_worker 只发 SYN 不完成握手（半开连接，测防火墙放行/速率）；
    - ICMP    : _icmp_worker    raw socket 手工组 ICMP echo request（需管理员权限）。

    所有 worker 共用同一套“时间差累积 → 折算应发包数 → 限幅 → 补发/休眠”的
    速率控制骨架；rate<=0 表示不限速（尽力而为）。发送量统一写入 self.stats
    供 UI 实时读取 pps/bps。多线程共享同一份预生成 payload（内容随机、长度
    固定为 packet_size）。TCP 模式下对“连接被拒”类错误做了日志限流，避免刷屏。
    """

    def __init__(self, target_ip: str, target_port_str: str, protocol: str,
                 concurrency: int, packet_size: int, rate: int,
                 log_callback=None):
        """初始化压测发生器（构造后即可调用 start() 开跑）。

        :param target_ip: 目标 IP 地址字符串；
        :param target_port_str: 目标端口描述，交给 parse_ports 解析成端口列表
            （self.target_ports 用于发包随机挑选；self.port_desc 为可读描述，供日志）；
        :param protocol: 协议名（内部 upper()），取值 UDP / TCP / 'TCP SYN' / ICMP，
            其它未知值在 start() 里一律按 TCP 处理；
        :param concurrency: 并发线程数，每个线程持独立 socket 各自发流；
        :param packet_size: 每包应用层负载字节数（SYN 模式无负载，仅影响统计口径）；
        :param rate: 每个线程每秒发包数上限，<=0 表示不限速；
        :param log_callback: 日志回调 log(msg)，缺省静默。
        :return: 无
        构造时即预生成 payload 并初始化 Stats、running=False；
        _tcp_connect_error_logged 用于给 TCP 连接错误日志限流（防刷屏）。
        """
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
        """从解析出的目标端口列表中随机挑选一个端口。

        :return: 一个目标端口号。随机挑选使各 worker 发往的端口分散开，
                 避免所有并发线程都打在同一个端口上（对多端口业务更接近真实流量）。
        """
        return random.choice(self.target_ports)

    def _generate_payload(self) -> bytes:
        """生成一包随机字节的负载数据，长度固定为 self.packet_size。

        :return: bytes，长度等于 packet_size（构造期已保证该值为正整数）。
        负载在 __init__ 时生成一次并全程复用：内容随机更贴近真实数据，
        又避免每轮发送都现场生成而拖慢发包速率、引入额外 GC 压力。
        """
        return bytes(random.getrandbits(8) for _ in range(self.packet_size))

    def _udp_worker(self, thread_id: int):
        """UDP 洪水线程：无连接 sendto，持续向目标随机端口发包。

        :param thread_id: 线程编号（0~concurrency-1），仅作区分/日志用（UDP 流程未使用）。
        :return: 无（running 置 False 后退出循环并关闭 socket）
        关键细节与易错点：
        - 速率控制骨架：用 perf_counter 记录真实流逝时间累积成“应发包数”to_send，
          发完后 accumulated -= to_send / rate 做“还债”防累积漂移；单轮上限 1000，
          防止机器卡顿后一次性补发过量造成突发；rate<=0 视为不限速：每轮发 1000 个
          再睡 1ms 近似满速跑；
        - UDP 无连接、不保证送达：目标端口无人监听只会由系统异步收到 ICMP 端口
          不可达，sendto 本身不报错，因此发送异常一律静默忽略（不中断线程、不刷日志）；
        - 发送缓冲调大到 8×64KB，降低灌包时因内核缓冲满而阻塞丢速的可能。
        """
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
        """TCP 洪水线程：反复建立真实连接，并沿连接按速率灌负载。

        :param thread_id: 线程编号，错误日志中用于标注来源线程。
        :return: 无（running 置 False 后退出；无论成败 finally 都关闭连接）
        流程：外层循环每次新建一条 TCP 连接（5s 连接超时、TCP_NODELAY 关闭
        Nagle 算法、发送缓冲 8×64KB）→ 连上后内层循环按速率 sendall 整包发送
        → 发送失败（BrokenPipe/ConnectionReset 等，如对端断开）则关闭连接并
        跳出重连；外层捕获各类连接错误后统一 sleep 0.5s 再试。
        易错点/协议细节：
        - sendall 会循环到把整段数据发完为止，绝不能改用 send()（后者可能只发
          一部分），故统计口径 = 整包长度，无“半包”误差；
        - 内层 while 里的发送异常用 raise 抛出到外层 except 分类处理：
          连接被拒(ConnectionRefused/Aborted)与连接超时(socket.timeout)基本表示
          “目标没有 TCP 服务在监听”——这是压测常见预期现象，只在前 3 次打日志
          （_tcp_connect_error_logged 限流），之后静默重试，避免每线程每轮刷屏；
        - 其它 OSError 只记 1 条日志；兜底 except Exception 静默吞掉，线程不崩。
        """
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
        """TCP SYN（半开连接）洪水线程：只发 SYN，不完成三次握手。

        :param thread_id: 线程编号，日志/标识用。
        :return: 无（running 置 False 后退出）
        原理：对非阻塞 socket 调 connect()，内核会立刻发出 TCP SYN 包，随即
        close() 丢弃该连接（不等 SYN-ACK 回来），用于压测防火墙 SYN 放行策略、
        或评估目标机半开连接的处理能力。
        关键细节与易错点（SYN 标志位相关）：
        - 非阻塞 connect 返回“正在连接中”的表现是抛 BlockingIOError——这正是
          SYN 已成功发出的信号，必须捕获并当作正常情况继续（不是错误）；
        - 若对端端口关闭会立即回 RST，connect 抛 ConnectionRefused 等异常：
          此时关闭该 socket 并跳过，不计入发包数；
        - 每轮把所有“成功发起 SYN”的 socket 收集进 socks，按批统计
          stats.add(1, count=sent)——SYN 包不携带应用负载，故每包按 1 字节计；
        - 单轮上限 500（比全连接模式更保守）：非阻塞 connect 后必须马上 close，
          否则大量半开连接/TIME_WAIT 会迅速耗尽本地 fd 与端口资源；
        - 速率控制骨架同其它 worker：rate>0 时按时间累积折算应发数并限幅 500，
          发完立即 sleep 补足周期；rate<=0 不限速时每轮 500 个后睡 1ms。
        """
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
        """ICMP echo flood 线程：raw socket 手工组 ICMP echo request 发包。

        :param thread_id: 线程编号，与进程 PID 一起参与 ident 字段计算
            （ident = os.getpid()&0xFFFF ^ thread_id&0xFFFF），使多线程发往同一
            目标的报文标识互不相同，便于对端（及本机抓包）区分来源线程。
        :return: 无（创建 socket 失败或 running 置 False 时退出）
        关键细节与易错点（组包/校验和/权限）：
        - 需要管理员/root 权限创建 SOCK_RAW+IPPROTO_ICMP socket：Windows 上抛
          PermissionError 时打印中文友好提示并把 running 置 False 停止，不崩溃；
        - 手工组包用 struct.pack('!BBHHH') 大端格式：type=8(echo request)/
          code=0 / 校验和 / ident / seq，后接 payload。先在校验和位填 0 组包，
          用 _icmp_checksum 对“头+负载”整包计算校验和，再回填 csum 重新组包
          （校验和覆盖整包，回填后无需重算）；
        - seq 每包 (seq+1)&0xFFFF 循环自增，溢出回绕是预期的；
        - 发送目标地址端口号填 0（ICMP 属网络层，没有端口概念）；
        - 运行期若发送再遇 PermissionError（权限被撤）同样提示后停止；
        - raw socket 下内核只代为封装 IP 头，ICMP 头与校验和需自己组；
          echo request 到达对端后由其内核自动回 echo reply，无需对端运行
          任何应用/监听服务——这也是 ICMP 模式常用于“探活”的原因。
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
        """按 protocol 分发并启动 concurrency 个发包线程。

        映射：UDP→_udp_worker，ICMP→_icmp_worker，'TCP SYN'→_tcp_syn_worker，
        其余（含 TCP）一律→_tcp_worker。每个线程以 (i,) 为 thread_id 的守护线程
        启动并登记进 self.threads 供 stop() join。若已在运行则直接返回，
        防止重复启动叠加线程。

        :return: 无
        """
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
        """停止压测：置 running=False 并等待所有发包线程退出。

        各 worker 的循环都以 self.running 为条件，置 False 后它们会在当前一轮
        结束处退出；对每个线程 join 最多 2 秒兜底（worker 内部单次 sleep 不超过
        0.1s，正常会很快自行退出）。

        :return: 无
        """
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
    """大小写无关的“任一关键字命中”判断，用于在设备输出文本里找特征词。

    实现：把 text 与每个 pattern 都转小写后做子串包含判断(in)，
    命中任意一个即返回 True。
    :param text: 待检查的原始输出文本（可含多行）；
    :param patterns: 变长关键字参数，如 ("disabled", "未使能", "disable")。
    :return: bool
    易错点/设计原因：
    - 华为/H3C 等 VRP 系设备中英文输出混杂（Disabled / 未使能 / 使能 / enable），
      所以调用处总是传一组中英文同义词以提高命中率；
    - 是子串匹配而非整词匹配：'disable' 会命中 'disabled'，且可能误伤
      "not disabled" 之类的否定语境——调用方须靠“先判关闭词、后判开启词”
      的判定顺序（见 judge_security_item）规避误判。
    """
    low = text.lower()
    return any(p.lower() in low for p in patterns)


def judge_security_item(devtype: str, item: str, outputs: dict) -> tuple:
    """判定单个安全核查项的合规状态（只读配置判断，不发起任何攻击）。

    判定思路：把该核查项所有命令的输出拼成一段文本，用 _text_has 在其中检索
    中英文特征关键字，按“明确关闭(fail) > 明确开启(ok) > 空输出(na) > 兜底
    (warn/fail)”的优先级组合出结论，并附带用于界面展示的输出摘要与修复建议。

    :param devtype: 设备厂商类型（huawei/cisco/h3c/ruijie）——查询命令按厂商
        区分（SECURITY_CHECKS 配置），本函数的判定本身主要依赖通用关键字，
        因此各厂商输出都能覆盖；
    :param item: 核查项标识，须为 SECURITY_ORDER 中的键：dhcp_snooping /
        dai / dns / vlan_isolate / port_security；
    :param outputs: dict {命令输出标题: 该命令原始输出文本}，键与
        SECURITY_CHECKS[item]['cmds'][厂商] 中的 title 对应，值为设备回显；
    :return: (status, detail_lines, advice) 三元组：
        - status: ok(绿-合规)/ warn(黄-需关注)/ fail(红-不合规)/
          na(灰-无输出或设备不支持，无法判断)；
        - detail_lines: list[str]，由 _head_lines 压出的输出摘要（证据行），
          na 分支为固定提示行；
        - advice: 修复建议文案（SECURITY_ADVICE），状态为 ok 时则是正向说明。
    易错点/判定逻辑：
    - 关键字均为子串匹配，正反语义词可能同时出现在不同命令输出里（如同一页
      既有 "enable" 又有 "disabled" 段）——因此每个分支都先判“关闭”类词命中
      →fail/warn，再判“开启”类词 →ok，最后空输出 →na；
    - dhcp_snooping 分支还会再检查绑定表(user-bind)输出：命令本身显示开启但
      绑定表无条目时降级为 warn（设备可能未上线/未学习到），有条目才算 ok；
    - DAI/端口安全等分支在“开启”命中后还会复查一次是否同时含禁用词，
      避免 enable 与 disabled 同时出现时误判为 ok。
    """
    joined = "\n".join(outputs.values())

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
    """把多条命令的完整输出压缩成用于界面展示的前若干行摘要。

    :param outputs: dict {命令标题: 输出文本}；
    :param max_total: 期望的摘要总行数上限（默认 6）。会按命令条数均分配额：
        每个命令展示 max(1, max_total//命令数) 行；某命令输出行数超出配额时，
        在其摘要末尾追加一行 “…共 N 行” 提示。
    :return: list[str] 摘要行列表：非首个命令前插入 “── [标题] ──” 分隔行；
        输出中的空行会被过滤；最后整体再截断到 max_total+8 行兜底，
        防止命令过多时摘要失控拉长界面。
    """
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
    """安全配置核查标签页 / Security audit panel (V3.2)。

    对一台交换机/路由器/服务器执行“安全配置核查”：通过 SSH 登录设备，按
    SECURITY_CHECKS 中预置的规则逐项下发**只读查询命令**（不发起任何攻击），
    解析命令回显并比对，给出 通过(ok)/告警(warn)/失败(fail)/不适用(na)
    三种以上结论与整改建议，支持导出文本报告。

    线程模型（本类最易错的地方）：
      * SSH 登录、命令下发等耗时操作全部在后台 worker 线程执行；
      * worker 线程**严禁**触碰任何 tkinter 控件/StringVar（跨线程访问会
        随机崩溃或界面卡死），只能把结果写入线程安全的 self.result_queue；
      * 队列消息为**二元组** (kind, data)，kind 取值：
          "sys"  -> (kind, 文本) 系统信息/进度，title 样式显示；
          "item" -> (kind, (label, status, detail, advice)) 单项核查结论；
          "done" -> (kind, None) 全部结束，恢复按钮状态；
      * 主线程用 after(100, self._poll_queue) 周期性轮询队列并刷新界面；
      * 点 Stop 按钮只置位 self.stop_event，worker 在每条核查项之间检查该
        事件实现“协作式停止”，不强制杀线程（避免 SSH 半开连接）。
    """

    def __init__(self, master: tk.Widget, app) -> None:
        """初始化“安全配置核查”页签。

        参数:
            master: 父容器（主窗口 Notebook 中的一个标签页框架）
            app: 主应用对象引用（存入 self._app），本类复用它提供的
                 _ssh_connect（SSH 登录）与 _run_commands_via_shell
                 （批量下发命令）等方法，避免重复实现 SSH 逻辑。

        完成四件事：
          1) 保存 app 引用；
          2) 创建协作式停止事件 stop_event（Stop 按钮通知后台线程退出）与
             线程安全的 result_queue（worker 线程 → 主线程的消息队列）；
          3) 调用 _build_ui() 搭建界面；
          4) 注册 after(100, self._poll_queue) 启动常驻队列轮询，使
             worker 线程投递的结果能周期性刷新到界面。
        """
        super().__init__(master)
        self._app = app
        self.stop_event = threading.Event()
        self.result_queue = queue.Queue()
        self._build_ui()
        self.after(100, self._poll_queue)

    def destroy(self) -> None:
        """销毁页面（窗口关闭/切换标签页由 tkinter 自动调用）时的清理。

        先置位 stop_event，通知正在后台执行 SSH 核查的 worker 线程尽快退出
        （否则线程会继续占用连接、甚至残留输出窗口），再调用父类 destroy
        释放全部 tkinter 控件。
        """
        self.stop_event.set()
        super().destroy()

    # ── UI ──
    def _build_ui(self):
        """构建“安全配置核查”页签的界面（只创建控件，不发起连接）。

        自上而下四个区域：
          1) Target Device 输入行：设备 IP、SSH 账号、密码（密文显示）、
             设备类型下拉（huawei/cisco/h3c/ruijie/linux）、端口；
          2) Security Checks 复选框区：按 SECURITY_ORDER 顺序为每个核查项
             生成默认勾选的 BooleanVar（存入 self.sec_check_vars，运行时由
             _on_start 读取勾选结果决定核查哪些项）；
          3) 按钮行：Start Security Test（绿色，触发 _on_start）、Stop（红色，
             默认禁用，触发 _on_stop）、Export Report（导出），右侧状态标签
             sec_status 用于显示 Running/Stopping/Done 等进度；
          4) 只读滚动文本框 sec_output：结果输出区，预先为 ok/warn/fail/na/
             title/advice 六种结论注册前景色+背景色 tag，供 _log 按结论着色。
        """
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
        """向输出区 sec_output 追加一行文本（**只能在主线程调用**）。

        参数:
            text: 要显示的文本内容（自动在末尾补一个换行）
            tag: 可选的颜色标签，取值 ok/warn/fail/na/title/advice，
                 None 表示用默认前景色

        实现要点：ScrolledText 平时处于 DISABLED 只读态，写入前必须临时
        config(state=NORMAL)，insert 完调用 see(END) 自动滚到底部，最后再
        置回 DISABLED 保持只读。该方法直接读写 tkinter 控件，严禁在后台
        worker 线程调用，只能由主线程（如 _poll_queue）触发。
        """
        self.sec_output.config(state=tk.NORMAL)
        self.sec_output.insert(tk.END, text + "\n", tag)
        self.sec_output.see(tk.END)
        self.sec_output.config(state=tk.DISABLED)

    def _set_busy(self, busy: bool):
        """切换 Start/Stop 按钮的可用状态，防止核查期间重复启动。

        参数:
            busy: True=核查进行中 → Start 禁用、Stop 启用；
                  False=核查结束 → Start 恢复可用、Stop 禁用。

        只能在主线程调用（按钮是 tkinter 控件）。_on_start 启动前调
        _set_busy(True)，收到队列 ("done", None) 消息后调 _set_busy(False)。
        """
        self.sec_start_btn.config(state=tk.DISABLED if busy else tk.NORMAL)
        self.sec_stop_btn.config(state=tk.NORMAL if busy else tk.DISABLED)

    # ── 控制 ──
    def _on_start(self):
        """“Start Security Test”按钮回调：校验输入并启动后台核查线程。

        流程：
          1) 读取 IP、端口、账号、密码等界面值；端口先 strip 再转 int，
             失败即弹“端口格式错误”；
          2) 过滤出用户勾选的核查项（sec_check_vars 中为 True 的 key），
             一个没勾就提示；
          3) 校验通过后：clear 停止事件、清空上一次输出、_set_busy(True)
             禁用 Start、状态栏置 Running...；
          4) 以 daemon=True 启动 threading.Thread 运行 self._worker，并把
             (host, port, user, pwd, 归一化设备类型, checked) 以**值**的
             形式作为线程参数传入。

        易错点：本函数运行在主线程，负责把 tkinter 变量（StringVar/
        BooleanVar）的取值快照下来再传给线程；后台 worker 线程绝不能再
        读这些变量。设备类型经 normalize_devtype 归一化，取不到时兜底为
        "huawei"。
        """
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
        """“Stop”按钮回调：请求停止正在进行的核查。

        只置位 self.stop_event（协作式停止），并不强制终止线程：worker 在
        每条核查命令下发前检查该事件，因此会等当前这条命令返回后才退出，
        避免把 SSH 会话卡在半路。随后把状态栏改为 "Stopping..." 提示用户。
        """
        self.stop_event.set()
        self.sec_status.config(text="Stopping...")

    def _on_export(self):
        """“Export Report”按钮回调：把输出区内容导出为文本文件。

        流程：读取 sec_output 全部内容，为空则提示“没有可导出的结果”；
        弹出“另存为”对话框，默认文件名形如
        security_test_<IP>_<YYYYMMDD_HHMM>.txt；确认路径后以 UTF-8 带 BOM
        （utf-8-sig）编码写入——带 BOM 可保证 Windows 记事本直接打开不乱码。

        注意：写文件前先判断用户是否取消保存（path 为空直接 return）。
        """
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
        """后台核查线程：SSH 登录设备并逐项下发只读命令做配置比对。

        参数:
            host: 设备 IP 地址
            port: SSH 端口号
            user/pwd: SSH 登录用户名/密码
            devtype: 归一化后的设备类型（huawei/h3c/cisco/ruijie/linux）
            checked: 用户勾选待核查项的 key 列表（来自 SECURITY_ORDER）

        流程：
          1) paramiko 建 SSHClient，复用 app._ssh_connect 登录；
          2) 按 SECURITY_ORDER 顺序遍历每个勾选项：从 SECURITY_CHECKS[key]
             取该设备类型对应的命令集（cmds_dict），经 app._run_commands_via_shell
             批量下发执行（单命令超时 25s），再把回显交给 judge_security_item
             判定得到 (status, detail, advice)；
          3) 全部完成后关闭连接。

        本函数运行于后台线程，三个硬性约束（易错点）：
          * **绝不触碰 tkinter 变量/控件**——所有输出一律通过
            self.result_queue.put() 投递，队列消息为**二元组**：
              ("sys", 文本)              → 系统提示/分隔标题
              ("item", (label,status,detail,advice)) → 单项核查结论
              ("done", None)             → 结束信号（finally 中保证投递）
          * 每执行一项前检查 self.stop_event.is_set()，实现 Stop 及时退出；
          * 连接/命令失败时用 app._friendly_conn_error 把 paramiko 异常
            翻译成友好的中文提示再投递。
        """
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
        """主线程常驻轮询：把 result_queue 中的消息刷到界面（每 100ms 一次）。

        由 __init__ 里的 after(100, self._poll_queue) 反复自调度，始终运行在
        tkinter 主线程——它是后台 worker 线程与 UI 之间**唯一的通信桥梁**，
        消息格式为二元组 (kind, data)：
          ("sys", 文本)          → 以 title 样式输出一行系统信息；
          ("item", (label,status,detail,advice))
                                 → 按 status 映射 ✅/⚠️/❌/➖ 记号，标题行
                                    按结论 tag 着色，明细缩进打印，建议以
                                    advice 样式展示（换行符替换成缩进+换行）；
          ("done", None)         → 恢复按钮可用并置状态栏 Done。

        实现要点：while + get_nowait 一次性取空当前所有消息，捕获
        queue.Empty 退出本轮；末尾再次注册 after(100) 让轮询持续下去，
        try/except 兜底窗口已销毁（TclError）等异常避免回调崩溃。
        """
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
    """获取本机 MAC 地址（供 DHCP Discover 报文的 chaddr 字段使用）。

    实现：调用 Windows 的 getmac 命令（参数 /fo csv /nh 表示输出不带表头的
    CSV），用正则提取形如 AA-BB-CC-DD-EE-FF 的第一组 MAC，去掉连字符后
    用 bytes.fromhex 转成 6 字节 bytes。

    返回:
        6 字节的 MAC；解析失败时返回 b"\\x00"*6（6 字节全 0），
        调用方 dhcp_probe 会原样把它填进 BOOTP 头。

    易错点（Windows 特有）：
      * getmac 是控制台程序，必须传 creationflags=_NO_WINDOW，否则每次探测
        都会闪一个黑窗口；
      * 中文系统下 getmac 输出为 GBK 编码，必须 encoding="gbk" 解码并配合
        errors="replace" 容错，否则 UnicodeDecodeError；
      * 必须处理“本机有多个网卡/虚拟网卡”的情况——正则取第一个匹配即可，
        探测只要一个可用的源 MAC，不必精确到用户选中的网卡。
    """
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
    """标准 ICMP ping（调用系统 ping 命令，无需管理员权限）。

    返回:
        (reachable, rtt_list, err) 三元组：
          reachable: bool，是否 ping 通；
          rtt_list: 解析出的往返时延（毫秒）列表，可能为空（首包丢失等）；
          err: 出错信息字符串；正常/判定为“不可达”时均为 None。

    参数:
        host: 目标 IP 或域名；count: 发包个数（默认 4）；timeout: 单包超时秒。

    设计取舍：主动探测用系统 ping 更可靠——raw socket 方式需要管理员权限，
    且本机回环（ping 自己）收不到 ICMP 回显；但流量压测的高压 ICMP 场景仍
    用 TrafficGenerator 的 raw socket 实现，两者用途不同。

    易错点（中文 Windows 环境最容易踩的坑）：
      * ping 是控制台命令：必须传 creationflags=_NO_WINDOW 隐藏黑窗；
      * 回显文本默认 GBK 编码：encoding="gbk" + errors="replace"，否则
        中文系统直接 UnicodeDecodeError；
      * 解析时延要中英文通吃：正则 (?:time|时间)[=<](\\d+)ms 同时匹配
        "time=32ms" 与 "时间=32ms"（超时用 -w 毫秒参数）；
      * 判定“不可达”需同时识别 中文“无法访问/超时” 与英文
        unreachable/timed out；而只有 TTL/存活/bytes 没有时延的回复
        （典型如首包被丢弃但后续可达）也要判为可达，不能漏判。
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
    """DNS A 记录查询（UDP 53 直连指定 DNS 服务器，不经过系统解析）。

    定位用途：把“用户填的 DNS 服务器 IP”作为解析源，查询 domain 的 A 记录，
    并与预期 IP 比对——用于发现 DNS 被重定向/劫持（例如私接路由器抢答、
    运营商/出口劫持等），在 ActiveTestPanel 的 “Probe DNS” 里被调用。

    返回:
        (status, answers, rtt, err) 四元组：
          status: "ok" 有响应且（若填了预期）与预期一致；
                  "warn" 有响应但解析 IP 与预期不符（疑似重定向）；
                  "fail" 无响应/无 A 记录/格式错误可查；
                  "na" 参数错误（DNS 服务器 IP 不是合法 IPv4）；
          answers: 解析出的 A 记录 IP 列表（可能为空）；
          rtt: 响应往返毫秒数（可能为 None）；err: 错误说明（None 表示正常）。

    参数:
        dns_server: DNS 服务器 IPv4 地址（先经 socket.inet_aton 校验合法性）；
        domain: 要查询的域名，默认 www.baidu.com；
        expected_ip: 期望解析到的 IP（可空，空则不校验一致性）；
        timeout: 等待响应的秒数（默认 5）。

    关键逻辑（协议细节，供学习）：
      1) 手工构造 DNS 查询报文：2 字节事务 ID（用进程号低位，便于关联响
         应）+ 标志 0x0100（标准查询、RD=1）+ QDCOUNT=1，域名按标签长度
         前缀编码（如 www.baidu.com → 03www05baidu03com00），QTYPE=1
         (A)、QCLASS=1 (IN)；
      2) 收包后先解析跳过 question 区（跳过每个标签或 0xc0 压缩指针），
         再遍历 answer 区：response 里 name 若以 0xc0 开头说明是指针压缩，
         直接跳 2 字节；类型 1(A) 且长度 4 的记录用 inet_ntoa 还原成 IP；
      3) socket.timeout → 判 fail 并带超时提示；OSError → 判 fail。

    易错点：UDP 是面向报文的，务必先校验 dns_server 是合法 IP 再做
    inet_aton，否则 OS 解析域名为“服务器地址”会造成二次解析歧义。
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
    """解析 DHCP options 区（从 magic cookie 之后开始），返回键值字典。

    参数:
        raw: BOOTP 报文中 magic cookie（99 130 83 99）之后的原始字节流。
    返回:
        dict，键为语义名、值为解析后的人类可读内容，例如：
          server_id: DHCP 服务器 IP（option 54）；
          router: 默认网关（option 3，取第一个 4 字节）；dns: DNS 列表
          （option 6，每 4 字节一个 IP 用空格连接）；
          subnet: 子网掩码（option 1）；lease: 租约秒数（option 51，
          大端 4 字节）；hostname: 主机名（option 12，UTF-8 容错解码）。

    协议格式（供学习）：DHCP option 是 TLV 结构——每项依次为
    1 字节 code + 1 字节长度 ln + ln 字节的 value；两个特殊码：
    code=0 是 padding（填充对齐，跳过即可），code=255 是 End 标记，
    遇到即停止解析。解析失败或越界时安全 break，不影响已解析的内容。
    """
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
    """DHCP 主动探测：广播 Discover，收集网段内所有 Offer 响应者。

    定位用途：发现“私接路由器抢答 DHCP”。正常网络只有 1 台合法 DHCP
    服务器应答；如果检测到 >1 个服务器响应，说明有人私接路由器/开了
    非法 DHCP，终端拿到错误地址、间歇断网的根因大概率在此。

    返回:
        (servers, err) 二元组：
          servers: 响应者列表，每个元素是 dict：
              ip      — Offer 来源地址（siaddr 或收包源地址）
              yiaddr  — 服务器打算分配给你的 IP（your IP address 字段）
              rtt     — 收到该 Offer 的毫秒时延
              以及 _parse_dhcp_options 解析出的 router/dns/subnet/lease 等；
          err: 出错时为中文错误描述字符串（无法绑定端口/无权限发送等），
               正常时返回 None。

    参数:
        timeout: 等待 Offer 的总时长（秒，默认 6）。

    实现要点（BOOTP 报文手工构造，供学习）：
      1) 组包：op=1(BOOTREQUEST)/htype=1(以太网)/hlen=6/xid=事务号/秒数
         0x8000 + 源 MAC（_local_mac）+ magic cookie 99 130 83 99；options
         含 53(Discover=1)、55(请求参数列表：1 3 6 15 51 54 119)、
         12(客户端主机名 "NADT-PROBE")、255(End)；
      2) UDP 源端口 68 → 广播 255.255.255.255:67；循环 recvfrom 直到超时，
         只收 BOOTREPLY(op=2)、长度 ≥240、xid 与己方一致的包，把网络上
         其它无关广播/组播数据过滤掉。

    易错点（Windows 特有）：
      * bind(("0.0.0.0", 68)) 可能失败——系统自带的 DHCP 客户端常占用 68
        端口，此时返回友好错误而不是崩溃；
      * 向 255.255.255.255 发广播在未开“允许广播”时可能抛 PermissionError，
        提示需以管理员身份运行；
      * SO_BROADCAST 必须先 setsockopt 打开，否则广播包发不出去。
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
    """用系统命令 `arp -a <ip>` 查询某 IP 对应的 MAC 地址。

    参数:
        ip: 要查询的目标 IP。
    返回:
        该 IP 在本地 ARP 表中的 MAC（格式统一为小写、冒号分隔，如
        "a4:bb:cc:dd:ee:ff"）；表里没有对应条目或命令失败时返回空串 ""。

    易错点（Windows 特有）：
      * arp 是控制台程序：必须传 creationflags=_NO_WINDOW 隐藏黑窗；
      * 中文系统输出为 GBK 编码：encoding="gbk" + errors="replace"；
      * Windows 的 arp 输出里 MAC 用连字符分隔（AA-BB-...），正则用
        [:-] 兼容两种分隔写法，最后统一 replace("-", ":") 转小写；
      * **ARP 只能解析同网段设备**——目标跨网段时数据走网关转发，本机
        ARP 表里不会有它的条目，返回空串是正常现象而非故障（arp_probe
        会据此区分“跨网段”与“真不可达”）。
    """
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
    """ARP 主动探测：ping 触发 + 多次采样 ARP 表，判断是否有冲突/欺骗。

    原理：Windows 的 ARP 表只有与目标通信过才生成条目，所以每轮先发一个
    ping “触发”目标应答，稍等片刻再查 arp -a。多次采样若发现同一 IP 对应
    多个不同 MAC，即为疑似 ARP 欺骗/重复 IP。

    返回:
        (macs, status, err) 三元组：
          macs: 采样到的不同 MAC 列表（去重后按发现顺序）；
          status: "ok"   单一稳定 MAC，无冲突；
                  "warn" 出现多个 MAC（疑似欺骗/重复 IP），或目标可达但
                         跨网段导致本机 ARP 无条目（无法下结论）；
                  "fail" 真不可达（ping 超时且无 ARP 条目）；
          err: 详细说明；None 表示正常。

    参数:
        ip: 目标 IP（通常是网关或疑似冲突的地址）；
        repeat: 采样轮数（默认 3）；timeout: 单次 ping 超时秒数。

    关键分支（易错点）：
      * ping 报错且提示“管理员”时直接判 fail（系统 ping 被禁，探测不可信）；
      * 一轮 ping 后 sleep 0.25s 等 ARP 表刷新，再查表；
      * 所有轮次都没有 MAC 时补一次 count=2 的 ping 区分两种情况：
          - ping 通 → "warn"，提示目标跨网段走网关路由、**ARP 只能解析
            同网段设备**，需到目标同网段机器上查或先查网关 ARP；
          - ping 不通 → "fail"，目标确实不可达。
    """
    macs = []
    for _ in range(repeat):
        reach, _, _err = icmp_ping(ip, count=1, timeout=timeout)
        if _err and "管理员" in _err:
            return [], "fail", _err
        time.sleep(0.25)
        mac = _arp_lookup(ip)
        if mac and mac not in macs:
            macs.append(mac)
    if macs:
        if len(macs) > 1:
            return macs, "warn", f"同一 IP 出现 {len(macs)} 个不同 MAC — 疑似 ARP 欺骗/重复 IP"
        return macs, "ok", None
    # 无 MAC：区分 跨网段（可达但 ARP 无条目） 与 真不可达
    reach, _, _err = icmp_ping(ip, count=2, timeout=timeout)
    if reach:
        return [], "warn", (
            f"{ip} 可达（ping 通）但本机 ARP 无条目 — 目标跨网段，走网关路由，"
            f"ARP 只能解析同网段设备。\n"
            f"  要查该 IP 的真实 MAC/欺骗：在目标同网段的机器上探测；或先查网关 ARP "
            f"确认路由是否正常")
    return [], "fail", f"{ip} 不可达（ping 超时）且无 ARP 条目"


def vlan_probe(target: str, count: int = 4, timeout: float = 2.0) -> tuple:
    """跨 VLAN 连通性探测：对目标发标准 ICMP（本质是 icmp_ping 的封装）。

    定位用途：验证两个 VLAN 之间到底通不通，从而判断故障/策略方向：
      * 本应隔离（如不同安全域）却 ping 通 → 缺少跨 VLAN 访问控制
        （缺 port-isolate / VLAN 间 ACL / 三层互访策略）；
      * 本应互通却不通 → 查 VLANIF/路由/ACL 配置。
    在 ActiveTestPanel 的 “Probe VLAN” 按钮里被调用。

    返回:
        与 icmp_ping 完全一致的三元组 (reachable, rtts, err)：
          reachable: 是否可达；rtts: 时延毫秒列表；err: 错误信息(None 正常)。

    参数:
        target: 跨 VLAN 的目标 IP；
        count: 发包个数（默认 4）；timeout: 单包超时秒数（默认 2.0）。

    易错点：这里“跨 VLAN”体现在**被测目标的网段**与**本机所在网段**不同
    ——流量经三层网关路由转发，本函数并不需要也不负责构造 VLAN 标签；
    Windows 上测试跨网段目标时，若中间路由/ACL 有故障，现象通常是
    4 个包全部超时且无回复。
    """
    return icmp_ping(target, count=count, timeout=timeout)


class ActiveTestPanel(ttk.Frame):
    """主动探测标签页 / Active test panel (V3.3) — 标准协议故障定位。

    典型场景：带新机器去现场，网络在“通信正常”的间歇期无法复现故障时，
    用本页的四个标准协议探测主动定位问题根因：
      1) Probe DHCP  — 广播 DHCP Discover，看是否有 >1 台服务器抢答
         （私接路由器/非法 DHCP）；
      2) Probe DNS   — 直连用户填的 DNS 服务器查询域名 A 记录，与预期
         IP 比对，发现 DNS 重定向/劫持；
      3) Probe ARP   — 对同一 IP 多次采样 MAC，发现 ARP 欺骗/重复 IP；
      4) Probe VLAN  — 跨 VLAN 标准 ICMP 连通测试。

    线程模型（易错点，与 SecurityTestPanel 类似）：
      * 按钮回调 _run 运行在**主线程**：它负责把四个输入框的 StringVar
        取值快照成普通 dict args 后，再启动后台 worker 线程；
      * worker 线程执行 dhcp_probe/dns_probe/arp_probe/vlan_probe 等耗时
        探测，**绝不能碰 tkinter 变量或控件**，只能往 result_queue 投递；
      * 本页队列消息为**三元组** ("line", text, tag)：文本 + 颜色标签；
        结束信号为 ("done", None)。与 SecurityTestPanel 的 (kind,data)
        二元组约定不同，阅读/扩展时注意区分；
      * 主线程通过 after(100, _poll_queue) 常驻轮询刷新输出区。
    """

    def __init__(self, master: tk.Widget) -> None:
        """初始化“主动探测”页签。

        参数:
            master: 父容器（主窗口 Notebook 中的一个标签页框架）。

        注意：与 SecurityTestPanel 不同，本页探测单次耗时短（ping/DHCP
        最长约几秒），因此**没有** stop_event 停止机制，只创建线程安全的
        result_queue（后台线程 → 主线程消息队列），然后 _build_ui() 搭界面、
        after(100, _poll_queue) 启动队列轮询。探测线程用完即止、daemon 退出，
        不做协作式取消。
        """
        super().__init__(master)
        self.result_queue = queue.Queue()
        self._build_ui()
        self.after(100, self._poll_queue)

    def destroy(self) -> None:
        """销毁页面（窗口关闭/切换标签页时由 tkinter 自动调用）。

        本页探测线程均为短任务且 daemon=True，无需像 SecurityTestPanel 那样
        置停止事件；直接调用父类 destroy 释放全部 tkinter 控件即可。窗口
        销毁后 _poll_queue 末尾的 try/except 会吞掉 after() 的异常。
        """
        super().destroy()

    def _build_ui(self):
        """构建“主动探测”页签的界面（只创建控件，不发起探测）。

        布局两块：
          1) Probe Targets 输入区（两行四个目标）：
             row0: ARP 目标 IP（网关/疑似冲突 IP）、DNS 服务器 IP、
                   预期解析 IP（用于重定向对比）；
             row1: 跨 VLAN 目标 IP、查询域名（默认 www.baidu.com）；
             各输入框均绑 StringVar：at_arp_ip/at_dns/at_dns_expected/
             at_vlan_ip/at_domain，运行时由 _run 在主线程统一取值；
          2) 四个探测按钮（各自 lambda 调 self._run(kind)，kind 取
             "dhcp"/"dns"/"arp"/"vlan"）+ 右侧状态标签 at_status；
          3) 只读滚动文本框 at_output：预注册 ok/warn/fail/na/title/plain
             六种配色 tag（注意：比 SecurityTestPanel 多一个 "plain" 普通
             文本色、少一个 "advice"——两页 tag 集合不同，扩展时留意）。
        """
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
        """向输出区 at_output 追加一行文本（**只能在主线程调用**）。

        参数:
            text: 要显示的文本（自动补换行）
            tag: 可选颜色标签（ok/warn/fail/na/title/plain），None 用默认色

        与 SecurityTestPanel._log 相同的“只读文本框写入三步曲”：临时置
        NORMAL → insert → see(END) 滚到底 → 置回 DISABLED。注意本方法只
        被主线程的 _poll_queue 调用；后台 worker 线程从不直接调用它，而是
        往 result_queue 投 ("line", text, tag)，由主线程取出来后转调本方法。
        """
        self.at_output.config(state=tk.NORMAL)
        self.at_output.insert(tk.END, text + "\n", tag)
        self.at_output.see(tk.END)
        self.at_output.config(state=tk.DISABLED)

    def _run(self, kind: str):
        """四个探测按钮的统一入口回调：按 kind 分发并启动后台线程。

        参数:
            kind: 探测类型，"dhcp"/"dns"/"arp"/"vlan" 之一（按钮 lambda 传入）。

        核心易错点（本方法最重要的设计）：
          本方法运行在 **tkinter 主线程**。它先在这一步把四个输入框的
          StringVar 取值一次性快照成普通 dict args（代码里那行注释
          “worker 线程不能碰 tkinter 变量”指的就是这个），然后才启动
          threading.Thread 执行 self._worker(kind, args)。后台线程只拿到
          args 这个普通字典，绝不直接读 tkinter 变量——StringVar 不是线程
          安全的，跨线程读会造成随机取值错误甚至崩溃。
        随后清空旧输出、状态栏显示 Probing <kind>...，以 daemon 线程开工。
        """
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
        """后台探测线程：按 kind 分发给对应探测函数并回投结果。

        参数:
            kind: 探测类型 "dhcp"/"dns"/"arp"/"vlan"（由 _run 传入）；
            args: 主线程快照下来的参数字典，含键 dns/domain/expected/
                  arp_ip/vlan_ip（具体用哪几个由各 _probe_* 决定）。

        约束与消息格式（易错点）：
          * 本线程运行后台，**严禁直接操作 tkinter 控件**；所有输出都以
            **三元组** ("line", text, tag) 投进 self.result_queue——tag 是
            颜色标签（ok/warn/fail/na/title/plain），用于主线程着色；
          * 分发到的 _probe_* 若抛任何异常，捕获后投 ("line", "✗ 探测异常:
            ...", "fail")，避免线程静默崩溃；
          * finally 中保证投递 ("done", None) 结束信号，主线程据此把状态
            栏置 Done。
        """
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
        """DHCP 抢答探测的执行体（运行于后台线程，只往队列投递结果）。

        调用模块级 dhcp_probe(timeout=6)：广播 Discover 收集所有 Offer
        响应者，然后按数量判定：
          * err 非空（端口被占/无权限）→ 投 ("line", f"✗ {err}", "fail")；
          * 无任何响应 → 投 “6s 内无 DHCP Offer 响应”，tag="na"（本网段
            可能没有 DHCP 服务器）；
          * 有响应：逐个列出服务器 IP / 分配地址 / 时延 / 网关 / 掩码 /
            DNS / 租约；若 **>1 台服务器** → 投 "fail" 提示“私接路由器/
            非法 DHCP 抢答”，并给出排查建议（交换机开 DHCP Snooping、
            上联口设 trusted）；只有 1 台 → 投 "ok" 表示无抢答。

        注意：本方法自身绝不调 _log() 或改任何控件——输出全部经
        result_queue 以三元组 ("line", text, tag) 投递，由主线程刷新。
        """
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
        """DNS 重定向探测的执行体（运行于后台线程，只往队列投递结果）。

        参数:
            args: 参数字典（主线程 _run 快照），用到 dns（DNS 服务器 IP）、
                  domain（查询域名）、expected（预期解析 IP，可空）。

        流程：DNS 服务器 IP 为空直接投 "fail" 提示先填 IP；否则调
        dns_probe()，把返回的 (status, answers, rtt, err) 转成结论：
          * err 非空 → 投 "fail"（查询本身出错/超时）；
          * status=="ok"   → 投 "ok"，列出解析 IP 与时延，提示与预期一致；
          * status=="warn" → 投 "warn"：解析结果与预期 IP 不符，疑似 DNS
            被重定向/劫持（私接路由器抢答、出口劫持等），并提示核对 DHCP
            下发的 DNS 与出口策略；
          * status=="na"   → 只在 DNS 服务器 IP 非法时出现，且必带 err，
            已被上面的 err 分支以 "fail" 方式提示，不会单独走到这里。

        易错点：本方法只读 args 字典 + 写 result_queue（三元组），
        绝不操作 tkinter 控件；domain 为空时回落到默认 www.baidu.com。
        """
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
        """ARP 冲突/欺骗探测的执行体（运行于后台线程，只往队列投递结果）。

        参数:
            args: 参数字典，用到 arp_ip（目标 IP，通常是网关或疑似冲突地址）。

        流程：目标 IP 为空投 "fail" 提示先填；否则调 arp_probe(ip, repeat=3)
        采样 3 轮，返回 (macs, status, err)：
          * status=="fail" → 投 "fail"（目标不可达，或系统 ping 被禁）；
          * status=="ok"   → 逐一列出各次采样 MAC，投 "ok" 提示 MAC 稳定、
                             无 ARP 冲突；
          * status=="warn" 时细分（注意判读顺序与 err 内容相关）：
              - err 含“跨网段”→ 投 "warn"：目标可达但本机 ARP 无条目，
                **ARP 只能解析同网段设备**，需到目标同网段机器上探测；
              - 采集到 >1 个 MAC → 投 "warn"：同一 IP 出现多个 MAC，
                疑似 ARP 欺骗/重复 IP，建议 display arp 查真实归属、开启
                DAI（arp anti-attack）；
              - 其余 → 原样投 "warn"。

        易错点：判断“>1 个 MAC”与“跨网段”都必须**在 status=="warn" 分支
        内**区分处理，且跨网段判断优先于多 MAC 判断，顺序不能颠倒。
        """
        ip = args.get("arp_ip", "")
        if not ip:
            self.result_queue.put(("line", "✗ 请填 ARP 目标 IP（网关或疑似冲突的 IP）", "fail"))
            return
        self.result_queue.put(("line", f"== ARP 主动探测：{ip} 采样 3 次（ping 触发 + arp 表）==", "title"))
        macs, status, err = arp_probe(ip, repeat=3)
        if status == "fail":
            self.result_queue.put(("line", f"✗ {err}", "fail"))
            return
        for i, m in enumerate(macs, 1):
            self.result_queue.put(("line", f"  采样 {i}: {m}", "plain"))
        if status == "ok":
            self.result_queue.put(("line", f"✅ {ip} → {macs[0]}（稳定，无 ARP 冲突）", "ok"))
        elif status == "warn":
            if "跨网段" in (err or ""):
                self.result_queue.put(("line", f"⚠️ {err}", "warn"))
            elif len(macs) > 1:
                self.result_queue.put(("line", f"⚠️ 同一 IP 出现 {len(macs)} 个不同 MAC — 疑似 ARP 欺骗/重复 IP！", "warn"))
                self.result_queue.put(("line", "   排查：display arp 查该 IP 真实归属，DAI(arp anti-attack) 未开是主因", "plain"))
            else:
                self.result_queue.put(("line", f"⚠️ {err}", "warn"))

    def _probe_vlan(self, args: dict):
        """跨 VLAN 连通探测的执行体（运行于后台线程，只往队列投递结果）。

        参数:
            args: 参数字典，用到 vlan_ip（跨 VLAN 的目标 IP）。

        流程：目标 IP 为空投 "fail" 提示先填；否则调 vlan_probe(ip, count=4)
        即 icmp_ping ×4，按返回 (reachable, rtts, err) 判定：
          * err 非空 → 投 "fail"（系统 ping 调用失败/被禁）；
          * 可达 → 列出各次 RTT 与平均值，投 "warn"（黄色）提示：跨 VLAN
            可达——若这两个 VLAN 本应隔离，说明缺少跨 VLAN 访问控制
            （port-isolate / VLAN 间 ACL / 三层互访策略），并附排查建议；
          * 不可达 → 投 "na"：4 次全部超时（若本应互通，查 VLANIF/路由/
            ACL 配置）。

        易错点：可达结论刻意用 "warn"（黄色）而非 "ok"，因为“该通却通”
        意味着安全隔离失效——结论颜色本身就在提示这是一条需要人工判断的
        告警，阅读代码时不要把它当成普通成功。
        """
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
            self.result_queue.put(("line", "✅ 跨 VLAN 可达 — 若这两个 VLAN 本应隔离，说明缺少跨 VLAN 访问控制！", "warn"))
            self.result_queue.put(("line", "   排查：port-isolate / VLAN 间 ACL / 三层互访策略", "plain"))
        else:
            self.result_queue.put(("line", "➖ 4 次全部超时 — 不可达（若本应互通，查 VLANIF/路由/ACL）", "na"))

    def _poll_queue(self):
        """主线程常驻轮询：把 result_queue 消息刷到输出区（每 100ms 一次）。

        由 __init__ 的 after(100, self._poll_queue) 反复自调度，运行于
        tkinter 主线程，是后台探测线程与 UI 间唯一的通信通道。

        消息格式（**三元组/变长元组**，与 SecurityTestPanel 不同，注意区分）：
          ("line", text[, tag]) → 一行输出：text 为正文，tag 为颜色标签
                                   （ok/warn/fail/na/title/plain），缺省
                                   tag 时为 None 用默认色；
          ("done", None)        → 探测结束，状态栏置 "Done"。

        实现：while + get_nowait 一次取空当前全部消息，queue.Empty 结束本轮；
        末尾重新注册 after(100) 保持轮询，try/except 兜底窗口已销毁的异常。
        """
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
    """流量压测（Traffic Test）页签面板 / Traffic stress-test panel (V3, green accents)。

    功能定位
    --------
    向指定目标 IP/端口发送大流量数据包（UDP / ICMP / TCP / TCP SYN），用于压测
    网络设备/服务器的吞吐能力与稳定性。除发包外还提供：
      - 网关自动探测（Detect）：读取本机默认网关并一键填入目标 IP，方便直接压测网关；
      - 内置 TCP 接收端（Built-in TCP Receiver）：本机开 TCP 监听口收包，
        配合 TCP 发包做本机/对端回环吞吐测试；
      - 并发线程数、单线程发包速率（限速）等压测参数控制（rate=0 表示不限速）；
      - 实时统计展示：PPS、带宽 Mbps、总包数/总字节、已运行时长，以及滚动日志。

    线程模型（学习重点 / 易错点）
    -----------------------------
    - 发包在后台进行：TrafficGenerator.start() 会按“并发数”创建多个 daemon 工作线程，
      各自循环发包直到 running=False；GUI 主线程只负责发“启动/停止”指令与周期轮询统计，
      绝不阻塞界面。
    - 周期刷新用 Tk 的 after() 链式定时器（_start_monitor 每 500ms 自续一次），
      回调运行在 Tk 主线程，直接更新界面变量是安全的。
    - 但 TrafficGenerator / TCPServer 会把 self._log 当作 log_callback 在它们自己的
      工作线程里调用，而 _log 会直接操作 Tk 控件——Tk 本身并非线程安全，短小写入多数
      情况可用，严格做法是经 queue + after 轮询转发（本类为简化未做，属已知取舍）。
    - 跨线程统计一律走 Stats 内部的 lock 保护，读快照用 stats.snapshot() 或在锁内读字段，
      勿在主线程裸读累计量。

    生命周期
    --------
    __init__ 结尾即调用 _start_monitor() 开启周期刷新；destroy() 必须依次取消
    after 定时器并 stop generator / tcp_server，否则后台线程与定时链会泄漏并
    在页面销毁后继续运行（触碰已销毁控件而报错）。

    本页签使用绿色系高亮（GreenAccent / Danger 样式按钮），与全窗 V3 主题一致。
    """

    def __init__(self, master: tk.Widget) -> None:
        """初始化流量压测页签：登记状态属性 → 搭建界面 → 开启周期监控。

        参数:
            master: 父级 Tk 容器（通常是主 Notebook 的某一页签父 Frame）。

        关键逻辑/易错点:
            - 先为关键状态属性赋初值：generator（发包器，未启动时为 None）、
              tcp_server（内置 TCP 接收端，未启动时为 None）、monitor_id
              （after 定时器 id，destroy 时凭它取消定时）、start_time（发包开始时刻，
              供统计耗时与“已运行时长”计算）。以 None 作为“当前无该对象”的判空语义。
            - 随后调用 _build_ui() 一次性搭好全部控件，再调 _start_monitor()
              启动 500ms 一次的监控链（即便尚未发包也会空转轮询）。
            - 注意：构造阶段不会创建任何发包线程，真正发包要等用户点击 Start 后
              由 _on_start() 实例化 TrafficGenerator 才发生。

        返回:
            None
        """
        super().__init__(master)
        self.generator: TrafficGenerator | None = None
        self.tcp_server: TCPServer | None = None
        self.monitor_id: str | None = None
        self.start_time: float = 0.0
        self._build_ui()
        self._start_monitor()

    def destroy(self) -> None:
        """页面销毁清理：取消定时监控并停掉所有后台资源，再销毁控件树。

        参数:
            无（Tk 控件销毁回调自动调用，不传参）。

        关键逻辑/易错点（顺序敏感，勿颠倒）:
            1. 先取消 after() 周期定时器：monitor_id 有值才 after_cancel，并包
               try/except 兜底——销毁过程中回调队列里可能残留已失效的 id，
               直接调用可能抛 TclError；
            2. 再依次停止发包器 generator 与 TCP 接收端 tcp_server（内部各自
               把 running 置 False、关闭 socket 并对工作线程 join），防止销毁后
               后台线程仍尝试触碰正在回收的控件；
            3. 最后才 super().destroy() 真正释放控件树。
            若只做第 3 步而不停后台资源，daemon 线程与 after 定时链会在窗口
            关闭后继续存活（线程泄漏 / 幽灵回调报错），这是本类最常见的坑。
            其中 generator.stop() 最多 join 2s，若压测线程未及时退出不会死等。

        返回:
            None
        """
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
        """一次性搭建本页签全部界面控件（纯 UI 布局，不包含业务逻辑）。

        参数:
            无。

        布局分区（自上而下，全部存为 self.* 属性供启停按钮与监控回调使用）:
            1. Target Configuration：目标 IP/端口/协议 + 网关探测按钮与下拉框；
            2. Built-in TCP Receiver：内置 TCP 接收端监听端口、Start/Stop Server
               按钮、状态文本与实时收包计数（Rx: ...）；
            3. Traffic Parameters：并发线程数滑杆、包大小单选框+可手输输入框、
               每线程速率滑杆与“(0 = unlimited burst)”提示、红色限速警告行；
            4. Start / Stop 主控按钮与状态行（初始 Stop 禁用）；
            5. Real-time Statistics：PPS / 带宽 Mbps / 总包数 / 总字节 / 已用时间；
            6. Log：ScrolledText 滚动日志区（初始 DISABLED 只读，绿色系配色）。

        关键联动（易错点，学习重点）:
            - 并发/速率滑杆：ttk.Scale 通过 variable= 绑定 tk.IntVar，拖动时产生的
              是“浮点数字符串”，需回调里 int(float(val)) 转整数再写回 IntVar；
              同时 IntVar 用 trace_add("write") 挂了解析回调刷新旁边数值 Label，
              因此“拖滑杆→command 回调手动刷新”与“写变量→trace 自动刷新”双路径
              并存，两个 _update_*_label 调用幂等重复执行，不影响正确性。
            - 包大小：5 个 Radiobutton 与一个可手输 Entry 共用同一个 pkt_size_var，
              手输非数字时 IntVar.get() 会抛 TclError，读取方（_on_start）必须捕获。
            - 速率滑杆下方预留 rate_warn_var 红色 Label，专用于 rate=0（不限速）
              时的 CPU 占用警告，正常时不显示任何内容。
        """
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
        """把并发线程数当前值同步显示到滑杆右侧的数值 Label（conc_label）上。

        参数:
            无。

        触发时机（易错点）:
            - concurrency_var 被写入时由 trace_add("write") 自动触发（如拖滑杆、
              代码 set 值都会触发）；
            - 也被 _on_concurrency_scale 手动调用。二者重复但幂等，
              仅是把 IntVar 的整数转为字符串 set 到 Label 上。

        返回:
            None
        """
        self.conc_label.config(text=str(self.concurrency_var.get()))

    def _on_concurrency_scale(self, val):
        """“并发线程数”滑杆拖动回调（ttk.Scale 的 command 指定的处理器）。

        参数:
            val: Scale 拖动产生的新值，类型是“浮点数的字符串”（如 "12.0"），
                 不能直接当 int 使用——这是 ttk.Scale + IntVar 联动的经典坑。

        关键逻辑/易错点:
            - 先 int(float(val)) 把浮点字符串转成整数再写回 concurrency_var：
              保证 IntVar 内部始终存合法整数（IntVar.get() 返回 int，供
              TrafficGenerator 直接当线程数使用）；
            - 再手动调 _update_conc_label() 刷新右侧数值 Label；
              由于 IntVar 上还挂了 trace_add("write")，写变量本身也会触发一次
              同样的刷新——双路径幂等，效果一致。
            - 滑块范围 1~500，此回调由用户每次拖动连续触发，函数须轻量
              （仅两次赋值），不可放入耗时逻辑。

        返回:
            None
        """
        self.concurrency_var.set(int(float(val)))
        self._update_conc_label()

    def _update_rate_label(self):
        """把速率滑杆当前值同步到 Label，并联动维护“rate=0 不限速”的红色警告行。

        参数:
            无。

        关键逻辑（联动点）:
            - rate_var 每次被写入（trace_add("write") 或手动调用）都会刷新
              rate_label 文本，与并发滑杆的 _update_conc_label 机制相同；
            - 差别在于它还管理 rate_warn_var 警告文案：
                若 rate == 0 → 置中文警告“⚠️ rate = 0 不限速全速发包！……”，
                否则置空字符串。警告 Label 在 _build_ui 中已用红色粗体样式
                创建并绑定该变量，此处只改变量即可生效。

        易错点:
            - rate=0 表示“不限速、全速突发发包”，会吃满 CPU 并可能打爆本机
              回环/低端设备，故给出醒目提示；界面把 0 作为一个“危险档位”专门
              提示，阅读代码时不要把 0 误当作“不发包”。

        返回:
            None
        """
        self.rate_label.config(text=str(self.rate_var.get()))
        if self.rate_var.get() == 0:
            self.rate_warn_var.set("⚠️ rate = 0 不限速全速发包！会占用大量 CPU，请勿用于环回/本机高并发测试")
        else:
            self.rate_warn_var.set("")

    def _on_rate_scale(self, val):
        """“每线程发包速率”滑杆拖动回调（pkt/s/thread，范围 0~50000）。

        参数:
            val: Scale 传入的“浮点数字符串”新值（如 "2500.0"）。

        关键逻辑/易错点:
            - 与 _on_concurrency_scale 完全同构：先 int(float(val)) 归一为整数
              写回 rate_var，再调用 _update_rate_label()；
            - 注意 _update_rate_label() 内部会检查 rate==0 并切换红色警告文案，
              所以“拖到 0（最左端）”会立刻在界面上亮起“不限速”警告——这是
              刻意设计的防护提示，不是 bug；
            - 滑杆最左端即 0（unlimited burst），阅读代码时留意 from_=0。

        返回:
            None
        """
        self.rate_var.set(int(float(val)))
        self._update_rate_label()

    def _on_detect_gateways(self):
        """点击 Detect 按钮：自动探测本机默认网关，供用户一键填入目标 IP。

        参数:
            无。

        关键逻辑/易错点（网关探测流程）:
            - detect_gateways() 通过 PowerShell（Get-NetRoute -DestinationPrefix
              0.0.0.0/0）查询本机默认路由，返回 [(显示名, IP), ...]；
              该调用是“同步”的（会临时拉起 PowerShell 子进程），在慢机器或
              杀软拦截时可能让界面短暂无响应，属可接受的取舍。
            - 一条网关都没有 → 弹 showwarning 提示常见原因（无活动网卡 /
              PowerShell 不可用），并记一条日志后 return。
            - 探测成功 → 动态创建 self._gateway_map = {显示名: IP}（注意该属性
              是“探测成功后才有”，后续 _on_gateway_selected 里用 hasattr 防御，
              这是阅读时的易错点）；把显示名列表写进下拉框 values，
              自动选中第 0 项并立即调用 _on_gateway_selected() 把 IP 填入
              ip_var（用户不点下拉也能直接得到第一个网关地址）。
            - 最后逐条把“显示名 → IP”写日志，方便追踪探测结果。

        返回:
            None
        """
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
        """网关下拉框选中事件：把所选网关的真实 IP 填入目标 IP 输入框。

        参数:
            event: Tk 事件对象，由 <<ComboboxSelected>> 事件绑定自动传入；
                   本方法体不依赖它（手动调用时传 None 也可，如
                   _on_detect_gateways 中自动选中第一项后的调用）。

        关键逻辑/易错点:
            - 下拉框显示的是“接口别名（显示名）”，而目标 IP 需要的是真实地址，
              因此必须经 _gateway_map（探测时建立的 {显示名: IP} 字典）反查，
              不能把显示名直接当 IP 用；
            - _gateway_map 只有在探测成功后才存在（动态属性），读取前必须用
              hasattr(self, '_gateway_map') 判空，否则首次运行尚未探测时
              用户手动从空下拉框操作会 AttributeError——这是本类经典防御点。

        返回:
            None
        """
        selected = self.gateway_var.get()
        if hasattr(self, '_gateway_map') and selected in self._gateway_map:
            self.ip_var.set(self._gateway_map[selected])

    def _on_start(self):
        """点击 Start：逐项校验压测参数，通过后创建并启动 TrafficGenerator 发包。

        参数:
            无（从各界面变量读取配置）。

        参数校验（顺序不可乱，每步失败都弹错并 return）:
            1. 目标 IP 去空格后不能为空；
            2. 包大小：pkt_size_var 可能被手输输入框写成非数字，IntVar.get()
               会抛 tk.TclError——必须 try/except 捕获并提示“Packet Size must
               be a number”；值须在 1 ~ 65535（IPv4 数据报负载上限）；
            3. 端口串：parse_ports() 解析 '8080' / '80,443' /
               '100-1000' / '100-1000:50' 等格式，返回 (端口列表, 描述文本)；
               解析失败时端口列表为空，按描述文本弹错（如范围倒置、含非法字符）。

        启动逻辑/易错点（线程调度重点）:
            - 用当前各变量一次性构造 TrafficGenerator，并把 self._log 作为
              log_callback 传入——发包工作线程会回调它写日志；
            - generator.start() 内部立刻按并发数创建 daemon 工作线程并返回，
              因此本方法不阻塞界面（Start 之后可以立刻拖滑杆/点 Stop）；
            - start_time 用 time.perf_counter() 打点（高精度单调时钟，不受
              系统改时间影响），供 _monitor_tick 计算已运行时长、_on_stop
              计算平均速率；
            - 按钮互斥：Start 置 DISABLED / Stop 置 NORMAL，防止重复启动
              产生两批并发线程；状态行置 "Running..."；
            - 启动日志一次性打印 threads / protocol / ip / ports / pkt_size /
              rate，便于事后核对“这次到底用什么参数压的”。

        返回:
            None
        """
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
        """点击 Stop：停止发包、按加锁读取的累计量输出平均统计，并复位界面。

        参数:
            无。

        关键逻辑/易错点:
            - 仅当 self.generator 存在时才执行停止流程（判空即“当前没有
              生成器”，与 destroy 的语义一致；若用户连点 Stop 也不会崩）；
            - generator.stop() 内部把 running 置 False，并对各工作线程
              join(timeout=2)——有 2s 上限，线程未及时退出也不死等界面；
            - 统计读取必须在 stats.lock 临界区内（total_packets / total_bytes
              由多个发包线程并发累加），不可裸读——这是多线程统计的正确姿势；
              也可改用 stats.snapshot() 等效；
            - 平均速率按“总量 ÷ 实际耗时”计算：avg_pps = 总包数/elapsed，
              avg_mbps = (总字节×8)/elapsed/1e6（字节×8 转比特再除 1e6 得 Mbps，
              此处 elapsed 来自 perf_counter 差，>0 才除，否则兜底 0）；
            - 停止后 self.generator 置 None——后续 destroy()/再次 Start 都靠
              这个判空语义判断“当前有无生成器”；
            - 界面复位：状态行回 "Idle"，PPS/带宽/总包/总字节清零、
              时长回 "00:00:00"，按钮换回 Start 可用 / Stop 禁用。

        返回:
            None
        """
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
        """点击 Start Server：校验端口并在本机启动内置 TCP 接收端。

        参数:
            无（端口取自 tcp_srv_port_var）。

        校验与易错点:
            - 监听端口输入框与 IntVar 绑定，留空或手输非数字时 IntVar.get()
              抛 tk.TclError，必须捕获并弹错；端口须在 1 ~ 65535。
            - TCPServer.start() 内部创建 daemon 的 accept 线程（每个连接再开
              一个收包线程），并尝试 bind 0.0.0.0:port；若端口被占用等 bind
              失败，它会把 running 置 False 并记日志返回——因此调用后不能
              盲目认为“一定成功”，必须检查 self.tcp_server.running 再更新界面：
              仅当确认监听成功，才把 Start Server 置 DISABLED、Stop Server
              置 NORMAL、状态文本改为 "Listening"。

        线程提醒: 接收端全程在后台线程收包，收包计数由 Stats.lock 保护，
        界面侧由 _monitor_tick 周期读取刷新 Rx 显示，本方法不做任何收包逻辑。

        返回:
            None
        """
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
        """点击 Stop Server：停止内置 TCP 接收端并复位其界面状态。

        参数:
            无。

        关键逻辑/易错点:
            - self.tcp_server 判空后停止并置 None（与 generator 相同——
              “None 即当前无对象”的语义贯穿本类，destroy 与再次 Start 都依赖它）；
            - TCPServer.stop() 内部把 running 置 False 并 close 监听 socket，
              使 accept 线程退出（收包线程随之结束），不会残留监听端口；
            - 界面复位：Start Server 恢复可点、Stop Server 置 DISABLED、
              状态文本回 "Stopped"，并把收包计数显示（tcp_srv_rx_var）清空，
              避免停服后仍显示旧统计。

        返回:
            None
        """
        if self.tcp_server:
            self.tcp_server.stop()
            self.tcp_server = None
        self.tcp_srv_start_btn.config(state=tk.NORMAL)
        self.tcp_srv_stop_btn.config(state=tk.DISABLED)
        self.tcp_srv_status_var.set("Stopped")
        self.tcp_srv_rx_var.set("")

    def _start_monitor(self):
        """开启并维持 500ms 一次的周期监控（链式 after 定时器，本类的心脏）。

        参数:
            无。

        关键逻辑/易错点（线程/定时调度重点）:
            - 结构是“先执行再续订”：立即执行一次 _monitor_tick() 让界面马上
              有数据，随后用 self.after(500, self._start_monitor) 预约 500ms 后
              再次调用本方法——回调里再次调用自己，形成自续定时链，等价于
              一个运行在 Tk 主线程上的轻量周期任务；
            - 每次续订都把返回的新定时器 id 存进 self.monitor_id，destroy()
              据此 after_cancel 取消链条——id 每次都在更新，cancel 的是最新
              那一个预约；
            - 本方法只在 __init__ 中调用一次；若误调用两次会出现两条并行
              定时链（刷新频率翻倍、且 destroy 只能取消最新一条），属经典陷阱；
            - after 回调始终在 Tk 主线程执行，因此 _monitor_tick 里直接改
              界面变量是线程安全的——这也是“界面刷新不放子线程”的原因。
            - 500ms 间隔同时决定了瞬时速率统计的采样窗口：_monitor_tick 里
              调 stats.tick(0.5) 与其保持一致。

        返回:
            None
        """
        self._monitor_tick()
        self.monitor_id = self.after(500, self._start_monitor)

    def _monitor_tick(self):
        """周期刷新回调：实时更新发包统计与 TCP 接收端收包统计到界面。

        参数:
            无（由 after 定时链驱动，运行于 Tk 主线程）。

        发包侧逻辑（_on_start 后生效）:
            - 仅当 generator 存在且 running 才统计，先算 elapsed（perf_counter
              差，即“已运行时长”）；
            - 调 stats.tick(0.5) 让 Stats 按 500ms 采样窗做滑动差分：以
              (本次累计 - 上次累计)/0.5 得到瞬时 PPS 与瞬时 BPS（字节/秒），
              再 snapshot() 在锁内一次取齐 (pps, bps, 总包数, 总字节) 四元组，
              避免多次加锁读到不一致的组合；
            - 显示换算（易错点）：界面带宽用 Mbps，而 Stats 的 bps 是
              “字节/秒”——需 ×8 转比特再 ÷1e6 才得 Mbps，即 (bps*8)/1e6；
            - 总字节用 _fmt_bytes() 人性化显示，时长格式化为 HH:MM:SS。

        TCP 接收端侧逻辑:
            - tcp_server 存在且 running 时，持其 stats.lock 读取累计收包数/
              字节（勿裸读），刷新右下角 Rx 文本（TCPServer._fmt 负责字节格式化）。

        易错点:
            - 本回调在主线程跑，只做轻量读与 set，绝不能放 sleep/发包等耗时
              逻辑，否则 500ms 周期被打乱、界面卡顿；
            - tick(0.5) 的 0.5 必须与 after 间隔一致，否则瞬时速率被错算。

        返回:
            None
        """
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
        """向页签底部日志区追加一行带时间戳的日志，并自动滚动到底部。

        参数:
            msg: 要打印的日志正文（不含时间戳；时间戳在方法内生成）。

        关键逻辑/易错点:
            - ScrolledText 平时处于 DISABLED（只读，防用户误改日志），写入必须
              先 config(state=NORMAL) 解锁 → insert → 再 config(state=DISABLED)
              锁回，否则 insert 静默无效；三个步骤顺序不能换；
            - insert 用 tk.END 追加在文末，随后的 see(tk.END) 把可视区滚到
              最新一行（长日志时否则不会自动滚动）；
            - 线程安全提醒（重要）：本方法会被 TrafficGenerator / TCPServer
              当作 log_callback 在各自的“工作线程”里调用，即后台线程直接操作
              Tk 控件。Tk 并非线程安全，多数平台下短小插入可用，但并发量高时
              有极小概率出现 Tcl 竞态；本类为保持简洁未做 queue+after 转发，
              阅读与扩展时请知晓这一已知取舍。

        返回:
            None
        """
        self.log_area.config(state=tk.NORMAL)
        timestamp = time.strftime("%H:%M:%S")
        self.log_area.insert(tk.END, f"[{timestamp}] {msg}\n")
        self.log_area.see(tk.END)
        self.log_area.config(state=tk.DISABLED)

    @staticmethod
    def _fmt_bytes(b: int) -> str:
        """把字节数格式化为人类易读的字符串（B / KB / MB / GB 自动选档）。

        参数:
            b: 字节总数（int，非负；如 1536 → '1.5 KB'）。

        返回:
            str：
              - b < 1024        → f"{b} B"        （整数，无小数）
              - b < 1024²       → f"{b/1024:.1f} KB"
              - b < 1024³       → f"{b/1024²:.1f} MB"
              - 其余            → f"{b/1024³:.2f} GB"
            分级按 1024 进制（KiB/MiB 意义上的“KB/MB”），与网络设备常用口径一致。

        关键逻辑/易错点:
            - 纯函数、不触碰实例状态，故装饰为 @staticmethod：既可 self._fmt_bytes(...)
              调用，也可在类外以 TrafficTestPanel._fmt_bytes(...) 直接用；
            - 注意 TCPServer 内部另有一个同名静态方法 _fmt（本类用 _fmt_bytes，
              接收端用 TCPServer._fmt），二者职责相同但实现独立、互不干扰，
              阅读时勿混淆；
            - 边界注意：恰好等于 1024 的幂（如 1024）会落到下一档输出 '1.0 KB'
              而不是 '1024 B'，属预期行为。
        """
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

    ── 界面结构 ──
    基于 ttk.Notebook 的七个页签 / seven tabs:
      - Single Host      : 单机巡检 / single device inspection
      - Batch Inspection : 并行批量巡检 + 异常检测 + 报告导出 / parallel batch
      - Config Backup    : 网络设备配置备份 / running-config backup
      - Profiles         : 连接信息增删改查 / connection profile CRUD
      - Traffic / Security / Active Test : 三个独立测试页签，分别由模块级面板类
        TrafficTestPanel / SecurityTestPanel / ActiveTestPanel 构建并注入本 Notebook

    ── 线程模型（阅读本类各方法前务必先理解）──
      1. tkinter 不是线程安全的：SSH 巡检等耗时操作一律放在后台 daemon 线程执行
         （单机走 _single_worker，批量走 _batch_worker_parallel）。
      2. 工作线程绝不直接操作任何 tk 控件，而是把 (target, msg_type, data) 三元组
         放入 self.result_queue（协议见下方「队列消息格式」注释），主线程通过
         _poll_queue() 每 100ms 轮询队列并刷新界面。
      3. 公共开关：self.stop_event（停止信号，Esc 触发 _stop_all）、self.running（是否在跑）。
      4. 易错点：启动任何巡检前，必须在主线程内把 tk 变量（Entry/BooleanVar 等）读成
         普通 Python 值再传给工作线程——本类所有 *_start* 方法都遵守这一约定。

    ── 数据持久化 ──
      - PROFILES_FILE（profiles.json）：连接档案列表 self.profiles
      - PRESETS_FILE（presets.json）：命令预设列表 self.presets
      读写均为 {"<类型>": [...]} 结构 + utf-8 编码 + ensure_ascii=False（中文可读、不转义）。

    ── 输出与异常检测 ──
      - detect_anomalies(devtype, title, output)：按设备类型与命令标题对命令输出做阈值匹配，
        返回 {severity, desc, value, unit, threshold} 形式的告警字典列表（severity: high/mid/low）。
      - _filter_output()：压缩输出、剔除命令回显中的噪声行（提示语/空行等），
        保留关键信息；严重/警告/一般级别行用不同颜色标签着色显示。
    """

    # ────────── 队列消息格式 / Queue Message Protocol ──────────
    # 三元组 (target, msg_type, data) / three-tuple
    #   target  : "single" | "batch" | "backup"  → 路由到哪个输出区 / output routing
    #   msg_type: "output" | "error" | "alert" | "result" | "summary"
    #             | "status" | "device_status" | "progress" | "done"
    #   data    : str (output/error/summary) | dict (alert) |
    #             tuple (result/device_status) | int (progress) | None (done)

    def __init__(self, root: tk.Tk) -> None:
        """
        构造函数：初始化线程通信设施、共享状态，加载持久化配置，并搭建全部 UI。

        :param root: tkinter 根窗口（Tk 实例），由外部创建后传入，本类只负责往窗口内装控件。

        主要流程：
          1. 设置窗口标题/尺寸/最小尺寸，并调用 setup_app_style() 套用蓝白主题；
          2. 建立线程通信基础：self.result_queue（工作线程 → UI 的消息队列）、
             self.stop_event（停止信号 Event）、self.running（是否正在巡检）；
          3. 从 JSON 文件加载 profiles（连接档案）与 presets（命令预设），
             并初始化 _device_row（host→树行 iid 映射）、_host_anom_level（异常级别缓存）；
          4. 注册全局快捷键：Esc=停止全部、Ctrl+Enter=按当前页签启动巡检；
          5. 调用 _setup_ui() 构建七个页签，最后启动 _poll_queue()（每 100ms 轮询结果队列）。

        易错点：
          - result_queue / stop_event 必须先于 _setup_ui() 创建，因为构建页签时
            按钮回调已可能引用它们；
          - 所有 tk 变量的读取必须在主线程完成（工作线程只收发队列消息）。
        """
        self.root = root
        self.root.title(f"Network Inspection System V5 (v{__version__}) — 网络巡检工具")
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
        """从 profiles.json 读取已保存的连接信息 / Load saved connections.

        功能：应用启动时调用，把磁盘上保存的「连接档案」读入内存（结果存入 self.profiles）。
        文件结构：{"profiles": [{"name","host","port","user","password","devtype"}, ...]}，
        具体条目字段见 _save_profile()。

        :return: profile 字典列表；若文件不存在、损坏或 JSON 解析失败则返回空列表。
                 注意这是刻意设计的容错——配置文件有问题时程序照常启动，绝不抛异常。
        """
        if not os.path.exists(PROFILES_FILE):
            return []
        try:
            with open(PROFILES_FILE, "r", encoding="utf-8") as f:
                return json.load(f).get("profiles", [])
        except Exception:
            return []

    def _save_profiles(self) -> None:
        """将 profiles 列表写回 profiles.json / Persist profiles to JSON.

        功能：把 self.profiles 以 {"profiles": [...]} 结构写入 PROFILES_FILE。
        写文件要点：
          - 编码 utf-8、ensure_ascii=False：密码/备注中的中文原样保存，便于人工查看；
          - indent=2 美化排版，方便同学直接打开 JSON 文件调试数据。

        :return: 无。每次「增/改/删 Profile」后都应调用本方法落盘，再刷新界面。
        """
        with open(PROFILES_FILE, "w", encoding="utf-8") as f:
            json.dump({"profiles": self.profiles}, f, indent=2, ensure_ascii=False)

    # ═══════════════════════════════════════════════════════════
    # Presets 持久化 / Presets Persistence (presets.json)
    # ═══════════════════════════════════════════════════════════

    def _load_presets(self) -> list:
        """从 presets.json 读入巡检预设方案 / Load inspection presets.

        功能：应用启动时调用，读取命令「预设方案」（一组带标题的命令）到 self.presets。
        文件结构：{"presets": [{"name","devtype","cmds": {标题:命令}}, ...]}。

        :return: preset 字典列表；文件缺失/损坏时静默返回空列表（与 _load_profiles 同款容错）。
        """
        if not os.path.exists(PRESETS_FILE):
            return []
        try:
            with open(PRESETS_FILE, "r", encoding="utf-8") as f:
                return json.load(f).get("presets", [])
        except Exception:
            return []

    def _save_presets(self) -> None:
        """将 presets 写回 presets.json / Persist presets to JSON.

        功能：把 self.presets 以 {"presets": [...]} 结构写入 PRESETS_FILE。
        与 _save_profiles 相同的 JSON 约定：utf-8 + ensure_ascii=False + indent=2。

        :return: 无。
        """
        with open(PRESETS_FILE, "w", encoding="utf-8") as f:
            json.dump({"presets": self.presets}, f, indent=2, ensure_ascii=False)

    # ═══════════════════════════════════════════════════════════
    # 顶层 UI：Notebook + 4 标签页 + 状态栏 / Top-level Layout
    # ═══════════════════════════════════════════════════════════

    def _setup_ui(self) -> None:
        """
        搭建顶层 UI：一个 ttk.Notebook + 七个页签 + 底部状态栏。

        功能：创建主布局骨架，并依次调用各页签的构建方法：
          - 四个核心页签由本类方法构建：_build_single_tab / _build_batch_tab /
            _build_backup_tab / _build_profiles_tab；
          - Traffic Test / Security Test / Active Test 三个页签直接实例化
            模块级面板类 TrafficTestPanel、SecurityTestPanel（传 self 以便回调本类方法）、
            ActiveTestPanel，再 add 进 Notebook；
          - 底部创建 self.status_var 状态栏（StringVar + SUNKEN 凹槽样式），
            供 _set_status() 更新提示文本。

        :return: 无。本方法只负责「创建并放置控件」，控件细节由各 _build_*_tab 完成。
        """
        notebook = ttk.Notebook(self.root)
        notebook.pack(fill=tk.BOTH, expand=True, padx=5, pady=5)

        self.tab_single   = ttk.Frame(notebook); notebook.add(self.tab_single,   text="Single Host")
        self.tab_batch    = ttk.Frame(notebook); notebook.add(self.tab_batch,    text="Batch Inspection")
        self.tab_backup   = ttk.Frame(notebook); notebook.add(self.tab_backup,   text="Config Backup")
        self.tab_profiles = ttk.Frame(notebook); notebook.add(self.tab_profiles, text="Profiles")
        self.tab_traffic  = TrafficTestPanel(notebook); notebook.add(self.tab_traffic, text="Traffic Test")
        self.tab_security = SecurityTestPanel(notebook, self); notebook.add(self.tab_security, text="Security Test")
        self.tab_active   = ActiveTestPanel(notebook);        notebook.add(self.tab_active,   text="Active Test")
        # 环路 / 异常告警页签（V4/V5 新增）
        if RingAlertPanel is not None:
            self.tab_ring = RingAlertPanel(notebook, self)
            notebook.add(self.tab_ring, text="Ring Alert")

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
        """构建单机巡检标签页 / Build single-host inspection tab.

        功能：在 tab_single 上布置三大区域（自上而下）：
          1) Connection 输入区（LabelFrame）：
             - profile_combo：档案快速下拉，选中触发 _on_profile_selected 回填表单；
             - single_devtype / single_host / single_port / single_user / single_pwd：
               设备类型、IP、端口（默认 22）、用户名、密码；
             - 复选框：anomaly_toggle_single（异常检测）、compact_toggle_single（压缩输出）、
               quick_toggle_single（快速巡检，切换回调 _on_quick_single_toggle）、
               precheck_var（ping 预检，与批量页共享同一开关）；
             - btn_single（开始）/ btn_single_stop（停止，初始 DISABLED）/ btn_ip_intel（IP 情报）。
             输入框内按回车 <Return> 等价于点「开始巡检」。
          2) Commands (editable) 命令编辑区：
             - single_cmds_text 文本框，每行格式「标题::命令」（见下方灰色提示）；
             - 按钮：Reset to Default（重置）、Presets 的 Load/Save/Del（预设方案）；
             - cmd_count_var 显示当前命令条数；本区域初始化后调用 _load_default_commands("linux")。
          3) Output 输出区：搜索栏（single_search_entry + ↑/↓/⚠下一异常 按钮）与
             single_output 只读文本框；并预先配置颜色标签：
             critical(红)/warning(橙)/minor(黄)/anom_cur(异常高亮)/search_match(黄)/search_current(橙)。

        :return: 无。所有控件都存成 self.* 属性，供其它方法（如 _start_single/_single_worker
                 经队列回调 _poll_queue）读写。
        """
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
        ttk.Button(search_row, text="⚠上一异常", width=11, command=lambda: self._jump_to_prev_anomaly(
            self.single_output, self.single_search_label)).pack(side=tk.LEFT, padx=(1, 5))
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
        """设备类型下拉框变更时重新加载对应命令集 / Reload commands on type change.

        功能：Single Host 页设备类型 Combobox 绑定的 <<ComboboxSelected>> 回调：
        根据所选类型（经 DEVTYPE_MAP 将界面标签映射为内部类型名，未知回退 "linux"）
        重新加载默认/快速命令集，并在状态栏提示已切换。

        :param event: tkinter 自动传入的事件对象（本方法未使用，保留仅为兼容回调签名）。

        :return: 无。
        易错点：DEVTYPE_MAP.get(..., "linux") 的兜底——界面值取不到时按 Linux 处理而非报错。
        """
        devtype = DEVTYPE_MAP.get(self.single_devtype.get(), "linux")
        self._load_commands_for_current_mode(devtype)
        self._set_status(f"Switched to {self.single_devtype.get()} — commands reloaded")

    def _on_quick_single_toggle(self) -> None:
        """简短巡检复选框切换：ON 锁定编辑并加载简短命令 / Toggle quick mode.

        功能：Single Host 页「Quick Inspection」复选框的 command 回调。
        勾选 ON ：加载该类型 QUICK_COMMANDS 并禁用命令文本框（灰底），防止误改；
        取消 OFF：恢复默认完整命令集，文本框回到可编辑（白底）状态。

        :return: 无。
        易错点：此回调只负责「切模式 + 换命令集」，用户直接改类型时应走
                _load_commands_for_current_mode 以同时考虑 Quick 开关状态。
        """
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
        """根据当前 Quick 开关状态加载对应命令集 / Load commands based on Quick toggle.

        功能：命令加载的统一入口——查看 quick_toggle_single 当前状态，
        为 True 则加载 QUICK_COMMANDS，否则加载 DEFAULT_COMMANDS。

        :param devtype: 内部设备类型名（linux/cisco/huawei/h3c/ruijie 之一），
                        用于从 QUICK_COMMANDS / DEFAULT_COMMANDS 字典中取值。

        :return: 无。
        """
        if self.quick_toggle_single.get():
            self._load_quick_commands(devtype)
        else:
            self._load_default_commands(devtype)

    def _load_quick_commands(self, devtype: str) -> None:
        """将 QUICK_COMMANDS 写入文本框并锁定编辑 / Load quick set & lock editing.

        功能：把 QUICK_COMMANDS.get(devtype, {})（键值: 标题→命令）写入命令文本框，
        并把文本框设为 DISABLED 只读。注意：这里不再改背景色（变色逻辑在切换回调里做）。

        :param devtype: 内部设备类型名；未知类型取空字典兜底（文本区会被清空）。

        :return: 无。
        """
        self._write_commands_to_text(QUICK_COMMANDS.get(devtype, {}))
        self.single_cmds_text.config(state=tk.DISABLED)

    def _load_default_commands(self, devtype: str) -> None:
        """将 DEFAULT_COMMANDS 写入文本框 / Load default full command set.

        功能：把 DEFAULT_COMMANDS.get(devtype, {}) 完整命令集写入命令文本框。
        只负责写内容，不负责改文本框的可编辑状态（与 _load_quick_commands 的差异点）。

        :param devtype: 内部设备类型名；未知类型取空字典兜底。

        :return: 无。
        """
        self._write_commands_to_text(DEFAULT_COMMANDS.get(devtype, {}))

    def _write_commands_to_text(self, cmds: dict) -> None:
        """把 {标题:命令} 字典写入文本框（格式 title::cmd）/ Write command dict to text area.

        功能：清空 single_cmds_text 并以每行「标题::命令」的形式写入整个命令集，
        随后刷新命令计数标签。

        :param cmds: 命令字典 {标题(str): 命令文本(str)}；写入顺序即字典迭代顺序。

        :return: 无。
        易错点：写入前会把文本框强制设为 NORMAL（否则 DISABLED 状态下无法 insert）；
                调用方如需保持只读，应在写完后自行再 config(state=DISABLED)。
        """
        lines = [f"{t}::{c}" for t, c in cmds.items()]
        self.single_cmds_text.config(state=tk.NORMAL)
        self.single_cmds_text.delete("1.0", tk.END)
        self.single_cmds_text.insert("1.0", "\n".join(lines))
        self._update_cmd_count()

    def _parse_commands_from_text(self) -> dict:
        """从文本框解析 {标题: 命令} 字典，跳过空行和 # 注释 / Parse text area to cmd dict.

        功能：把命令文本框当前内容解析回 {标题: 命令} 字典，供启动巡检时传给 worker。
        解析规则（按行处理）：
          1. 去首尾空白；空行与以 # 开头的行直接跳过（支持写注释说明）；
          2. 含 :: 的行才有效，且只用 split("::", 1) 切第一刀——
             即命令本身即使再含 :: 也不会被误拆，标题与命令分别 strip；
          3. 标题与命令都非空才收录。

        :return: 解析出的命令字典；无有效行时返回空 dict（调用方会据此提示「无命令」）。

        易错点：get("1.0", tk.END) 会带回文末换行，splitlines() 已处理，无需额外 strip 整体。
        """
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
        """恢复当前设备类型的默认/简短命令集 / Reset commands to defaults (or quick).

        功能：命令编辑区「Reset to Default」按钮回调——按当前设备类型重新加载命令集；
        若 Quick 模式开着则仍加载简短集（即尊重开关状态）。

        :return: 无。
        """
        devtype = DEVTYPE_MAP.get(self.single_devtype.get(), "linux")
        self._load_commands_for_current_mode(devtype)

    def _update_cmd_count(self) -> None:
        """更新命令计数标签 / Update command count label.

        功能：实时解析文本框内容，把有效命令条数显示到 cmd_count_var
        （右侧灰色标签，形如 "N command(s)"）。

        :return: 无。每次命令内容被改写后都应调用一次以保持计数同步。
        """
        self.cmd_count_var.set(f"{len(self._parse_commands_from_text())} command(s)")

    # ────────── Profile 快速加载 / Profile Quick Load ──────────

    def _on_profile_selected(self, event=None) -> None:
        """选择 Profile 后自动填入 IP/端口/用户/密码/设备类型 / Auto-fill form from profile.

        功能：Single Host 页 Load Profile 下拉框的 <<ComboboxSelected>> 回调。
        按所选档案名在 self.profiles 中查找，命中后把 host/port/user/password 分别
        delete+insert 回填到对应 Entry，并把设备类型下拉框切到该档案的 devtype，
        同时按档案类型重载命令集，最后在状态栏提示。

        :param event: tkinter 事件对象（未使用，仅兼容回调签名）。

        :return: 无。
        易错点：档案里存的是内部类型键（devtype），写进下拉框前必须经
                DEVTYPE_LABEL_OF 换成界面显示标签；查不到同名档案时函数静默返回。
        """
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
        """构建批量巡检标签页 / Build batch inspection tab.

        功能：在 tab_batch 上布置批量巡检完整控件（自上而下）：
          1) Device List File 区：batch_filepath（默认 devices.txt）+ Browse(_browse_file)
             + Load(_load_devices)；灰色提示行给出了设备文件格式
             IP:user:password:[linux|cisco|huawei]:"cmd1,cmd2,..."（type 可省略，默认 cisco）。
          2) Devices 设备树 device_tree（五列 host/type/user/status/commands，extended 多选）：
             行的 tag 编码了完整连接信息 host|devtype|user|pwd|cmds（供 _get_selected_devices 反解）；
             预配 4 种状态色：row_high 红 / row_mid 橙 / row_ok 绿 / row_fail 灰。
          3) 操作按钮行：Run(_start_batch_selected) / Stop(_stop_all) / IP Intel；
             concurrency_var 并发数 Spinbox(1~10, 默认 3)；
             anomaly/compact/quick 三个复选框 + 右端 Export HTML/CSV（初始 DISABLED，
             巡检完成后才由 _poll_queue 启用）与 batch_progress 进度条、progress_label。
          4) Output 区：搜索栏 + batch_output 输出框，配 critical/warning/minor/anom_cur/
             success 等颜色标签。

        :return: 无。控件全部保存为 self.* 供线程回调与导出方法使用。
        易错点：设备行 tag 是后续取设备/取密码的唯一载体，勿改动 treeview 的
                item(tags=...) 结构。
        """
        # ── 设备文件选择 / device file selection ──
        ff = ttk.LabelFrame(self.tab_batch, text="Device List File", padding=10)
        ff.pack(fill=tk.X, padx=10, pady=(10, 5))
        ttk.Label(ff,
            text='Format: IP:user:password:[linux|cisco|huawei]:"cmd1,cmd2,..."  (type optional, default cisco)  |  Excel(.xlsx) 亦可: IP|用户名|密码|类型|命令 五列',
            foreground="gray", font=("", 8)
        ).pack(anchor=tk.W, pady=(0,5))
        row = ttk.Frame(ff); row.pack(fill=tk.X)
        # 默认设备文件：同目录存在 devices.xlsx 时优先用它（便于在 Excel 里维护设备表），否则回退 devices.txt
        # Default device file: prefer devices.xlsx when present (easier to maintain in Excel), else devices.txt
        _default_devfile = "devices.xlsx" if os.path.exists("devices.xlsx") else "devices.txt"
        self.batch_filepath = tk.StringVar(value=_default_devfile)
        ttk.Entry(row, textvariable=self.batch_filepath).pack(side=tk.LEFT, fill=tk.X, expand=True)
        ttk.Button(row, text="Browse...", command=self._browse_file).pack(side=tk.LEFT, padx=(5,0))
        ttk.Button(row, text="Load", command=self._load_devices).pack(side=tk.LEFT, padx=(5,0))
        # 把当前设备文件（txt/xlsx 皆可）导出为 Excel 表 / export current device file to Excel
        ttk.Button(row, text="→ Excel", command=self._export_devices_excel).pack(side=tk.LEFT, padx=(5,0))

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
        ttk.Button(srow, text="⚠上一异常", width=11, command=lambda: self._jump_to_prev_anomaly(
            self.batch_output, self.batch_search_label)).pack(side=tk.LEFT, padx=(1,5))
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
        """构建配置备份标签页 / Build config backup tab.

        功能：在 tab_backup 上布置配置备份控件：
          1) Device List 区：backup_filepath + Browse(_browse_backup_file)/Load(_load_backup_devices)；
             Backup Dir 区：backup_dir_var（默认 BACKUP_DIR 常量）+ 目录选择按钮 _choose_backup_dir。
          2) Devices 树 backup_tree（三列 host/type/user，extended 多选）：
             行的 tag 编码为 host|devtype|user|pwd —— 注意只有 4 段，
             与 batch 树 5 段 tag 不同（备份不需要命令列表）；
             本页只显示非 Linux 设备（Linux 无需保存 running-config 的备份逻辑）。
          3) 按钮行：Backup Selected(_start_backup) / Stop + backup_progress 进度条；
             下方 Backup Log 日志区 backup_output（只读）。

        :return: 无。备份树数据流向：_load_backup_devices → _start_backup（在类后段实现）。
        """
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
        """
        弹出文件选择框挑选设备列表文件（Config Backup 页用）。

        功能：用 filedialog.askopenfilename 让用户选择 txt 设备文件；
        选到（非空路径）后写入 backup_filepath 并立即调用 _load_backup_devices() 刷新备份树。
        与 _browse_file（batch 页版）逻辑同构，只是目标 StringVar 与加载函数不同。

        :return: 无。用户取消选择时不做任何事。
        """
        path = filedialog.askopenfilename(title="Select device list file",
                                          filetypes=[("Device lists","*.txt *.xlsx *.xlsm"),
                                                     ("Text files","*.txt"),
                                                     ("Excel files","*.xlsx *.xlsm"),
                                                     ("All files","*.*")],
                                          initialfile="devices.txt")
        if path:
            self.backup_filepath.set(path); self._load_backup_devices()

    def _choose_backup_dir(self) -> None:    # 选择备份目录 / select backup dir
        """
        弹出目录选择框设定配置备份保存目录（Config Backup 页用）。

        功能：filedialog.askdirectory 选择目录；选到后写入 backup_dir_var，
        后续备份文件将保存到该目录下（命名规则见 _start_backup 实现）。

        :return: 无。用户取消时目录保持原值。
        """
        path = filedialog.askdirectory(title="Select backup directory")
        if path:
            self.backup_dir_var.set(path)

    def _load_backup_devices(self) -> None:
        """加载设备列表到备份树视图（过滤 Linux）/ Load devices into backup treeview (excl. Linux).

        功能：清空 backup_tree 后重新解析 backup_filepath 指定的设备文件，
        只把非 linux 设备（网络设备，需备份 running-config）插入树中。
        行 tag 编码为 host|devtype|user|pwd（4 段），后续 _start_backup 从 tag 还原
        账号密码建 SSH 连接。

        :return: 无。
        易错点：
          - 解析返回元组 (devices, error_lines) 中 devices 每个元素为
            (host, devtype, user, pwd, cmds) 五元组——即使备份用不到 cmds 也要按位解包；
          - 端口未在此显示：备份连接统一走 22 端口（见 _start_backup 的实现约定）。
        """
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
        """构建 Profiles 管理标签页 / Build profiles management tab.

        功能：在 tab_profiles 上布置「连接档案」管理界面：
          1) Saved Profiles 树 profile_tree（四列 name/host/type/user，browse 单选）：
             选中行触发 <<TreeviewSelect>> → _on_profile_tree_select 回填表单；
             初始调用 _refresh_profile_list() 填充已有档案。
          2) Add / Edit Profile 编辑表单：
             prof_name / prof_type（设备类型下拉，默认第 0 项）/ prof_host / prof_port（默认 22）
             / prof_user / prof_password（掩码输入）;
             按钮行：Save(_save_profile) / Delete(_delete_profile) / Clear Form(_clear_profile_form)。

        :return: 无。表单与树中的档案数据最终经 _save_profile 落盘到 profiles.json。
        易错点：树单选模式（selectmode="browse"）与批量页多选模式不同，
                本页所有取值都固定取 selection()[0]。
        """
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
        """刷新 Profile 列表树视图 / Refresh profile treeview.

        功能：先清空 profile_tree 所有行，再把 self.profiles 逐条按
        (name, host, devtype.upper(), user) 插入树。devtype 显示为大写内部键
        （如 CISCO），不做标签映射——便于一眼看出类型。

        :return: 无。任何对 self.profiles 的增删改之后都应调用本方法保持界面同步。
        """
        for item in self.profile_tree.get_children():
            self.profile_tree.delete(item)
        for p in self.profiles:
            self.profile_tree.insert("", tk.END, values=(
                p.get("name",""), p.get("host",""), p.get("devtype","linux").upper(), p.get("user","")
            ))

    def _on_profile_tree_select(self, event=None) -> None:
        """选中列表中的 Profile 后回填编辑表单 / Fill edit form from selected profile.

        功能：Profiles 页树的 <<TreeviewSelect>> 回调——取第一行选中行的 name 列，
        到 self.profiles 中找同名档案并把 name/host/port/user/password 逐项
        delete+insert 回填到编辑表单（devtype 经 DEVTYPE_LABEL_OF 换显示标签）。

        :param event: tkinter 事件对象（未使用）。

        :return: 无。无选中或找不到同名档案时静默返回。
        易错点：树值列顺序与列定义一致（name 是第 0 列），取值用 item(sel[0], "values")[0]。
        """
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
        """保存当前表单为 Profile / Save current form as a profile.

        功能：把编辑表单内容组装成一条 profile 字典并写入 self.profiles：
          1. 校验：Name 与 Host 必填（弹 Warning）；Port 必须能转成 int（默认 22）；
          2. devtype 经 DEVTYPE_MAP 由界面标签转内部键（未知回退 "linux"）；
          3. 同名处理：用 Python 的 for...else 惯用法——若已有同名档案则原地覆盖
             self.profiles[i]，循环没 break（即不存在同名）才走 else 分支 append 新档案；
          4. 落盘 _save_profiles() 并刷新树(_refresh_profile_list)、Single Host 页
             下拉框(_refresh_profile_combo)与状态栏。

        :return: 无。
        易错点：profile 字典键名必须与 _load_profiles/_on_profile_selected 中
                p.get("name"/"host"/...) 的键完全一致，否则回填会得到空值。
        """
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
        """删除选中的 Profile / Delete selected profile.

        功能：Profiles 页「Delete」按钮回调：
          1. 无选中行时弹 Warning 提示先选择；
          2. 取选中行的 name，用列表推导重建 self.profiles（过滤掉同名项）；
          3. 落盘并刷新树、Single Host 下拉框，清空表单，更新状态栏。

        :return: 无。删除按「名称」匹配，同名档案会被一并删掉（名称是本工具的唯一键）。
        """
        sel = self.profile_tree.selection()
        if not sel:
            messagebox.showwarning("Warning","Select a profile to delete."); return
        name = self.profile_tree.item(sel[0],"values")[0]
        self.profiles = [p for p in self.profiles if p.get("name") != name]
        self._save_profiles(); self._refresh_profile_list()
        self._refresh_profile_combo(); self._clear_profile_form()
        self._set_status(f"Profile deleted: {name}")

    def _clear_profile_form(self) -> None:
        """清空 Profile 编辑表单 / Clear profile edit form.

        功能：把 name/host/user/password 四个 Entry 全部 delete 清空；
        port 重置为默认 "22"；设备类型下拉回到第 0 项（current(0)）。

        :return: 无。
        """
        for w in (self.prof_name, self.prof_host, self.prof_user, self.prof_password):
            w.delete(0,tk.END)
        self.prof_port.delete(0,tk.END); self.prof_port.insert(0,"22")
        self.prof_type.current(0)

    def _refresh_profile_combo(self) -> None:
        """刷新 Single Host 标签页的 Profile 下拉框列表 / Refresh profile combobox.

        功能：把 self.profiles 的名字列表写进 Single Host 页 profile_combo 的 values，
        使档案增删后下拉框选项保持最新。

        :return: 无。
        """
        self.profile_combo["values"] = [p.get("name","") for p in self.profiles]

    # ═══════════════════════════════════════════════════════════
    # 预设方案管理 / Preset Management
    # ═══════════════════════════════════════════════════════════

    def _refresh_preset_combo(self) -> None:
        """刷新预设方案下拉框 / Refresh preset combobox.

        功能：把 self.presets 的名字列表写进 preset_combo（Single Host 页命令区的
        预设下拉框）的 values。

        :return: 无。
        """
        self.preset_combo["values"] = [p.get("name","") for p in self.presets]

    def _load_preset(self) -> None:
        """加载选中的预设方案到命令文本框和设备类型 / Load selected preset.

        功能：按 preset_combo 当前名字在 self.presets 中查找；命中后：
          1. 设备类型下拉切到预设的 devtype（DEVTYPE_LABEL_OF 转显示标签）；
          2. 强制关闭 Quick 模式并把命令文本框恢复 NORMAL + 白底
             （否则 DISABLED 状态下无法写入新命令——必须先解除锁定再 _write_commands_to_text）；
          3. 把预设的 cmds 字典写入文本框，更新状态栏。
        找不到（未选择）时弹 Warning。

        :return: 无。
        """
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
        """将当前命令集保存为新预设方案 / Save current commands as a preset.

        功能：把命令文本框当前内容存成一条 preset：
          1. simpledialog.askstring 弹框让用户输入预设名（取消或空名直接返回）；
          2. 解析文本框命令（_parse_commands_from_text），为空则弹 Warning 不保存；
          3. 记录当前设备类型（DEVTYPE_MAP 转内部键）；
          4. 同名覆盖（for...else 惯用法，逻辑同 _save_profile）；
          5. 落盘 _save_presets()、刷新下拉框并把下拉框定位到刚保存的名字。

        :param 无（输入经 simpledialog 弹窗获取）。
        :return: 无。
        """
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
        """删除选中的预设方案 / Delete selected preset.

        功能：预设区「Del」按钮回调：
          未选择先 Warning；然后 askyesno 二次确认，确认后按名字过滤 self.presets、
          落盘、刷新下拉框并清空当前选择。

        :return: 无。
        """
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
        """浏览并加载设备列表文件 / Browse and load device list file.

        功能：Batch 页「Browse...」回调——askopenfilename 选择 txt 设备文件，
        选到后写入 batch_filepath 并立即 _load_devices() 填充批量设备树。

        :return: 无。取消选择时无动作。
        易错点：这里选的是批量巡检文件；Config Backup 页用的是 _browse_backup_file，
                两者文件路径变量互不干扰（batch_filepath vs backup_filepath）。
        """
        path = filedialog.askopenfilename(title="Select device list file",
                                          filetypes=[("Device lists","*.txt *.xlsx *.xlsm"),
                                                     ("Text files","*.txt"),
                                                     ("Excel files","*.xlsx *.xlsm"),
                                                     ("All files","*.*")],
                                          initialfile="devices.txt")
        if path:
            self.batch_filepath.set(path); self._load_devices()

    def _load_devices(self) -> None:
        """解析设备文件并填充 batch 树视图，同时建立 host→iid 映射 / Load & populate tree.

        功能：清空 device_tree 与 _device_row 映射后，解析 batch_filepath 设备文件，
        把每台设备插入树（状态列初值 "---"），并把整行完整连接信息编码进行 tag：
        host|devtype|user|pwd|cmd1,cmd2,...（5 段，供 _get_selected_devices 反解）。
        同时维护 _device_row[host] = iid 映射，供 _start_batch_selected 重置状态用。

        :return: 无。加载结果（含错误数）汇总到状态栏：
        解析错误行数>0 时额外显示前 3 条错误细节（行号:原因），超出用省略号截断。
        易错点：tag 中的命令以逗号连接——命令本身不应含逗号或竖线，否则反解会错位。
        """
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

        功能：读取设备列表文本文件，逐行解析为巡检设备元组列表。
        它是批量巡检与配置备份共用的文件解析核心（batch 树/备份树都由它供数据）。

        :param filepath: 设备文件路径；文件不存在时直接返回空结果（不弹窗）。

        支持格式 / Supported formats（每行一条，空行与 # 注释行跳过）:
          带类型: IP:user:password:linux|cisco|huawei:"cmd1,cmd2"
          无类型: IP:user:password:"cmd1,cmd2"                  → 默认 cisco / defaults to cisco
        实现上先后用两条正则匹配：
          - pat_with_type：5 段（含类型段，类型段任意非冒号文本，后续 normalize_devtype 归一化校验，
            支持中文别名 华为/华三/思科/锐捷；非法类型记错误行）；
          - pat_no_type：4 段，匹配成功默认 devtype="cisco"；
          两条都匹配不上、或命令列表为空的行都会记入错误行。

        :return: 二元组 (devices, error_lines)：
                 - devices: 合法设备列表，元素为五元组 (host, devtype, user, pwd, [cmds])，
                   命令由逗号分隔并按 c.strip() 过滤空段；
                 - error_lines: 错误行列表，元素为 (行号, 原文, 原因字符串)。
        易错点：文件用 utf-8 读取；打开失败（如编码/权限异常）时弹 messagebox.showerror
                并返回空结果，不会中断程序。
        """
        devices, error_lines = [], []
        if not os.path.exists(filepath):
            return devices, error_lines
        # Excel 设备表（.xlsx/.xlsm）走专用解析器，返回结构与文本解析完全一致，调用方无需区分
        # Excel device sheets (.xlsx/.xlsm) use a dedicated parser with an identical return shape
        if str(filepath).lower().endswith((".xlsx", ".xlsm")):
            return self._parse_device_excel(filepath)
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

    def _parse_device_excel(self, filepath: str) -> tuple:
        """
        解析 Excel 设备表 / Parse Excel device sheet.

        功能：读取 .xlsx/.xlsm 设备表，把每行转成与 _parse_device_file 完全一致的五元组
        (host, devtype, user, pwd, [cmds])。两种格式返回结构相同，上层的批量巡检与配置备份
        共用同一份解析结果，无需区分文件类型（旧 devices.txt 用法完全不受影响）。

        表结构 / Sheet layout（第 1 行表头，按列位读取，表头文字仅作提示）:
            A=IP   B=用户名   C=密码   D=类型   E=命令
        容错规则 / Tolerances:
          - IP 列为空的行跳过；IP 以 # 开头视为注释行跳过（与文本格式一致）；
          - 类型列留空 → 默认 cisco；中文别名（华为/华三/思科/锐捷）由 normalize_devtype 归一化；
            未知类型 → 记入 error_lines；
          - 命令列支持「逗号」或「换行」分隔（Excel 单元格内换行亦可），空白段自动过滤；
            用户名缺失或命令列表为空 → 记入 error_lines。

        :param filepath: Excel 设备表路径。
        :return: 二元组 (devices, error_lines)，结构与 _parse_device_file 相同。
        易错点：依赖 openpyxl（未安装时弹 messagebox 提示安装，返回空结果且不中断程序）；
                用 read_only 模式读取，避免大表占用内存。
        """
        devices, error_lines = [], []
        try:
            from openpyxl import load_workbook
        except ImportError:
            messagebox.showerror("Error", "Excel 支持需要 openpyxl，请先安装：\n\npip install openpyxl")
            return devices, error_lines
        try:
            wb = load_workbook(filepath, read_only=True, data_only=True)
            ws = wb.active
            for lineno, row in enumerate(ws.iter_rows(min_row=2, values_only=True), start=2):
                cells = list(row) + [None] * 5          # 补齐 5 列，防短行
                host = str(cells[0]).strip() if cells[0] is not None else ""
                if not host or host.startswith("#"):    # 跳过空行与注释行
                    continue
                user = str(cells[1]).strip() if cells[1] is not None else ""
                pwd  = str(cells[2]) if cells[2] is not None else ""   # 密码不 strip，允许含空格
                type_raw = str(cells[3]).strip() if cells[3] is not None else ""
                cmds_raw = str(cells[4]) if cells[4] is not None else ""
                if type_raw:
                    devtype = normalize_devtype(type_raw)
                    if devtype is None:
                        error_lines.append((lineno, host,
                            f"未知类型 {type_raw!r}（可用: linux/cisco/huawei/h3c/ruijie，"
                            "或中文别名 华为/华三/思科/锐捷）"))
                        continue
                else:
                    devtype = "cisco"                   # 留空默认思科 / default cisco
                cmds = [c.strip() for c in re.split(r"[,\n\r]+", cmds_raw) if c.strip()]
                if not user or not cmds:
                    error_lines.append((lineno, host, "用户名缺失或命令列表为空"))
                    continue
                devices.append((host, devtype, user, pwd, cmds))
            wb.close()
        except Exception as e:
            messagebox.showerror("Error", f"Cannot open Excel file:\n{e}")
        return devices, error_lines

    def _export_devices_excel(self) -> None:
        """
        把当前设备文件导出为 Excel 设备表 / Export the current device file to an Excel sheet.

        功能：读取 batch_filepath 指定的设备文件（.txt 或 .xlsx 均可，复用 _parse_device_file），
        经保存对话框选定目标路径后，生成五列表格（IP / 用户名 / 密码 / 类型 / 命令），
        含表头样式、冻结首行、自动筛选；命令列用换行分隔，便于在 Excel 里阅读与复制。
        列序与 _parse_device_excel 的读取列序完全对应，导出文件可被本工具直接读回。

        :return: 无。无设备可导出、用户取消保存时直接返回（仅给出提示/静默）。
        易错点：依赖 openpyxl（缺失时弹提示而非崩溃）；目标文件被 Excel 占用时写入失败，
                捕获异常并 messagebox 说明原因。
        """
        filepath = self.batch_filepath.get().strip()
        devices, _ = self._parse_device_file(filepath)
        if not devices:
            messagebox.showwarning("Export to Excel",
                                   "当前设备文件没有可导出的设备。\n请先选择并加载设备文件（Browse... / Load）。")
            return
        out = filedialog.asksaveasfilename(title="Export devices to Excel",
                                           defaultextension=".xlsx",
                                           filetypes=[("Excel files", "*.xlsx")],
                                           initialfile="devices.xlsx")
        if not out:
            return
        try:
            from openpyxl import Workbook
            from openpyxl.styles import Font, PatternFill, Alignment, Border, Side
        except ImportError:
            messagebox.showerror("Error", "导出 Excel 需要 openpyxl，请先安装：\n\npip install openpyxl")
            return
        try:
            wb = Workbook()
            ws = wb.active
            ws.title = "设备列表"
            head_fill = PatternFill("solid", fgColor="1F4E79")
            head_font = Font(name="微软雅黑", size=11, bold=True, color="FFFFFF")
            thin = Side(style="thin", color="B4C7DC")
            border = Border(left=thin, right=thin, top=thin, bottom=thin)
            center = Alignment(horizontal="center", vertical="center", wrap_text=True)
            wrap = Alignment(vertical="top", wrap_text=True)
            data_font = Font(name="微软雅黑", size=10)
            ws.append(["IP", "用户名", "密码", "类型", "命令（逗号或换行分隔）"])
            for c in range(1, 6):
                cell = ws.cell(1, c)
                cell.fill = head_fill; cell.font = head_font
                cell.alignment = center; cell.border = border
            for host, devtype, user, pwd, cmds in devices:
                ws.append([host, user, pwd, devtype, "\n".join(cmds)])   # 命令换行，Excel 里更好读
            for r in range(2, ws.max_row + 1):
                ws.row_dimensions[r].height = 70
                for c in range(1, 6):
                    cell = ws.cell(r, c)
                    cell.font = data_font; cell.border = border
                    cell.alignment = center if c <= 4 else wrap
            for col, w in zip("ABCDE", [16, 12, 16, 12, 62]):
                ws.column_dimensions[col].width = w
            ws.freeze_panes = "A2"
            ws.auto_filter.ref = f"A1:E{ws.max_row}"
            wb.save(out)
        except Exception as e:
            messagebox.showerror("Error", f"导出失败（目标文件可能正被 Excel 打开）：\n{e}")
            return
        self._set_status(f"Exported {len(devices)} device(s) -> {out}")
        messagebox.showinfo("Export to Excel", f"已导出 {len(devices)} 台设备：\n{out}")

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
            return (host, devtype, "UNREACHABLE", [("Ping", "Host unreachable")], [])

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
            return (host, devtype, "FAILED", [("Connection", self._friendly_conn_error(e))], [])

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
        """Ctrl+Enter: 根据当前活跃标签页启动对应巡检 / Start inspection on active tab.

        功能：全局快捷键 Ctrl+Enter 的统一入口（单机/批量/备份等输入框都绑定了该键）。
        从根窗口的子控件里找到唯一的 ttk.Notebook（选项卡容器），再按当前选中页
        的索引分派任务：索引0=单机巡检 _start_single()、索引1=批量巡检
        _start_batch_selected()、索引2=配置备份 _start_backup()。
        这样无论焦点在哪个页签，按快捷键都会启动“当前页”对应的巡检，不会误启动其它页的任务。

        参数：无（所需状态全部从控件 / self 读取）。
        返回值：None。

        关键逻辑与易错点：
        - 开头那段 nametowidget() 只是容错尝试，真正生效的是下一行用
          isinstance(c, ttk.Notebook) 过滤出的 Notebook 列表；
        - 整体 try/except 静默吞异常：当焦点不在 Notebook（如弹出子窗口）时
          notebook.index(...) 会失败，此时什么都不做，避免把异常抛进 Tk 事件循环。
        """
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
        """停止所有正在执行的巡检（单机/批量/备份共用 stop_event）/ Stop all running ops.

        功能：工具栏/各页签“停止”按钮的回调，实现方式是协作式取消：把
        self.stop_event（threading.Event）置位，各后台工作线程在“每台设备之间、
        每条命令之间”轮询 stop_event.is_set()，发现被置位后自行结束循环退出。

        参数：无。
        返回值：None。

        关键逻辑与易错点：
        - 这是“请求停止”而非“强杀线程”：正在 sleep 或阻塞读网络数据的代码
          要等当前这一步结束才会响应，无法打断已经发出的命令；
        - 置位后仅把状态栏改为 "Stopping..."；按钮复位、状态栏回 "Ready" 等
          收尾工作由线程结束时投递的 ("done") 消息在 _poll_queue 里统一处理。
        """
        self.stop_event.set()
        self._set_status("Stopping...")

    # ═══════════════════════════════════════════════════════════
    # 配置备份 / Config Backup
    # ═══════════════════════════════════════════════════════════

    def _start_backup(self) -> None:
        """启动配置备份线程 / Launch backup worker thread.

        功能：“配置备份”页签“开始备份”按钮的回调：收集待备份设备 → 复位界面状态
        → 启动后台线程执行 _backup_worker。
        步骤：
        1) 取备份设备树 backup_tree 中被选中的行；没有任何选中时退化为备份全部行；
        2) 每行的第一个 tag 形如 "IP|设备类型|用户名|密码"（split("|",3)），
           解析成 (host, devtype, user, pwd) 四元组加入列表；
        3) 一个合法设备都没有 → 弹警告框并直接返回；
        4) 禁用“开始”按钮、启用“停止”按钮、清空备份输出区、stop_event.clear()
           复位、按设备总数设置进度条 maximum、计数标签归零、状态栏提示；
        5) 开 daemon 线程执行 _backup_worker(devices, backup_dir_var.get())，
           线程内只能通过 result_queue 与界面通信。

        参数：无。
        返回值：None。

        注意：backup_dir_var 是界面上“备份保存目录”输入框的 StringVar，
        工作线程写盘前会拿它的值做保存根目录。
        """
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
        """配置备份工作线程 / Backup worker thread.

        功能：配置备份的后台工作线程。逐台设备 SSH 登录、抓取配置、落盘保存。
        全程不直接碰 Tk 控件，进度与结果一律打包成消息投进 self.result_queue：
          ("backup","output",文本)  → 输出到备份页；
          ("backup","progress",n)   → 进度条前进到 n；
          ("backup","done",None)    → 通知主线程整批结束。

        参数：
          devices   : list，元素为 [host, devtype, user, pwd]
                      （由 _start_backup 从设备树行 tag 解析而来）；
          backup_dir: str，备份保存根目录（界面输入框的值）。
        返回值：None。

        关键逻辑与易错点：
        - 每轮循环先查 stop_event，被停止就投一条提示消息并 break，不再连下一台；
        - 该设备类型在 BACKUP_COMMANDS 里没有备份命令 → 提示后 continue 跳过；
        - SSH 连接失败必须“逐台容错”：记录 FAILED、completed+1、continue，
          绝不能因一台设备失败中断整批任务；连接成功则用
          _run_commands_via_shell(client, devtype, {"backup": backup_cmd}, timeout=60)
          抓取配置，并记得 client.close() 释放连接；
        - 保存路径为 <backup_dir>/<设备类型>/<IP>/<IP>_<时间戳>.cfg，时间戳精确到秒，
          重复备份不会互相覆盖；写文件用 utf-8 编码（设备配置可能含中文注释）；
        - completed 计数与 progress 消息一一对应，保证界面进度条能走满。
        """
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

        功能：SSH 登录前的 ICMP 连通性预检——只发 1 个 ping 包，能在 timeout 秒内
        收到响应就认为主机可达，避免把昂贵的连接超时浪费在离线设备上。

        参数：
          host   : str，目标 IP 或主机名；
          timeout: int，等待响应的秒数，默认 2 秒。
        返回值：bool——ping 成功（returncode==0）返回 True；失败或任何异常返回 False。

        关键逻辑与易错点：
        - 平台差异必须区分：Windows 的 ping -w 参数单位是“毫秒”，所以要乘 1000
          （ping -n 1 -w <毫秒>）；Linux/macOS 用 -W <秒>（ping -c 1 -W <秒>）；
        - subprocess.run 额外套了 timeout+1 的保护，防止 ping 进程本身卡死；
        - 预检失败只是返回 False，绝不抛异常打断后续的巡检流程。
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
        """创建并配置 SSH 客户端 (AutoAddPolicy) / Create pre-configured SSH client.

        功能：集中创建“已配好 host key 策略”的 paramiko SSH 客户端。
        单机巡检 / 批量巡检 / 配置备份三条路径都先调它拿客户端，再交给
        _ssh_connect 去真正连接，保证各处行为一致、参数好维护。

        参数：无。
        返回值：paramiko.SSHClient——已执行
        set_missing_host_key_policy(paramiko.AutoAddPolicy()) 的客户端实例：
        首次遇到陌生主机的 host key 时自动接受并加入 known_hosts，省去交互确认。

        关键逻辑与易错点：
        - AutoAddPolicy 牺牲了防中间人攻击的安全性，换取“零交互可用”——校园网 /
          实验网设备 IP 频繁变更，默认的 StrictHostKeyChecking 遇到陌生 key 会
          直接拒绝连接导致脚本失败；生产环境建议改用 WarningPolicy；
        - 这里只负责“造客户端”，连接失败后同一个对象可以换 host/port/凭据再次
          connect（_ssh_connect 的老算法降级重试正是复用了这一点）。
        """
        c = paramiko.SSHClient()
        c.set_missing_host_key_policy(paramiko.AutoAddPolicy())
        return c

    @staticmethod
    def _friendly_conn_error(e: Exception) -> str:
        """把连接异常转成可操作的提示 / human-friendly connection error.

        功能：把底层（paramiko / socket）连接异常翻译成带中文排查建议的提示。
        原始异常信息（如 "Connection timed out"）对使用者不友好，本方法按
        关键字归类，在原始信息后面追加针对华为 / H3C 现场的操作建议，
        直接显示到输出区方便运维同学照着排查。

        参数：e —— 捕获到的异常对象（Exception）。
        返回值：str——加工后的提示文本；无法识别的异常原样返回 str(e)。

        关键逻辑与易错点：
        - 判断关键字前先把信息转小写（low = msg.lower()），保证 "Timeout"、
          "timed out"、"timedout" 等大小写变体都能命中同一分支；
        - “超时”与“拒绝”的排查方向完全不同：超时多为 IP 不可达 / 防火墙丢包；
          拒绝多为 SSH 端口未开（H3C Comware 默认不开 SSH，需先配置
          ssh server enable；若设备只开 telnet，可把端口改成 23）；
        - algorithm/compatible/agreement 对应“加解密算法协商失败”，
          提示会说明程序已自动用老算法 ssh-rsa 重试过。
        """
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

        功能：统一的 SSH 连接封装（单机/批量/备份都走它），并内置“老设备算法
        降级重试”：第一次连接若因密钥算法协商失败，自动禁用 rsa-sha2 算法族、
        回退到 ssh-rsa 再连一次，兼容 H3C Comware V5 / 华为 VRP5 等老设备。

        参数：
          client : paramiko.SSHClient，来自 _create_ssh_client()；
          host   : str，设备 IP / 主机名；
          port   : int，SSH 端口（网络设备默认 22，telnet 映射场景可传 23）；
          user   : str，登录用户名；
          pwd    : str，登录密码；
          timeout: int，连接 / banner / 认证各阶段超时秒数，默认 10。
        返回值：None——连接成功即返回（client 进入已连接状态）；失败抛出原始异常，
        由调用方 try/except 负责处理。

        关键逻辑与易错点：
        - 内层 _connect(disabled) 统一拼 connect() 的 kwargs；其中
          look_for_keys=False 与 allow_agent=False 表示“不读本机 SSH 私钥、
          不借用 ssh-agent”，避免拿错凭据反复试探认证；
        - 为何要重试：老设备 host key 只支持 ssh-rsa（SHA-1），而 paramiko 3.x
          默认只提议 rsa-sha2-256/512，直接协商会报 “no compatible key exchange”；
        - 只有错误信息含 algorithm / compatible / agreement 才降级重试，其它错误
          （超时、拒绝）原样抛出；重试前先 client.close() 释放失败残留的半开连接。
        """
        def _connect(disabled=None):
            """执行一次 client.connect()；disabled 传算法禁用表时用于老设备降级重试。"""
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

        功能：Compact（紧凑）模式的输出过滤器。批量巡检开启紧凑输出时，
        对每条命令的原始输出按规则“只保留关键行”，去掉噪声行，让结果更易读。
        （调用点见批量巡检循环：if compact_enabled: output = self._filter_output(...)）

        参数：
          devtype: str，设备类型关键字（如 "huawei"/"h3c"/"ruijie"/"cisco"），
                   用于查 OUTPUT_FILTERS 规则表；
          title  : str，命令标题，在规则表里对应一组正则；
          output : str，命令的原始输出文本。
        返回值：str——过滤后的文本。

        关键逻辑与易错点：
        - 规则表是“设备类型 → {命令标题: 正则列表或 None}”的三级结构：
            · title 不在该设备规则里 → 原样返回（该命令不做过滤）；
            · 规则值是 None           → 显式“不过滤”，原样返回；
            · 规则是一组正则         → 保留“非空行 且 命中任一正则
              （re.IGNORECASE 忽略大小写）”的行；
        - 最典型的坑：过滤后一行都不剩时不能返回空串（解析和阅读都会出问题），
          代码在这里兜底返回原始输出，保证结果永远有内容。
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

        功能：通过交互式 SSH 通道（invoke_shell，伪终端）依次执行多条命令并收集
        输出。华为 / H3C / Cisco 等网络设备没有干净的 exec 语义，逐条 exec_command
        容易丢格式或撞上分页提示，因此这里模拟“人敲键盘”：开一个伪终端 →
        发禁用分页命令 → 逐条 send 命令 → 轮询读回显 → 把每条输出存进字典返回。

        参数：
          client : 已连接的 paramiko.SSHClient；
          devtype: str，设备类型，用于查 DISABLE_PAGING 拿到对应的关分页命令
                   （如 screen-length 0 / terminal length 0）；
          cmds   : dict {标题: 命令}，标题同时作为返回字典的键；
          timeout: int，单条命令“静默多久算结束”的硬上限秒数，默认 30。
        返回值：dict[str,str]——{标题: 该命令的输出文本（已 strip）}。整段执行
        抛异常时，会把尚未取到输出的标题统一填为 "[ERROR] ..."，保证调用方
        拿到的键永远齐全。

        关键逻辑与易错点（最容易踩的坑都集中在这里）：
        - invoke_shell(width=200, height=100)：宽终端防止长行回显被折行截断；
          随后睡 1.5s 等设备就绪，并清空登录 banner；
        - 必须先发“禁用分页”命令再执行正式命令，否则长输出会卡在
          "---- More ----" 等待按键 → 静默计时耗尽 → 输出被误判结束而残缺；
        - 判断“一条命令输出结束”的机制：每 0.15s 轮询一次 channel.recv_ready()，
          有数据就读走 65535 字节并清零静默计数；连续无数据（且已有输出）超过
          20 个周期（约 3 秒）即视为输出结束，提前退出循环；
        - 解码统一 utf-8 + errors='replace'：个别乱码字节只会变成替换符，
          不会让 decode 抛异常中断整批；
        - 每条命令执行前检查 stop_event，用户点“停止”后不再发送后续命令；
        - 循环结束 channel.close() 释放通道；一次 recv(65535) 读不完的数据
          会在下一轮循环继续读，不会丢。
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
        """Linux 设备的分页禁用（网络设备已在 invoke_shell 中处理）。

        功能：给 Linux 主机单独发送“禁用分页”命令。网络设备（Cisco/Huawei/H3C/
        Ruijie）已经在 _run_commands_via_shell 的伪终端里发过 DISABLE_PAGING；
        而 Linux 走的是 _exec_commands_linux 的 exec_command 路径，需要在这里
        关掉分页，避免长输出被 --More-- 类提示截断。

        参数：
          client : 已连接的 paramiko.SSHClient；
          devtype: str，设备类型——只有等于 "linux" 才真正执行。
        返回值：None。

        关键逻辑与易错点：
        - 非 linux 设备直接 return，作为双保险：即使被误调用也不会发错命令；
        - 用 exec_command 发命令后调用 stdout.read() 把回显读干净，防止残留输出
          污染后续读取；整个过程 try/except 静默吞异常——关分页失败只是输出
          会长一点，不影响主流程。
        """
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
        """导出最近一次批量巡检结果为 HTML / Export latest results as HTML.

        功能：把“最近一次批量巡检结果”导出为 HTML 报告。对应批量标签页的
        “导出 HTML”按钮：把 self.last_results（批量 worker 结束时回传的结果
        结构）交给独立函数 generate_html_report() 渲染落盘。

        参数：无。
        返回值：None。

        关键逻辑与易错点：
        - 前置守卫：没有 last_results 时弹警告并 return，避免空导出；
        - 文件名为 report_<时间戳>.html，放在全局 REPORT_DIR 目录，时间戳由
          datetime.now() 生成，连续导出不会互相覆盖；
        - 成功时更新状态栏并弹 info 框给出完整路径；generate_html_report 抛出的
          异常被捕获后以错误框展示，不让异常打断界面。
        """
        if not self.last_results:
            messagebox.showwarning("Warning","No inspection results to export."); return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        # 让用户自选导出位置（默认上次用过的目录 / 报告目录），不再只能去 Temp 里翻。
        # Let the user choose the destination (last used dir, else REPORT_DIR).
        default_dir = getattr(self, "_last_export_dir", None) or REPORT_DIR
        fp = filedialog.asksaveasfilename(
            title="Export HTML report",
            defaultextension=".html",
            filetypes=[("HTML files", "*.html"), ("All files", "*.*")],
            initialdir=default_dir,
            initialfile=f"report_{ts}.html",
        )
        if not fp:
            return                       # 用户取消 / cancelled
        self._last_export_dir = os.path.dirname(fp)
        try:
            generate_html_report(self.last_results, fp)
            self._set_status(f"HTML report saved: {fp}")
            messagebox.showinfo("Export",f"HTML report saved:\n{fp}")
        except Exception as e:
            messagebox.showerror("Export Error",str(e))

    def _export_csv(self) -> None:
        """导出最近一次批量巡检结果为 CSV / Export latest results as CSV.

        功能：把最近一次批量巡检结果导出为 CSV 表格，对应批量标签页的
        “导出 CSV”按钮。与 _export_html 结构一致，只是改调 generate_csv_report()
        落盘成 report_<时间戳>.csv，方便用 Excel / WPS 打开做二次分析。

        参数：无。
        返回值：None。

        关键逻辑与易错点：
        - 复用“无结果先警告”的守卫与时间戳命名策略，两个导出函数保持对称便于维护；
        - 表格内容（表头、异常行展开等）都在独立函数里生成，本方法只负责路径
          拼接、调用、状态栏与弹窗反馈，职责单一；
        - 写文件失败（如文件正被 Excel 占用）会被捕获并以错误框提示用户。
        """
        if not self.last_results:
            messagebox.showwarning("Warning","No inspection results to export."); return
        ts = datetime.now().strftime("%Y%m%d_%H%M%S")
        # 与 HTML 导出同样：让用户自选位置，并记住上次目录。
        # Same as the HTML export: let the user choose, remember the last dir.
        default_dir = getattr(self, "_last_export_dir", None) or REPORT_DIR
        fp = filedialog.asksaveasfilename(
            title="Export CSV report",
            defaultextension=".csv",
            filetypes=[("CSV files", "*.csv"), ("All files", "*.*")],
            initialdir=default_dir,
            initialfile=f"report_{ts}.csv",
        )
        if not fp:
            return                       # 用户取消 / cancelled
        self._last_export_dir = os.path.dirname(fp)
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

        功能：UI 主线程的“消息泵”——周期性清空 self.result_queue，把后台线程
        发来的消息逐条取出并刷新到界面。tkinter 不是线程安全的，后台线程
        （单机/批量/备份 worker）一律不得直接操作控件，只能往队列投
        (target, msg_type, data) 三元组；本方法每 100ms 由
        root.after(100, self._poll_queue) 自我续期，在 Tk 事件循环里排队执行，
        是“后台线程 → 界面”之间唯一的桥梁。

        参数：无。
        返回值：None（每次执行完毕都会注册下一次 100ms 轮询，形成常驻循环，
        直到窗口销毁）。

        消息协议与各类型处理要点：
        - target ∈ "single"|"batch"|"backup"：决定消息路由到哪个输出区
          （单机/批量/备份页；未知 target 兜底到单机输出区 single_output）；
        - msg_type 各值对应的处理：
          · output        → _append_output_auto 逐行自动高亮追加；
          · status        → 更新底部状态栏；
          · device_status → 更新设备树 Status 列文本，并按 _host_anom_level 的
            high/mid 分级配 row_high（红）/ row_mid（黄）/ row_ok（绿）等行标签；
          · alert         → 单条异常告警（超阈值），critical 红 / 其它 warning 黄；
          · result        → 单台设备完整结果：设备头 + 告警清单 + 逐条命令输出；
          · summary       → 黄字总结文本；
          · stats         → 记录每台设备异常统计到 _batch_stats，并同步设备列表颜色；
          · error         → 红字 [ERROR] 输出；
          · progress      → 按 target 更新批量 / 备份各自的进度条与 “n/m” 计数文本；
          · done          → 整批收尾：running=False、恢复所有按钮、打印按设备异常
            统计摘要、清空 _batch_stats 与 _host_anom_level、状态栏回 "Ready"，
            最后画 "Complete." 分隔线；
          · section       → 预留，暂无动作。

        关键逻辑与易错点：
        - 用 while True + get_nowait() 一次排空队列（队空抛 queue.Empty 被捕获
          后退出），而不是每条消息都重新调度一次 after，避免消息多时 UI 越来越卡；
        - 本函数运行在 Tk 事件循环内，必须“短平快”：任何长时间阻塞（网络、sleep、
          大文件读写）都会冻结整个窗口；
        - 所有颜色输出都依赖输出框初始化时 tag_config 定义好的标签（critical /
          warning / minor / success 等），想新增颜色要先补 tag 配置。
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
        """更新设备树 Status 列文本并设置行颜色 / Update tree Status cell + row tag.

        功能：更新批量巡检设备树里某台设备的“状态”列文本，并同步整行颜色。
        这是设备列表状态的统一写入口：_poll_queue 在处理 device_status / stats /
        done 等消息时都调它，避免各处直接改树导致状态不一致。

        参数：
          host: str，设备标识（IP），用于在 self._device_row 映射表里查出它
                在设备树中的行 id（iid）；
          text: str，要写入第 4 列（values[3]，状态列）的文本，例如 "Running..."、
                "OK" / "WARNING" / "CRITICAL" / "FAILED"；
          tag : str 或 None，行颜色标签 row_ok / row_mid / row_high / row_fail 等
                （红黄绿状态色在树初始化时 tag_configure 定义）；None 表示只改
                文本、不改颜色。
        返回值：None。

        关键逻辑与易错点：
        - 先查 iid 并用 self.device_tree.exists(iid) 确认行还存在——设备行可能
          尚未插入或已被删除，直接 item() 会抛 TclError；
        - 行标签采用“先清后加”：把旧的状态色标签（row_high/row_mid/row_ok/
          row_fail）全部剔除，再追加新标签，防止多次刷新后颜色叠加错乱。
        """
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

        功能：向只读输出框（ScrolledText）尾部追加一段文本，可整段指定一种
        颜色标签。_poll_queue 等主线程代码输出巡检日志的统一入口。

        参数：
          widget: 目标输出控件（如 single_output / batch_output / backup_output）；
          text  : str，要追加的文本；
          tag   : str 或 None，颜色标签名（"critical"/"warning"/"success"/"minor"
                  等，颜色在控件初始化时 tag_config 定义）；None 表示用默认前景色。
                  注意：一个 tag 作用于整段 text，无法让同一段内不同行不同色。
        返回值：None。

        关键逻辑与易错点：
        - 输出框常态是 tk.DISABLED（只读防误编辑），因此追加前必须先切回
          tk.NORMAL，插入后 widget.see(tk.END) 自动滚到底部，再切回 DISABLED；
          顺序颠倒或漏切会抛 TclError 或留下可编辑状态；
        - 需要“逐行不同颜色”时请用 _append_output_auto；
        - 只能在主线程调用（Tk 控件非线程安全），后台线程请走 result_queue。
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

        功能：智能逐行输出：把整块文本按行拆开、逐行 insert，使每一行都能拥有
        独立颜色；同时做两级“自动标色”：① 按命令区块标题（行内方括号里的
        标题，如 "--- [Alarm Active] ---"）用 count_flagged_lines 统计告警
        关键字；② 对日志类文本（logbuffer / auth / access 等，由 _looks_like_log
        判定）叠加 attack_scan 攻击特征扫描（SQLi / 暴力破解 / 恶意扫描等）。
        命中后还在文本末尾附加一行统计摘要。

        参数：
          widget: 目标输出控件；
          text  : str，待追加的整块多行文本；
          tag   : 兜底颜色，仅在“关键字计分与攻击命中都没覆盖某行”时使用。
        返回值：None。

        关键逻辑与易错点：
        - 为什么必须逐行 insert：Text 控件的 tag 按“字符区间”生效，整块一次
          insert 后无法给其中不同行分别上色；拆行插入后每行单独打 tag 即可；
        - 区块标题识别：正则 r"[\[【]([^\]】]*)[\]】]" 取每行第一个方括号里的
          内容作为 title（转小写）来匹配关键字规则——输出里务必保留
          "--- [xxx] ---" 这类节标题，否则关键字判定会退化；
        - 关键字配色：Critical=红 critical、Major=橙 warning、Minor/Warning=黄
          minor；Device 类输出 Unregistered / NotSupply / Abnormal=红 critical；
        - 攻击检测只在日志样文本上做，命中按行号建索引（atk_by_line）；同一行
          既有关键字又命中攻击时“攻击颜色覆盖关键字颜色”；info 级攻击事件
          （如正常 SSH 登录成功）只提示不标色，避免正常日志整屏飘红；
        - 末尾摘要：Alarm summary / Device status / 攻击检测 三选一或叠加输出，
          一眼看出问题量级；info 级攻击只计数不标行色。
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
        """IP 被动情报查询弹窗 / IP passive-intel dialog (ip-api, no Key).

        功能：弹出“IP 被动情报查询”模态子窗口。通过免费接口 ip-api.com（无需
        API Key）查询目标 IP 的归属地、运营商、时区等被动情报并展示，供排查
        攻击来源 / 溯源使用。主界面上的“IP Intel”按钮调用本方法（单机页会把
        当前输入的主机 IP 预填进查询框）。

        参数：initial_ip —— str，预填到输入框的 IP（可为空，表示手动输入）。
        返回值：None（窗口对象只存在于局部作用域，由 Tk 内部引用保证存活）。

        关键逻辑与易错点：
        - 网络请求（ip_intel_lookup）放在 daemon 线程 _worker 里执行，避免卡住
          UI；线程拿到结果后用 self.root.after(0, ...) 把 _show 调度回主线程再
          改控件——跨线程直接操作 Tk 控件是必踩的坑；
        - win.transient(self.root) + win.grab_set() 把子窗口设为模态：关闭前
          主窗口不可操作；
        - 查询期间禁用“查询”按钮防重复提交，结果区先显示“查询中...”；
        - 结果排版统一走 format_ip_intel()；结束时 status 标签显示 "完成 ✓" 或
          "查询失败"；
        - 支持回车直接查询：entry.bind("<Return>", do_query) 并自动 focus 输入框。
        """
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
            """IP 情报查询按钮回调：取输入框 IP → 禁用按钮 → 起 daemon 线程查询（避免卡 UI）。"""
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
                """后台查询线程：调用 ip_intel_lookup 拿数据，再调度回主线程显示。"""
                data = ip_intel_lookup(ip)
                self.root.after(0, lambda: _show(data))

            threading.Thread(target=_worker, daemon=True).start()

        def _show(data):
            """主线程回调：把查询结果写入结果区、恢复按钮与状态标签。"""
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

        功能：输出区“下一异常”按钮的回调：从上次位置往后找下一条带 critical
        （红色）标签的异常行，滚动到可视区，并用 anom_cur 标签把该行临时高亮
        成橙色；跳到最后一条之后再点会回绕到第一条（循环浏览）。每个输出框
        独立记忆“上次跳到哪”，与用户手动滚动位置无关，连续点击始终前进。

        参数：
          widget: 目标输出控件（单机 / 批量输出框）；
          label : 显示命中位置的标签控件，更新为 "第 N 行"；
                  没有任何异常行时显示 "无异常"。
        返回值：None。

        关键逻辑与易错点：
        - tag_ranges("critical") 返回的是“起点,终点,起点,终点…”交错排列的索引
          列表，遍历步长必须是 2，只取偶数下标作为行起点；
        - 前进状态存于 self._anom_state[id(widget)]：记录上次跳到的起点，用
          widget.compare(start, ">", last) 判断是否在它后面；找不到（或从没
          跳过）就取第一条实现回绕；
        - 每次跳转前先把上一轮的 anom_cur 标记 tag_remove 掉，避免多行同时
          高亮成橙色；
        - 行号 = Tk index 字符串（"行.列" 格式）按 "." 切分后的前半段；
          anom_cur 的橙色（#ffb74d）在输出框初始化时 tag_config 定义。
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

    def _jump_to_prev_anomaly(self, widget, label) -> None:
        """
        跳到上一个红色异常行并临时橙色高亮它；已到第一个时循环回最后一个。

        Jump to the previous red-flagged line; wraps back to the last one after
        the first. Mirror of _jump_to_next_anomaly in the opposite direction.

        功能：输出区「上一异常」按钮的回调——与「下一异常」完全对称，只是方向相反：
        从上次位置往前找上一条带 critical（红色）标签的异常行，滚动到可视区并用
        anom_cur 标签橙色高亮；到第一条之后再点会回绕到最后一条（循环浏览）。
        每个输出框独立记忆位置，且与「下一异常」的状态分开保存，交替点击互不干扰。

        参数：
          widget: 目标输出控件（单机 / 批量输出框）；
          label : 显示命中位置的标签控件，更新为 "第 N 行"；没有任何异常行时显示 "无异常"。
        返回值：None。

        关键逻辑与易错点：
        - tag_ranges("critical") 返回“起点,终点,起点,终点…”交错索引，步长必须是 2；
        - 反向查找：从最后一个起点倒序遍历，取第一个严格小于上次位置的
          （widget.compare(start, "<", last)）；找不到（或从没跳过）则取最后一条实现回绕；
        - 反向状态存在 self._anom_state_rev（与 next 版的 self._anom_state 分开），
          这样「上一异常」和「下一异常」各自的“上次位置”互不影响；
        - 跳转前同样先 tag_remove 掉 anom_cur，避免多行同时高亮成橙色。
        """
        widget.tag_remove("anom_cur", "1.0", tk.END)
        ranges = list(widget.tag_ranges("critical"))
        if not ranges:
            label.config(text="无异常")
            return
        state = getattr(self, "_anom_state_rev", None)
        if state is None:
            self._anom_state_rev = {}
            state = self._anom_state_rev
        key = id(widget)
        last = state.get(key)                # 上次跳到的位置 / last jumped start
        prv = None
        if last is not None:
            for i in range(len(ranges) - 2, -1, -2):   # 倒序取起点 / walk backwards
                start = ranges[i]
                if widget.compare(start, "<", last):
                    prv = start
                    break
        if prv is None:                      # 无记录或已到开头 → 循环回最后一条
            prv = ranges[-2]
        widget.see(prv)
        widget.tag_add("anom_cur", prv, widget.index(f"{prv} lineend"))
        state[key] = prv
        line_no = int(str(prv).split(".")[0])
        label.config(text=f"⚠ 第 {line_no} 行")

    def _clear_output(self, widget):
        """清空 ScrolledText 内容 / Clear all text in output area."""
        state = getattr(self, "_anom_state", None)
        if state:
            state.pop(id(widget), None)      # 清空时重置跳转状态 / reset jump state
        rev_state = getattr(self, "_anom_state_rev", None)
        if rev_state:
            rev_state.pop(id(widget), None)  # 「上一异常」状态一并重置 / reset reverse state
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

def main() -> None:
    """程序入口（pyproject 的 [project.scripts] 指向这里）。"""
    root = tk.Tk()
    NetworkInspectGUI(root)
    root.mainloop()


if __name__ == "__main__":
    main()

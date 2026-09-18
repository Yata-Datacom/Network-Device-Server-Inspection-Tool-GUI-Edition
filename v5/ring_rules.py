#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ring_rules.py —— 环路 / 异常告警判据引擎（P1，纯逻辑层）

设计定位
--------
本模块**只做判据计算**，不碰 GUI、不碰 SSH、不碰文本解析。
输入是**结构化的采样数据**（见下方「数据契约」），输出是**统一告警列表**。
厂商差异被隔离在"解析器"里（解析器负责把各家命令输出转成这里的结构），
因此本引擎**完全厂商无关**——这也是能同时给 V4（阉割版）和 V5（完整版）使用的原因。

对应规格见同目录《环路检测-规则清单.md》的 D1~D12。

数据契约 / Data contract
-----------------------
单台设备一次采样 sample::

    {
      "device": "192.0.2.1",
      "vendor": "huawei",              # huawei|h3c|ruijie|cisco|linux|unknown
      "device_class": "core",          # core|aggregation|access（决定阈值档）
      "ts": 1789000000,                # 采样时间戳（秒）
      "interfaces": [
        {"name": "GE0/0/1", "bcast": 12345, "mcast": 100, "crc": 12,
         "input_err": 3, "up_down": 0,
         "rx_power": -15.2, "tx_power": -2.1}      # 光功率可缺省(None)
      ],
      "macs": [ {"mac": "aabb.ccdd.eeff", "vlan": 10,
                 "port": "GE0/0/2", "type": "dynamic"} ],
      "stp": {"tc_count": 12, "root_id": "32768.aabb.ccdd.eeff",
              "root_port": "GE0/0/1", "local_bridge_id": "32768.1111.2222.3333",
              "bpdu_in": 100, "bpdu_out": 120},
      "power": [ {"id": "PWR1", "status": "Normal"} ],
      "temperatures": [ {"sensor": "Slot1", "value": 45} ],
      "logs": [ "原始日志行（用于关键字映射）" ]
    }

告警输出 alert::

    {"rule_id": "D1", "signal": "MAC_FLAPPING", "severity": "high",
     "confidence": "high", "device": "...", "interface": "...",
     "evidence": "原始证据文本", "delta": 2, "threshold": 1,
     "advice": "建议动作"}

规则实现约定
------------
- 每条规则 = 一个独立函数，可**单独启用/禁用**（配合 UI 选项框）；
- 阈值一律从 rules 字典读取，**缺失即用内置默认**（rules.yaml 可选）；
- 数值判定统一用**严格大于**（`>`），刚好等于阈值不告警；
- 关键字匹配**一律大小写不敏感**（华为同型号不同版本输出大小写会变）；
- 每条告警**必须带 evidence**（原始依据），便于人工复核——宁可疑勿武断。
"""

from __future__ import annotations

import re
from typing import Any, Dict, Iterable, List, Optional, Sequence

# ══════════════════════════════════════════════════════════════════
# 默认阈值（rules.yaml 缺省时使用；与《规则清单》§4 保持一致）
# ══════════════════════════════════════════════════════════════════
DEFAULTS: Dict[str, Any] = {
    "tc_per_minute": {"access": 5, "aggregation": 15, "core": 30},
    "broadcast_pps": 1000,
    "broadcast_bandwidth_pct": 5,
    "crc_per_minute": {"warn": 100, "high": 1000},
    "link_flap_per_hour": {"warn": 3, "high": 10},
    "mac_move_count": {"warn": 1, "high": 2},
    "mac_table_swing_pct": 10,
    "rx_power_dbm": {"warn": -20.0, "high": -25.0},
    "rx_power_drop_db": 3.0,
    "temp_c": {"warn": 65, "high": 75},
    "temp_rise_c": 10,
    "power_abnormal_states": ["Abnormal", "Fault", "Absent", "NotSupply", "Unregistered"],
    "bpdu_in_per_second": 1000,
    # D13：同一 MAC 出现在同一设备多少个非聚合端口才算冲突
    "mac_multi_port": {"min_ports": 2},
    # D4 分组容差：端口 pps 相差百分比以内算"同一环路环流"
    "broadcast_group_tolerance_pct": 20,
}

# 规则编号 → (信号名, 说明)，供 UI 选项框展示
RULE_CATALOG: List[Dict[str, str]] = [
    {"id": "D1", "signal": "MAC_FLAPPING",        "name": "MAC 漂移（端口归属变化）",        "scope": "single"},
    {"id": "D2", "signal": "STP_TOPO_CHANGE",     "name": "STP 拓扑变化（TC 增量）",         "scope": "single"},
    {"id": "D3", "signal": "ROOT_BRIDGE_CHANGE",  "name": "根桥变更",                        "scope": "single"},
    {"id": "D4", "signal": "BROADCAST_STORM",     "name": "广播/组播风暴",                   "scope": "single"},
    {"id": "D5", "signal": "INTERFACE_ERRORS",    "name": "接口错误计数（CRC/input errors）", "scope": "single"},
    {"id": "D6", "signal": "LINK_FLAPPING",       "name": "链路震荡（up/down）",              "scope": "single"},
    {"id": "D7", "signal": "LOG_KEYWORD",         "name": "厂商告警关键字映射",              "scope": "single"},
    {"id": "D8", "signal": "BPDU_ANOMALY",        "name": "BPDU 收发异常",                   "scope": "single"},
    {"id": "D9", "signal": "CROSS_DEVICE_CONFLICT", "name": "跨设备关联（MAC 全局冲突）",    "scope": "cross"},
    {"id": "D10", "signal": "OPTICAL_DEGRADE",    "name": "光模块收发功率（光衰）",           "scope": "single"},
    {"id": "D11", "signal": "TEMPERATURE",        "name": "温度告警",                        "scope": "single"},
    {"id": "D12", "signal": "POWER",              "name": "电源状态告警",                       "scope": "single"},
    {"id": "D13", "signal": "MAC_MULTI_PORT",     "name": "同设备 MAC 多端口冲突（环路直证）",  "scope": "single"},
]
# V4（阉割版）启用范围：离线 + 基础项（不含 BPDU / 跨设备）
V4_RULES = [r["id"] for r in RULE_CATALOG if r["id"] not in ("D8", "D9")]
# V5（完整版）启用范围：全部
V5_RULES = [r["id"] for r in RULE_CATALOG]


# ══════════════════════════════════════════════════════════════════
# 小工具
# ══════════════════════════════════════════════════════════════════
def _th(rules: Optional[Dict[str, Any]], key: str, default: Any) -> Any:
    """
    从 rules 字典取阈值，缺失/类型不符时回退默认值 / fetch a threshold with fallback.

    ⚠️ 支持两种写法（rules.yaml 用的是**嵌套**写法，load_rules() 也保持嵌套）：
      * 顶层：`broadcast_pps: 1000`
      * 嵌套：`thresholds: { broadcast_pps: 1000 }`   ← rules.yaml 实际格式
    早期只读顶层 → 用户按文档改 `rules.yaml` 的阈值**完全不生效**（静默回退内置默认值）。
    顶层优先（便于测试/覆盖），其次嵌套；都没有才回退 default。
    """
    if isinstance(rules, dict):
        v = rules.get(key)
        if v is None:
            nested = rules.get("thresholds")
            if isinstance(nested, dict):
                v = nested.get(key)
        if v is not None:
            return v
    return default


def _f(v: Any, default: float = 0.0) -> float:
    """宽松转 float：None/非法值 → default（解析层偶有缺字段）/ lenient float cast."""
    try:
        if v is None:
            return default
        return float(v)
    except (TypeError, ValueError):
        return default


def _alert(rule_id: str, signal: str, severity: str, confidence: str, device: str,
           evidence: str, advice: str, interface: str = "", delta: Any = None,
           threshold: Any = None, **extra: Any) -> Dict[str, Any]:
    """构造一条统一格式的告警 / build one unified alert dict."""
    a: Dict[str, Any] = {
        "rule_id": rule_id, "signal": signal, "severity": severity,
        "confidence": confidence, "device": device, "interface": interface,
        "evidence": evidence, "delta": delta, "threshold": threshold, "advice": advice,
    }
    a.update(extra)
    if not a.get("fault_hint"):
        a["fault_hint"] = FAULT_HINT.get(rule_id, "")
    return a


def _class_of(sample: Dict[str, Any]) -> str:
    """取设备分档（core/aggregation/access），缺省 access（阈值最宽松档）/ device class."""
    c = (sample or {}).get("device_class") or "access"
    return c if c in ("core", "aggregation", "access") else "access"


def _rate(delta: float, seconds: float) -> float:
    """把计数增量换成"每分钟"速率。/ convert a counter delta into per-minute rate."""
    if seconds is None or seconds <= 0:
        return 0.0
    return delta / (seconds / 60.0)


def _match_any(text: str, patterns: Sequence[str]) -> Optional[str]:
    """在 text 中做大小写不敏感的正则搜索，命中则返回命中的模式 / case-insensitive search."""
    if not text or not patterns:
        return None
    for pat in patterns:
        try:
            if re.search(pat, text, re.IGNORECASE):
                return pat
        except re.error:
            # 用户自定义规则里的正则可能写错：跳过而不是崩 / tolerate bad user regex
            continue
    return None


# ══════════════════════════════════════════════════════════════════
# D1 · MAC 漂移（同一 MAC 在两轮间换了端口）
# ══════════════════════════════════════════════════════════════════
# ══════════════════════════════════════════════════════════════════
# 日志上下文抽取 / log context extraction（D7 升级用；事件层复用）
# ══════════════════════════════════════════════════════════════════

_RE_MAC = re.compile(r"([0-9a-fA-F]{4}[-:][0-9a-fA-F]{4}[-:][0-9a-fA-F]{4})")
_RE_VLAN = re.compile(r"(?:VlanId|VLAN|Vlan|vlan)\s*[=:：]?\s*(\d{1,4})")
_RE_PORT = re.compile(r"(?:Interface|interface|Port|port|PORT)\s*[=:：]\s*([A-Za-z][A-Za-z0-9\-]*\d[\w/\.:\-]*)")
_RE_PORT2 = re.compile(r"\b((?:Eth-Trunk|XGE|10GE|40GE|100GE|GE|GigabitEthernet|MEth)\d[\w/\.:]*)")
_RE_EVENT = re.compile(r"%%\d+([A-Za-z0-9_]+)/(\d+)/([A-Za-z0-9_()\-]+)")


def extract_log_ctx(line: str) -> Dict[str, Any]:
    """
    从一行设备日志里抽出 MAC / VLAN / 端口 / 事件名。

    为什么需要：设备日志里**本来就把环路与 MAC 漂移涉及的端口、VLAN 写清楚了**，
    早期只当"关键字命中"处理，把这些信息丢掉了，非专业使用者就看不到"到底哪个口"。
    华为真实例子::

        Sep 17 2026 08:46:59 HOST %%01FEI/4/hwMflpVlanLoopPeriodicTrap(s):...VlanId=100
        Sep 17 2026 09:01:27 HOST %%01MAC/4/MAC_MOVE(l)[1]:MAC f033-e508-0567 moved to port GE1/0/4

    :return: ``{"mac","vlan","port","event"}``（取不到的字段为 None）。
    """
    s = str(line or "")
    mac = _RE_MAC.search(s)
    vlan = _RE_VLAN.search(s)
    port = _RE_PORT.search(s) or _RE_PORT2.search(s)
    ev = _RE_EVENT.search(s)
    return {
        "mac": (mac.group(1).lower() if mac else None),
        "vlan": (int(vlan.group(1)) if vlan else None),
        "port": (port.group(1) if port else None),
        "event": (f"{ev.group(1)}/{ev.group(2)}/{ev.group(3)}" if ev else None),
    }


# 规则 → 故障类型（供事件聚合器归并；集中一处，规则本身不必各自声明）
FAULT_HINT: Dict[str, str] = {
    "D13": "loop", "D1": "loop", "D9": "loop",
    "D4": "storm", "D7": "log",
    "D5": "phy", "D6": "phy",
    "D10": "hw", "D11": "hw", "D12": "hw",
    "D2": "stp", "D3": "stp", "D8": "stp",
}


def rule_d13_mac_multi_port(sample: Dict[str, Any],
                            rules: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    D13 · 同设备 MAC 多端口冲突 / same-device multi-port MAC conflict.

    判据（**单轮即可判定**）：同一 `MAC + VLAN` 在同一台设备的 **≥2 个非聚合端口**上同时出现。
    含义：同一个终端的"身份"同时挂在两个口上 → 这两个口之间**被环接**了
          （或两根线接到了同一台上游设备）。这是环路最直接、也最容易照着处理的证据。

    排除：聚合口/堆叠口（`is_aggregate` / `is_stack_member`）天然多口同 MAC；三层设备
          （BRAS 等，`l2_table_na`）没有二层表，直接跳过。

    :return: 告警列表，每条带 `mac` / `vlan` / `ports`（端口列表，界面可直接点名两个口）。
    """
    out: List[Dict[str, Any]] = []
    if sample.get("l2_table_na"):
        return out
    th = _th(rules, "mac_multi_port", DEFAULTS["mac_multi_port"])
    need = int(th.get("min_ports", 2)) if isinstance(th, dict) else 2
    by_mac: Dict[Any, List[str]] = {}
    for m in (sample.get("macs") or []):
        if m.get("is_aggregate") or m.get("is_stack_member"):
            continue
        port = str(m.get("port") or "").strip()
        if not port:
            continue
        key = (m.get("mac"), m.get("vlan"))
        by_mac.setdefault(key, [])
        if port not in by_mac[key]:
            by_mac[key].append(port)
    for (mac, vlan), ports in by_mac.items():
        if len(ports) < need:
            continue
        out.append(_alert(
            "D13", "MAC_MULTI_PORT", "high", "high", sample.get("device", "?"),
            evidence=(f"MAC {mac}（VLAN {vlan}）同时出现在 {len(ports)} 个端口：{'、'.join(ports)}"
                      f" —— 这些端口之间疑似被环接"),
            advice=("到该设备上依次拔掉这些端口的网线，观察广播量是否下降；"
                    "若两端接在同一台上游设备/小交换机上，说明这两根线形成了环路"),
            interface=ports[0], mac=mac, vlan=vlan, ports=ports, port_count=len(ports),
        ))
    return out



def rule_d1_mac_flap(s1: Dict[str, Any], s2: Dict[str, Any],
                     rules: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    D1 · MAC 漂移检测 / MAC address flapping detection.

    判据：比较两轮采样中「同一 MAC + 同一 VLAN」所对应的端口。
      端口发生变化 → 记 1 次"漂移"。
    阈值：max(1, mac_move_count.warn) 次 → 可疑；mac_move_count.high 次 → 高危。
    说明：单次变化即报警（warn=1），要求"来回跳"（≥2）才升级为高危，以压制
          终端正常换口的误报。
    """
    out: List[Dict[str, Any]] = []
    m1 = {(m.get("mac"), m.get("vlan")): m.get("port") for m in (s1.get("macs") or [])}
    m2 = {(m.get("mac"), m.get("vlan")): m.get("port") for m in (s2.get("macs") or [])}
    moves = []
    for key, p2 in m2.items():
        p1 = m1.get(key)
        if p1 and p2 and p1 != p2:
            moves.append((key[0], key[1], p1, p2))
    if not moves:
        return out
    th = _th(rules, "mac_move_count", DEFAULTS["mac_move_count"])
    warn_n = int(th.get("warn", 1)) if isinstance(th, dict) else 1
    high_n = int(th.get("high", 2)) if isinstance(th, dict) else 2
    dev = s1.get("device", "?")
    for mac, vlan, p1, p2 in moves:
        sev = "high" if len(moves) >= max(high_n, warn_n) else ("medium" if len(moves) >= warn_n else "low")
        # 单条 MAC 漂移：默认 medium（可疑）；整体漂移数达到 high 阈值则升级
        if sev == "low":
            sev = "medium"
        out.append(_alert(
            "D1", "MAC_FLAPPING", sev, "high", dev,
            evidence=f"MAC {mac} (VLAN {vlan}) 端口由 {p1} 变为 {p2}",
            advice="确认该 MAC 是否为无线/漫游终端；若不是，检查两端口是否形成二层环路",
            interface=f"{p1} ↔ {p2}", delta=len(moves), threshold=warn_n,
            mac=mac, vlan=vlan, ports=[p1, p2], port_count=2,
            port_before=p1, port_after=p2,
        ))
    return out


# ══════════════════════════════════════════════════════════════════
# D2 · STP 拓扑变化（TC 计数增量）
# ══════════════════════════════════════════════════════════════════
def rule_d2_stp_tc(s1: Dict[str, Any], s2: Dict[str, Any],
                   rules: Optional[Dict[str, Any]] = None,
                   interval_seconds: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    D2 · STP 拓扑变化速率 / STP topology-change (TC) rate.

    判据：两轮采样间 tc_count 增量 ÷ 间隔 = 每分钟 TC 次数。
    阈值：按设备分档取（access 5 / aggregation 15 / core 30 次每分钟），超阈值报警。
    说明：正常网络 TC 稀疏；持续高频 TC 是二层抖动/环路的典型征兆。
    """
    out: List[Dict[str, Any]] = []
    t1 = _f((s1.get("stp") or {}).get("tc_count"))
    t2 = _f((s2.get("stp") or {}).get("tc_count"))
    if t2 < t1:                       # 计数器回绕/重置：本轮跳过，避免假告警
        return out
    dt = interval_seconds or (s2.get("ts", 0) - s1.get("ts", 0)) or None
    delta = t2 - t1
    rate = _rate(delta, dt) if dt else 0.0
    cls = _class_of(s1)
    th = _th(rules, "tc_per_minute", DEFAULTS["tc_per_minute"])
    limit = _f((th or {}).get(cls), 5)
    if rate > limit:
        sev = "high" if rate > limit * 3 else "medium"
        out.append(_alert(
            "D2", "STP_TOPO_CHANGE", sev, "high", s1.get("device", "?"),
            evidence=f"TC 计数 {int(t1)} → {int(t2)}（增量 {int(delta)}，约 {rate:.1f} 次/分钟；"
                     f"设备档 {cls}，阈值 {limit:g}）",
            advice="检查该设备主干端口是否频繁 up/down、或存在二层环路/单向链路",
            delta=round(rate, 2), threshold=limit,
        ))
    return out


# ══════════════════════════════════════════════════════════════════
# D3 · 根桥变更
# ══════════════════════════════════════════════════════════════════
def rule_d3_root_change(s1: Dict[str, Any], s2: Dict[str, Any],
                        rules: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    D3 · 根桥变更检测 / Root bridge change.

    判据：两轮间 root_id（或 root_port）发生变化。变化本身是 medium；
          若同时伴随 TC 高增量（由 D2 报出），人工合并判断为高危。
    """
    out: List[Dict[str, Any]] = []
    a, b = (s1.get("stp") or {}), (s2.get("stp") or {})
    r1, r2 = a.get("root_id"), b.get("root_id")
    p1, p2 = a.get("root_port"), b.get("root_port")
    if r1 and r2 and r1 != r2:
        out.append(_alert(
            "D3", "ROOT_BRIDGE_CHANGE", "medium", "high", s1.get("device", "?"),
            evidence=f"根桥 ID 由 {r1} 变为 {r2}",
            advice="确认是否为计划性主备切换；若非，检查原根桥是否掉电/链路中断导致重新收敛",
            delta=1, threshold=1,
        ))
    if p1 and p2 and p1 != p2 and not (r1 and r2 and r1 != r2):
        out.append(_alert(
            "D3", "ROOT_BRIDGE_CHANGE", "low", "medium", s1.get("device", "?"),
            evidence=f"根端口由 {p1} 变为 {p2}（根桥未变）",
            advice="观察该端口对应链路质量；如伴随 TC 抖动需一并排查",
            interface=f"{p1} → {p2}", delta=1, threshold=1,
        ))
    return out


# ══════════════════════════════════════════════════════════════════
# D4 · 广播/组播风暴
# ══════════════════════════════════════════════════════════════════
def rule_d4_broadcast_storm(s1: Dict[str, Any], s2: Dict[str, Any],
                            rules: Optional[Dict[str, Any]] = None,
                            interval_seconds: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    D4 · 广播/组播风暴 **并按"环路组"聚合** / broadcast storm, grouped into loop groups.

    判据：两轮间接口 broadcast(+multicast) 计数增量 ÷ 间隔 = pps；超阈值报警。
    分组：同一台设备上 **pps 相近（容差 broadcast_group_tolerance_pct，默认 ±20%）** 且同时越阈的
          端口 → 合成 **一条** 告警（"环路组"）。物理含义：环路里的帧会在组内所有端口上
          以几乎相同的速率循环 → 同速率的多个端口 = 同一个环。

    为什么要聚合：真实环境一次环路会让十几二十个端口同时越阈，逐端口各报一条会得到上百条
    散点告警，使用者看不出"这是一件事"。聚合后 1 个环路 = 1 条告警，且天然把
    "单端口小广播（终端/摄像头，不是环路）"与"多端口同速率（环路）"区分开。

    :return: 告警列表；组告警带 `ports`（端口列表）/`port_count`/`grouped=True`。
    """
    out: List[Dict[str, Any]] = []
    dt = interval_seconds or (s2.get("ts", 0) - s1.get("ts", 0)) or None
    if not dt:
        return out
    i1 = {i.get("name"): i for i in (s1.get("interfaces") or [])}
    th = _f(_th(rules, "broadcast_pps", DEFAULTS["broadcast_pps"]), 1000)
    hits: List[tuple] = []
    for i2 in (s2.get("interfaces") or []):
        name = i2.get("name")
        a = i1.get(name)
        if not a:
            continue
        d = (_f(i2.get("bcast")) + _f(i2.get("mcast"))) - (_f(a.get("bcast")) + _f(a.get("mcast")))
        if d <= 0:
            continue
        pps = d / dt
        if pps > th:
            hits.append((name, pps))
    if not hits:
        return out
    dev = s1.get("device", "?")
    tol = _f(_th(rules, "broadcast_group_tolerance_pct", DEFAULTS["broadcast_group_tolerance_pct"]), 20.0) or 20.0
    hits.sort(key=lambda x: -x[1])
    groups: List[List[tuple]] = []
    for name, pps in hits:
        for g in groups:                                  # 与已有组的代表速率比较
            base = g[0][1]
            if base > 0 and abs(pps - base) / base * 100.0 <= tol:
                g.append((name, pps))
                break
        else:
            groups.append([(name, pps)])
    for g in groups:
        top_pps = g[0][1]
        sev = "high" if top_pps > th * 5 else "medium"
        if len(g) >= 2:
            ports = [n for n, _ in g]
            shown = "、".join(ports[:8]) + ("…" if len(ports) > 8 else "")
            out.append(_alert(
                "D4", "BROADCAST_STORM", sev, "high", dev,
                evidence=(f"{len(g)} 个端口广播+组播量相近（各约 {top_pps:.0f} pps，阈值 {th:g} pps）："
                          f"{shown} —— 同速率的多个端口通常表示同一个环路在环流"),
                advice=("这些端口属于同一个环路：按端口顺序**依次拔掉网线**，每拔一根观察广播量是否下降，"
                        "降下来那根就是环路的接入点；确认后再顺着该线找对端"),
                interface=ports[0], ports=ports, port_count=len(ports),
                delta=round(top_pps, 1), threshold=th, grouped=True,
            ))
        else:
            name, pps = g[0]
            out.append(_alert(
                "D4", "BROADCAST_STORM", sev, "medium", dev,
                evidence=f"接口 {name} 广播+组播约 {pps:.0f} pps（阈值 {th:g} pps）",
                advice=("单端口高广播：多半是终端/摄像头在猛发广播，**不是环路**；"
                        "先观察，若持续增长再查该端口下面的设备"),
                interface=name, delta=round(pps, 1), threshold=th, grouped=False,
            ))
    return out


# ══════════════════════════════════════════════════════════════════
# D5 · 接口错误计数（CRC / input errors）
# ══════════════════════════════════════════════════════════════════
def rule_d5_interface_errors(s1: Dict[str, Any], s2: Dict[str, Any],
                             rules: Optional[Dict[str, Any]] = None,
                             interval_seconds: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    D5 · 接口错误计数增长 / Interface error counters growing.

    判据：两轮间 crc + input_err 增量 ÷ 分钟；超阈值报警。
    阈值：crc_per_minute.warn(100) / .high(1000)。
    说明：计数持续增长是物理层劣化的硬证据（不等于环路，但必然要处理）。
    """
    out: List[Dict[str, Any]] = []
    dt = interval_seconds or (s2.get("ts", 0) - s1.get("ts", 0)) or None
    if not dt:
        return out
    i1 = {i.get("name"): i for i in (s1.get("interfaces") or [])}
    th = _th(rules, "crc_per_minute", DEFAULTS["crc_per_minute"])
    warn_n = _f((th or {}).get("warn"), 100)
    high_n = _f((th or {}).get("high"), 1000)
    for i2 in (s2.get("interfaces") or []):
        name = i2.get("name")
        a = i1.get(name)
        if not a:
            continue
        d = (_f(i2.get("crc")) + _f(i2.get("input_err"))) - (_f(a.get("crc")) + _f(a.get("input_err")))
        if d <= 0:
            continue
        per_min = _rate(d, dt)
        if per_min > warn_n:
            sev = "high" if per_min > high_n else "medium"
            out.append(_alert(
                "D5", "INTERFACE_ERRORS", sev, "high", s1.get("device", "?"),
                evidence=f"接口 {name} CRC+输入错误约 {per_min:.0f} 次/分钟"
                         f"（增量 {int(d)} / {dt:.0f}s；阈值 {warn_n:g}）",
                advice="检查网线/水晶头/光模块与端口，排除线序、接触不良或光衰",
                interface=name, delta=round(per_min, 1), threshold=warn_n,
            ))
    return out


# ══════════════════════════════════════════════════════════════════
# D6 · 链路震荡（up/down 次数）
# ══════════════════════════════════════════════════════════════════
def rule_d6_link_flap(s1: Dict[str, Any], s2: Dict[str, Any],
                      rules: Optional[Dict[str, Any]] = None,
                      interval_seconds: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    D6 · 链路震荡 / Link flapping (up/down).

    判据：两轮间接口 up_down 计数增量 ÷ 小时；超阈值报警。
    阈值：link_flap_per_hour.warn(3) / .high(10)。
    """
    out: List[Dict[str, Any]] = []
    dt = interval_seconds or (s2.get("ts", 0) - s1.get("ts", 0)) or None
    if not dt:
        return out
    i1 = {i.get("name"): i for i in (s1.get("interfaces") or [])}
    th = _th(rules, "link_flap_per_hour", DEFAULTS["link_flap_per_hour"])
    warn_n = _f((th or {}).get("warn"), 3)
    high_n = _f((th or {}).get("high"), 10)
    for i2 in (s2.get("interfaces") or []):
        name = i2.get("name")
        a = i1.get(name)
        if not a:
            continue
        d = _f(i2.get("up_down")) - _f(a.get("up_down"))
        if d <= 0:
            continue
        per_h = d / (dt / 3600.0)
        if per_h > warn_n:
            sev = "high" if per_h > high_n else "medium"
            out.append(_alert(
                "D6", "LINK_FLAPPING", sev, "high", s1.get("device", "?"),
                evidence=f"接口 {name} 两轮间 up/down {int(d)} 次（约 {per_h:.1f} 次/小时；阈值 {warn_n:g}）",
                advice="检查光模块/网线/对端端口；若同时有 CRC 增长优先换线换模块",
                interface=name, delta=round(per_h, 1), threshold=warn_n,
            ))
    return out


# ══════════════════════════════════════════════════════════════════
# D7 · 厂商告警关键字映射（日志/告警文本）
# ══════════════════════════════════════════════════════════════════
def rule_d7_log_keywords(sample: Dict[str, Any],
                         rules: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    D7 · 厂商告警关键字映射 / Vendor log keyword mapping.

    输入：sample["logs"] 的原始文本行 + rules["signals"] 的关键字表。
    关键字表结构（rules.yaml）::

        signals:
          MAC_FLAPPING:
            severity: high
            patterns:
              huawei: ["MFLPVLAN", "MAC.{0,20}flapping"]
              ".*":   ["loop.{0,10}detect"]      # .* = 全厂商通用

    行为：按样本的 vendor 取对应模式（并合并 ".*" 通用模式），大小写不敏感匹配；
          命中即产出一条告警，带原始日志行作为证据。
    """
    out: List[Dict[str, Any]] = []
    logs = sample.get("logs") or []
    signals = (rules or {}).get("signals") or {}
    vendor = (sample.get("vendor") or "unknown").lower()
    for name, spec in signals.items():
        if not isinstance(spec, dict):
            continue
        pats: List[str] = []
        by_vendor = spec.get("patterns") or {}
        for vk, vv in by_vendor.items():
            if vk in (vendor, ".*", "*", "all") and isinstance(vv, list):
                pats.extend(vv)
        sev = spec.get("severity", "medium")
        for line in logs:
            hit = _match_any(str(line), pats)
            if hit:
                ctx = extract_log_ctx(line)
                bits = []
                if ctx["port"]:
                    bits.append(f"端口 {ctx['port']}")
                if ctx["vlan"] is not None:
                    bits.append(f"VLAN {ctx['vlan']}")
                if ctx["mac"]:
                    bits.append(f"MAC {ctx['mac']}")
                if ctx["event"]:
                    bits.append(f"事件 {ctx['event']}")
                tag = ("｜" + "｜".join(bits)) if bits else ""
                out.append(_alert(
                    "D7", name, sev, "medium", sample.get("device", "?"),
                    evidence=f"[{vendor}] 命中 '{hit}'{tag}：{str(line)[:200]}",
                    advice="按告警语义排查：MAC 漂移/环路→查两端线路；拓扑变化→查链路抖动",
                    interface=(ctx["port"] or ""), mac=ctx["mac"], vlan=ctx["vlan"],
                    event=ctx["event"], log_line=str(line)[:400],
                    delta=None, threshold=None, matched_keyword=hit,
                ))
                break       # 同一信号只报一次，避免刷屏
    return out


# ══════════════════════════════════════════════════════════════════
# D8 · BPDU 收发异常（V5）
# ══════════════════════════════════════════════════════════════════
def rule_d8_bpdu_anomaly(s1: Dict[str, Any], s2: Dict[str, Any],
                         rules: Optional[Dict[str, Any]] = None,
                         interval_seconds: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    D8 · BPDU 收发异常 / BPDU send-receive anomaly（V5 专属）.

    判据 A：两轮间接口 BPDU 接收速率异常高（默认 > 1000/s）。
    判据 B（强证据）：设备在**非边缘端口**上收到**本机 bridge ID** 的 BPDU → 自环。
                       本引擎只做判据 A（B 需解析层提供 bpdu_self_seen 标志）。
    """
    out: List[Dict[str, Any]] = []
    dt = interval_seconds or (s2.get("ts", 0) - s1.get("ts", 0)) or None
    a, b = (s1.get("stp") or {}), (s2.get("stp") or {})
    if b.get("bpdu_self_seen"):          # 解析层若发现"收到自己的 BPDU"
        out.append(_alert(
            "D8", "BPDU_ANOMALY", "high", "high", s1.get("device", "?"),
            evidence="在非边缘端口收到本机 Bridge ID 的 BPDU（自环特征）",
            advice="立即检查该端口链路是否被环回（接错线/插同一交换机两口）",
            delta=None, threshold=None,
        ))
    if dt:
        d = _f(b.get("bpdu_in")) - _f(a.get("bpdu_in"))
        if d > 0:
            pps = d / dt
            th = _f(_th(rules, "bpdu_in_per_second", DEFAULTS["bpdu_in_per_second"]), 1000)
            if pps > th:
                out.append(_alert(
                    "D8", "BPDU_ANOMALY", "medium", "medium", s1.get("device", "?"),
                    evidence=f"BPDU 接收约 {pps:.0f} 包/秒（阈值 {th:g}）",
                    advice="确认是否存在二层环路或 BPDU 泛洪来源",
                    delta=round(pps, 1), threshold=th,
                ))
    return out


# ══════════════════════════════════════════════════════════════════
# D9 · 跨设备关联（V5）
# ══════════════════════════════════════════════════════════════════
def rule_d9_cross_device(samples: Sequence[Dict[str, Any]],
                         rules: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    D9 · 跨设备关联 / Cross-device correlation（V5 专属）.

    判据 A：同一 MAC（同 VLAN）**同时出现在两台不同设备的端口上** → 环路强证据。
    判据 B：多台设备在同一采样窗口 TC 同时跳增 → 广播域级环路（由调用方传入同 ts 的样本）。
    判据 C：单设备 MAC 表条目数两轮剧烈波动（±mac_table_swing_pct%）。

    参数 samples：同一轮的**多台设备样本**（判据 A/B）或 [前轮, 后轮]（判据 C 另行传入）。
    说明：真实网络里聚合口/堆叠成员间同 MAC 多口是正常的，需在解析层标记
          `is_aggregate` / `is_stack_member` 后由本引擎排除——本函数只处理已标注的数据。

    :return: 告警列表。
    """
    out: List[Dict[str, Any]] = []
    # 判据 A：MAC 全局冲突
    seen: Dict[Any, List[tuple]] = {}
    for s in samples:
        dev = s.get("device", "?")
        for m in (s.get("macs") or []):
            if m.get("is_aggregate") or m.get("is_stack_member"):
                continue                        # 聚合/堆叠属正常多口，排除
            key = (m.get("mac"), m.get("vlan"))
            seen.setdefault(key, []).append((dev, m.get("port")))
    for (mac, vlan), holders in seen.items():
        devs = {d for d, _ in holders}
        if len(devs) > 1:
            detail = "；".join(f"{d}:{p}" for d, p in holders)
            out.append(_alert(
                "D9", "CROSS_DEVICE_CONFLICT", "high", "high", "多设备",
                evidence=f"MAC {mac} (VLAN {vlan}) 同时出现在多台设备：{detail}",
                advice="这是二层环路的最强证据：核对这些端口之间的物理链路，检查是否环接",
                delta=len(devs), threshold=1, mac=mac, vlan=vlan,
                peer=detail, ports=[p for _, p in holders], port_count=len(holders),
            ))
    # 判据 B：同窗口多设备 TC 同时跳增（要求 ≥2 台）
    if samples and all(s.get("loop_pair") for s in samples if s.get("loop_pair") is not None):
        pass    # 由调用方通过 analyze_cross() 传入成对样本时判定，见下
    return out


def rule_d9_tc_same_window(pairs: Sequence[Sequence[Dict[str, Any]]],
                           rules: Optional[Dict[str, Any]] = None,
                           interval_seconds: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    D9 判据 B · 同一采样窗口内多台设备 TC 同时跳增 / simultaneous TC burst.

    :param pairs: 形如 [[dev1_t1, dev1_t2], [dev2_t1, dev2_t2], ...] 的成对样本列表。
    :return: 命中时一条汇总告警（≥2 台设备在同一轮次 TC 增量超阈值）。
    """
    out: List[Dict[str, Any]] = []
    th = _th(rules, "tc_per_minute", DEFAULTS["tc_per_minute"])
    hits = []
    for pair in pairs:
        if len(pair) < 2:
            continue
        s1, s2 = pair[0], pair[1]
        t1 = _f((s1.get("stp") or {}).get("tc_count"))
        t2 = _f((s2.get("stp") or {}).get("tc_count"))
        if t2 < t1:
            continue
        dt = interval_seconds or (s2.get("ts", 0) - s1.get("ts", 0)) or None
        rate = _rate(t2 - t1, dt) if dt else 0.0
        limit = _f((th or {}).get(_class_of(s1)), 5)
        if rate > limit:
            hits.append(f"{s1.get('device', '?')}({rate:.0f}/min)")
    if len(hits) >= 2:
        out.append(_alert(
            "D9", "CROSS_DEVICE_CONFLICT", "high", "medium", "多设备",
            evidence=f"同一采样窗口内 {len(hits)} 台设备 TC 同时跳增：{'、'.join(hits)}",
            advice="广播域级环路特征：优先排查这些设备的公共上行/互联链路",
            delta=len(hits), threshold=2,
        ))
    return out


# ══════════════════════════════════════════════════════════════════
# D10 · 光模块收发功率（光衰）
# ══════════════════════════════════════════════════════════════════
def rule_d10_optical(s1: Dict[str, Any], s2: Dict[str, Any],
                     rules: Optional[Dict[str, Any]] = None,
                     interval_seconds: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    D10 · 光衰检测 / Optical power degradation.

    判据 A（绝对）：本轮 rx_power 低于阈值（warn -20 / high -25 dBm；dBm 越负越弱）。
    判据 B（趋势，更早预警）：两轮间 rx_power **下降** 超过 rx_power_drop_db（默认 3 dB）。
    判据 C：解析层标记 rx_alarm=True（模块 DDM 自报 Alarm/Warning）。
    说明：不同模块/距离正常范围差异大；模块类型未知时只信趋势（判据 B）。
    """
    out: List[Dict[str, Any]] = []
    i1 = {i.get("name"): i for i in (s1.get("interfaces") or [])}
    th = _th(rules, "rx_power_dbm", DEFAULTS["rx_power_dbm"])
    warn_dbm = _f((th or {}).get("warn"), -20.0)
    high_dbm = _f((th or {}).get("high"), -25.0)
    drop_db = _f(_th(rules, "rx_power_drop_db", DEFAULTS["rx_power_drop_db"]), 3.0)
    dev = s1.get("device", "?")
    for i2 in (s2.get("interfaces") or []):
        name = i2.get("name")
        rx2 = i2.get("rx_power")
        if rx2 is None:
            continue
        rx2 = _f(rx2)
        a = i1.get(name) or {}
        rx1 = a.get("rx_power")
        # 判据 C：模块自报
        if i2.get("rx_alarm"):
            out.append(_alert(
                "D10", "OPTICAL_DEGRADE", "high", "high", dev,
                evidence=f"接口 {name} 光模块自报 DDM 告警（RxPower {rx2:.2f} dBm）",
                advice="更换光模块或检查光纤接头/熔接点",
                interface=name, delta=None, threshold=None,
            ))
            continue
        # 判据 A：绝对值
        if rx2 < warn_dbm:
            sev = "high" if rx2 < high_dbm else "medium"
            out.append(_alert(
                "D10", "OPTICAL_DEGRADE", sev, "high" if a.get("module_type") else "medium", dev,
                evidence=f"接口 {name} 收光功率 {rx2:.2f} dBm（阈值 {warn_dbm:g} dBm）",
                advice="检查光纤链路（清洁端面/跳纤/法兰）；若模块类型未知，先对比同型号正常值",
                interface=name, delta=rx2, threshold=warn_dbm,
            ))
            continue
        # 判据 B：趋势变差
        if rx1 is not None:
            rx1 = _f(rx1)
            if (rx1 - rx2) > drop_db:
                out.append(_alert(
                    "D10", "OPTICAL_DEGRADE", "medium", "high", dev,
                    evidence=f"接口 {name} 收光功率两轮间 {rx1:.2f} → {rx2:.2f} dBm"
                             f"（下降 {rx1 - rx2:.2f} dB，阈值 {drop_db:g} dB）",
                    advice="光路正在劣化（灰尘/松动/弯曲半径），尽快清洁或更换跳纤",
                    interface=name, delta=round(rx1 - rx2, 2), threshold=drop_db,
                ))
    return out


# ══════════════════════════════════════════════════════════════════
# D11 · 温度告警
# ══════════════════════════════════════════════════════════════════
def rule_d11_temperature(s1: Dict[str, Any], s2: Dict[str, Any],
                         rules: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    D11 · 温度检测 / Temperature alarm.

    判据 A：传感器温度超阈值（warn 65°C / high 75°C）。
    判据 B（趋势）：两轮间升温超过 temp_rise_c（默认 10°C）→ 快速升温，多为风道/风扇问题。
    """
    out: List[Dict[str, Any]] = []
    t1 = {t.get("sensor"): t.get("value") for t in (s1.get("temperatures") or [])}
    th = _th(rules, "temp_c", DEFAULTS["temp_c"])
    warn_c = _f((th or {}).get("warn"), 65)
    high_c = _f((th or {}).get("high"), 75)
    rise_c = _f(_th(rules, "temp_rise_c", DEFAULTS["temp_rise_c"]), 10)
    dev = s1.get("device", "?")
    for t2 in (s2.get("temperatures") or []):
        sensor = t2.get("sensor")
        v2 = t2.get("value")
        if v2 is None:
            continue
        v2 = _f(v2)
        if v2 > warn_c:
            sev = "high" if v2 > high_c else "medium"
            out.append(_alert(
                "D11", "TEMPERATURE", sev, "high", dev,
                evidence=f"传感器 {sensor} 温度 {v2:.0f}°C（阈值 {warn_c:g}°C）",
                advice="检查机房环境温度、设备风扇与进出风道是否堵塞",
                interface=sensor, delta=v2, threshold=warn_c,
            ))
            continue
        v1 = t1.get(sensor)
        if v1 is not None and (_f(v2) - _f(v1)) > rise_c:
            out.append(_alert(
                "D11", "TEMPERATURE", "medium", "high", dev,
                evidence=f"传感器 {sensor} 两轮间由 {_f(v1):.0f}°C 升至 {v2:.0f}°C（阈值 +{rise_c:g}°C）",
                advice="短时快速升温：优先检查风扇是否停转/降速、风道是否被遮挡",
                interface=sensor, delta=round(v2 - _f(v1), 1), threshold=rise_c,
            ))
    return out


# ══════════════════════════════════════════════════════════════════
# D12 · 电源状态告警
# ══════════════════════════════════════════════════════════════════
def rule_d12_power(s1: Dict[str, Any], s2: Dict[str, Any],
                   rules: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    D12 · 电源状态检测 / Power supply status.

    判据 A：任一电源状态**非 Normal**（Abnormal/Fault/Absent/NotSupply/Unregistered）→ 高危。
    判据 B：在位电源数量减少（如双电源 → 单电源，冗余丢失）→ 高危。
    说明：字段语义明确，几乎无误报；V3 已有 display device 状态列解析经验，可直接复用。
    """
    out: List[Dict[str, Any]] = []
    bad_states = _th(rules, "power_abnormal_states", DEFAULTS["power_abnormal_states"])
    bad = {str(x).lower() for x in (bad_states or [])}
    dev = s1.get("device", "?")
    p2 = s2.get("power") or []
    for p in p2:
        st = str(p.get("status") or "").strip()
        if st and st.lower() in bad:
            out.append(_alert(
                "D12", "POWER", "high", "high", dev,
                evidence=f"电源 {p.get('id', '?')} 状态为 {st}",
                advice="确认电源模块是否在位/故障；双电源设备应尽快恢复冗余",
                interface=str(p.get("id") or ""), delta=None, threshold=None,
            ))
    n1 = len([p for p in (s1.get("power") or []) if str(p.get("status") or "").lower() == "normal"])
    n2 = len([p for p in p2 if str(p.get("status") or "").lower() == "normal"])
    if n1 and n2 and n2 < n1:
        out.append(_alert(
            "D12", "POWER", "high", "high", dev,
            evidence=f"正常供电电源数由 {n1} 变为 {n2}（冗余丢失）",
            advice="立即排查失效电源：模块故障/市电异常/电源线松脱",
            delta=n2 - n1, threshold=0,
        ))
    return out


# ══════════════════════════════════════════════════════════════════
# 主入口
# ══════════════════════════════════════════════════════════════════
_SINGLE_PAIR_RULES = {
    "D1": lambda s1, s2, r, dt: rule_d1_mac_flap(s1, s2, r),
    "D2": rule_d2_stp_tc,
    "D3": lambda s1, s2, r, dt: rule_d3_root_change(s1, s2, r),
    "D4": rule_d4_broadcast_storm,
    "D5": rule_d5_interface_errors,
    "D6": rule_d6_link_flap,
    "D8": rule_d8_bpdu_anomaly,
    "D10": rule_d10_optical,
    "D11": lambda s1, s2, r, dt: rule_d11_temperature(s1, s2, r),
    "D12": lambda s1, s2, r, dt: rule_d12_power(s1, s2, r),
    "D13": lambda s1, s2, r, dt: rule_d13_mac_multi_port(s2, r),
}


def analyze_pair(s1: Dict[str, Any], s2: Dict[str, Any],
                 rules: Optional[Dict[str, Any]] = None,
                 enabled: Optional[Iterable[str]] = None,
                 interval_seconds: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    对**同一台设备的两次采样**跑全部单设备规则 / run all single-device rules on a pair.

    :param s1: 第一轮采样（结构化，见模块 docstring）。
    :param s2: 第二轮采样。
    :param rules: 阈值与关键字配置（对应 rules.yaml；可为 None → 全用默认）。
    :param enabled: 启用的规则编号集合（对应 UI 选项框）；None = 启用全部单设备规则。
    :param interval_seconds: 两轮实际间隔（秒）；None 时用 s2.ts - s1.ts。
    :return: 告警列表（按 severity 排序：high → medium → low）。
    """
    ids = set(enabled) if enabled is not None else set(_SINGLE_PAIR_RULES.keys()) | {"D7"}
    out: List[Dict[str, Any]] = []
    for rid, fn in _SINGLE_PAIR_RULES.items():
        if rid not in ids:
            continue
        try:
            out.extend(fn(s1, s2, rules, interval_seconds))
        except Exception as exc:      # 单条规则异常不影响其它规则
            out.append(_alert(rid, "RULE_ERROR", "low", "low", s1.get("device", "?"),
                              evidence=f"规则 {rid} 执行异常：{exc}",
                              advice="该条规则内部错误，请反馈；其余规则结果仍有效",
                              delta=None, threshold=None))
    if "D7" in ids:
        try:
            out.extend(rule_d7_log_keywords(s2, rules))
        except Exception as exc:
            out.append(_alert("D7", "RULE_ERROR", "low", "low", s2.get("device", "?"),
                              evidence=f"规则 D7 执行异常：{exc}",
                              advice="该条规则内部错误，请反馈",
                              delta=None, threshold=None))
    return sort_alerts(out)


def analyze_cross(pairs: Sequence[Sequence[Dict[str, Any]]],
                  rules: Optional[Dict[str, Any]] = None,
                  enabled: Optional[Iterable[str]] = None,
                  interval_seconds: Optional[float] = None) -> List[Dict[str, Any]]:
    """
    跨设备分析（V5 专属）/ cross-device analysis.

    :param pairs: [[设备1_第1轮, 设备1_第2轮], [设备2_第1轮, 设备2_第2轮], ...]
    :param rules: 配置。
    :param enabled: 启用的规则编号（应含 "D9"）。
    :param interval_seconds: 两轮间隔（秒）。
    :return: 告警列表。
    """
    ids = set(enabled) if enabled is not None else {"D9"}
    if "D9" not in ids:
        return []
    latest = [p[-1] for p in pairs if p]      # 每台设备的最后一轮 → 用于 MAC 全局冲突
    out = rule_d9_cross_device(latest, rules)
    out += rule_d9_tc_same_window(pairs, rules, interval_seconds)
    return sort_alerts(out)


def sort_alerts(alerts: List[Dict[str, Any]]) -> List[Dict[str, Any]]:
    """按严重级排序：high → medium → low（同级按规则编号）/ sort by severity."""
    rank = {"high": 0, "medium": 1, "low": 2}
    return sorted(alerts, key=lambda a: (rank.get(a.get("severity", "low"), 9),
                                         str(a.get("rule_id", "")),
                                         str(a.get("device", ""))))


if __name__ == "__main__":
    # 快速自检：构造两轮数据，跑一遍全部规则（详细用例见 test_ring_rules.py）
    a = {"device": "SW1", "vendor": "huawei", "device_class": "access", "ts": 0,
         "interfaces": [{"name": "GE0/0/1", "bcast": 100, "mcast": 0, "crc": 0,
                         "input_err": 0, "up_down": 0, "rx_power": -12.0}],
         "macs": [{"mac": "aabb.ccdd.0001", "vlan": 10, "port": "GE0/0/1"}],
         "stp": {"tc_count": 10, "root_id": "R1", "root_port": "GE0/0/1"},
         "power": [{"id": "PWR1", "status": "Normal"}],
         "temperatures": [{"sensor": "Slot1", "value": 40}], "logs": []}
    b = {"device": "SW1", "vendor": "huawei", "device_class": "access", "ts": 60,
         "interfaces": [{"name": "GE0/0/1", "bcast": 90000, "mcast": 0, "crc": 5000,
                         "input_err": 0, "up_down": 5, "rx_power": -26.0}],
         "macs": [{"mac": "aabb.ccdd.0001", "vlan": 10, "port": "GE0/0/2"}],
         "stp": {"tc_count": 60, "root_id": "R2", "root_port": "GE0/0/2"},
         "power": [{"id": "PWR1", "status": "Abnormal"}],
         "temperatures": [{"sensor": "Slot1", "value": 80}],
         "logs": ["STP/6/TC BPDU received on GE0/0/1"]}
    for al in analyze_pair(a, b, rules=None):
        print(f"[{al['severity']:>6}] {al['rule_id']} {al['signal']}: {al['evidence'][:90]}")

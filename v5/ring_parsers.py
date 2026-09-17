#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ring_parsers.py —— 厂商命令输出 → 结构化采样数据（P2 解析层）

设计定位
--------
`ring_rules.py`（判据引擎）只吃**结构化数据**，本模块负责把各厂商的**原始命令
输出文本**翻译成那个结构。厂商差异**全部集中在这里**——引擎侧零厂商代码。

数据流::

    V3 导出的报告 CSV ──┐
                        ├─→ 本模块 parse_report() ─→ sample(dict) ─→ ring_rules.analyze_*
    现场手动采集的 txt ─┘

命令 → 字段映射（华为）
----------------------
| 命令 | 喂给引擎的字段 |
|---|---|
| `display interface brief` | `interfaces[].input_err`、`in_uti/out_uti`、`is_aggregate` |
| `display interface` | `interfaces[].crc`、速率、up/down 状态、显式 `CRC:` 行 |
| `display mac-address` | `macs[]`（MAC/VLAN/端口/类型，聚合口标记）|
| `display stp` | `stp.root_id`、`stp.tc_count`、`bpdu_*`、`enabled` |
| `display device` | `power[]`（**槽位/电源组件的 Status 列**，见下）|
| `display logbuffer` | `logs[]`（D7 关键字映射的原料）|
| `display alarm active` | 转成 `ALARM[级别] …` 文本追加进 `logs[]` |
| `display transceiver diagnosis interface` | `interfaces[].rx_power/tx_power/rx_alarm` |
| `display temperature all` | `temperatures[]` |

三条重要约定（都来自真实样本踩坑）
----------------------------------
1. **不认识/参数错的命令必须显式识别**——华为 `display transceiver diagnosis
   interface` 在 ME60 上报 `Error: Unrecognized command`，`display temperature all`
   报 `Error: Too many parameters`。此时对应字段**留空并记录 `unsupported`**，
   绝不把报错文本当数据解析（否则会误报告警）。
2. **计数器语义**：`display interface brief` 的 `inErrors` 与 `display interface`
   里的 `N errors` 是**同一个计数器**，只能取其一填入 `input_err`/`crc`，
   否则 D5 会把增量算成两倍。本模块的规则：有 brief 用 brief（填 `input_err`），
   详细输出里的显式 `CRC:` 行才填 `crc`。
3. **`display device` 在 ME60 这类平台给的是槽位表**（不是电源模块表）——
   槽位/电源的状态列都是 Normal/Abnormal/Fault/…，语义与 D12 的判据一致，
   所以统一映射到 `power[]`（id 形如 `Slot9(MPU)`）。**证据文本会把电源一词
   用在组件上，属已知的措辞妥协**（真正区分 PSU 需要在支持的平台上换命令）。

用法
----
::

    from ring_parsers import parse_report
    import ring_rules

    devs = parse_report("report_20260917_145530.csv")        # {device: sample}
    alerts = ring_rules.analyze_pair(devs_a[dev], devs_b[dev])   # 单设备两轮差分

命令行自检（读取同目录 samples/ 下的真实样本）::

    python ring_parsers.py
"""

from __future__ import annotations

import csv
import os
import re
import sys
from typing import Any, Dict, Iterable, List, Optional, Tuple

# ══════════════════════════════════════════════════════════════════
# 命令不支持 / 报错识别
# ══════════════════════════════════════════════════════════════════

# 各厂商"命令不存在 / 参数错"的典型措辞（大小写不敏感）
_ERROR_PATTERNS = [
    r"unrecognized command",                 # 华为 / 华三
    r"too many parameters",                  # 华为
    r"wrong parameter",
    r"incomplete command",
    r"ambiguous command",
    r"invalid input detected",               # 思科
    r"invalid command",                      # 锐捷 / 思科
    r"^\s*%\s*(unrecognized|invalid|unknown)",  # 华三 / 锐捷 的 % 提示
    r"error:\s*.+at '\^' position",          # 华为统一格式
]


def is_cmd_error(text: str) -> Tuple[bool, str]:
    """
    判断一段命令输出是不是"命令不支持/参数错"。

    :param text: 命令原始输出。
    :return: `(是否报错, 报错摘要)`。摘要取第一行命中行，便于写进日志/界面。
    """
    if not text:
        return False, ""
    for line in text.splitlines():
        s = line.strip()
        if not s:
            continue
        low = s.lower()
        for pat in _ERROR_PATTERNS:
            if re.search(pat, low):
                return True, s[:160]
    return False, ""


# ══════════════════════════════════════════════════════════════════
# 通用小工具
# ══════════════════════════════════════════════════════════════════

def _lines(text: str) -> List[str]:
    """去空行 + 去首尾空格的文本行列表（样本文件可能含重复换行，必须容忍）。"""
    return [l.strip() for l in (text or "").replace("\r", "\n").split("\n") if l.strip()]


def norm_mac(raw: str) -> str:
    """
    归一化 MAC 格式：只留 12 位十六进制，输出 `xxxx-xxxx-xxxx`（小写）。

    华为用 `aabb-cccc-dddd`，思科用 `aabb.cccc.dddd`，Linux 用 `f0:33:e5:b5:26:6e`。
    归一化后跨轮/跨设备比较才可靠（引擎靠字符串相等判断"同一 MAC"）。
    """
    h = re.sub(r"[^0-9a-fA-F]", "", raw or "").lower()
    if len(h) != 12:
        return (raw or "").strip().lower()
    return f"{h[0:4]}-{h[4:8]}-{h[8:12]}"


def _num(raw: Any, default: float = 0.0) -> float:
    """宽松数字转换（容忍 `--`、`-`、空、带单位残留）。"""
    if raw is None:
        return default
    if isinstance(raw, (int, float)):
        return float(raw)
    m = re.search(r"-?\d+(?:\.\d+)?", str(raw))
    return float(m.group()) if m else default


def _is_aggregate_name(name: str) -> bool:
    """判断接口名是否为聚合口/堆叠成员（引擎 D9 需要据此排除"正常多口"）。"""
    n = (name or "").lower()
    return ("eth-trunk" in n or n.startswith("trunk")
            or re.match(r"^(port-channel|bundle-ether|bridge-aggregation)", n) is not None
            or "stack-port" in n)


def norm_ifname(name: str) -> str:
    """
    接口名归一化：去掉结尾的 `(10G)` / `(100M)` / `(GE)` 这类**速率后缀**。

    为什么必须做：同一条链路在 `display interface brief` 里叫
    `GigabitEthernet1/0/2(10G)`，在 `display interface` 里却叫
    `GigabitEthernet1/0/2` —— 不归一化就会被当成两个接口，两边的
    错误计数/速率永远合不到一起（实测 66 个接口全对不上）。

    只剥**结尾圆括号**，子接口的点号（`…/0.990`）保持原样。
    """
    return re.sub(r"\([^()]*\)\s*$", "", (name or "").strip()).strip()


# ══════════════════════════════════════════════════════════════════
# 华为 VRP 解析器
# ══════════════════════════════════════════════════════════════════

_BRIEF_ROW = re.compile(
    r"^(?P<name>\S+)\s+"           # 接口名（可能带 (10G) 后缀）
    r"(?P<phy>\*?down|up|\*down|\^down|\S+)\s+"
    r"(?P<proto>\S+)\s+"
    r"(?P<in_uti>-{1,2}|\d+(?:\.\d+)?%?)\s+"
    r"(?P<out_uti>-{1,2}|\d+(?:\.\d+)?%?)\s+"
    r"(?P<in_err>\d+)\s+"
    r"(?P<out_err>\d+)\s*$"
)


def parse_huawei_interface_brief(text: str) -> List[Dict[str, Any]]:
    """
    解析 `display interface brief`。

    真实样例行（ME60）::

        Interface                   PHY   Protocol  InUti OutUti   inErrors  outErrors
        Eth-Trunk1                  up    up       25.88%  8.27%        169          0
          GigabitEthernet1/0/2(10G) up    up       25.74%  8.30%          0          0
        Vlanif1000                  up    up           --     --          0          0

    :return: `[{"name","phy","proto","in_uti","out_uti","input_err","out_err","is_aggregate"}]`
    """
    out: List[Dict[str, Any]] = []
    for line in _lines(text):
        if line.lower().startswith("interface"):        # 表头
            continue
        if line.startswith(("*down:", "^down:", "(l)", "PHY:", "InUti/OutUti")):
            continue
        m = _BRIEF_ROW.match(line)
        if not m:
            continue
        d = m.groupdict()
        out.append({
            "name": d["name"],
            "phy": d["phy"],
            "proto": d["proto"],
            "in_uti": _num(d["in_uti"].rstrip("%"), 0.0),
            "out_uti": _num(d["out_uti"].rstrip("%"), 0.0),
            "input_err": _num(d["in_err"]),          # ← D5 用
            "out_err": _num(d["out_err"]),
            "is_aggregate": _is_aggregate_name(d["name"]),
        })
    return out


# ── display interface（详细）字段 ──
# ⚠ 实测华为同一命令有**两种排版**，必须都支持（只认一种会静默漏采）：
#   A. 聚合口（Eth-Trunk）：`Input: N packets,M bytes` + 下一行 `N errors,M drops`
#   B. 物理端口：`Input: N bytes, M packets` + `Unicast/Multicast/Broadcast/CRC/Symbol…`
#      逐类计数，**并额外给出 Rx Power / Tx Power / 光模块型号 / Link quality grade**
#      ——光功率就在这里，不需要 `display transceiver`（ME60 上那条命令根本不存在）。
_DET_STATE = re.compile(r"^(?P<name>\S+)\s+current state\s*:\s*(?P<state>\S+)")
_DET_PROTO = re.compile(r"^Line protocol current state\s*:\s*(?P<state>\S+)")
_DET_RATE = re.compile(
    r"^Last \d+ seconds (?P<dir>input|output) rate\s*:?\s*"
    r"(?P<bps>\d+)\s+bits/sec,\s*(?P<pps>\d+)\s+packets/sec")
_DET_UTI = re.compile(r"^Last \d+ seconds (?P<dir>input|output) utility rate\s*:\s*(?P<v>[\d.]+)%")
_DET_IO_HDR = re.compile(
    r"^(?P<dir>Input|Output):\s*(?P<a>\d+)\s+(?P<ua>packets|bytes),\s*"
    r"(?P<b>\d+)\s+(?P<ub>bytes|packets)")
_DET_ERRS = re.compile(r"^(?P<err>\d+)\s+errors,\s*(?P<drop>\d+)\s+drops")
# 逐类计数：一行里可能塞多个（"Unicast: …, Multicast: …" / "CRC: 0, Overrun: 0"）
_DET_COUNTERS = re.compile(
    r"(?P<k>CRC|Symbol|Overrun|Alignment|Fragment|Jabber|LongPacket|InRangeLength|"
    r"Undersized Frame|RxPause|Unicast|Multicast|Broadcast|JumboOctets)\s*:\s*(?P<v>\d+)")
_DET_POWER = re.compile(
    r"^(?P<dir>Rx|Tx) Power:\s*(?P<v>-?\d+(?:\.\d+)?)\s*dBm"
    r"(?:,\s*Warning range:\s*\[\s*(?P<lo>-?\d+(?:\.\d+)?)\s*,\s*(?P<hi>-?\d+(?:\.\d+)?)\s*\])?")
_DET_PN = re.compile(r"^The Vendor PN is\s*(?P<v>.+)$")
_DET_VENDOR = re.compile(r"^The Vendor Name is\s*(?P<v>.+)$")
_DET_QUALITY = re.compile(r"^Link quality grade\s*:\s*(?P<q>\S+)")
_DET_LAST_UP = re.compile(r"^Last physical up time\s*:\s*(?P<v>.+)$")
_DET_LAST_DOWN = re.compile(r"^Last physical down time\s*:\s*(?P<v>.+)$")


def parse_huawei_interface_detail(text: str) -> List[Dict[str, Any]]:
    """
    解析 `display interface`（详细）——**兼容两种排版**，块状排列用状态机切块。

    A. 聚合口（实测 ME60 Eth-Trunk）::

        Eth-Trunk1 current state : UP (ifindex: 35)
        Line protocol current state : UP
        Last 300 seconds input rate 10346801693 bits/sec, 1022185 packets/sec
        Input: 52777497075475 packets,56580263369400625 bytes
          169 errors,0 drops

    B. 物理端口（实测 ME60 GE2/1/4，信息更全）::

        GigabitEthernet2/1/4 current state : UP (ifindex: 150)
        Link quality grade : GOOD
        The Vendor PN is MTRS-1E21-01
        The Vendor Name is HG GENUINE
        Port BW: 10G, Transceiver Mode: SingleMode
        Rx Power:  -4.99dBm, Warning range: [-14.400,  0.499]dBm
        Tx Power:  -3.63dBm, Warning range: [-8.198,  0.499]dBm
        Last 300 seconds input rate: 2673119412 bits/sec, 260270 packets/sec
        Input: 18495439075977750 bytes, 16369881512913 packets
        Input:
        Unicast: 16369865048593 packets, Multicast: 14916022 packets
        Broadcast: 1548298 packets, JumboOctets: 41302 packets
        CRC: 12535001 packets, Symbol: 1199524 packets

    产出字段（引擎会读的）：
      * `crc` ← 物理口的 `CRC:` 累计计数（**D5 的硬证据**）；
      * `bcast`/`mcast` ← Broadcast/Multicast 累计计数（**D4 差分就能算 pps**）；
      * `rx_power`/`tx_power` ← 光功率 dBm；**超出设备自报的 Warning range 即置
        `rx_alarm=True`**（D10 判据 C 直接用设备自己的判定，比自己猜阈值可靠）；
      * `input_err` ← 只有聚合口那种 `N errors,M drops` 行才有（与 brief 同一个计数器，
        合并阶段会去重）；
      * `module_type` ← 光模块厂商+型号（D10 需据此判断正常范围差异）。

    :return: 每个接口一个 dict（见模块文档的字段表）。
    """
    out: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    pending: Optional[str] = None        # "in"/"out"：下一行 `N errors` 属于谁

    for line in _lines(text):
        m = _DET_STATE.match(line)
        if m:
            cur = {
                "name": m.group("name"), "phy": m.group("state"), "proto": None,
                "in_bps": 0.0, "out_bps": 0.0, "in_pps": 0.0, "out_pps": 0.0,
                "in_pkts": 0.0, "out_pkts": 0.0,
                "input_err": 0.0, "out_err": 0.0, "crc": 0.0,
                "bcast": 0.0, "mcast": 0.0, "in_uti": 0.0, "out_uti": 0.0,
                "rx_power": None, "tx_power": None, "rx_alarm": False,
                "module_type": None, "quality": None,
                "last_up": None, "last_down": None,
                "is_aggregate": _is_aggregate_name(m.group("name")),
            }
            out.append(cur)
            pending = None
            continue
        if cur is None:
            continue

        m = _DET_PROTO.match(line)
        if m:
            cur["proto"] = m.group("state"); continue

        m = _DET_RATE.match(line)
        if m:
            e = "in" if m.group("dir") == "input" else "out"
            cur[f"{e}_bps"] = _num(m.group("bps"))
            cur[f"{e}_pps"] = _num(m.group("pps"))
            continue

        m = _DET_UTI.match(line)
        if m:
            e = "in" if m.group("dir") == "input" else "out"
            cur[f"{e}_uti"] = _num(m.group("v"))
            continue

        m = _DET_IO_HDR.match(line)
        if m:
            # 两种顺序都要认：packets,bytes（聚合口）/ bytes,packets（物理口）
            pair = {m.group("ua"): _num(m.group("a")), m.group("ub"): _num(m.group("b"))}
            e = "in" if m.group("dir") == "Input" else "out"
            cur[f"{e}_pkts"] = pair.get("packets", 0.0)
            pending = e
            continue

        m = _DET_ERRS.match(line)
        if m:
            if pending == "in":
                cur["input_err"] = _num(m.group("err"))
            elif pending == "out":
                cur["out_err"] = _num(m.group("err"))
            pending = None
            continue

        for cm in _DET_COUNTERS.finditer(line):
            k, v = cm.group("k"), _num(cm.group("v"))
            if k == "CRC":
                cur["crc"] = v
            elif k == "Broadcast":
                cur["bcast"] = v
            elif k == "Multicast":
                cur["mcast"] = v

        m = _DET_POWER.match(line)
        if m:
            val = _num(m.group("v"))
            if m.group("dir") == "Rx":
                cur["rx_power"] = val
                lo, hi = m.group("lo"), m.group("hi")
                if lo is not None and hi is not None:
                    cur["rx_lo"], cur["rx_hi"] = _num(lo), _num(hi)
                    # 设备自己给了 Warning range，越界就是模块自报异常（D10 判据 C）
                    if val < cur["rx_lo"] or val > cur["rx_hi"]:
                        cur["rx_alarm"] = True
            else:
                cur["tx_power"] = val
            continue

        m = _DET_PN.match(line)
        if m:
            cur["_mpn"] = m.group("v").strip(); continue
        m = _DET_VENDOR.match(line)
        if m:
            cur["_mname"] = m.group("v").strip(); continue
        m = _DET_QUALITY.match(line)
        if m:
            cur["quality"] = m.group("q"); continue
        m = _DET_LAST_UP.match(line)
        if m:
            cur["last_up"] = m.group("v"); continue
        m = _DET_LAST_DOWN.match(line)
        if m:
            cur["last_down"] = m.group("v"); continue

    for c in out:                                  # 光模块型号：厂商 + PN 拼一起
        c["module_type"] = " ".join(
            x for x in (c.pop("_mname", None), c.pop("_mpn", None)) if x) or None
    return out


_MAC_ROW = re.compile(
    r"^(?P<mac>[0-9a-fA-F]{4}[-.][0-9a-fA-F]{4}[-.][0-9a-fA-F]{4}|[0-9a-fA-F]{2}(?::[0-9a-fA-F]{2}){5})\s+"
    r"(?P<vlan>\d+)\s+"
    r"(?P<pevlan>\S+)\s+(?P<cevlan>\S+)\s+"
    r"(?P<port>\S+)\s+"
    r"(?P<type>\S+)"
)


def parse_huawei_mac(text: str) -> List[Dict[str, Any]]:
    """
    解析 `display mac-address`（华为按 **slot 分段**，每段一张表）。真实样例::

        MAC address table of slot 1:
        MAC Address    VLAN/BD/     PEVLAN CEVLAN Port/Peerip   Type      LSP/LSR-ID
        0000-5e00-0101 1000         -      -       GE2/0/4      dynamic   1/-
        Total matching items on slot 1 displayed = 3

    跳过表头/分隔线/合计行；`is_aggregate` 按端口名判断（Eth-Trunk 等）供 D9 排除。

    :return: `[{"mac","vlan","port","type","is_aggregate"}]`
    """
    out: List[Dict[str, Any]] = []
    for line in _lines(text):
        if line.startswith("MAC ") or line.startswith("MAC address table") \
                or line.startswith("Total matching") or line.startswith("---"):
            continue
        if line.startswith("VSI/SI") or line.startswith("MAC-Tunnel"):
            continue
        m = _MAC_ROW.match(line)
        if not m:
            continue
        d = m.groupdict()
        out.append({
            "mac": norm_mac(d["mac"]),
            "vlan": int(_num(d["vlan"])),
            "port": d["port"],
            "type": d["type"].lower(),
            "is_aggregate": _is_aggregate_name(d["port"]),
        })
    # 去重：华为按 slot 分段，同一 MAC 会在每个 slot 的表里各出现一次
    # （端口相同、只有 LSP/LSR-ID 不同），不去重会污染 D1/D9 的统计。
    seen = set()
    dedup: List[Dict[str, Any]] = []
    for m in out:
        k = (m["mac"], m["vlan"], m["port"])
        if k in seen:
            continue
        seen.add(k)
        dedup.append(m)
    return dedup


def parse_huawei_stp(text: str) -> Dict[str, Any]:
    """
    解析 `display stp`。

    两种形态都要兼容：
    * **汇总型**（ME60 实测）：`Protocol Status :Disabled` / `CIST Bridge Priority :32768`
      / `MAC address :aabb-cccc-dddd` → 只拿得到 `enabled` 与本地桥信息；
    * **详细型**（交换机）：`CIST Root/ERPC :32768.f033-… / 0`、`Topology change :YES`、
      部分平台有 `Topology Changes :N`。

    :return: `{"enabled","local_bridge_id","root_id","root_port","tc_count","tc_flag","raw"}`
             未出现的键为 `None`（引擎侧会当 0/空处理，不告警）。
    """
    stp: Dict[str, Any] = {
        "enabled": None, "local_bridge_id": None, "bridge_priority": None,
        "root_id": None, "root_port": None, "tc_count": None, "tc_flag": None,
        "bpdu_in": None, "bpdu_self_seen": None,
    }
    for line in _lines(text):
        low = line.lower()
        if "protocol status" in low:
            stp["enabled"] = "disabled" not in low
        elif low.startswith("cist root") or low.startswith("root bridge"):
            m = re.search(r":\s*(?P<rid>\d+\.\S+)", line)
            if m:
                stp["root_id"] = m.group("rid").rstrip("/ ")
                rp = re.search(r"/\s*(?P<rp>\d+)", line)
                if rp and not rp.group("rp").strip("0"):
                    stp["root_port"] = None
        elif low.startswith("cist bridge priority"):
            # ⚠ 必须先判这个——否则 "CIST Bridge Priority :32768" 会被
            #   下面的 "cist bridge" 分支吃掉，把 32768 当成 bridge ID。
            m = re.search(r":\s*(?P<p>\d+)", line)
            if m:
                stp["bridge_priority"] = int(m.group("p"))
        elif low.startswith("cist bridge") and "priority" not in low:
            m = re.search(r":\s*(?P<bid>\d+\.\S+)", line)
            if m:
                stp["local_bridge_id"] = m.group("bid").rstrip("/ ")
        elif low.startswith("mac address") and stp["local_bridge_id"] is None:
            # 汇总型输出（ME60）：本机桥 MAC 单独一行，没有 priority 前缀
            m = re.search(r":\s*(?P<mc>[0-9a-fA-F]{4}-[0-9a-fA-F]{4}-[0-9a-fA-F]{4})", line)
            if m:
                stp["local_bridge_id"] = norm_mac(m.group("mc"))
        elif "topology change" in low:
            m = re.search(r":\s*(?P<n>\d+)\s*$", line)
            if m:
                stp["tc_count"] = int(m.group("n"))
            else:
                stp["tc_flag"] = "yes" in low
        elif low.startswith("bpdu") and re.search(r":\s*\d+", line):
            m = re.search(r":\s*(?P<n>\d+)", line)
            if m:
                stp["bpdu_in"] = int(m.group("n"))
    # 只有 STP 真的在跑时，才把"本机即根桥"作为合理推断（禁用时不该声称自己是根）
    if stp["root_id"] is None and stp["local_bridge_id"] and stp["enabled"]:
        stp["root_id"] = stp["local_bridge_id"]
    return stp


_SLOT_ROW = re.compile(
    r"^(?P<slot>\d+)\s+(?P<type>\S+)\s+(?P<online>\S+)\s+(?P<reg>\S+)\s+"
    r"(?P<status>\S+)\s+(?P<role>\S+)\s+(?P<lsid>\d+)\s+(?P<primary>\S+)"
)


def parse_huawei_device(text: str) -> List[Dict[str, Any]]:
    """
    解析 `display device`（槽位/组件表）。真实样例::

        Slot #   Type    Online     Register     Status     Role   LsId   Primary
        1        BSU     Present    Registered   Normal     LC     0      NA
        9        MPU     Present    Registered   Normal     MMB    0      Master

    **映射说明**：这里产出的是**组件**（槽位）状态，会由 `parse_device_sample`
    映射进引擎的 `power[]`（id 形如 `Slot9(MPU)`）——因为判据只关心
    "状态列是否 Normal"，槽位异常（Abnormal/Fault/Unregistered/NotSupply）
    同样是必须告警的硬件故障。真正区分 PSU 需要平台支持 `display power`。

    :return: `[{"slot","type","online","register","status","role","primary"}]`
    """
    out: List[Dict[str, Any]] = []
    for line in _lines(text):
        if line.lower().startswith("slot") or line.startswith("---"):
            continue
        m = _SLOT_ROW.match(line)
        if not m:
            continue
        d = m.groupdict()
        out.append({
            "slot": int(_num(d["slot"])), "type": d["type"], "online": d["online"],
            "register": d["reg"], "status": d["status"], "role": d["role"],
            "primary": d["primary"],
        })
    return out


_LOGBUF_HDR_END = re.compile(r"^Current messages\s*:\s*\d+")


def parse_huawei_logbuffer(text: str) -> List[str]:
    """
    解析 `display logbuffer`：丢掉配置头，只保留日志正文行。

    真实样例::

        Logging buffer configuration and contents : enabled
        Allowed max buffer size : 10240
        ...
        Current messages : 512
        Sep 17 2026 14:14:28+08:00 ME60 %%01CPUDEFEND/4/SETARPFILTERENHANCECAR(s):CID=0x…;The port …

    ⚠ 日志里 `alarmID=0x…` 这类字段会让裸词匹配（如 `Alarm`）命中几百次 →
    规则表（`rules.yaml` 的 `signals`）必须用**完整事件名**匹配，别用裸词。

    :return: 日志正文行列表（原样，供 D7 关键字映射）。
    """
    lines = _lines(text)
    start = 0
    for i, l in enumerate(lines):
        if _LOGBUF_HDR_END.match(l):
            start = i + 1
            break
    else:
        for i, l in enumerate(lines):        # 没有头就直接找时间戳起始
            if re.match(r"^(Jan|Feb|Mar|Apr|May|Jun|Jul|Aug|Sep|Oct|Nov|Dec)\s+\d+\s+\d{4}", l):
                start = i
                break
    out = []
    for l in lines[start:]:
        if l.startswith(("display logbuffer", "<", "Info:", "Warning:")):
            continue
        out.append(l)
    return out


_ALARM_ROW = re.compile(
    r"^(?P<seq>\d+)\s+(?P<aid>0x[0-9a-fA-F]+|\S+)\s+(?P<lvl>[1-4])\s+"
    r"(?P<date>\d{4}-\d{2}-\d{2})\s+(?P<time>\S+)\s+(?P<desc>.*)$"
)
_ALARM_LEVELS = {"1": "Critical", "2": "Major", "3": "Minor", "4": "Warning"}


def parse_huawei_alarm(text: str) -> List[Dict[str, Any]]:
    """
    解析 `display alarm active`。真实样例::

        1:Critical  2:Major  3:Minor  4:Warning
        Sequence   AlarmId    Level Date Time  Description
        27826077   0x9E02000  4     2026-09-17 Security Operation Center detected one at
                                     14:05:05+ tack. (EventNo=66310,Reason=Access-user attack,
                                    08:00      Location=GigabitEthernet3/0/0…)

    描述会**跨行折行**（续行缩进对齐），所以按"新记录正则"做状态机，续行拼回。

    :return: `[{"seq","alarm_id","level","level_name","date","time","desc"}]`
    """
    out: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    for line in _lines(text):
        m = _ALARM_ROW.match(line)
        if m:
            if cur:
                out.append(cur)
            d = m.groupdict()
            cur = {
                "seq": d["seq"], "alarm_id": d["aid"],
                "level": int(d["lvl"]), "level_name": _ALARM_LEVELS[d["lvl"]],
                "date": d["date"], "time": d["time"], "desc": d["desc"],
            }
            continue
        if cur and not line.startswith(("Sequence", "---", "1:Critical", "display alarm")):
            cur["desc"] = (cur["desc"] + " " + line).strip()      # 折行续接
    if cur:
        out.append(cur)
    return out


def parse_huawei_transceiver(text: str) -> List[Dict[str, Any]]:
    """
    解析 `display transceiver diagnosis interface`（光模块 DDM）。

    真实形态（交换机；**ME60 不支持此命令**，调用方须先用 `is_cmd_error` 拦掉）::

        GigabitEthernet0/0/1 transceiver diagnostic information:
          Current diagnostic parameters:
            Temp.(C)  Voltage(V)  Bias(mA)  RX power(dBm)  TX power(dBm)
            36        3.29        6.20      -12.34         -2.11

    以"接口名 + transceiver … information"开新块，取表头后的第一行数值；
    同时扫描 `RX power … alarm/warning` 之类行设置 `rx_alarm`。

    :return: `[{"name","temp","rx_power","tx_power","rx_alarm"}]`
    """
    out: List[Dict[str, Any]] = []
    cur: Optional[Dict[str, Any]] = None
    hdr_seen = False

    for line in _lines(text):
        m = re.match(r"^(?P<name>\S+)\s+transceiver\b.*information", line, re.I)
        if m:
            cur = {"name": m.group("name"), "temp": None, "rx_power": None,
                   "tx_power": None, "rx_alarm": False}
            out.append(cur)
            hdr_seen = False
            continue
        if cur is None:
            continue
        low = line.lower()
        if "rx power" in low and "tx power" in low:      # 表头
            hdr_seen = True
            continue
        if "alarm" in low or "warning" in low:
            cur["rx_alarm"] = True
            continue
        if hdr_seen and not cur.get("_filled"):
            nums = re.findall(r"-?\d+(?:\.\d+)?", line)
            if len(nums) >= 5:
                cur["temp"] = _num(nums[0])
                cur["rx_power"] = _num(nums[3])
                cur["tx_power"] = _num(nums[4])
                cur["_filled"] = True
    for c in out:
        c.pop("_filled", None)
    return out


def parse_huawei_temperature(text: str) -> List[Dict[str, Any]]:
    """
    解析 `display temperature all`（**ME60 不支持此命令**，须先拦错）::

        Slot  Card  Sensor  Temperature(C)  Upper(C)  Lower(C)
        1     -     -       45              80        0

    取值策略（按可靠性排序）：
      1. 用**表头列起始字符位置**定位 Temperature(C) 列（固定宽度表格，最稳）；
      2. 退化到**表头词序号**取第 N 个 token；
      3. 都没有表头时才用启发式：行内第一个 -20~120 的数字。

    ⚠️ 早期实现直接用「行内第一个 -20~120 的数字」——在槽位表里取到的是**槽位号**（1），
    于是 D11 温度告警永远拿 1~N 度去比，真实过温（如 90 度）**静默漏报**。

    :return: `[{"sensor","value"}]`
    """
    out: List[Dict[str, Any]] = []
    col_starts: List[int] = []          # 表头各列起始字符位置
    t_idx: Optional[int] = None         # Temperature 列序号

    for line in _lines(text):
        if "temperature" in line.lower():
            toks = list(re.finditer(r"\S+", line))
            col_starts = [m.start() for m in toks]
            for k, m in enumerate(toks):
                if "temperature" in m.group(0).lower():
                    t_idx = k
            continue
        if not line.strip():
            continue

        value: Optional[float] = None
        if t_idx is not None:
            if col_starts and t_idx < len(col_starts) and col_starts[t_idx] < len(line):
                a = col_starts[t_idx]
                b = col_starts[t_idx + 1] if t_idx + 1 < len(col_starts) else len(line)
                m = re.search(r"-?\d+(?:\.\d+)?", line[a:b])
                if m:
                    value = float(m.group(0))
            if value is None:
                toks = line.split()
                if t_idx < len(toks):
                    m = re.search(r"-?\d+(?:\.\d+)?", toks[t_idx])
                    if m:
                        value = float(m.group(0))
        if value is None:
            nums = [float(x) for x in re.findall(r"-?\d+(?:\.\d+)?", line)]
            temps = [n for n in nums if -20 <= n <= 120]
            if not temps:
                continue
            value = temps[0]
        if not (-50 <= value <= 150):
            continue

        head = re.match(r"^(?P<slot>\d+)", line)
        sensor = f"Slot{head.group('slot')}" if head else (line.split()[0] if line.split() else "?")
        out.append({"sensor": sensor, "value": value})
    return out


# ══════════════════════════════════════════════════════════════════
# 汇总：命令输出字典 → 引擎可用的 sample
# ══════════════════════════════════════════════════════════════════

# 命令名（去空格小写后）→ 解析器
_HUAWEI_PARSERS = {
    "displayinterfacebrief": ("interfaces_brief", parse_huawei_interface_brief),
    "displayinterface": ("interfaces_detail", parse_huawei_interface_detail),
    "displaymac-address": ("macs", parse_huawei_mac),
    "displaymacaddress": ("macs", parse_huawei_mac),
    "displaystp": ("stp", parse_huawei_stp),
    "displaystpbrief": ("stp", parse_huawei_stp),
    "displaydevice": ("components", parse_huawei_device),
    "displaylogbuffer": ("logs", parse_huawei_logbuffer),
    "displayalarmactive": ("alarms", parse_huawei_alarm),
    "displaytransceiverdiagnosisinterface": ("transceiver", parse_huawei_transceiver),
    "displaytemperatureall": ("temperatures", parse_huawei_temperature),
}


def parse_device_sample(cmd_outputs: Dict[str, str], device: str = "?",
                        vendor: str = "huawei", ts: Optional[float] = None,
                        device_class: str = "access") -> Dict[str, Any]:
    """
    把一台设备的「命令 → 输出」字典翻译成引擎的 sample 结构。

    :param cmd_outputs: 形如 `{"display stp": "…", "display mac-address": "…"}`。
    :param device: 设备标识（IP/名称，写进告警的 device 字段）。
    :param vendor: 厂商（决定命令集与阈值档默认）。
    :param ts: 采样时间戳（秒）；缺省取 `time.time()`。
    :param device_class: `core|aggregation|access`，决定 D2 阈值档。
    :return: 引擎 sample；额外含 `unsupported`（命令 → 报错摘要）便于界面提示。
    """
    if ts is None:
        import time
        ts = time.time()

    sample: Dict[str, Any] = {
        "device": device, "vendor": vendor, "device_class": device_class, "ts": ts,
        "interfaces": [], "macs": [], "stp": {}, "power": [],
        "temperatures": [], "logs": [], "unsupported": {}, "alarms": [],
    }
    if vendor.lower() != "huawei":
        # 其他厂商解析器后续按同样接口补：parse_<vendor>_xxx + 这里的映射
        sample["unsupported"]["*"] = f"厂商 {vendor} 的解析器尚未实现"
        return sample

    brief_ifaces: Dict[str, Dict[str, Any]] = {}
    detail_ifaces: Dict[str, Dict[str, Any]] = {}

    for cmd, out in (cmd_outputs or {}).items():
        key = re.sub(r"\s+", "", (cmd or "").lower())
        entry = _HUAWEI_PARSERS.get(key)
        if entry is None:
            continue
        field, fn = entry
        err, msg = is_cmd_error(out)
        if err:
            # 命令不被该平台支持（如 ME60 的 transceiver / temperature）——
            # 记录并跳过，绝不把报错文本当数据解析。
            sample["unsupported"][cmd] = msg
            continue
        try:
            parsed = fn(out)
        except Exception as e:                      # 解析异常隔离，不影响其他命令
            sample["unsupported"][cmd] = f"解析失败: {e}"
            continue

        if field == "interfaces_brief":
            for i in parsed:
                brief_ifaces[i["name"]] = i
        elif field == "interfaces_detail":
            for i in parsed:
                detail_ifaces[i["name"]] = i
        elif field == "components":
            # 组件（槽位/电源）状态 → 引擎的 power[]；Normal 的也保留，
            # 这样 D12 判据 B（正常数减少=冗余丢失）同样生效。
            for c in parsed:
                sample["power"].append({
                    "id": f"Slot{c['slot']}({c['type']})",
                    "status": c["status"],
                    "role": c.get("role"),
                    "online": c.get("online"),
                })
        elif field == "logs":
            sample["logs"].extend(parsed)
        elif field == "alarms":
            sample["alarms"] = parsed
            # 告警转成日志行 → 供 D7 关键字映射（带级别标记，便于规则表写精确模式）
            for a in parsed:
                sample["logs"].append(
                    f"ALARM[{a['level']}/{a['level_name']}] {a['date']} {a['time']} {a['desc']}"
                )
        elif field == "transceiver":
            for t in parsed:
                d = detail_ifaces.setdefault(t["name"], {"name": t["name"]})
                d["rx_power"] = t["rx_power"]
                d["tx_power"] = t["tx_power"]
                d["rx_alarm"] = t["rx_alarm"]
        elif field in ("macs", "stp", "temperatures"):
            sample[field] = parsed

    # ── 合并接口：brief 提供错误计数/利用率，detail 提供速率/显式 CRC/光功率 ──
    # 用 norm_ifname() 做 key：brief 的名字带 (10G) 后缀、detail 不带，不归一化会对不上。
    merged: Dict[str, Dict[str, Any]] = {}
    for name, i in brief_ifaces.items():
        merged[norm_ifname(name)] = dict(i)          # 保留带后缀的展示名
    for name, i in detail_ifaces.items():
        k = norm_ifname(name)
        if k in merged:
            base = merged[k]
        else:
            base = dict(i)
            base.setdefault("name", name)
            merged[k] = base
        for kk, vv in i.items():
            if kk == "input_err" and base.get("input_err"):
                # brief 与 detail 的 errors 是**同一个计数器**，只能取一次，
                # 否则 D5 会把增量算成两倍（真实样本里 169 errors 两边都在）
                continue
            if vv not in (None, "", False) or kk not in base:
                base[kk] = vv
        base.setdefault("is_aggregate", _is_aggregate_name(base.get("name", name)))
    # 补齐引擎会读的数值键（缺失时补 0，光功率保持 None 表示"未知/不支持"）
    for base in merged.values():
        for kk in ("bcast", "mcast", "crc", "input_err", "up_down"):
            base.setdefault(kk, 0.0)
    sample["interfaces"] = list(merged.values())
    return sample


# ══════════════════════════════════════════════════════════════════
# 报告 CSV 读取（V3 导出格式）
# ══════════════════════════════════════════════════════════════════

def iter_report_csv(path: str) -> Iterable[Dict[str, str]]:
    """
    流式读取 V3 导出的报告 CSV（列：`Device,Type,Status,Anomalies,Command,Output`）。

    ⚠️ 两个必须的坑处理：
    1. `csv.field_size_limit` 要放大——单条命令输出可达几百 KB，
       默认 128 KB 会抛 `field larger than field limit (131072)`；
    2. **必须流式**（生成器逐行 yield），报告可达 85 MB+，整体载入会吃满内存。

    :param path: 报告 CSV 路径。
    :yield: 每行的 dict（列名 → 值）。
    """
    try:
        csv.field_size_limit(200_000_000)
    except OverflowError:
        csv.field_size_limit(10_000_000)
    with open(path, "r", encoding="utf-8-sig", errors="replace", newline="") as f:
        for row in csv.DictReader(f):
            yield row


def parse_report(path: str, device_class: str = "access") -> Dict[str, Dict[str, Any]]:
    """
    读取一份 V3 报告 CSV → `{设备: sample}`（每台设备一个采样）。

    同一设备出现多条记录时按**最后一条**为准（报告按设备顺序写，最后一条是
    最后一次巡检的结果）。

    :param path: 报告 CSV 路径。
    :param device_class: 统一阈值档（报告里没有设备档信息时用手动指定）。
    :return: `{device: sample}`，可直接喂 `ring_rules.analyze_pair`（两轮）
             或 `ring_rules.analyze_single`（单轮）。
    """
    grouped: Dict[str, Dict[str, Any]] = {}
    for row in iter_report_csv(path):
        dev = (row.get("Device") or "").strip()
        if not dev:
            continue
        g = grouped.setdefault(dev, {
            "vendor": (row.get("Type") or "huawei").strip().lower() or "huawei",
            "cmds": {}, "ts": None,
        })
        cmd = (row.get("Command") or "").strip()
        if cmd:
            g["cmds"][cmd] = row.get("Output") or ""
    out: Dict[str, Dict[str, Any]] = {}
    for dev, g in grouped.items():
        out[dev] = parse_device_sample(g["cmds"], device=dev, vendor=g["vendor"],
                                       device_class=device_class)
    return out


def parse_report_timed(path: str, ts: Optional[float] = None,
                       device_class: str = "access") -> Dict[str, Dict[str, Any]]:
    """
    同 `parse_report`，但把**文件名里的时间戳**（`report_YYYYmmdd_HHMMSS.csv`）
    解析成 sample["ts"]——做两轮差分时必须用真实采样时间算速率，
    否则间隔会退化成 0 导致无法计算。

    :return: `{device: sample}`（sample["ts"] 为文件时间戳，解析失败则用 `ts` 参数）。
    """
    import time as _t
    m = re.search(r"(\d{8})_(\d{6})", os.path.basename(path or ""))
    if m:
        try:
            import datetime as _dt
            ts = _dt.datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").timestamp()
        except Exception:
            ts = ts if ts is not None else _t.time()
    elif ts is None:
        ts = os.path.getmtime(path) if os.path.exists(path) else _t.time()
    samples = parse_report(path, device_class=device_class)
    for s in samples.values():
        s["ts"] = ts
    return samples
# ══════════════════════════════════════════════════════════════════
# 规则表加载（rules.yaml：V4/V5 唯一共享的外置数据）
# ══════════════════════════════════════════════════════════════════

# 内置默认规则表：目标文件不存在时自动释放一份，用户不用手工拷贝。
# 内容与开发目录的 rules.yaml 保持一致；改规则请直接改释放出来的那份。
_DEFAULT_RULES_YAML = r'''# ══════════════════════════════════════════════════════════════════════════
# rules.yaml —— 环路 / 异常告警 规则表
# ══════════════════════════════════════════════════════════════════════════
#
# 这个文件是 **V4（阉割版）与 V5（完整版）唯一共享的东西**（纯数据，改一处两边生效）。
# 检测逻辑各版本各自带（用户要求物理隔离）。
#
# 怎么用：
#   1. 程序启动时自动读取本文件（放在 exe / .py 同目录）；
#   2. 文件不存在会自动释放一份默认版；
#   3. 改完保存即可生效（不用重新打包）。
#
# 改关键字时注意（踩过的坑）：
#   * 关键字是 **正则**，大小写不敏感；
#   * **别用裸词**！比如 `Alarm` 会命中日志里的 `alarmID=0x…`（实测 256 次误报），
#     要写完整事件名，例如 `MSTP/4/PORT_STATE_DISCARDING`；
#   * `.*` 是"全部厂商"通配键，其他键写厂商名（huawei / h3c / ruijie / cisco / linux）。
#
# 事件名从哪来：把巡检里的 `display logbuffer` 输出抓出来，
# 用正则 `%%\d+([A-Za-z0-9_]+)/(\d)/([A-Za-z0-9_()\-]+)` 统计即可
# （本文件里的华为事件名就是从 43 台真实设备、58 种事件里挑的）。
# ══════════════════════════════════════════════════════════════════════════

# ── 阈值（引擎侧缺省用内置值；这里写出来是为了方便你调）────────────────────
thresholds:
  # STP 拓扑变化：每分钟 TC 次数，按设备角色分档
  tc_per_minute:      { access: 5, aggregation: 15, core: 30 }
  # 广播/组播风暴：包速率（pps）与占带宽百分比
  broadcast_pps:      1000
  broadcast_bandwidth_pct: 5
  # 接口错误：每分钟增量（warn 可疑 / high 高危）
  crc_per_minute:     { warn: 100, high: 1000 }
  # 链路震荡：每小时 up/down 次数
  link_flap_per_hour: { warn: 3, high: 10 }
  # MAC 漂移：两轮间同一 MAC 换口次数
  mac_move_count:     { warn: 1, high: 2 }
  # 光衰：收光功率绝对值（dBm，越负越弱）与两轮下降幅度
  rx_power_dbm:       { warn: -20.0, high: -25.0 }
  rx_power_drop_db:   3.0
  # 温度：摄氏度
  temp_c:             { warn: 65, high: 75 }
  temp_rise_c:        10
  # 电源/组件异常状态（大小写不敏感）
  power_abnormal_states: [Abnormal, Fault, Absent, NotSupply, Unregistered, Failed]

  # 单设备覆盖示例（不改全局，只针对某台机器放宽/收紧）：
  #   device_overrides:
  #     "192.0.2.1": { tc_per_minute: { core: 60 } }

# ── 日志关键字 → 抽象信号映射 ──────────────────────────────────────────────
# 这是把"各家五花八门的日志事件名"统一成几个判断信号的核心。
signals:

  # ① STP / MSTP 拓扑变化：二层抖动、环路的典型征兆
  STP_TOPO_CHANGE:
    severity: medium
    patterns:
      huawei:
        - 'MSTP/4/PORT_STATE_(DISCARDING|FORWARDING|LEARNING)'
        - 'MSTP/4/MSTPLOG_PROPORT_STATE'
        - 'MSTP/4/SET_PORT_FORWARDING'
        - 'MSTP/4/PROPORT_ROOT_PROTECTION'
        - 'STP/4/'
      h3c:   ['STP/4/', 'MSTP/4/']
      ruijie: ['SPANTREE-']
      cisco: ['SPANTREE-', 'STP-']
      '.*':  ['topology change', 'TCN']

  # ② MAC 漂移 / flapping：环路最直接的特征
  MAC_FLAPPING:
    severity: high
    patterns:
      huawei:
        - 'MAC/4/MAC_MOVE'
        - 'MAC/3/MAC_MOVE'
        - 'MFLPVLAN'
        - 'MAC.{0,20}(MOVE|FLAPPING|FLAP)'
      h3c:   ['MAC_MOVE', 'MAC_MOVE_DETECT']
      ruijie: ['MACFLAP', 'MAC_FLAPPING']
      cisco: ['MACFLAP', 'MAC_MOVE_NOTIFICATION']
      '.*':  ['MAC_MOVE', 'MACFLAPPING', 'MAC_FLAPPING']

  # ③ 链路震荡：物理层不稳（常与环路/劣化伴生）
  LINK_FLAP:
    severity: medium
    patterns:
      huawei:
        - 'IFPDT/4/IF_STATE'
        - 'DEVM/2/hwPortDown'
        - 'DEVM/4/hwPortUp'
        - 'IFADP/4/PORTDOWNINFO'
        - 'PHY/4/'
      cisco: ['LINK-3-UPDOWN', 'LINEPROTO-5-UPDOWN']
      '.*':  ['LINK_?(UP|DOWN)', 'PORT_?DOWN']
      # 注意：华为 BRAS 的 `CMREG/4/LINK_STATE_CHANGED` 是**用户侧上下线**，
      # 一天几百条属正常，故意不收进来（收了会天天误报）。

  # ④ 环路检测（设备自带 loop-detect 功能的告警）
  LOOP_DETECT:
    severity: high
    patterns:
      huawei: ['LOOP_?DETECT', 'LOOPBACK_?DETECT', 'LDT/']
      h3c:   ['LOOP_?DETECT']
      ruijie: ['LOOP_?DETECT']
      cisco: ['LOOP_?DETECT', 'LOOPBACK']
      '.*':  ['loop.{0,12}detect']

  # ⑤ 广播风暴 / 抑制触发
  BROADCAST_STORM:
    severity: high
    patterns:
      huawei:
        - 'ARP/4/.{0,30}(SUPPRESS|EXCEED|THRESHOLD)'
        - 'BROADCAST_?STORM'
        - 'MFF/4/'
      '.*':  ['broadcast.{0,12}storm', 'storm.{0,12}control', 'STORM_CONTROL']

  # ⑥ 光模块 / 光功率异常
  OPTICAL_DEGRADE:
    severity: medium
    patterns:
      huawei: ['OPTICAL_?MODULE', 'RX_?POWER_?(LOW|HIGH|ALARM)', 'TRANSCEIVER_.{0,20}(FAIL|ALARM|ABSENT)']
      '.*':  ['optical.{0,20}(alarm|fail|low)', 'rx.?power.{0,20}(low|alarm)']

  # ⑦ 温度
  TEMPERATURE:
    severity: medium
    patterns:
      huawei: ['TEMP(ERATURE)?_?(HIGH|ALARM|OVER|ABNORMAL)', 'OVER_?TEMP']
      '.*':  ['over.{0,6}temp', 'temperature.{0,20}(high|alarm)']

  # ⑧ 电源 / 硬件组件
  POWER:
    severity: high
    patterns:
      huawei: ['POWER_?(FAIL|ABNORMAL|ABSENT)', 'PSU_', 'PWR_']
      '.*':  ['power.{0,12}(fail|absent|abnormal)']

  # ⑨ 端口安全 / 安全攻击（用户原有 V3 攻击检测的补充）
  PORT_SECURITY:
    severity: high
    patterns:
      huawei: ['SECURITY/3/', 'CPUDEFEND/3/', 'ARP_.{0,20}ATTACK', 'DHCP_.{0,20}SNOOPING.{0,20}(FAIL|ALARM)']
      h3c:   ['SECURITY/3/']
      cisco: ['PORT_SECURITY', 'DHCP_SNOOPING']

  # ⑩ 用户/终端上线失败（BRAS 场景常见，低危但值得看一眼）
  ONLINE_FAIL:
    severity: low
    patterns:
      huawei: ['CMREG/3/ONLINE_FAIL', 'DHCPSNP_ONLINE_FAIL']
'''


def app_dir() -> str:
    """程序所在目录：**打包成 exe 后必须用 exe 所在目录**。

    PyInstaller 单文件模式会把 __file__ 指向临时解包目录（%TEMP%/_MEIxxxx），
    规则表若跟着落到那里，用户既找不到、重启还会被清理。
    """
    if getattr(sys, "frozen", False):
        return os.path.dirname(os.path.abspath(sys.executable))
    return os.path.dirname(os.path.abspath(__file__))


def default_rules_path() -> str:
    """规则表默认路径：与程序同目录的 rules.yaml。"""
    return os.path.join(app_dir(), "rules.yaml")


def _parse_rules_text(raw: str, warnings: List[str]) -> Dict[str, Any]:
    """
    解析规则表文本：优先 PyYAML，没装 yaml 时退化 JSON（同结构可直接改名 .json）。

    解析失败只记警告不抛异常（返回空 dict，由调用方用内置默认值补齐）。
    """
    if not raw or not raw.strip():
        return {}
    try:
        import yaml  # type: ignore
        return yaml.safe_load(raw) or {}
    except ImportError:
        try:
            import json
            return json.loads(raw)
        except Exception as e:
            warnings.append(f"规则表解析失败(无 yaml 且非 JSON): {e}")
    except Exception as e:
        warnings.append(f"规则表 YAML 语法错误: {e}")
    return {}


def load_rules(path: Optional[str] = None, auto_release: bool = True) -> Dict[str, Any]:
    """
    读取规则表（rules.yaml），缺失时自动释放内置默认版。

    行为：
      * 文件不存在且 auto_release=True → 写出内置默认规则表（首次运行无感）；
      * 优先用 PyYAML 解析；没装 yaml 时尝试 JSON（同结构可直接改名 .json）；
      * 解析结果与 ring_rules.DEFAULTS 合并（缺的阈值用内置值补齐，
        删掉某一项也不会导致检测失效）；
      * 任何异常都不抛给调用方——返回可用规则表 + 警告列表（放在 _warnings）。

    :param path: 规则表路径；None → 同目录 rules.yaml。
    :param auto_release: 文件缺失时是否自动写出默认版。
    :return: 规则表 dict（可直接传给 ring_rules.analyze_pair）。
    """
    warnings: List[str] = []
    path = path or default_rules_path()
    if not os.path.exists(path):
        if auto_release:
            try:
                os.makedirs(os.path.dirname(os.path.abspath(path)), exist_ok=True)
                with open(path, "w", encoding="utf-8") as f:
                    f.write(_DEFAULT_RULES_YAML)
                warnings.append(f"已释放默认规则表: {path}")
                # ⚠️ 必须把刚写出的文件解析回来：否则本次调用只有 thresholds、没有 signals，
                # 首次运行（新装 exe / rules.yaml 被删）时 D7 日志关键字会静默失效
                data = _parse_rules_text(_DEFAULT_RULES_YAML, warnings)
            except Exception as e:
                warnings.append(f"规则表释放失败({e})，改用内置默认值")
                data: Dict[str, Any] = {}
        else:
            warnings.append(f"规则表不存在: {path}")
            data: Dict[str, Any] = {}
    else:
        raw = ""
        try:
            with open(path, encoding="utf-8") as f:
                raw = f.read()
        except Exception as e:
            warnings.append(f"规则表读取失败({e})")
        data = {}
        data = _parse_rules_text(raw, warnings)
    if not isinstance(data, dict):
        warnings.append("规则表顶层不是映射，已忽略")
        data = {}

    # 与引擎内置默认值合并：缺项用内置值补齐，检测不会因漏配而失效
    from ring_rules import DEFAULTS as _ENGINE_DEFAULTS
    merged: Dict[str, Any] = dict(data)
    th = dict(_ENGINE_DEFAULTS)
    th.update({k: v for k, v in (data.get("thresholds") or {}).items() if v is not None})
    merged["thresholds"] = th
    sig = data.get("signals")
    if sig is not None and not isinstance(sig, dict):
        warnings.append("signals 段不是映射，已忽略")
        merged["signals"] = {}
    if warnings:
        merged["_warnings"] = warnings
    return merged




# ══════════════════════════════════════════════════════════════════
# 命令行自检（用真实样本验证解析结果）
# ══════════════════════════════════════════════════════════════════

def _self_test(sample_dir: Optional[str] = None) -> int:
    """读取 samples/*.txt 跑一遍所有解析器，打印摘要（真实数据的回归检查）。"""
    d = sample_dir or os.path.join(os.path.dirname(os.path.abspath(__file__)), "samples")
    if not os.path.isdir(d):
        print(f"样本目录不存在: {d}")
        return 1
    cmds: Dict[str, str] = {}
    for fn in sorted(os.listdir(d)):
        if not fn.endswith(".txt"):
            continue
        txt = open(os.path.join(d, fn), encoding="utf-8", errors="replace").read()
        m = re.search(r"^#\s*command=(.+)$", txt, re.M)
        if not m:
            continue
        cmds[m.group(1).strip()] = txt
    print(f"载入 {len(cmds)} 条命令样本\n")
    s = parse_device_sample(cmds, device="(样本设备)", vendor="huawei", device_class="core")
    print(f"接口数: {len(s['interfaces'])}   MAC 表: {len(s['macs'])}   "
          f"日志行: {len(s['logs'])}   告警: {len(s['alarms'])}   "
          f"组件: {len(s['power'])}   温度: {len(s['temperatures'])}")
    print(f"STP: {s['stp']}")
    if s["unsupported"]:
        print("\n不支持的/解析失败的命令:")
        for k, v in s["unsupported"].items():
            print(f"  - {k}: {v}")
    print("\n接口样例（前 5，含错误的优先）:")
    shown = sorted(s["interfaces"], key=lambda i: -(i.get("input_err") or 0))[:5]
    for i in shown:
        print(f"  {i['name']:<34} in_err={i.get('input_err')} crc={i.get('crc')} "
              f"uti={i.get('in_uti')}% in_pps={i.get('in_pps')} agg={i.get('is_aggregate')}")
    print("\nMAC 样例（前 5）:")
    for m in s["macs"][:5]:
        print(f"  {m['mac']}  vlan={m['vlan']}  port={m['port']}  {m['type']}")
    print("\n告警样例（前 3）:")
    for a in s["alarms"][:3]:
        print(f"  [{a['level']}/{a['level_name']}] {a['date']} {a['time']} {a['desc'][:80]}")
    return 0


if __name__ == "__main__":
    sys.exit(_self_test())

#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
fake_data.py —— 测试用的**虚构**厂商命令输出与采样构造器（非测试文件，pytest 不收集）

约定
----
* 所有数据都是手工编造的：设备 IP 用文档保留段 `192.0.2.x` / 私网段 `10.0.0.x`，
  主机名 `SW-1` / `SW-2`，MAC 用 `0000-5e00-xxxx` 这类协议示例值。
  **不含任何真实设备、单位或客户信息**（仓库是公开的）。
* 样例**内嵌在代码里**，不读 `samples/` 目录（那是被 .gitignore 的真实样本目录）。
* 排版刻意对齐仓库文档记录的两种华为实测形态：
  A. 聚合口：`Input: N packets,M bytes` + 下一行 `N errors,M drops`
  B. 物理口：`Input: N bytes, M packets` + `Unicast/Multicast/Broadcast/CRC/Symbol: N`
"""

from __future__ import annotations

from typing import Any, Dict, Optional

import ring_parsers as RP

# ══════════════════════════════════════════════════════════════════
# 华为命令输出样例（全部虚构）
# ══════════════════════════════════════════════════════════════════


def _brief_row(name: str, phy: str, proto: str, in_uti: str, out_uti: str,
               in_err: int, out_err: int = 0) -> str:
    """按 `display interface brief` 的列宽生成一行（列间至少一个空格）。"""
    return f"{name:<28}{phy:<6}{proto:<10}{in_uti:>7}{out_uti:>8}{in_err:>10}{out_err:>10}"


def brief(eth_trunk_in_errors: int = 169, ge_errors: int = 0, ge_bcast_hint: int = 0) -> str:
    """`display interface brief` 输出；可改聚合口/物理口 inErrors 造两轮差分。"""
    rows = [
        "Interface                   PHY   Protocol  InUti OutUti   inErrors  outErrors",
        _brief_row("Eth-Trunk1", "up", "up", "25.88%", "8.27%", eth_trunk_in_errors),
        _brief_row("GigabitEthernet2/1/4(10G)", "up", "up", "25.74%", "8.30%", ge_errors),
        _brief_row("GigabitEthernet2/2/1", "up", "up", "12.00%", "3.10%", 0),
        _brief_row("Vlanif1000", "up", "up", "--", "--", 0),
    ]
    return "\n".join(rows) + "\n"


DETAIL_TMPL = """Eth-Trunk1 current state : UP (ifindex: 35)
Line protocol current state : UP
Last 300 seconds input rate 10346801693 bits/sec, 1022185 packets/sec
Input: 52777497075475 packets,56580263369400625 bytes
  169 errors,0 drops
GigabitEthernet2/1/4 current state : UP (ifindex: 150)
Link quality grade : GOOD
The Vendor PN is MTRS-1E21-01
The Vendor Name is HG GENUINE
Port BW: 10G, Transceiver Mode: SingleMode
Rx Power:  {rx}dBm, Warning range: [-14.400,  0.499]dBm
Tx Power:  -3.63dBm, Warning range: [-8.198,  0.499]dBm
Last 300 seconds input rate: 2673119412 bits/sec, 260270 packets/sec
Input: 18495439075977750 bytes, 16369881512913 packets
Input:
Unicast: 16369865048593 packets, Multicast: {mcast} packets
Broadcast: {bcast} packets, JumboOctets: 41302 packets
CRC: {crc} packets, Symbol: 1199524 packets
"""

DETAIL = DETAIL_TMPL.format(rx="-4.99", mcast=14916022, bcast=1548298, crc=12535001)


def detail(rx: str = "-4.99", bcast: int = 1548298, mcast: int = 14916022,
           crc: int = 12535001) -> str:
    """`display interface` 输出（聚合口 + 物理口两种排版）；可改收光/计数。"""
    return DETAIL_TMPL.format(rx=rx, bcast=bcast, mcast=mcast, crc=crc)


_MAC_TABLE_TMPL = """MAC address table of slot {slot}:
MAC Address    VLAN/BD/     PEVLAN CEVLAN Port/Peerip   Type      LSP/LSR-ID
{mac} {vlan}         -      -       {port}      dynamic   {slot}/-
Total matching items on slot {slot} displayed = 1
"""


def mac_table(port: str = "GE2/0/4", mac: str = "0000-5e00-0101", slots: int = 2,
              vlan: int = 1000) -> str:
    """
    `display mac-address` 输出：默认**两个 slot 段**各出现同一 (MAC, VLAN, 端口)，
    用于验证按 mac+vlan+port 去重（华为按 slot 分段会让同一项重复）。
    """
    return "\n".join(_MAC_TABLE_TMPL.format(slot=s, mac=mac, port=port, vlan=vlan)
                     for s in range(1, slots + 1))


STP = """Protocol Status :Enabled
CIST Bridge Priority :32768
MAC address :aabb-cccc-dddd
Topology Changes :3
"""

DEVICE = """Slot #   Type    Online     Register     Status     Role   LsId   Primary
1        BSU     Present    Registered   Normal     LC     0      NA
9        MPU     Present    Registered   Normal     MMB    0      Master
"""

LOGBUFFER = """Logging buffer configuration and contents : enabled
Allowed max buffer size : 10240
Actual buffer size : 512
Channel number : 4 , Channel name : logbuffer
Dropped messages : 0
Overwritten messages : 0
Current messages : 2
Sep 17 2026 14:14:28+08:00 SW-1 %%01MSTP/4/PORT_STATE_DISCARDING(s):CID=0x80fa;MSTP set port
Sep 17 2026 14:15:02+08:00 SW-1 %%01MAC/4/MAC_MOVE(l):MAC move detected on GE2/0/4
"""

ALARM = """1:Critical  2:Major  3:Minor  4:Warning
Sequence   AlarmId    Level Date Time  Description
27826077   0x9E02000  4     2026-09-17 Security Operation Center detected one at
                             14:05:05+ tack. (EventNo=66310,Reason=access attack,
                             08:00      Location=GigabitEthernet2/0/4)
"""

TRANSCEIVER = """GigabitEthernet2/1/4 transceiver diagnostic information:
  Current diagnostic parameters:
    Temp.(C)  Voltage(V)  Bias(mA)  RX power(dBm)  TX power(dBm)
    36        3.29        6.20      -12.34         -2.11
GigabitEthernet2/2/1 transceiver diagnostic information:
    Temp.(C)  Voltage(V)  Bias(mA)  RX power(dBm)  TX power(dBm)
    38        3.30        6.10      -13.20         -2.50
"""

TEMPERATURE = """Slot  Card  Sensor  Temperature(C)  Upper(C)  Lower(C)
1     -     -       45              80        0
2     -     -       52              80        0
"""

ERR_UNRECOGNIZED = "Error: Unrecognized command found at '^' position."
ERR_TOO_MANY = "Error: Too many parameters found at '^' position."


# ══════════════════════════════════════════════════════════════════
# 构造器
# ══════════════════════════════════════════════════════════════════

def device_cmds(port: str = "GE2/0/4", eth_trunk_in_errors: int = 169,
                rx: str = "-4.99", mac: str = "0000-5e00-0101", vlan: int = 1000,
                with_unsupported: bool = True, **det_kw: Any) -> Dict[str, str]:
    """一台设备的「命令 → 输出」字典（喂 `parse_device_sample`）。"""
    cmds = {
        "display interface brief": brief(eth_trunk_in_errors=eth_trunk_in_errors),
        "display interface": detail(rx=rx, **det_kw),
        "display mac-address": mac_table(port=port, mac=mac, vlan=vlan),
        "display stp": STP,
        "display device": DEVICE,
        "display logbuffer": LOGBUFFER,
        "display alarm active": ALARM,
    }
    if with_unsupported:
        # 这两条命令在 ME60 类平台不支持，必须落进 unsupported 而不是当数据解析
        cmds["display transceiver diagnosis interface"] = ERR_UNRECOGNIZED
        cmds["display temperature all"] = ERR_TOO_MANY
    return cmds


def device_sample(device: str = "192.0.2.10", ts: float = 0.0,
                  device_class: str = "aggregation", **kw: Any) -> Dict[str, Any]:
    """解析后的采样 dict（喂引擎 / 编排层）。"""
    return RP.parse_device_sample(device_cmds(**kw), device=device, vendor="huawei",
                                  ts=ts, device_class=device_class)


# ── 引擎侧的最小采样构造器（不经过解析层）──────────────────────────

def iface(name: str = "GE1/0/1", bcast: float = 0, mcast: float = 0, crc: float = 0,
          ierr: float = 0, flap: float = 0, rx: Optional[float] = None,
          **kw: Any) -> Dict[str, Any]:
    d: Dict[str, Any] = {"name": name, "bcast": bcast, "mcast": mcast, "crc": crc,
                         "input_err": ierr, "up_down": flap, "rx_power": rx}
    d.update(kw)
    return d


def mac(addr: str = "0000-5e00-0001", vlan: int = 10, port: str = "GE1/0/1",
        **kw: Any) -> Dict[str, Any]:
    d: Dict[str, Any] = {"mac": addr, "vlan": vlan, "port": port}
    d.update(kw)
    return d


def engine_sample(device: str = "SW-1", vendor: str = "huawei", cls: str = "access",
                  ts: float = 0, **kw: Any) -> Dict[str, Any]:
    """引擎输入契约里的单台设备采样（interfaces/macs/stp/power/temperatures/logs）。"""
    s: Dict[str, Any] = {
        "device": device, "vendor": vendor, "device_class": cls, "ts": ts,
        "interfaces": kw.pop("interfaces", []), "macs": kw.pop("macs", []),
        "stp": kw.pop("stp", {}), "power": kw.pop("power", []),
        "temperatures": kw.pop("temperatures", []), "logs": kw.pop("logs", []),
    }
    s.update(kw)
    return s

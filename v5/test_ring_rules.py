#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_ring_rules.py —— ring_rules 判据引擎的回归测试（P1 验收）

覆盖：
  1) 每条规则 ≥ 1 个"应触发"用例 + 1 个"不应触发"用例；
  2) 边界值（增量恰好等于阈值 → 不告警，因为判定用严格 `>`）；
  3) 计数器回绕（第二轮计数变小 → 跳过，不误报）；
  4) 规则开关（enabled 集合）生效；
  5) 关键字映射的大小写不敏感；
  6) 跨设备关联（D9）正例 + 聚合口排除；
  7) 规则内部异常被隔离，不影响其它规则。

运行： python test_ring_rules.py     （全部通过时退出码 0）
"""
from __future__ import annotations

import sys
import traceback
from typing import Any, Dict, List

from ring_rules import analyze_pair, RULE_CATALOG
try:                       # 阉割版（V4）的引擎里没有跨设备关联，导入要容错
    from ring_rules import analyze_cross
    HAVE_CROSS = True
except ImportError:
    analyze_cross = None
    HAVE_CROSS = False
RULE_IDS = {c["id"] for c in RULE_CATALOG}
HAVE_D8 = "D8" in RULE_IDS


# ══════════════════════════════════════════════════════════════════
# 构造样本的小工具
# ══════════════════════════════════════════════════════════════════
def dev(device="SW1", vendor="huawei", cls="access", ts=0, *,
        interfaces=None, macs=None, stp=None, power=None, temps=None, logs=None) -> Dict[str, Any]:
    """造一台设备某轮采样 / build one sample."""
    return {
        "device": device, "vendor": vendor, "device_class": cls, "ts": ts,
        "interfaces": interfaces or [], "macs": macs or [],
        "stp": stp or {}, "power": power or [],
        "temperatures": temps or [], "logs": logs or [],
    }


def iface(name="GE0/0/1", *, bcast=0, mcast=0, crc=0, ierr=0, flap=0, rx=None, **kw):
    d = {"name": name, "bcast": bcast, "mcast": mcast, "crc": crc,
         "input_err": ierr, "up_down": flap, "rx_power": rx}
    d.update(kw)
    return d


def mac(addr="aabb.ccdd.0001", vlan=10, port="GE0/0/1", **kw):
    d = {"mac": addr, "vlan": vlan, "port": port}
    d.update(kw)
    return d


ALERTS: List[tuple] = []       # (rule_id, signal) 命中记录
FAILURES: List[str] = []


def check(cond: bool, label: str) -> None:
    """断言 + 记录 / assert and record."""
    if cond:
        print(f"  ✓ {label}")
    else:
        print(f"  ✗ {label}")
        FAILURES.append(label)


def hits(alerts, rule_id) -> bool:
    return any(a.get("rule_id") == rule_id for a in alerts)


def case(title: str, s1, s2, *, expect: List[str] = (), reject: List[str] = (),
         rules=None, enabled=None, interval=60):
    """跑一对样本并校验：expect 的规则必须命中，reject 的必须不命中。"""
    print(f"\n[{title}]")
    alerts = analyze_pair(s1, s2, rules=rules, enabled=enabled, interval_seconds=interval)
    for rid in expect:
        check(hits(alerts, rid), f"{rid} 应触发")
    for rid in reject:
        check(not hits(alerts, rid), f"{rid} 不应触发")
    return alerts


def norm(name: str) -> Dict[str, Any]:
    """返回一套"完全正常"的两轮样本（各规则均应静默）。"""
    mk = lambda ts: dev(ts=ts,
        interfaces=[iface("GE0/0/1", bcast=100, crc=0, flap=0, rx=-12.0)],
        macs=[mac(port="GE0/0/1")],
        stp={"tc_count": 10, "root_id": "R1", "root_port": "GE0/0/1"},
        power=[{"id": "PWR1", "status": "Normal"}],
        temps=[{"sensor": "Slot1", "value": 40}])
    return mk(0), mk(60)


def main() -> int:
    print("=" * 70)
    print("  ring_rules 判据引擎 · 回归测试")
    print("=" * 70)

    # ── 0) 基线：全正常数据应零告警 ──────────────────────────────
    a, b = norm("x")
    al = analyze_pair(a, b, interval_seconds=60)
    print("\n[基线 · 全正常数据]")
    check(len(al) == 0, f"零告警（实际 {len(al)} 条）")
    for x in al:
        print("     意外告警:", x["rule_id"], x["evidence"][:80])

    # ── D1 MAC 漂移 ──────────────────────────────────────────────
    case("D1 · MAC 换端口",
         dev(ts=0, macs=[mac(port="GE0/0/1")]),
         dev(ts=60, macs=[mac(port="GE0/0/2")]),
         expect=["D1"])
    case("D1 · MAC 未变（负例）",
         dev(ts=0, macs=[mac(port="GE0/0/1")]),
         dev(ts=60, macs=[mac(port="GE0/0/1")]),
         reject=["D1"])

    # ── D2 STP TC ────────────────────────────────────────────────
    case("D2 · access 档 TC 10→60（50/min > 5）",
         dev(ts=0, cls="access", stp={"tc_count": 10}),
         dev(ts=60, cls="access", stp={"tc_count": 60}),
         expect=["D2"])
    case("D2 · 边界：增量恰等于阈值（5/min）→ 不报警",
         dev(ts=0, stp={"tc_count": 10}),
         dev(ts=60, stp={"tc_count": 15}),
         reject=["D2"])
    case("D2 · 计数器回绕（第二轮变小）→ 跳过",
         dev(ts=0, stp={"tc_count": 100}),
         dev(ts=60, stp={"tc_count": 3}),
         reject=["D2"])

    # ── D3 根桥变更 ──────────────────────────────────────────────
    case("D3 · 根桥 ID 变化",
         dev(ts=0, stp={"root_id": "R1"}),
         dev(ts=60, stp={"root_id": "R2"}),
         expect=["D3"])
    case("D3 · 根桥未变（负例）",
         dev(ts=0, stp={"root_id": "R1"}),
         dev(ts=60, stp={"root_id": "R1"}),
         reject=["D3"])

    # ── D4 广播风暴 ──────────────────────────────────────────────
    case("D4 · 广播 100→90000（约 1498 pps > 1000）",
         dev(ts=0, interfaces=[iface(bcast=100)]),
         dev(ts=60, interfaces=[iface(bcast=90000)]),
         expect=["D4"])
    case("D4 · 边界：恰 1000 pps → 不报警",
         dev(ts=0, interfaces=[iface(bcast=0)]),
         dev(ts=60, interfaces=[iface(bcast=60000)]),      # 60000/60 = 1000 pps
         reject=["D4"])

    # ── D5 接口错误计数 ──────────────────────────────────────────
    case("D5 · CRC 0→5000（5000/min > 100）",
         dev(ts=0, interfaces=[iface(crc=0)]),
         dev(ts=60, interfaces=[iface(crc=5000)]),
         expect=["D5"])
    case("D5 · 边界：恰 100/min → 不报警",
         dev(ts=0, interfaces=[iface(crc=0)]),
         dev(ts=60, interfaces=[iface(crc=100)]),
         reject=["D5"])

    # ── D6 链路震荡 ──────────────────────────────────────────────
    case("D6 · up/down 5 次/分钟（300/h > 3）",
         dev(ts=0, interfaces=[iface(flap=0)]),
         dev(ts=60, interfaces=[iface(flap=5)]),
         expect=["D6"])
    case("D6 · 边界：恰 3 次/小时 → 不报警",
         dev(ts=0, interfaces=[iface(flap=0)]),
         dev(ts=3600, interfaces=[iface(flap=3)]),
         reject=["D6"], interval=3600)

    # ── D7 关键字映射（大小写不敏感 + vendor 归属）───────────────
    RULES = {"signals": {
        "MAC_FLAPPING": {"severity": "high",
                         "patterns": {"huawei": ["MFLPVLAN", "MAC.{0,20}flapping"],
                                      "cisco": ["MACFLAP_NOTIF"]}},
        "STP_TOPO_CHANGE": {"severity": "medium",
                            "patterns": {".*": ["topology.{0,20}change", "STP/\\d/TC"]}},
    }}
    case("D7 · 华为日志命中 MFLPVLAN（小写输入也要命中）",
         dev(ts=0), dev(ts=60, vendor="huawei", logs=["%Apr 1 10:00 mflpvlan detected on GE0/0/1"]),
         expect=["D7"], rules=RULES)
    case("D7 · 通用模式命中 topology change（思科）",
         dev(ts=0), dev(ts=60, vendor="cisco", logs=["%SPANTREE: topology change detected"]),
         expect=["D7"], rules=RULES)
    case("D7 · 思科日志不命中华为专属关键字（负例）",
         dev(ts=0), dev(ts=60, vendor="cisco", logs=["MFLPVLAN"]),
         reject=["D7"], rules=RULES)

    # ── D8 BPDU（仅完整版；阉割版已删该规则 → 跳过）────────────
    if HAVE_D8:
        case("D8 · 自环 BPDU 标志 → 高危",
             dev(ts=0, stp={"bpdu_in": 0}),
             dev(ts=60, stp={"bpdu_in": 10, "bpdu_self_seen": True}),
             expect=["D8"])

    # ── D10 光衰 ─────────────────────────────────────────────────
    case("D10 · 绝对值 -26 dBm（< -25 高危）",
         dev(ts=0, interfaces=[iface(rx=-12.0)]),
         dev(ts=60, interfaces=[iface(rx=-26.0)]),
         expect=["D10"])
    case("D10 · 趋势下降 5 dB（> 3 dB）但绝对值正常",
         dev(ts=0, interfaces=[iface(rx=-10.0)]),
         dev(ts=60, interfaces=[iface(rx=-15.0)]),
         expect=["D10"])
    case("D10 · 光功率正常（负例）",
         dev(ts=0, interfaces=[iface(rx=-12.0)]),
         dev(ts=60, interfaces=[iface(rx=-12.5)]),          # 仅降 0.5 dB
         reject=["D10"])

    # ── D11 温度 ─────────────────────────────────────────────────
    case("D11 · 温度 80°C（> 75 高危）",
         dev(ts=0, temps=[{"sensor": "S1", "value": 40}]),
         dev(ts=60, temps=[{"sensor": "S1", "value": 80}]),
         expect=["D11"])
    case("D11 · 温度正常（负例）",
         dev(ts=0, temps=[{"sensor": "S1", "value": 40}]),
         dev(ts=60, temps=[{"sensor": "S1", "value": 42}]),
         reject=["D11"])

    # ── D12 电源 ─────────────────────────────────────────────────
    case("D12 · 状态 Abnormal",
         dev(ts=0, power=[{"id": "PWR1", "status": "Normal"}]),
         dev(ts=60, power=[{"id": "PWR1", "status": "Abnormal"}]),
         expect=["D12"])
    case("D12 · 双电源掉一个（冗余丢失）",
         dev(ts=0, power=[{"id": "PWR1", "status": "Normal"}, {"id": "PWR2", "status": "Normal"}]),
         dev(ts=60, power=[{"id": "PWR1", "status": "Normal"}, {"id": "PWR2", "status": "Fault"}]),
         expect=["D12"])
    case("D12 · 双电源都正常（负例）",
         dev(ts=0, power=[{"id": "PWR1", "status": "Normal"}, {"id": "PWR2", "status": "Normal"}]),
         dev(ts=60, power=[{"id": "PWR1", "status": "Normal"}, {"id": "PWR2", "status": "Normal"}]),
         reject=["D12"])

    # ── 规则开关（对应 UI 选项框）───────────────────────────────
    print("\n[规则开关]")
    a, b = (dev(ts=0, interfaces=[iface(bcast=0), iface(crc=0)], stp={"tc_count": 0}),
            dev(ts=60, interfaces=[iface(bcast=90000), iface(crc=5000, flap=5)], stp={"tc_count": 60}))
    only_d2 = analyze_pair(a, b, enabled=["D2"], interval_seconds=60)
    check([x["rule_id"] for x in only_d2] == ["D2"], "enabled=['D2'] 时只跑 D2")
    check(all(i in RULE_IDS for i in ("D1", "D2", "D3", "D4", "D5", "D6", "D7",
                                       "D10", "D11", "D12")),
          f"基础规则齐全（共 {len(RULE_IDS)} 条：{','.join(sorted(RULE_IDS))}）")
    if HAVE_CROSS:
        check("D8" in RULE_IDS and "D9" in RULE_IDS, "完整版含深度项 D8/D9")
    else:
        check("D8" not in RULE_IDS and "D9" not in RULE_IDS,
              "阉割版物理上不含 D8/D9")

    # ── D9 跨设备关联（仅完整版）─────────────────────────────────
    if HAVE_CROSS:
        print("\n[D9 跨设备关联]")
        d1 = dev("SW1", ts=60, macs=[mac("aabb.ccdd.9999", vlan=10, port="GE0/0/1")])
        d2 = dev("SW2", ts=60, macs=[mac("aabb.ccdd.9999", vlan=10, port="GE0/0/5")])
        cross = analyze_cross([[d1, d1], [d2, d2]], enabled=["D9"], interval_seconds=60)
        check(any(a["rule_id"] == "D9" for a in cross), "同 MAC 出现在两台设备 → D9 触发")
        check("SW1" in cross[0]["evidence"] and "SW2" in cross[0]["evidence"],
              "证据里含两台设备定位")
        # 聚合口应被排除
        d2agg = dev("SW2", ts=60, macs=[mac("aabb.ccdd.9999", vlan=10, port="Eth-Trunk1", is_aggregate=True)])
        cross2 = analyze_cross([[d1, d1], [d2agg, d2agg]], enabled=["D9"], interval_seconds=60)
        check(not any(a["rule_id"] == "D9" for a in cross2), "聚合口成员不算冲突（已排除）")

    # ── 异常隔离 ─────────────────────────────────────────────────
    print("\n[异常隔离]")
    bad = {"device": "SW9", "ts": 0, "interfaces": "不是列表", "stp": None, "macs": None}
    bad2 = {"device": "SW9", "ts": 60, "interfaces": "还是不是列表", "stp": None, "macs": None}
    try:
        al = analyze_pair(bad, bad2, interval_seconds=60)
        check(isinstance(al, list), "畸形输入不崩溃，返回列表")
    except Exception:
        check(False, "畸形输入不应抛异常：" + traceback.format_exc(limit=1))

    # ── 汇总 ─────────────────────────────────────────────────────
    print("\n" + "=" * 70)
    if FAILURES:
        print(f"  ✗ 失败 {len(FAILURES)} 项：")
        for f in FAILURES:
            print("     -", f)
        return 1
    print("  ✅ 全部通过")
    return 0


if __name__ == "__main__":
    sys.exit(main())

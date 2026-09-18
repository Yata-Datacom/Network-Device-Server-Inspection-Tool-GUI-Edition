"""故障定位新增能力的回归用例（D13 同设备 MAC 多端口 / D4 环路组 / D7 日志抽取 / 故障事件层）。

对应需求：告警要能**直接说出问题设备与涉及端口**，并把多条告警聚合成"一个故障 + 人话处理步骤"，
让不会数通的人也能照着处理。
"""

from __future__ import annotations

import ring_events as RE
import ring_rules as RR


def _s(dev="SW-1", ts=0, ifaces=None, macs=None, logs=None):
    return {"device": dev, "vendor": "huawei", "device_class": "access", "ts": ts,
            "interfaces": ifaces or [], "macs": macs or [], "stp": {},
            "power": [], "temperatures": [], "logs": logs or []}


def _mac(mac, vlan, port, agg=False, stack=False):
    return {"mac": mac, "vlan": vlan, "port": port, "type": "dynamic",
            "is_aggregate": agg, "is_stack_member": stack}


# ── D13 同设备 MAC 多端口 ──────────────────────────────────────────────
def test_d13_hits_when_same_mac_on_two_ports():
    s = _s(macs=[_mac("f033-e508-0567", 1000, "GE1/0/1"), _mac("f033-e508-0567", 1000, "GE1/0/2")])
    al = RR.rule_d13_mac_multi_port(s)
    assert len(al) == 1
    a = al[0]
    assert a["rule_id"] == "D13" and a["signal"] == "MAC_MULTI_PORT" and a["severity"] == "high"
    assert a["mac"] == "f033-e508-0567" and a["vlan"] == 1000
    assert a["ports"] == ["GE1/0/1", "GE1/0/2"] and a["port_count"] == 2
    assert a["fault_hint"] == "loop"
    assert "GE1/0/1" in a["evidence"] and "GE1/0/2" in a["evidence"]


def test_d13_ignores_aggregate_and_stack_ports():
    """聚合口/堆叠口天然多口同 MAC，必须排除，否则误报成环路。"""
    s = _s(macs=[_mac("aabb-ccdd-0001", 10, "GE1/0/1"),
                 _mac("aabb-ccdd-0001", 10, "Eth-Trunk1", agg=True),
                 _mac("aabb-ccdd-0001", 10, "GE2/0/1", stack=True)])
    assert RR.rule_d13_mac_multi_port(s) == []


def test_d13_skips_l3_device_without_l2_table():
    """BRAS/ME60 这类三层设备没有二层表（l2_table_na），不该报环路。"""
    s = _s(macs=[_mac("0000-5e00-0101", 1000, "GE2/0/4"), _mac("0000-5e00-0101", 1000, "GE1/0/4")])
    s["l2_table_na"] = True
    assert RR.rule_d13_mac_multi_port(s) == []


def test_d13_single_port_no_alert():
    s = _s(macs=[_mac("aabb-ccdd-0001", 10, "GE1/0/1")])
    assert RR.rule_d13_mac_multi_port(s) == []


# ── D4 环路组聚合 ─────────────────────────────────────────────────────
def test_d4_groups_similar_rate_ports_into_one_alert():
    ifc = [{"name": f"XGE0/0/{i}", "bcast": 100, "mcast": 0} for i in range(2, 6)]
    s1 = _s(ts=0, ifaces=[dict(x, bcast=100) for x in ifc])
    s2 = _s(ts=300, ifaces=[dict(x, bcast=2_000_000) for x in ifc])   # 每口 ≈6666 pps
    al = RR.rule_d4_broadcast_storm(s1, s2, None, 300)
    assert len(al) == 1, f"同速率多口应聚合成 1 条，实际 {len(al)} 条"
    assert al[0]["grouped"] is True and al[0]["port_count"] == 4
    assert set(al[0]["ports"]) == {"XGE0/0/2", "XGE0/0/3", "XGE0/0/4", "XGE0/0/5"}


def test_d4_single_port_kept_separate_and_low_keyword():
    s1 = _s(ts=0, ifaces=[{"name": "GE0/0/5", "bcast": 10, "mcast": 0}])
    s2 = _s(ts=300, ifaces=[{"name": "GE0/0/5", "bcast": 400_000, "mcast": 0}])   # ≈1330 pps > 阈值 1000
    al = RR.rule_d4_broadcast_storm(s1, s2, None, 300)
    assert len(al) == 1 and al[0]["grouped"] is False


# ── D7 日志结构化抽取 ─────────────────────────────────────────────────
def test_extract_log_ctx_pulls_mac_vlan_port_event():
    line = ("Sep 17 2026 09:01:27 SW %%01MAC/4/MAC_MOVE(l)[1]:"
            "MAC f033-e508-0567 moved to port GE1/0/4 in VLAN 1000")
    ctx = RR.extract_log_ctx(line)
    assert ctx["mac"] == "f033-e508-0567" and ctx["vlan"] == 1000
    assert ctx["port"] == "GE1/0/4" and ctx["event"].startswith("MAC/4/MAC_MOVE")


def test_extract_log_ctx_handles_mflp_trap():
    ctx = RR.extract_log_ctx("Sep 17 2026 08:46:59 H %%01FEI/4/hwMflpVlanLoopPeriodicTrap(s):VlanId=100")
    assert ctx["vlan"] == 100 and "Mflp" in ctx["event"]


def test_d7_alert_carries_structured_fields():
    rules = {"signals": {"MAC_FLAPPING": {"severity": "high",
                                          "patterns": {"huawei": ["MFLPVLAN"]}}}}
    s = _s(logs=["Sep 17 2026 08:46:59 H %%01FEI/4/hwMflpVlanLoopPeriodicTrap(s):VlanId=100"])
    al = RR.rule_d7_log_keywords(s, rules)
    assert len(al) == 1
    assert al[0]["vlan"] == 100 and al[0]["fault_hint"] == "log"
    assert al[0]["log_line"]


# ── 故障事件层 ────────────────────────────────────────────────────────
def _demo_alerts():
    return [
        {"rule_id": "D4", "signal": "BROADCAST_STORM", "severity": "high", "device": "10.21.11.193",
         "interface": "XGE0/0/2", "evidence": "8 口同速率", "grouped": True, "delta": 7244,
         "threshold": 1000, "ports": ["XGE0/0/2", "XGE0/0/3", "XGE0/0/4"], "port_count": 3,
         "fault_hint": "storm"},
        {"rule_id": "D13", "signal": "MAC_MULTI_PORT", "severity": "high", "device": "10.21.11.193",
         "interface": "GE1/0/1", "evidence": "同 MAC 多口", "mac": "f033-e508-0567", "vlan": 1000,
         "ports": ["GE1/0/1", "GE1/0/2"], "port_count": 2, "fault_hint": "loop"},
        {"rule_id": "D7", "signal": "MAC_FLAPPING", "severity": "high", "device": "10.21.11.193",
         "interface": "", "evidence": "命中 MFLPVLAN", "matched_keyword": "MFLPVLAN",
         "fault_hint": "log"},
        {"rule_id": "D4", "signal": "BROADCAST_STORM", "severity": "medium", "device": "172.18.2.148",
         "interface": "GE0/0/5", "evidence": "单口 1200 pps", "grouped": False, "delta": 1200,
         "threshold": 1000, "fault_hint": "storm"},
    ]


def test_faults_merge_storm_and_log_into_one_loop_fault():
    fs = RE.build_faults(_demo_alerts())
    assert len(fs) == 2, [f["title"] for f in fs]          # 环路 1 + 轻微合并 1
    loop = fs[0]
    assert loop["severity"] == "high" and loop["device"] == "10.21.11.193"
    assert len(loop["alerts"]) == 3                        # D4+D13+D7 合成一个故障
    assert loop["macs"] == ["f033-e508-0567"] and loop["vlans"] == [1000]
    assert "GE1/0/2" in " ".join(loop["steps"])            # 处理步骤点名具体端口
    assert fs[0]["first"] is True


def test_faults_single_port_storm_is_mild_and_low():
    fs = RE.build_faults([a for a in _demo_alerts() if a["rule_id"] == "D4" and not a["grouped"]])
    assert len(fs) == 1 and fs[0]["severity"] == "low" and fs[0]["kind"] == "mild"


def test_faults_text_and_html_render():
    fs = RE.build_faults(_demo_alerts())
    txt = RE.faults_to_text(fs)
    assert "故障" in txt and "怎么处理" in txt and "术语解释" in txt
    h = RE.faults_to_html(fs)
    assert "故障清单" in h and "<details>" in h and "怎么处理" in h


def test_faults_empty():
    assert RE.build_faults([]) == []
    assert "未发现故障级问题" in RE.faults_to_text([])

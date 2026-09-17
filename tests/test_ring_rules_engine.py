#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_ring_rules_engine.py —— ring_rules 判据引擎（D1~D12）的 pytest 测试

每个规则都覆盖：正例 / 负例 / 阈值边界（严格 `>`，等于阈值不告警）/ 计数器回绕 /
关键字大小写不敏感 / 规则开关（enabled）。所有样本都是虚构值（SW-1、192.0.2.x）。

放在 tests/ 下且改名带 `_engine` 后缀，是为了不和仓库根目录那份脚本式
`test_ring_rules.py` 撞 basename（pytest 会报 import file mismatch）。
"""

from __future__ import annotations

import fake_data as fd
import pytest

import ring_rules as RR

# ══════════════════════════════════════════════════════════════════
# 小工具
# ══════════════════════════════════════════════════════════════════


def ids(alerts):
    return [a["rule_id"] for a in alerts]


def pick(alerts, rule_id):
    return [a for a in alerts if a["rule_id"] == rule_id]


def ev(alerts, rule_id):
    return " | ".join(a["evidence"] for a in pick(alerts, rule_id))


def normal_pair(ts1=0, ts2=60):
    """一套完全正常的两轮采样（任何规则都不应告警）。"""
    def mk(ts):
        return fd.engine_sample(
            ts=ts,
            interfaces=[fd.iface("GE1/0/1", bcast=100, crc=0, flap=0, rx=-12.0)],
            macs=[fd.mac(port="GE1/0/1")],
            stp={"tc_count": 10, "root_id": "32768.0000-5e00-0001", "root_port": "GE1/0/1"},
            power=[{"id": "PWR1", "status": "Normal"}],
            temperatures=[{"sensor": "S1", "value": 40}],
        )
    return mk(ts1), mk(ts2)


SIGNALS = {"signals": {
    "MAC_FLAPPING": {"severity": "high", "patterns": {
        "huawei": ["MFLPVLAN", "MAC.{0,20}(MOVE|FLAPPING|FLAP)"],
        "cisco": ["MACFLAP"]}},
    "STP_TOPO_CHANGE": {"severity": "medium", "patterns": {
        ".*": ["topology change", r"STP/\d/TC"]}},
}}


# ══════════════════════════════════════════════════════════════════
# 基线
# ══════════════════════════════════════════════════════════════════

def test_baseline_normal_pair_has_no_alerts():
    s1, s2 = normal_pair()
    assert RR.analyze_pair(s1, s2, interval_seconds=60) == []


# ══════════════════════════════════════════════════════════════════
# D1 · MAC 漂移
# ══════════════════════════════════════════════════════════════════

def test_d1_mac_moves_to_other_port():
    s1 = fd.engine_sample(macs=[fd.mac(port="GE1/0/1")])
    s2 = fd.engine_sample(macs=[fd.mac(port="GE1/0/2")])
    out = RR.rule_d1_mac_flap(s1, s2)
    assert len(out) == 1
    a = out[0]
    assert (a["rule_id"], a["signal"], a["severity"]) == ("D1", "MAC_FLAPPING", "medium")
    assert a["port_before"] == "GE1/0/1" and a["port_after"] == "GE1/0/2"
    assert "GE1/0/1" in a["evidence"] and "GE1/0/2" in a["evidence"]


def test_d1_same_port_is_not_flapping():
    s1 = fd.engine_sample(macs=[fd.mac(port="GE1/0/1")])
    s2 = fd.engine_sample(macs=[fd.mac(port="GE1/0/1")])
    assert RR.rule_d1_mac_flap(s1, s2) == []


def test_d1_same_mac_on_other_vlan_is_not_flapping():
    """VLAN 参与判据：换 VLAN 但端口相同 → 不是漂移。"""
    s1 = fd.engine_sample(macs=[fd.mac(vlan=10, port="GE1/0/1")])
    s2 = fd.engine_sample(macs=[fd.mac(vlan=20, port="GE1/0/2")])
    assert RR.rule_d1_mac_flap(s1, s2) == []


def test_d1_port_missing_in_one_round_is_ignored():
    s1 = fd.engine_sample(macs=[fd.mac(port=None)])
    s2 = fd.engine_sample(macs=[fd.mac(port="GE1/0/2")])
    assert RR.rule_d1_mac_flap(s1, s2) == []


def test_d1_two_moves_escalate_to_high():
    s1 = fd.engine_sample(macs=[fd.mac("0000-5e00-0001", port="GE1/0/1"),
                                fd.mac("0000-5e00-0002", port="GE1/0/1")])
    s2 = fd.engine_sample(macs=[fd.mac("0000-5e00-0001", port="GE1/0/2"),
                                fd.mac("0000-5e00-0002", port="GE1/0/2")])
    out = RR.rule_d1_mac_flap(s1, s2)
    assert len(out) == 2
    assert {a["severity"] for a in out} == {"high"}
    assert all(a["delta"] == 2 for a in out)


def test_d1_threshold_override_from_rules():
    """把 high 提到 5：2 次漂移只算 medium。"""
    s1 = fd.engine_sample(macs=[fd.mac("0000-5e00-0001", port="GE1/0/1"),
                                fd.mac("0000-5e00-0002", port="GE1/0/1")])
    s2 = fd.engine_sample(macs=[fd.mac("0000-5e00-0001", port="GE1/0/2"),
                                fd.mac("0000-5e00-0002", port="GE1/0/2")])
    out = RR.rule_d1_mac_flap(s1, s2, rules={"mac_move_count": {"warn": 1, "high": 5}})
    assert {a["severity"] for a in out} == {"medium"}
    assert {a["threshold"] for a in out} == {1}


# ══════════════════════════════════════════════════════════════════
# D2 · STP TC 增量
# ══════════════════════════════════════════════════════════════════

def test_d2_tc_rate_above_access_threshold():
    s1 = fd.engine_sample(cls="access", stp={"tc_count": 10})
    s2 = fd.engine_sample(cls="access", stp={"tc_count": 60}, ts=60)
    out = RR.rule_d2_stp_tc(s1, s2, interval_seconds=60)
    assert len(out) == 1
    assert out[0]["signal"] == "STP_TOPO_CHANGE"
    assert out[0]["delta"] == 50.0          # 50 次/分钟
    assert out[0]["severity"] == "high"     # > 阈值 5 的 3 倍
    assert out[0]["threshold"] == 5


def test_d2_medium_between_threshold_and_3x():
    s1 = fd.engine_sample(cls="access", stp={"tc_count": 0})
    s2 = fd.engine_sample(cls="access", stp={"tc_count": 10}, ts=60)   # 10/min
    out = RR.rule_d2_stp_tc(s1, s2, interval_seconds=60)
    assert out[0]["severity"] == "medium" and out[0]["delta"] == 10.0


def test_d2_boundary_equal_threshold_does_not_alert():
    """增量恰好 5/min（access 阈值 5）→ 严格 `>` 不告警。"""
    s1 = fd.engine_sample(cls="access", stp={"tc_count": 10})
    s2 = fd.engine_sample(cls="access", stp={"tc_count": 15}, ts=60)
    assert RR.rule_d2_stp_tc(s1, s2, interval_seconds=60) == []


@pytest.mark.parametrize("cls,expect", [("access", True), ("aggregation", True), ("core", False)])
def test_d2_threshold_depends_on_device_class(cls, expect):
    """30 次/分钟：access(5) 报 / aggregation(15) 报 / core(30) 恰好等于阈值不报。"""
    s1 = fd.engine_sample(cls=cls, stp={"tc_count": 0})
    s2 = fd.engine_sample(cls=cls, stp={"tc_count": 300}, ts=600)
    out = RR.rule_d2_stp_tc(s1, s2, interval_seconds=600)
    assert bool(out) is expect


def test_d2_high_severity_above_3x_threshold():
    s1 = fd.engine_sample(cls="access", stp={"tc_count": 0})
    s2 = fd.engine_sample(cls="access", stp={"tc_count": 61}, ts=60)      # 61 > 5*3
    assert RR.rule_d2_stp_tc(s1, s2, interval_seconds=60)[0]["severity"] == "high"


def test_d2_counter_wrap_is_skipped():
    s1 = fd.engine_sample(stp={"tc_count": 1000000})
    s2 = fd.engine_sample(stp={"tc_count": 3}, ts=60)
    assert RR.rule_d2_stp_tc(s1, s2, interval_seconds=60) == []


def test_d2_uses_sample_ts_when_interval_not_given():
    s1 = fd.engine_sample(stp={"tc_count": 0}, ts=1000)
    s2 = fd.engine_sample(stp={"tc_count": 100}, ts=1120)                 # 120s → 50/min
    assert len(RR.rule_d2_stp_tc(s1, s2)) == 1


def test_d2_no_time_info_no_alert():
    s1 = fd.engine_sample(stp={"tc_count": 0}, ts=0)
    s2 = fd.engine_sample(stp={"tc_count": 100}, ts=0)
    assert RR.rule_d2_stp_tc(s1, s2) == []


# ══════════════════════════════════════════════════════════════════
# D3 · 根桥变更
# ══════════════════════════════════════════════════════════════════

def test_d3_root_bridge_change():
    s1 = fd.engine_sample(stp={"root_id": "32768.0000-5e00-0001"})
    s2 = fd.engine_sample(stp={"root_id": "32768.0000-5e00-0002"})
    out = RR.rule_d3_root_change(s1, s2)
    assert len(out) == 1
    assert (out[0]["severity"], out[0]["confidence"]) == ("medium", "high")
    assert "0000-5e00-0001" in out[0]["evidence"] and "0000-5e00-0002" in out[0]["evidence"]


def test_d3_root_unchanged_no_alert():
    s1 = fd.engine_sample(stp={"root_id": "32768.0000-5e00-0001"})
    s2 = fd.engine_sample(stp={"root_id": "32768.0000-5e00-0001"})
    assert RR.rule_d3_root_change(s1, s2) == []


def test_d3_root_port_only_change_is_low():
    s1 = fd.engine_sample(stp={"root_id": "R1", "root_port": "GE1/0/1"})
    s2 = fd.engine_sample(stp={"root_id": "R1", "root_port": "GE1/0/2"})
    out = RR.rule_d3_root_change(s1, s2)
    assert len(out) == 1 and out[0]["severity"] == "low"
    assert "根端口" in out[0]["evidence"]


def test_d3_root_and_port_change_reports_once():
    """根桥+根端口同时变 → 只报根桥那条（避免同一事件两条告警）。"""
    s1 = fd.engine_sample(stp={"root_id": "R1", "root_port": "GE1/0/1"})
    s2 = fd.engine_sample(stp={"root_id": "R2", "root_port": "GE1/0/2"})
    out = RR.rule_d3_root_change(s1, s2)
    assert len(out) == 1 and out[0]["severity"] == "medium"


# ══════════════════════════════════════════════════════════════════
# D4 · 广播/组播风暴
# ══════════════════════════════════════════════════════════════════

def test_d4_broadcast_storm_medium():
    s1 = fd.engine_sample(interfaces=[fd.iface(bcast=100, mcast=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(bcast=120100, mcast=0)], ts=60)
    out = RR.rule_d4_broadcast_storm(s1, s2, interval_seconds=60)      # 2000 pps
    assert len(out) == 1
    assert out[0]["signal"] == "BROADCAST_STORM" and out[0]["severity"] == "medium"
    assert out[0]["threshold"] == 1000


def test_d4_multicast_counts_towards_storm():
    s1 = fd.engine_sample(interfaces=[fd.iface(bcast=0, mcast=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(bcast=1000, mcast=59900)], ts=60)
    assert len(RR.rule_d4_broadcast_storm(s1, s2, interval_seconds=60)) == 1


def test_d4_high_above_5x_threshold():
    s1 = fd.engine_sample(interfaces=[fd.iface(bcast=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(bcast=300060)], ts=60)  # 5001 pps
    assert RR.rule_d4_broadcast_storm(s1, s2, interval_seconds=60)[0]["severity"] == "high"


def test_d4_boundary_exactly_1000pps_no_alert():
    s1 = fd.engine_sample(interfaces=[fd.iface(bcast=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(bcast=60000)], ts=60)   # 1000 pps
    assert RR.rule_d4_broadcast_storm(s1, s2, interval_seconds=60) == []


def test_d4_counter_wrap_or_decrease_no_alert():
    s1 = fd.engine_sample(interfaces=[fd.iface(bcast=900000)])
    s2 = fd.engine_sample(interfaces=[fd.iface(bcast=10)], ts=60)
    assert RR.rule_d4_broadcast_storm(s1, s2, interval_seconds=60) == []


def test_d4_new_interface_ignored():
    """第二轮才出现的接口没有基线，不判增速。"""
    s1 = fd.engine_sample(interfaces=[fd.iface("GE1/0/1", bcast=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface("GE1/0/9", bcast=900000)], ts=60)
    assert RR.rule_d4_broadcast_storm(s1, s2, interval_seconds=60) == []


def test_d4_no_time_info_no_alert():
    s1 = fd.engine_sample(interfaces=[fd.iface(bcast=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(bcast=900000)], ts=0)
    assert RR.rule_d4_broadcast_storm(s1, s2) == []


def test_d4_threshold_override_from_rules():
    s1 = fd.engine_sample(interfaces=[fd.iface(bcast=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(bcast=120000)], ts=60)
    assert RR.rule_d4_broadcast_storm(s1, s2, rules={"broadcast_pps": 10 ** 9},
                                      interval_seconds=60) == []


# ══════════════════════════════════════════════════════════════════
# D5 · 接口错误计数（CRC / input errors）
# ══════════════════════════════════════════════════════════════════

def test_d5_crc_growth_alerts():
    s1 = fd.engine_sample(interfaces=[fd.iface(crc=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(crc=500)], ts=60)     # 500 次/分钟
    out = RR.rule_d5_interface_errors(s1, s2, interval_seconds=60)
    assert len(out) == 1
    assert out[0]["signal"] == "INTERFACE_ERRORS" and out[0]["severity"] == "medium"
    assert out[0]["delta"] == 500.0 and out[0]["threshold"] == 100


def test_d5_input_errors_growth_alerts():
    s1 = fd.engine_sample(interfaces=[fd.iface(ierr=100)])
    s2 = fd.engine_sample(interfaces=[fd.iface(ierr=5100)], ts=60)
    assert len(RR.rule_d5_interface_errors(s1, s2, interval_seconds=60)) == 1


def test_d5_high_above_1000_per_minute():
    s1 = fd.engine_sample(interfaces=[fd.iface(crc=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(crc=60100)], ts=60)
    assert RR.rule_d5_interface_errors(s1, s2, interval_seconds=60)[0]["severity"] == "high"


def test_d5_boundary_exactly_100_per_minute_no_alert():
    s1 = fd.engine_sample(interfaces=[fd.iface(crc=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(crc=100)], ts=60)
    assert RR.rule_d5_interface_errors(s1, s2, interval_seconds=60) == []


def test_d5_counter_reset_no_alert():
    s1 = fd.engine_sample(interfaces=[fd.iface(crc=900000)])
    s2 = fd.engine_sample(interfaces=[fd.iface(crc=5)], ts=60)
    assert RR.rule_d5_interface_errors(s1, s2, interval_seconds=60) == []


def test_d5_interface_only_in_round2_ignored():
    s1 = fd.engine_sample(interfaces=[fd.iface("GE1/0/1", crc=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface("GE1/0/9", crc=900000)], ts=60)
    assert RR.rule_d5_interface_errors(s1, s2, interval_seconds=60) == []


def test_d5_threshold_override_from_rules():
    s1 = fd.engine_sample(interfaces=[fd.iface(crc=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(crc=5000)], ts=60)
    assert RR.rule_d5_interface_errors(s1, s2, rules={"crc_per_minute": {"warn": 10 ** 9, "high": 10 ** 9}},
                                       interval_seconds=60) == []


# ══════════════════════════════════════════════════════════════════
# D6 · 链路震荡
# ══════════════════════════════════════════════════════════════════

def test_d6_flapping_per_hour_alerts():
    s1 = fd.engine_sample(interfaces=[fd.iface(flap=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(flap=5)], ts=60)
    out = RR.rule_d6_link_flap(s1, s2, interval_seconds=60)      # 300 次/小时
    assert len(out) == 1
    assert out[0]["signal"] == "LINK_FLAPPING" and out[0]["severity"] == "high"


def test_d6_medium_between_warn_and_high():
    s1 = fd.engine_sample(interfaces=[fd.iface(flap=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(flap=5)], ts=3600)
    assert RR.rule_d6_link_flap(s1, s2, interval_seconds=3600)[0]["severity"] == "medium"


def test_d6_boundary_exactly_3_per_hour_no_alert():
    s1 = fd.engine_sample(interfaces=[fd.iface(flap=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(flap=3)], ts=3600)
    assert RR.rule_d6_link_flap(s1, s2, interval_seconds=3600) == []


def test_d6_counter_wrap_no_alert():
    s1 = fd.engine_sample(interfaces=[fd.iface(flap=100)])
    s2 = fd.engine_sample(interfaces=[fd.iface(flap=1)], ts=60)
    assert RR.rule_d6_link_flap(s1, s2, interval_seconds=60) == []


# ══════════════════════════════════════════════════════════════════
# D7 · 日志关键字映射
# ══════════════════════════════════════════════════════════════════

def test_d7_huawei_keyword_case_insensitive():
    out = RR.rule_d7_log_keywords(
        fd.engine_sample(vendor="huawei", logs=["%Apr  1 10:00 mflpvlan detected on GE1/0/1"]), SIGNALS)
    assert len(out) == 1
    a = out[0]
    assert (a["rule_id"], a["signal"], a["severity"]) == ("D7", "MAC_FLAPPING", "high")
    assert a["matched_keyword"] == "MFLPVLAN"
    assert a["evidence"].startswith("[huawei]")


def test_d7_regex_pattern_case_insensitive():
    out = RR.rule_d7_log_keywords(
        fd.engine_sample(vendor="huawei", logs=["mac move detected on GE1/0/4"]), SIGNALS)
    assert ids(out) == ["D7"]


def test_d7_generic_pattern_applies_to_every_vendor():
    out = RR.rule_d7_log_keywords(
        fd.engine_sample(vendor="ruijie", logs=["%SPANTREE: TOPOLOGY CHANGE detected"]), SIGNALS)
    assert {a["signal"] for a in out} == {"STP_TOPO_CHANGE"}
    assert "topology change" in ev(out, "D7")      # 命中的是 `.*` 通用模式


def test_d7_vendor_isolation_negative():
    """思科设备上出现华为专属关键字 → 不告警。"""
    out = RR.rule_d7_log_keywords(
        fd.engine_sample(vendor="cisco", logs=["MFLPVLAN"]), SIGNALS)
    assert out == []


def test_d7_same_signal_reported_once():
    logs = ["MSTP/4/PORT_STATE_DISCARDING on GE1/0/1",
            "MSTP/4/PORT_STATE_DISCARDING on GE1/0/2",
            "topology change detected"]
    out = RR.rule_d7_log_keywords(fd.engine_sample(vendor="huawei", logs=logs), SIGNALS)
    assert ids(out) == ["D7"]           # 同一信号只报一次，避免刷屏


def test_d7_bad_user_regex_does_not_crash():
    rules = {"signals": {"X": {"severity": "low", "patterns": {"huawei": ["(["]}}}}
    assert RR.rule_d7_log_keywords(fd.engine_sample(logs=["anything"]), rules) == []


def test_d7_no_logs_no_alert():
    assert RR.rule_d7_log_keywords(fd.engine_sample(logs=[]), SIGNALS) == []


def test_d7_without_keyword_table_no_alert():
    """rules 里没有 signals（默认 / rules=None）→ D7 静默。"""
    assert RR.rule_d7_log_keywords(fd.engine_sample(logs=["mflpvlan"]), None) == []


def test_d7_via_analyze_pair_and_can_be_disabled():
    s1 = fd.engine_sample(ts=0)
    s2 = fd.engine_sample(ts=60, logs=["mflpvlan detected on GE1/0/1"])
    assert "D7" in ids(RR.analyze_pair(s1, s2, rules=SIGNALS, interval_seconds=60))
    assert "D7" not in ids(RR.analyze_pair(s1, s2, rules=SIGNALS, enabled=["D2"], interval_seconds=60))


# ══════════════════════════════════════════════════════════════════
# D8 · BPDU 收发异常
# ══════════════════════════════════════════════════════════════════

def test_d8_self_bpdu_seen_is_high():
    s1 = fd.engine_sample(stp={"bpdu_in": 0})
    s2 = fd.engine_sample(stp={"bpdu_in": 10, "bpdu_self_seen": True}, ts=60)
    out = RR.rule_d8_bpdu_anomaly(s1, s2, interval_seconds=60)
    assert len(out) == 1
    assert out[0]["severity"] == "high" and "自环" in out[0]["evidence"]


def test_d8_bpdu_receive_rate_anomaly():
    s1 = fd.engine_sample(stp={"bpdu_in": 0})
    s2 = fd.engine_sample(stp={"bpdu_in": 120000}, ts=60)      # 2000 pkt/s
    out = RR.rule_d8_bpdu_anomaly(s1, s2, interval_seconds=60)
    assert len(out) == 1 and out[0]["severity"] == "medium"
    assert out[0]["threshold"] == 1000


def test_d8_boundary_exactly_1000_per_second_no_alert():
    s1 = fd.engine_sample(stp={"bpdu_in": 0})
    s2 = fd.engine_sample(stp={"bpdu_in": 60000}, ts=60)
    assert RR.rule_d8_bpdu_anomaly(s1, s2, interval_seconds=60) == []


def test_d8_counter_wrap_no_alert():
    s1 = fd.engine_sample(stp={"bpdu_in": 500000})
    s2 = fd.engine_sample(stp={"bpdu_in": 10}, ts=60)
    assert RR.rule_d8_bpdu_anomaly(s1, s2, interval_seconds=60) == []


# ══════════════════════════════════════════════════════════════════
# D9 · 跨设备关联
# ══════════════════════════════════════════════════════════════════

def test_d9_same_mac_on_two_devices():
    a = fd.engine_sample("SW-1", macs=[fd.mac("0000-5e00-9999", vlan=10, port="GE1/0/1")])
    b = fd.engine_sample("SW-2", macs=[fd.mac("0000-5e00-9999", vlan=10, port="GE1/0/5")])
    out = RR.rule_d9_cross_device([a, b])
    assert len(out) == 1
    assert out[0]["severity"] == "high" and out[0]["device"] == "多设备"
    assert "SW-1" in out[0]["evidence"] and "SW-2" in out[0]["evidence"]


def test_d9_same_device_same_mac_no_alert():
    a = fd.engine_sample("SW-1", macs=[fd.mac(vlan=10, port="GE1/0/1")])
    assert RR.rule_d9_cross_device([a]) == []


def test_d9_same_mac_other_vlan_no_alert():
    a = fd.engine_sample("SW-1", macs=[fd.mac(vlan=10, port="GE1/0/1")])
    b = fd.engine_sample("SW-2", macs=[fd.mac(vlan=20, port="GE1/0/5")])
    assert RR.rule_d9_cross_device([a, b]) == []


@pytest.mark.parametrize("flag", ["is_aggregate", "is_stack_member"])
def test_d9_aggregate_or_stack_member_excluded(flag):
    """聚合口 / 堆叠成员之间同 MAC 多口是正常的，必须排除。"""
    a = fd.engine_sample("SW-1", macs=[fd.mac(port="GE1/0/1")])
    b = fd.engine_sample("SW-2", macs=[fd.mac(port="Eth-Trunk1", **{flag: True})])
    assert RR.rule_d9_cross_device([a, b]) == []


def test_d9_tc_burst_on_two_devices_same_window():
    p1 = [fd.engine_sample("SW-1", cls="access", stp={"tc_count": 0}, ts=0),
          fd.engine_sample("SW-1", cls="access", stp={"tc_count": 100}, ts=60)]
    p2 = [fd.engine_sample("SW-2", cls="access", stp={"tc_count": 0}, ts=0),
          fd.engine_sample("SW-2", cls="access", stp={"tc_count": 200}, ts=60)]
    out = RR.rule_d9_tc_same_window([p1, p2], interval_seconds=60)
    assert len(out) == 1 and "2 台" in out[0]["evidence"]


def test_d9_tc_burst_single_device_not_enough():
    p1 = [fd.engine_sample("SW-1", stp={"tc_count": 0}, ts=0),
          fd.engine_sample("SW-1", stp={"tc_count": 100}, ts=60)]
    assert RR.rule_d9_tc_same_window([p1], interval_seconds=60) == []


def test_analyze_cross_respects_enabled_and_defaults():
    a = fd.engine_sample("SW-1", macs=[fd.mac("0000-5e00-9999", port="GE1/0/1")])
    b = fd.engine_sample("SW-2", macs=[fd.mac("0000-5e00-9999", port="GE1/0/5")])
    assert RR.analyze_cross([[a, a], [b, b]], enabled=["D1"], interval_seconds=60) == []
    assert ids(RR.analyze_cross([[a, a], [b, b]], interval_seconds=60)) == ["D9"]


# ══════════════════════════════════════════════════════════════════
# D10 · 光衰
# ══════════════════════════════════════════════════════════════════

def test_d10_absolute_high_below_minus_25():
    s1 = fd.engine_sample(interfaces=[fd.iface(rx=-12.0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(rx=-26.0)], ts=60)
    out = RR.rule_d10_optical(s1, s2)
    assert len(out) == 1
    assert out[0]["severity"] == "high" and out[0]["delta"] == -26.0


def test_d10_absolute_medium_between_warn_and_high():
    s1 = fd.engine_sample(interfaces=[fd.iface(rx=-12.0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(rx=-22.0)], ts=60)
    assert RR.rule_d10_optical(s1, s2)[0]["severity"] == "medium"


@pytest.mark.parametrize("rx,expect_sev", [(-20.0, None), (-25.0, "medium"), (-25.01, "high")])
def test_d10_absolute_threshold_boundaries(rx, expect_sev):
    """阈值用严格 `<`：-20.00 不报、-25.00 只算 medium、再低一点才 high。"""
    s1 = fd.engine_sample(interfaces=[])          # 没有第一轮基线 → 无趋势判定干扰
    s2 = fd.engine_sample(interfaces=[fd.iface(rx=rx)], ts=60)
    out = RR.rule_d10_optical(s1, s2)
    assert [a["severity"] for a in out] == ([] if expect_sev is None else [expect_sev])


def test_d10_trend_drop_over_3db():
    s1 = fd.engine_sample(interfaces=[fd.iface(rx=-12.0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(rx=-16.0)], ts=60)
    out = RR.rule_d10_optical(s1, s2)
    assert len(out) == 1 and out[0]["severity"] == "medium" and out[0]["delta"] == 4.0


def test_d10_trend_boundary_exactly_3db_no_alert():
    s1 = fd.engine_sample(interfaces=[fd.iface(rx=-12.0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(rx=-15.0)], ts=60)
    assert RR.rule_d10_optical(s1, s2) == []


def test_d10_improving_power_no_alert():
    s1 = fd.engine_sample(interfaces=[fd.iface(rx=-18.0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(rx=-11.0)], ts=60)
    assert RR.rule_d10_optical(s1, s2) == []


def test_d10_module_ddm_alarm_flag_is_high(  ):
    s1 = fd.engine_sample(interfaces=[fd.iface(rx=-5.0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(rx=-5.0, rx_alarm=True)], ts=60)
    out = RR.rule_d10_optical(s1, s2)
    assert len(out) == 1 and out[0]["severity"] == "high"
    assert "DDM" in out[0]["evidence"]


def test_d10_missing_rx_power_skipped():
    s1 = fd.engine_sample(interfaces=[fd.iface(rx=-30.0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(rx=None)], ts=60)
    assert RR.rule_d10_optical(s1, s2) == []


def test_d10_new_interface_still_judged_absolutely():
    """第二轮新出现的接口没有基线，但绝对值越界照报。"""
    s1 = fd.engine_sample(interfaces=[])
    s2 = fd.engine_sample(interfaces=[fd.iface("GE1/0/9", rx=-27.0)], ts=60)
    assert len(RR.rule_d10_optical(s1, s2)) == 1


# ══════════════════════════════════════════════════════════════════
# D11 · 温度
# ══════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("t,expect_sev", [(70.0, "medium"), (75.0, "medium"), (75.1, "high"), (80.0, "high")])
def test_d11_absolute_temperature(t, expect_sev):
    s1 = fd.engine_sample(temperatures=[{"sensor": "S1", "value": t}])   # 无升温趋势干扰
    s2 = fd.engine_sample(temperatures=[{"sensor": "S1", "value": t}], ts=60)
    assert [a["severity"] for a in RR.rule_d11_temperature(s1, s2)] == [expect_sev]


def test_d11_boundary_exactly_65_no_alert():
    s1 = fd.engine_sample(temperatures=[{"sensor": "S1", "value": 65}])
    s2 = fd.engine_sample(temperatures=[{"sensor": "S1", "value": 65}], ts=60)
    assert RR.rule_d11_temperature(s1, s2) == []


def test_d11_fast_rise_alerts():
    s1 = fd.engine_sample(temperatures=[{"sensor": "S1", "value": 39}])
    s2 = fd.engine_sample(temperatures=[{"sensor": "S1", "value": 50}], ts=60)
    out = RR.rule_d11_temperature(s1, s2)
    assert len(out) == 1 and out[0]["severity"] == "medium" and out[0]["delta"] == 11.0


def test_d11_rise_boundary_exactly_10c_no_alert():
    s1 = fd.engine_sample(temperatures=[{"sensor": "S1", "value": 40}])
    s2 = fd.engine_sample(temperatures=[{"sensor": "S1", "value": 50}], ts=60)
    assert RR.rule_d11_temperature(s1, s2) == []


def test_d11_sensor_missing_in_round1_and_none_value():
    s1 = fd.engine_sample(temperatures=[{"sensor": "S2", "value": 30}])
    s2 = fd.engine_sample(temperatures=[{"sensor": "S1", "value": 50},
                                        {"sensor": "S2", "value": None}], ts=60)
    assert RR.rule_d11_temperature(s1, s2) == []


# ══════════════════════════════════════════════════════════════════
# D12 · 电源状态
# ══════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("status", ["Abnormal", "Fault", "Absent", "NotSupply", "Unregistered"])
def test_d12_abnormal_states_alert(status):
    s1 = fd.engine_sample(power=[{"id": "PWR1", "status": "Normal"}])
    s2 = fd.engine_sample(power=[{"id": "PWR1", "status": status}], ts=60)
    out = RR.rule_d12_power(s1, s2)
    assert out and out[0]["severity"] == "high"


def test_d12_status_match_is_case_and_space_insensitive():
    s1 = fd.engine_sample(power=[{"id": "PWR1", "status": "Normal"}])
    s2 = fd.engine_sample(power=[{"id": "PWR1", "status": "  abnormal "}], ts=60)
    assert RR.rule_d12_power(s1, s2)


def test_d12_all_normal_no_alert():
    s1 = fd.engine_sample(power=[{"id": "PWR1", "status": "Normal"}, {"id": "PWR2", "status": "Normal"}])
    s2 = fd.engine_sample(power=[{"id": "PWR1", "status": "Normal"}, {"id": "PWR2", "status": "Normal"}], ts=60)
    assert RR.rule_d12_power(s1, s2) == []


def test_d12_redundancy_loss():
    s1 = fd.engine_sample(power=[{"id": "PWR1", "status": "Normal"}, {"id": "PWR2", "status": "Normal"}])
    s2 = fd.engine_sample(power=[{"id": "PWR1", "status": "Normal"}, {"id": "PWR2", "status": "Fault"}], ts=60)
    out = RR.rule_d12_power(s1, s2)
    assert len(out) == 2                       # 状态异常 1 条 + 冗余丢失 1 条
    assert any("冗余丢失" in a["evidence"] for a in out)


def test_d12_no_round1_power_no_redundancy_alert():
    s1 = fd.engine_sample(power=[])
    s2 = fd.engine_sample(power=[{"id": "PWR1", "status": "Fault"}], ts=60)
    out = RR.rule_d12_power(s1, s2)
    assert len(out) == 1 and "冗余丢失" not in out[0]["evidence"]


def test_d12_abnormal_states_list_override():
    s1 = fd.engine_sample(power=[{"id": "PWR1", "status": "Normal"}])
    s2 = fd.engine_sample(power=[{"id": "PWR1", "status": "Abnormal"}], ts=60)
    assert RR.rule_d12_power(s1, s2, rules={"power_abnormal_states": ["Weird"]}) == []


# ══════════════════════════════════════════════════════════════════
# analyze_pair · 开关 / 隔离 / 排序
# ══════════════════════════════════════════════════════════════════

def test_analyze_pair_enabled_subset_only_runs_that_rule():
    s1 = fd.engine_sample(stp={"tc_count": 0}, interfaces=[fd.iface(bcast=0, crc=0)])
    s2 = fd.engine_sample(stp={"tc_count": 60}, interfaces=[fd.iface(bcast=90000, crc=5000, flap=5)], ts=60)
    assert ids(RR.analyze_pair(s1, s2, enabled=["D2"], interval_seconds=60)) == ["D2"]


def test_analyze_pair_default_enables_all_single_rules():
    s1 = fd.engine_sample(stp={"tc_count": 0}, interfaces=[fd.iface(bcast=0, crc=0)])
    s2 = fd.engine_sample(stp={"tc_count": 60}, interfaces=[fd.iface(bcast=90000, crc=5000, flap=5)], ts=60)
    got = set(ids(RR.analyze_pair(s1, s2, interval_seconds=60)))
    assert {"D2", "D4", "D5", "D6"} <= got


def test_analyze_pair_malformed_input_returns_list():
    bad = {"device": "SW-9", "ts": 0, "interfaces": "not-a-list", "stp": None,
           "macs": None, "power": None, "temperatures": None, "logs": None}
    bad2 = dict(bad, ts=60)
    out = RR.analyze_pair(bad, bad2, interval_seconds=60)
    assert isinstance(out, list)


def test_analyze_pair_rule_exception_is_isolated():
    """规则内部抛异常 → 只产出一条 RULE_ERROR，其他规则照跑。"""
    s1 = fd.engine_sample(macs=[fd.mac(port="GE1/0/1")], stp={"tc_count": 0}, interfaces=[fd.iface(bcast=0)])
    s2 = fd.engine_sample(macs=[fd.mac(port="GE1/0/2")], stp={"tc_count": 60},
                          interfaces=[fd.iface(bcast=90000)], ts=60)
    out = RR.analyze_pair(s1, s2, rules={"mac_move_count": {"warn": "abc", "high": 2}},
                          interval_seconds=60)
    errs = [a for a in out if a["signal"] == "RULE_ERROR"]
    assert len(errs) == 1 and errs[0]["rule_id"] == "D1" and errs[0]["severity"] == "low"
    assert {"D2", "D4"} <= set(ids(out))


def test_sort_alerts_orders_high_medium_low():
    alerts = [{"rule_id": "D10", "severity": "low", "device": "SW-1"},
              {"rule_id": "D1", "severity": "high", "device": "SW-1"},
              {"rule_id": "D5", "severity": "medium", "device": "SW-1"}]
    assert [a["severity"] for a in RR.sort_alerts(alerts)] == ["high", "medium", "low"]


def test_rule_catalog_and_v4_v5_sets():
    assert [c["id"] for c in RR.RULE_CATALOG] == [f"D{i}" for i in range(1, 13)]
    assert "D8" not in RR.V4_RULES and "D9" not in RR.V4_RULES
    assert len(RR.V5_RULES) == 12


def test_thresholds_fallback_when_rules_shape_is_wrong():
    """rules 不是 dict / 缺键 → 用内置默认值，不抛异常。"""
    s1 = fd.engine_sample(interfaces=[fd.iface(bcast=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(bcast=120000)], ts=60)
    assert len(RR.rule_d4_broadcast_storm(s1, s2, rules=[], interval_seconds=60)) == 1
    assert RR.rule_d4_broadcast_storm(s1, s2, rules={"broadcast_pps": None},
                                      interval_seconds=60)[0]["threshold"] == 1000


# ══════════════════════════════════════════════════════════════════
# 内部小工具
# ══════════════════════════════════════════════════════════════════

def test_helper_class_of_defaults_to_access():
    assert RR._class_of({"device_class": "core"}) == "core"
    assert RR._class_of({"device_class": "bogus"}) == "access"
    assert RR._class_of({}) == "access"


def test_helper_rate_guards_non_positive_interval():
    assert RR._rate(10, 60) == 10.0
    assert RR._rate(10, 0) == 0.0 and RR._rate(10, None) == 0.0


def test_helper_match_any_skips_bad_regex_and_reports_first_hit():
    assert RR._match_any("Hello World", ["([", "world"]) == "world"
    assert RR._match_any("", ["x"]) is None
    assert RR._match_any("abc", []) is None


def test_helper_th_and_f_are_lenient():
    assert RR._th({"x": 5}, "x", 1) == 5
    assert RR._th({}, "x", 1) == 1
    assert RR._th(None, "x", 1) == 1
    assert RR._f("3.5") == 3.5 and RR._f(None, 7) == 7.0 and RR._f("abc", 9) == 9.0


def test_helper_alert_payload_shape():
    a = RR._alert("D1", "SIG", "high", "low", "SW-1", "ev", "adv", extra_field=1)
    assert set(a) == {"rule_id", "signal", "severity", "confidence", "device",
                      "interface", "evidence", "delta", "threshold", "advice", "extra_field"}
    assert a["extra_field"] == 1

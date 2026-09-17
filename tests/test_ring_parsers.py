#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_ring_parsers.py —— ring_parsers（厂商输出 → 结构化数据）的 pytest 测试

样例全部内嵌在 tests/fake_data.py 里（虚构值），**不读 samples/ 目录**
（那个目录被 .gitignore，CI / 干净检出里并不存在）。
"""

from __future__ import annotations

import csv
import datetime
import hashlib
from pathlib import Path

import fake_data as fd
import pytest

import ring_parsers as RP

# ══════════════════════════════════════════════════════════════════
# norm_mac
# ══════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("raw,expected", [
    ("aabb-cccc-dddd", "aabb-cccc-dddd"),
    ("AABB.CCCC.DDDD", "aabb-cccc-dddd"),
    ("aa:bb:cc:dd:ee:ff", "aabb-ccdd-eeff"),
    ("aabb cccc dddd", "aabb-cccc-dddd"),
    ("  aabb-cccc-dddd  ", "aabb-cccc-dddd"),
])
def test_norm_mac_unifies_all_vendor_formats(raw, expected):
    assert RP.norm_mac(raw) == expected


def test_norm_mac_invalid_input_falls_back_to_trimmed_lowercase():
    """位数不对（不是 12 位十六进制）时不做臆造，只去空格 + 转小写。"""
    assert RP.norm_mac("not-a-mac") == "not-a-mac"
    assert RP.norm_mac("") == ""
    assert RP.norm_mac(None) == ""


# ══════════════════════════════════════════════════════════════════
# norm_ifname
# ══════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("raw", ["GE1/0/1(10G)", "GE1/0/1(100M)", "GE1/0/1 (10G)",
                                 "GE1/0/1(GE)", "GE1/0/1", "  GE1/0/1(10G)  "])
def test_norm_ifname_strips_speed_suffix(raw):
    assert RP.norm_ifname(raw) == "GE1/0/1"


def test_norm_ifname_keeps_subinterface_dot():
    assert RP.norm_ifname("GE1/0/1.990") == "GE1/0/1.990"
    assert RP.norm_ifname("GE1/0/1.990(10G)") == "GE1/0/1.990"


def test_norm_ifname_brief_and_detail_names_meet():
    """同一物理口在 brief（带 (10G)）与 detail（不带）里必须归一成同一个 key。"""
    assert RP.norm_ifname("GigabitEthernet2/1/4(10G)") == RP.norm_ifname("GigabitEthernet2/1/4")


# ══════════════════════════════════════════════════════════════════
# is_cmd_error
# ══════════════════════════════════════════════════════════════════

@pytest.mark.parametrize("text", [
    "Error: Unrecognized command found at '^' position.",
    "Error: Too many parameters found at '^' position.",
    "% Unrecognized command found at '^' position.",
    "% Invalid input detected at '^' marker.",
    "Error: Wrong parameter found at '^' position.",
    "Incomplete command found at '^' position.",
])
def test_is_cmd_error_detects_unsupported_commands(text):
    err, msg = RP.is_cmd_error(text)
    assert err is True and text.strip()[:20] in msg


@pytest.mark.parametrize("text", ["", None,
                                  fd.TRANSCEIVER,
                                  "Interface  PHY  Protocol\nGE1/0/1  up  up"])
def test_is_cmd_error_false_on_normal_output(text):
    err, msg = RP.is_cmd_error(text)
    assert err is False and msg == ""


def test_is_cmd_error_scans_every_line():
    err, msg = RP.is_cmd_error("some preamble line\nError: Unrecognized command found at '^' position.")
    assert err is True and msg.startswith("Error: Unrecognized")


# ══════════════════════════════════════════════════════════════════
# parse_huawei_interface_brief
# ══════════════════════════════════════════════════════════════════

def test_brief_parses_all_rows_and_marks_aggregate():
    out = RP.parse_huawei_interface_brief(fd.brief())
    assert [i["name"] for i in out] == ["Eth-Trunk1", "GigabitEthernet2/1/4(10G)",
                                        "GigabitEthernet2/2/1", "Vlanif1000"]
    trunk = out[0]
    assert trunk["input_err"] == 169.0 and trunk["is_aggregate"] is True
    assert out[1]["is_aggregate"] is False


def test_brief_dash_utilization_becomes_zero():
    out = RP.parse_huawei_interface_brief(fd.brief())
    vlanif = [i for i in out if i["name"] == "Vlanif1000"][0]
    assert vlanif["in_uti"] == 0.0 and vlanif["out_uti"] == 0.0


def test_brief_header_only_returns_empty():
    assert RP.parse_huawei_interface_brief(
        "Interface                   PHY   Protocol  InUti OutUti   inErrors  outErrors\n") == []


def test_brief_ignores_legend_lines():
    text = fd.brief() + "*down: The interface is down\n^down: The interface is down\n"
    assert len(RP.parse_huawei_interface_brief(text)) == 4


# ══════════════════════════════════════════════════════════════════
# 内部小工具
# ══════════════════════════════════════════════════════════════════

def test_lines_strips_blank_lines_and_normalizes_cr():
    assert RP._lines("a\n\n  b  \r\nc") == ["a", "b", "c"]      # \r 会被换成换行
    assert RP._lines("") == [] and RP._lines(None) == []


@pytest.mark.parametrize("raw,expected", [("--", 0.0), ("-", 0.0), ("", 0.0), (None, 0.0),
                                          ("25.88%", 25.88), ("-4.99 dBm", -4.99),
                                          ("0", 0.0), (5, 5.0), ("abc", 0.0)])
def test_num_is_lenient(raw, expected):
    assert RP._num(raw) == expected


@pytest.mark.parametrize("name,expected", [
    ("Eth-Trunk1", True), ("Trunk2", True), ("Port-Channel1", True),
    ("Bridge-Aggregation1", True), ("Stack-Port1/1", True),
    ("GE2/0/4", False), ("Vlanif1000", False), ("GigabitEthernet2/1/4(10G)", False),
])
def test_is_aggregate_name(name, expected):
    assert RP._is_aggregate_name(name) is expected


def test_app_dir_and_default_rules_path_point_at_module_dir(repo_root):
    assert Path(RP.app_dir()) == repo_root
    assert Path(RP.default_rules_path()) == repo_root / "rules.yaml"
    assert Path(RP.default_rules_path()).is_file()


# ══════════════════════════════════════════════════════════════════
# parse_huawei_interface_detail（两种排版）
# ══════════════════════════════════════════════════════════════════

def test_detail_layout_a_aggregate_packets_bytes_then_errors():
    """聚合口排版：`Input: N packets,M bytes` + 下一行 `N errors,M drops`。"""
    out = RP.parse_huawei_interface_detail(
        "Eth-Trunk1 current state : UP (ifindex: 35)\n"
        "Line protocol current state : UP\n"
        "Last 300 seconds input rate 10346801693 bits/sec, 1022185 packets/sec\n"
        "Input: 52777497075475 packets,56580263369400625 bytes\n"
        "  169 errors,0 drops\n")
    assert len(out) == 1
    i = out[0]
    assert i["name"] == "Eth-Trunk1" and i["is_aggregate"] is True
    assert i["input_err"] == 169.0          # ← D5 的 input_err 就在这里
    assert i["in_pkts"] == 52777497075475.0
    assert i["in_bps"] == 10346801693.0 and i["in_pps"] == 1022185.0
    assert i["proto"] == "UP"


def test_detail_layout_b_physical_counters_and_optical_power():
    """物理口排版：`Input: N bytes, M packets` + 逐类计数 + 光功率与告警区间。"""
    out = RP.parse_huawei_interface_detail(fd.detail())
    ge = [i for i in out if i["name"] == "GigabitEthernet2/1/4"][0]
    assert ge["in_pkts"] == 16369881512913.0
    assert ge["crc"] == 12535001.0                  # ← D5 的 CRC
    assert ge["bcast"] == 1548298.0                 # ← D4 的广播计数
    assert ge["mcast"] == 14916022.0                # ← D4 的组播计数
    assert ge["rx_power"] == pytest.approx(-4.99)
    assert ge["tx_power"] == pytest.approx(-3.63)
    assert ge["rx_lo"] == pytest.approx(-14.400) and ge["rx_hi"] == pytest.approx(0.499)
    assert ge["rx_alarm"] is False                  # -4.99 在 [-14.4, 0.499] 内
    assert ge["module_type"] == "HG GENUINE MTRS-1E21-01"
    assert ge["quality"] == "GOOD"


def test_detail_rx_power_outside_warning_range_sets_rx_alarm():
    """越界即由设备自己判定（D10 判据 C）——不靠我们猜阈值。"""
    out = RP.parse_huawei_interface_detail(fd.detail(rx="-14.50"))
    ge = [i for i in out if i["name"] == "GigabitEthernet2/1/4"][0]
    assert ge["rx_power"] == pytest.approx(-14.50) and ge["rx_alarm"] is True


def test_detail_rx_power_without_warning_range_not_alarmed():
    out = RP.parse_huawei_interface_detail(
        "GigabitEthernet2/2/1 current state : UP (ifindex: 151)\n"
        "Rx Power:  -13.10dBm\n")
    i = out[0]
    assert i["rx_power"] == pytest.approx(-13.10) and i["rx_alarm"] is False
    assert "rx_lo" not in i


def test_detail_errors_line_attaches_to_the_right_interface():
    """`N errors` 行属于上一个 Input/Output 段，不能串到下一个接口上。"""
    out = RP.parse_huawei_interface_detail(
        "Eth-Trunk1 current state : UP\nInput: 10 packets,20 bytes\n  7 errors,0 drops\n"
        "GigabitEthernet2/1/4 current state : UP\nRx Power:  -4.99dBm\n")
    assert [i["input_err"] for i in out] == [7.0, 0.0]


def test_detail_empty_and_junk_text_returns_empty_or_list():
    assert RP.parse_huawei_interface_detail("") == []
    assert RP.parse_huawei_interface_detail("just some noise\nmore noise\n") == []


# ══════════════════════════════════════════════════════════════════
# parse_huawei_mac（按 slot 分段会重复 → 去重）
# ══════════════════════════════════════════════════════════════════

def test_mac_table_deduplicated_across_slots():
    out = RP.parse_huawei_mac(fd.mac_table(port="GE2/0/4", slots=2))
    assert len(out) == 1                       # 两个 slot 段里的同一条 → 1 条
    assert out[0] == {"mac": "0000-5e00-0101", "vlan": 1000, "port": "GE2/0/4",
                      "type": "dynamic", "is_aggregate": False}


def test_mac_table_keeps_distinct_entries():
    text = fd.mac_table(port="GE2/0/4", mac="0000-5e00-0101", slots=1) + "\n" + \
           fd.mac_table(port="GE2/0/9", mac="0000-5e00-0202", slots=1)
    out = RP.parse_huawei_mac(text)
    assert {(m["mac"], m["port"]) for m in out} == {
        ("0000-5e00-0101", "GE2/0/4"), ("0000-5e00-0202", "GE2/0/9")}


def test_mac_table_same_mac_on_two_ports_is_not_deduped():
    """同 MAC 同 VLAN 出现在两个端口 → 两条（这是 D1 判据的原始素材）。"""
    text = fd.mac_table(port="GE2/0/4", slots=1) + "\n" + fd.mac_table(port="GE2/0/9", slots=1)
    assert len(RP.parse_huawei_mac(text)) == 2


def test_mac_table_marks_aggregate_port():
    out = RP.parse_huawei_mac(fd.mac_table(port="Eth-Trunk1", slots=1))
    assert out[0]["is_aggregate"] is True and out[0]["port"] == "Eth-Trunk1"


def test_mac_table_skips_headers_and_totals():
    assert RP.parse_huawei_mac("MAC address table of slot 1:\n"
                               "MAC Address    VLAN/BD/     PEVLAN CEVLAN Port/Peerip   Type\n"
                               "Total matching items on slot 1 displayed = 0\n") == []


# ══════════════════════════════════════════════════════════════════
# parse_huawei_stp
# ══════════════════════════════════════════════════════════════════

def test_stp_bridge_priority_is_not_mistaken_for_bridge_id():
    """`CIST Bridge Priority :32768` 绝不能被当成 bridge ID（踩过的坑）。"""
    stp = RP.parse_huawei_stp("Protocol Status :Enabled\nCIST Bridge Priority :32768\n")
    assert stp["bridge_priority"] == 32768
    assert stp["local_bridge_id"] is None
    assert stp["root_id"] is None


def test_stp_summary_form_local_bridge_from_mac_line():
    stp = RP.parse_huawei_stp(fd.STP)
    assert stp["enabled"] is True
    assert stp["local_bridge_id"] == "aabb-cccc-dddd"
    assert stp["root_id"] == "aabb-cccc-dddd"      # STP 在跑 → 本机即根桥
    assert stp["tc_count"] == 3


def test_stp_detail_form_root_and_bridge_ids():
    stp = RP.parse_huawei_stp(
        "Protocol Status :Enabled\n"
        "CIST Bridge :32768.0000-5e00-0002\n"
        "CIST Root/ERPC :32768.0000-5e00-0001 / 0\n"
        "Topology changes :12\n"
        "BPDU received : 128\n")
    assert stp["local_bridge_id"] == "32768.0000-5e00-0002"
    assert stp["root_id"] == "32768.0000-5e00-0001"
    assert stp["tc_count"] == 12
    assert stp["bpdu_in"] == 128


def test_stp_disabled_does_not_claim_to_be_root():
    stp = RP.parse_huawei_stp("Protocol Status :Disabled\nMAC address :aabb-cccc-dddd\n")
    assert stp["enabled"] is False
    assert stp["local_bridge_id"] == "aabb-cccc-dddd"
    assert stp["root_id"] is None


def test_stp_tc_flag_without_count():
    stp = RP.parse_huawei_stp("Protocol Status :Enabled\nTopology change :YES\n")
    assert stp["tc_flag"] is True and stp["tc_count"] is None


def test_stp_missing_keys_are_none_not_zero():
    stp = RP.parse_huawei_stp("")
    assert stp["tc_count"] is None and stp["bpdu_in"] is None and stp["enabled"] is None


# ══════════════════════════════════════════════════════════════════
# display device / logbuffer / alarm active / transceiver / temperature
# ══════════════════════════════════════════════════════════════════

def test_parse_huawei_device_rows():
    out = RP.parse_huawei_device(fd.DEVICE)
    assert [(r["slot"], r["type"], r["status"]) for r in out] == [(1, "BSU", "Normal"),
                                                                  (9, "MPU", "Normal")]


def test_logbuffer_drops_configuration_header():
    logs = RP.parse_huawei_logbuffer(fd.LOGBUFFER)
    assert len(logs) == 2
    assert logs[0].startswith("Sep 17 2026")
    assert all("Allowed max buffer size" not in l for l in logs)


def test_alarm_active_reassembles_wrapped_description():
    out = RP.parse_huawei_alarm(fd.ALARM)
    assert len(out) == 1
    a = out[0]
    assert a["seq"] == "27826077" and a["level"] == 4 and a["level_name"] == "Warning"
    assert a["date"] == "2026-09-17"
    assert "EventNo=66310" in a["desc"] and "Location=GigabitEthernet2/0/4" in a["desc"]


def test_transceiver_diagnosis_values():
    out = RP.parse_huawei_transceiver(fd.TRANSCEIVER)
    assert [t["name"] for t in out] == ["GigabitEthernet2/1/4", "GigabitEthernet2/2/1"]
    assert out[0]["rx_power"] == pytest.approx(-12.34)
    assert out[0]["tx_power"] == pytest.approx(-2.11)
    assert out[0]["temp"] == pytest.approx(36.0)


def test_parse_huawei_temperature_reads_the_temperature_column():
    """温度必须取 Temperature(C) 列（早期取到槽位号 → D11 静默漏报，2026-09-17 已修）。"""
    out = RP.parse_huawei_temperature(fd.TEMPERATURE)
    assert [t["value"] for t in out] == [45.0, 52.0]


def test_parse_huawei_temperature_row_shape():
    out = RP.parse_huawei_temperature(fd.TEMPERATURE)
    assert len(out) == 2                                    # 每条数据一行，不吞行
    assert all(t["sensor"].startswith("Slot") for t in out)
    assert RP.parse_huawei_temperature("Slot  Temperature(C)\n") == []


# ══════════════════════════════════════════════════════════════════
# parse_device_sample（命令字典 → sample）
# ══════════════════════════════════════════════════════════════════

def test_device_sample_unsupported_commands_are_recorded_not_parsed():
    s = fd.device_sample()
    assert set(s["unsupported"]) == {"display transceiver diagnosis interface",
                                     "display temperature all"}
    assert "Unrecognized command" in s["unsupported"]["display transceiver diagnosis interface"]
    # 报错文本绝不能被当成数据
    assert s["temperatures"] == []
    assert s["interfaces"], "其他命令仍要正常解析"


def test_device_sample_merges_brief_and_detail_without_double_counting():
    """brief 与 detail 的 errors 是同一个计数器 → input_err 只能算一次。"""
    s = fd.device_sample()
    by_name = {RP.norm_ifname(i["name"]): i for i in s["interfaces"]}
    trunk = by_name["Eth-Trunk1"]
    assert trunk["input_err"] == 169.0                  # 不是 338
    assert trunk["is_aggregate"] is True
    ge = by_name["GigabitEthernet2/1/4"]                # brief 的 (10G) 与 detail 归一到同一口
    assert ge["input_err"] == 0.0
    assert ge["crc"] == 12535001.0 and ge["rx_power"] == pytest.approx(-4.99)
    assert ge["in_uti"] == pytest.approx(25.74)         # brief 的利用率保留下来了
    assert len(s["interfaces"]) == 4                    # 4 个接口，没有重复项


def test_device_sample_fills_engine_required_numeric_keys():
    s = fd.device_sample()
    for i in s["interfaces"]:
        for k in ("bcast", "mcast", "crc", "input_err", "up_down"):
            assert k in i and isinstance(i[k], (int, float))


def test_device_sample_propagates_rx_alarm_from_ddm():
    s = fd.device_sample(rx="-14.50")
    ge = [i for i in s["interfaces"] if i["name"] == "GigabitEthernet2/1/4"][0]
    assert ge["rx_alarm"] is True


def test_device_sample_alarms_become_log_lines_for_d7():
    s = fd.device_sample()
    assert s["alarms"] and any(l.startswith("ALARM[4/Warning]") for l in s["logs"])
    # 日志正文也在（D7 关键字映射的原料）
    assert any("MSTP/4/PORT_STATE_DISCARDING" in l for l in s["logs"])


def test_device_sample_power_from_display_device():
    s = fd.device_sample()
    assert [p["id"] for p in s["power"]] == ["Slot1(BSU)", "Slot9(MPU)"]
    assert {p["status"] for p in s["power"]} == {"Normal"}


def test_device_sample_unknown_command_is_ignored():
    """未登记的命令名既不解析也不进 unsupported（静默跳过，现状行为）。"""
    s = RP.parse_device_sample({"display foo bar": "whatever output"},
                               device="192.0.2.10", ts=0)
    assert s["unsupported"] == {} and s["interfaces"] == []


def test_device_sample_non_huawei_vendor_reports_unsupported():
    s = RP.parse_device_sample({"display stp": fd.STP}, device="192.0.2.9",
                               vendor="ruijie", ts=0)
    assert s["unsupported"]["*"].startswith("厂商 ruijie")
    assert s["stp"] == {}


def test_device_sample_default_ts_is_now():
    s = RP.parse_device_sample({}, device="192.0.2.10")
    assert isinstance(s["ts"], float) and s["ts"] > 1_600_000_000


def test_device_sample_honours_ts_and_fields():
    s = fd.device_sample(device="10.0.0.1", ts=12345.0, device_class="core")
    assert (s["device"], s["ts"], s["device_class"], s["vendor"]) == \
        ("10.0.0.1", 12345.0, "core", "huawei")


# ══════════════════════════════════════════════════════════════════
# 报告 CSV 读取
# ══════════════════════════════════════════════════════════════════

def _write_report(path: Path, rows) -> Path:
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Device", "Type", "Status", "Anomalies", "Command", "Output"])
        for r in rows:
            w.writerow(r)
    return path


def test_parse_report_groups_by_device(tmp_path):
    p = _write_report(tmp_path / "report_20260917_145530.csv", [
        ["192.0.2.10", "huawei", "OK", "", "display stp", fd.STP],
        ["192.0.2.10", "huawei", "OK", "", "display interface brief", fd.brief()],
        ["192.0.2.11", "huawei", "OK", "", "display stp", fd.STP],
    ])
    samples = RP.parse_report(str(p), device_class="core")
    assert set(samples) == {"192.0.2.10", "192.0.2.11"}
    assert samples["192.0.2.10"]["stp"]["tc_count"] == 3
    assert samples["192.0.2.10"]["device_class"] == "core"
    assert len(samples["192.0.2.10"]["interfaces"]) == 4
    assert samples["192.0.2.11"]["interfaces"] == []


def test_parse_report_last_row_wins_for_same_device(tmp_path):
    p = _write_report(tmp_path / "report_x.csv", [
        ["192.0.2.10", "huawei", "OK", "", "display stp", "Protocol Status :Disabled\n"],
        ["192.0.2.10", "huawei", "OK", "", "display stp", fd.STP],
    ])
    assert RP.parse_report(str(p))["192.0.2.10"]["stp"]["enabled"] is True


def test_iter_report_csv_handles_fields_larger_than_default_limit(tmp_path):
    """单条命令输出可达几百 KB，默认 128KB 上限会直接抛异常。"""
    big = "x" * 200_000
    p = _write_report(tmp_path / "report_big.csv", [["192.0.2.10", "huawei", "OK", "", "display x", big]])
    rows = list(RP.iter_report_csv(str(p)))
    assert len(rows) == 1 and len(rows[0]["Output"]) == 200_000


def test_parse_report_timed_uses_timestamp_from_filename(tmp_path):
    p = _write_report(tmp_path / "report_20260917_145530.csv",
                      [["192.0.2.10", "huawei", "OK", "", "display stp", fd.STP]])
    samples = RP.parse_report_timed(str(p))
    expected = datetime.datetime.strptime("20260917145530", "%Y%m%d%H%M%S").timestamp()
    assert samples["192.0.2.10"]["ts"] == expected


def test_parse_report_timed_falls_back_to_given_ts(tmp_path):
    p = _write_report(tmp_path / "no_ts_here.csv",
                      [["192.0.2.10", "huawei", "OK", "", "display stp", fd.STP]])
    assert RP.parse_report_timed(str(p), ts=777.0)["192.0.2.10"]["ts"] == 777.0


# ══════════════════════════════════════════════════════════════════
# load_rules（规则表）
# ══════════════════════════════════════════════════════════════════

def _sha(path) -> str:
    return hashlib.sha256(Path(path).read_bytes()).hexdigest()


def test_load_rules_existing_file_is_read_only(rules_yaml_path):
    """仓库自带的 rules.yaml 存在时只读：内容与 mtime 都不被改动。"""
    before, mtime = _sha(rules_yaml_path), Path(rules_yaml_path).stat().st_mtime
    rules = RP.load_rules(rules_yaml_path)
    assert _sha(rules_yaml_path) == before
    assert Path(rules_yaml_path).stat().st_mtime == mtime
    assert rules["thresholds"]["broadcast_pps"] == 1000


def test_load_rules_merges_engine_defaults(rules_yaml_path):
    rules = RP.load_rules(rules_yaml_path)
    assert rules["thresholds"]["broadcast_pps"] == 1000
    assert rules["thresholds"]["crc_per_minute"] == {"warn": 100, "high": 1000}
    assert {"STP_TOPO_CHANGE", "MAC_FLAPPING", "LINK_FLAP", "LOOP_DETECT"} <= set(rules["signals"])


def test_load_rules_missing_file_without_auto_release(tmp_path):
    missing = tmp_path / "rules.yaml"
    rules = RP.load_rules(str(missing), auto_release=False)
    assert not missing.exists()
    assert any("规则表不存在" in w for w in rules["_warnings"])
    assert rules["thresholds"]["broadcast_pps"] == 1000        # 仍可用（内置默认）


def test_load_rules_auto_releases_default_into_tmp(tmp_path):
    """缺失时释放默认表——写盘目标用 tmp_path 重定向，不碰仓库。"""
    target = tmp_path / "sub" / "rules.yaml"
    rules = RP.load_rules(str(target))
    assert target.exists() and target.read_text(encoding="utf-8").startswith("#")
    assert "已释放默认规则表" in " ".join(rules["_warnings"])
    assert rules["thresholds"]["temp_c"] == {"warn": 65, "high": 75}
    # ⚠ 注意：本次返回值里**没有 signals**（见 bug 报告第 2 条 / 下面的 xfail 用例）


def test_load_rules_auto_release_should_return_signals(tmp_path):
    """首次自动释放规则表后必须回读：本次调用就要带 signals（否则 D7 静默失效，2026-09-17 已修）。"""
    rules = RP.load_rules(str(tmp_path / "rules.yaml"))
    assert "signals" in rules and rules["signals"]


def test_load_rules_bad_yaml_reports_warning_not_crash(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text("thresholds: [unclosed\n", encoding="utf-8")
    rules = RP.load_rules(str(p))
    assert any("YAML" in w for w in rules["_warnings"])
    assert rules["thresholds"]["broadcast_pps"] == 1000


def test_load_rules_non_mapping_top_level(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text("- just\n- a list\n", encoding="utf-8")
    rules = RP.load_rules(str(p))
    assert any("顶层不是映射" in w for w in rules["_warnings"])


def test_load_rules_non_mapping_signals(tmp_path):
    p = tmp_path / "rules.yaml"
    p.write_text("signals: not-a-map\n", encoding="utf-8")
    rules = RP.load_rules(str(p))
    assert any("signals" in w for w in rules["_warnings"]) and rules["signals"] == {}


def test_rules_yaml_thresholds_take_effect_in_engine(tmp_path):
    """
    rules.yaml 里改阈值必须**真的生效**。

    回归点（2026-09-17 修复）：rules.yaml 用 `thresholds:` 嵌套写法，而引擎 `_th()` 只读顶层键
    → 用户按文档改阈值（如广播风暴 100000）全部被静默忽略、一律回退内置默认值。
    现在：顶层优先，其次读 `thresholds` 子键。
    """
    import ring_rules as RR
    p = tmp_path / "rules.yaml"
    p.write_text("thresholds:\n  broadcast_pps: 100000\n", encoding="utf-8")
    rules = RP.load_rules(str(p))
    assert rules["thresholds"]["broadcast_pps"] == 100000

    s1 = fd.engine_sample(interfaces=[fd.iface(bcast=0)])
    s2 = fd.engine_sample(interfaces=[fd.iface(bcast=120000)], ts=60)
    # 2000 pps < 用户设的 100000 → 不告警（修复前会按内置 1000 误报）
    assert RR.rule_d4_broadcast_storm(s1, s2, rules=rules, interval_seconds=60) == []
    # 兼容：顶层写法与 thresholds 子键写法都生效
    assert RR.rule_d4_broadcast_storm(s1, s2, rules={"broadcast_pps": 100000},
                                      interval_seconds=60) == []
    assert RR.rule_d4_broadcast_storm(s1, s2, rules={"thresholds": {"broadcast_pps": 100000}},
                                      interval_seconds=60) == []
    # 不给 rules（内置默认 1000）→ 报警
    default_alerts = RR.rule_d4_broadcast_storm(s1, s2, interval_seconds=60)
    assert len(default_alerts) == 1 and default_alerts[0]["threshold"] == 1000


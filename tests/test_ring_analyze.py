#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_ring_analyze.py —— ring_analyze 编排层（报告 → 告警清单）的 pytest 测试

重点：
* `available_rules()` 返回 **dict {ID: 元信息}**、`default_enabled()` 默认关掉 D8/D9；
* 文件名时间戳推算间隔（`_round_ts_from_name`）与人话格式化（`_fmt_interval`）；
* `analyze_samples` 的**两轮差分**：第 2 轮把 MAC 换端口（D1）+ 聚合口 inErrors
  169 → 500000（D5），并断言 `summary["two_round"] is True`；
* `analyze_reports` 走真实 CSV 文件（写在 pytest 的 tmp_path，**不写仓库目录**）。
"""

from __future__ import annotations

import csv
import datetime

import fake_data as fd
import pytest

import ring_analyze as RA
import ring_parsers as RP

ALL_RULES = [f"D{i}" for i in range(1, 13)]


# ══════════════════════════════════════════════════════════════════
# 规则清单 / 默认开关
# ══════════════════════════════════════════════════════════════════

def test_available_rules_returns_dict_of_metadata():
    rules = RA.available_rules()
    assert isinstance(rules, dict)
    assert set(rules) == set(ALL_RULES)
    for rid, meta in rules.items():
        assert meta["id"] == rid
        assert set(meta) >= {"id", "signal", "name", "scope"}
        assert meta["scope"] in ("single", "cross")


def test_available_rules_scopes():
    rules = RA.available_rules()
    assert rules["D9"]["scope"] == "cross"
    assert rules["D7"]["scope"] == "single"
    assert rules["D1"]["signal"] == "MAC_FLAPPING"


def test_default_enabled_excludes_deep_rules():
    ids = RA.default_enabled()
    assert "D8" not in ids and "D9" not in ids
    assert set(ids) == set(ALL_RULES) - {"D8", "D9"}


def test_default_enabled_can_take_rules_arg():
    subset = {"D1": RA.available_rules()["D1"]}
    assert RA.default_enabled(subset) == ["D1"]


# ══════════════════════════════════════════════════════════════════
# 文件名 → 时间戳 / 间隔格式化
# ══════════════════════════════════════════════════════════════════

def test_round_ts_from_name_parses_report_filename():
    ts = RA._round_ts_from_name("report_20260917_145530.csv")
    assert ts == datetime.datetime.strptime("20260917145530", "%Y%m%d%H%M%S").timestamp()


def test_round_ts_from_name_handles_paths_and_bad_names():
    assert RA._round_ts_from_name(r"C:\reports\report_20260101_000000.csv") == \
        datetime.datetime.strptime("20260101000000", "%Y%m%d%H%M%S").timestamp()
    assert RA._round_ts_from_name("alerts.csv") is None
    assert RA._round_ts_from_name("") is None
    assert RA._round_ts_from_name(None) is None


@pytest.mark.parametrize("sec,expected", [
    (30, "30 秒"), (89, "89 秒"), (90, "1.5 分钟"), (600, "10.0 分钟"),
    (5399, "90.0 分钟"), (5400, "1.5 小时"), (7200, "2.0 小时"),
    (0, "未知"), (None, "未知"), (-5, "未知"),
])
def test_fmt_interval(sec, expected):
    assert RA._fmt_interval(sec) == expected


# ══════════════════════════════════════════════════════════════════
# analyze_samples · 单轮
# ══════════════════════════════════════════════════════════════════

def test_analyze_samples_single_round_snapshot():
    s1 = {"192.0.2.10": fd.device_sample(rx="-26.0")}
    res = RA.analyze_samples(s1, None, rules=RP.load_rules(), enabled=RA.default_enabled())
    s = res["summary"]
    assert s["two_round"] is False
    assert s["interval_text"] == "—" and s["interval_seconds"] == 0.0
    assert s["devices"] == 1
    assert s["devices_with_alerts"] == 1
    assert "D10" in {a["rule_id"] for a in res["alerts"]}      # 绝对值判据（收光 -26）
    assert res["by_device"]["192.0.2.10"]


def test_analyze_samples_single_round_runs_d7_keywords():
    signals = {"signals": {"MAC_FLAPPING": {"severity": "high",
                                            "patterns": {"huawei": ["MFLPVLAN"]}}}}
    s1 = {"192.0.2.10": fd.engine_sample(ts=0, vendor="huawei",
                                         logs=["MFLPVLAN detected on GE2/0/4"])}
    res = RA.analyze_samples(s1, None, rules=signals, enabled=["D7"])
    assert [a["rule_id"] for a in res["alerts"]] == ["D7"]


def test_analyze_samples_empty_input():
    res = RA.analyze_samples({}, None)
    assert res["summary"]["total"] == 0 and res["summary"]["devices"] == 0
    assert res["alerts"] == [] and res["by_device"] == {}


# ══════════════════════════════════════════════════════════════════
# analyze_samples · 两轮差分（D1 + D5）
# ══════════════════════════════════════════════════════════════════

def two_round_samples():
    """两轮采样：MAC 换端口（D1）+ 聚合口 inErrors 169→500000（D5）。"""
    s1 = {"192.0.2.10": fd.device_sample(ts=0, port="GE2/0/4", eth_trunk_in_errors=169)}
    s2 = {"192.0.2.10": fd.device_sample(ts=60, port="GE2/0/5", eth_trunk_in_errors=500000)}
    return s1, s2


def test_analyze_samples_two_round_hits_d1_and_d5():
    s1, s2 = two_round_samples()
    res = RA.analyze_samples(s1, s2, rules=RP.load_rules(),
                             enabled=RA.default_enabled(), interval_seconds=60)
    s = res["summary"]
    assert s["two_round"] is True
    assert s["interval_seconds"] == 60
    assert s["interval_text"] == "60 秒"
    got = {a["rule_id"] for a in res["alerts"]}
    assert {"D1", "D5"} <= got, res["alerts"]

    d1 = [a for a in res["alerts"] if a["rule_id"] == "D1"][0]
    assert d1["port_before"] == "GE2/0/4" and d1["port_after"] == "GE2/0/5"
    assert d1["device"] == "192.0.2.10"

    d5 = [a for a in res["alerts"] if a["rule_id"] == "D5"][0]
    assert d5["delta"] == pytest.approx(499831.0) and d5["interface"] == "Eth-Trunk1"
    assert d5["severity"] == "high"
    assert list(res["summary"]["signals"]) and res["summary"]["total"] == len(res["alerts"])


def test_analyze_samples_two_round_unchanged_data_only_log_rule_fires():
    """两轮数据完全一致 → 增长类判据全部静默（只有日志关键字 D7 命中）。"""
    s1 = {"192.0.2.10": fd.device_sample(ts=0)}
    s2 = {"192.0.2.10": fd.device_sample(ts=60)}
    res = RA.analyze_samples(s1, s2, rules=RP.load_rules(), enabled=RA.default_enabled(),
                             interval_seconds=60)
    assert res["summary"]["two_round"] is True
    got = {a["rule_id"] for a in res["alerts"]}
    assert got == {"D7"}, res["alerts"]          # 样本日志命中 rules.yaml 的华为事件名
    assert not (got & {"D1", "D2", "D3", "D4", "D5", "D6", "D10", "D11", "D12"})

    # 关掉 D7 → 零告警（确认其余判据真的静默）
    no_d7 = [r for r in RA.default_enabled() if r != "D7"]
    res2 = RA.analyze_samples(s1, s2, rules=RP.load_rules(), enabled=no_d7, interval_seconds=60)
    assert res2["alerts"] == [], res2["alerts"]


def test_analyze_samples_missing_interval_falls_back_to_300s_with_warning():
    s1 = {"192.0.2.10": fd.engine_sample(ts=0, interfaces=[fd.iface(bcast=0)])}
    s2 = {"192.0.2.10": fd.engine_sample(ts=0, interfaces=[fd.iface(bcast=600000)])}
    res = RA.analyze_samples(s1, s2, enabled=["D4"], interval_seconds=0)
    assert res["summary"]["interval_seconds"] == 300.0
    assert any("300 秒" in w for w in res["warnings"])
    assert [a["rule_id"] for a in res["alerts"]] == ["D4"]      # 600000/300 = 2000 pps


def test_analyze_samples_device_only_in_round1_is_warned():
    s1 = {"192.0.2.10": fd.engine_sample(ts=0),
          "192.0.2.11": fd.engine_sample("192.0.2.11", ts=0)}
    s2 = {"192.0.2.10": fd.engine_sample(ts=60)}
    res = RA.analyze_samples(s1, s2, enabled=["D2"], interval_seconds=60)
    assert any("只有第一轮数据" in w for w in res["warnings"])
    assert set(res["by_device"]) == {"192.0.2.10", "192.0.2.11"}


def test_analyze_samples_enabled_subset():
    s1, s2 = two_round_samples()
    res = RA.analyze_samples(s1, s2, enabled=["D1"], interval_seconds=60)
    assert {a["rule_id"] for a in res["alerts"]} == {"D1"}
    assert res["summary"]["rules_enabled"] == ["D1"]


def test_analyze_samples_unknown_rule_ids_are_dropped():
    s1, s2 = two_round_samples()
    res = RA.analyze_samples(s1, s2, enabled=["D1", "DX"], interval_seconds=60)
    assert res["summary"]["rules_enabled"] == ["D1"]


def test_analyze_samples_unsupported_commands_are_reported():
    """设备不支持的检测项要能在结果里看到（不能悄悄少检）。"""
    s1, s2 = two_round_samples()
    res = RA.analyze_samples(s1, s2, enabled=["D1"], interval_seconds=60)
    assert set(res["unsupported"]["192.0.2.10"]) == {
        "display transceiver diagnosis interface", "display temperature all"}


def test_analyze_samples_cross_device_d9_between_devices():
    same = "0000-5e00-9999"
    s1 = {"192.0.2.10": fd.device_sample(ts=0, port="GE2/0/4", mac=same, eth_trunk_in_errors=169),
          "192.0.2.11": fd.device_sample("192.0.2.11", ts=0, port="GE2/0/9", mac=same,
                                         eth_trunk_in_errors=169)}
    s2 = {k: fd.device_sample(k, ts=60, port=("GE2/0/4" if k.endswith(".10") else "GE2/0/9"),
                              mac=same, eth_trunk_in_errors=169) for k in s1}
    res = RA.analyze_samples(s1, s2, enabled=["D9"], interval_seconds=60)
    assert [a["rule_id"] for a in res["alerts"]] == ["D9"]
    assert "192.0.2.10" in res["alerts"][0]["evidence"]
    assert "192.0.2.11" in res["alerts"][0]["evidence"]
    assert "（跨设备）" in res["by_device"]


def test_analyze_samples_allow_cross_false_warns():
    s1, s2 = two_round_samples()
    res = RA.analyze_samples(s1, s2, enabled=["D9"], allow_cross=False, interval_seconds=60)
    assert res["alerts"] == []
    assert any("跨设备关联能力不可用" in w for w in res["warnings"])


def test_analyze_samples_progress_callback_and_meta():
    seen = []
    s1, s2 = two_round_samples()
    res = RA.analyze_samples(s1, s2, enabled=["D1"], interval_seconds=60,
                             progress=lambda m, c, t: seen.append((m, c, t)),
                             meta={"round1_path": "r1.csv", "round2_path": "r2.csv",
                                   "round1_time": "2026-09-17 14:55:30",
                                   "round2_time": "2026-09-17 15:05:30"})
    assert seen and seen[0][0].startswith("分析 ")
    assert res["summary"]["round1_path"] == "r1.csv"
    assert res["summary"]["round2_path"] == "r2.csv"
    assert res["summary"]["round1_time"] == "2026-09-17 14:55:30"


def test_analyze_samples_breaking_progress_callback_is_tolerated():
    def boom(*_a):
        raise RuntimeError("callback exploded")
    res = RA.analyze_samples({"192.0.2.10": fd.engine_sample()}, None, enabled=["D2"],
                             progress=boom)
    assert res["summary"]["total"] == 0


def test_analyze_samples_alerts_sorted_by_severity():
    s1, s2 = two_round_samples()
    res = RA.analyze_samples(s1, s2, enabled=["D1", "D5"], interval_seconds=60)
    rank = {"high": 0, "medium": 1, "low": 2}
    sev = [rank[a["severity"]] for a in res["alerts"]]
    assert sev == sorted(sev)


# ══════════════════════════════════════════════════════════════════
# analyze_reports · 走真实 CSV（tmp_path）
# ══════════════════════════════════════════════════════════════════

def write_report(path, rows):
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Device", "Type", "Status", "Anomalies", "Command", "Output"])
        for r in rows:
            w.writerow(r)
    return str(path)


def report_rows(dev, port="GE2/0/4", eth_trunk_in_errors=169, rx="-4.99"):
    cmds = fd.device_cmds(port=port, eth_trunk_in_errors=eth_trunk_in_errors, rx=rx)
    return [[dev, "huawei", "OK", "", cmd, out] for cmd, out in cmds.items()]


def test_analyze_reports_two_rounds_interval_from_filename(tmp_path):
    r1 = write_report(tmp_path / "report_20260917_145530.csv", report_rows("192.0.2.10"))
    r2 = write_report(tmp_path / "report_20260917_150530.csv",
                      report_rows("192.0.2.10", port="GE2/0/5", eth_trunk_in_errors=500000))
    res = RA.analyze_reports(r1, r2, rules=RP.load_rules(), enabled=RA.default_enabled())
    s = res["summary"]
    assert s["two_round"] is True
    assert s["interval_seconds"] == 600.0 and s["interval_text"] == "10.0 分钟"
    assert s["round1_path"] == r1 and s["round2_path"] == r2
    got = {a["rule_id"] for a in res["alerts"]}
    assert {"D1", "D5"} <= got, res["alerts"]
    assert "192.0.2.10" in res["samples1"] and "192.0.2.10" in res["samples2"]


def test_analyze_reports_interval_fallback_when_names_have_no_timestamp(tmp_path):
    r1 = write_report(tmp_path / "round_a.csv", report_rows("192.0.2.10"))
    r2 = write_report(tmp_path / "round_b.csv", report_rows("192.0.2.10", port="GE2/0/5"))
    res = RA.analyze_reports(r1, r2, enabled=["D1"])
    assert res["summary"]["interval_seconds"] == 300.0
    assert any("无法从文件名推算两轮间隔" in w for w in res["warnings"])
    assert [a["rule_id"] for a in res["alerts"]] == ["D1"]


def test_analyze_reports_explicit_interval_wins(tmp_path):
    r1 = write_report(tmp_path / "report_20260917_145530.csv", report_rows("192.0.2.10"))
    r2 = write_report(tmp_path / "report_20260917_150530.csv",
                      report_rows("192.0.2.10", port="GE2/0/5"))
    res = RA.analyze_reports(r1, r2, enabled=["D1"], interval_seconds=42.0)
    assert res["summary"]["interval_seconds"] == 42.0
    assert res["summary"]["interval_text"] == "42 秒"


def test_analyze_reports_single_round(tmp_path):
    r1 = write_report(tmp_path / "report_20260917_145530.csv", report_rows("192.0.2.10"))
    res = RA.analyze_reports(r1, rules=RP.load_rules(), device_class="access")
    assert res["summary"]["two_round"] is False
    assert res["summary"]["device_class"] == "access"
    assert res["summary"]["round2_path"] == ""
    assert res["summary"]["round2_time"] == "—"


def test_analyze_reports_warns_when_round2_has_no_devices(tmp_path):
    r1 = write_report(tmp_path / "report_20260917_145530.csv", report_rows("192.0.2.10"))
    r2 = tmp_path / "report_20260917_150530.csv"
    with open(r2, "w", encoding="utf-8-sig", newline="") as f:
        csv.writer(f).writerow(["Device", "Type", "Status", "Anomalies", "Command", "Output"])
    res = RA.analyze_reports(r1, str(r2), enabled=["D1"])
    assert any("没有解析出任何设备" in w for w in res["warnings"])
    assert res["summary"]["two_round"] is False        # 第二轮无效 → 退回单轮


def test_analyze_reports_empty_round1_warns(tmp_path):
    r1 = tmp_path / "report_20260917_145530.csv"
    with open(r1, "w", encoding="utf-8-sig", newline="") as f:
        csv.writer(f).writerow(["Device", "Type", "Status", "Anomalies", "Command", "Output"])
    res = RA.analyze_reports(str(r1), enabled=["D1"])
    assert any("没有解析出任何设备" in w for w in res["warnings"])
    assert res["summary"]["total"] == 0


def test_analyze_reports_missing_file_raises(tmp_path):
    """现状行为：报告路径不存在时异常直接抛出（由调用方/GUI 兜）。"""
    with pytest.raises(FileNotFoundError):
        RA.analyze_reports(str(tmp_path / "not_there.csv"))


# ══════════════════════════════════════════════════════════════════
# 导出
# ══════════════════════════════════════════════════════════════════

def _result_for_export():
    s1, s2 = two_round_samples()
    return RA.analyze_samples(s1, s2, rules=RP.load_rules(), enabled=RA.default_enabled(),
                             interval_seconds=60)


def test_alerts_to_csv_writes_bom_csv(tmp_path):
    out = tmp_path / "alerts.csv"
    RA.alerts_to_csv(_result_for_export(), str(out))
    raw = out.read_bytes()
    assert raw.startswith(b"\xef\xbb\xbf")                  # Excel 双击不乱码
    with open(out, encoding="utf-8-sig", newline="") as f:
        rows = list(csv.reader(f))
    assert rows[0] == ["Severity", "Signal", "Rule", "Device", "Interface", "Evidence", "Advice"]
    assert any(r[2] == "D1" and r[0] == "一般" for r in rows[1:])


def test_alerts_to_html_contains_evidence_and_no_credentials(tmp_path):
    out = tmp_path / "alerts.html"
    RA.alerts_to_html(_result_for_export(), str(out))
    doc = out.read_text(encoding="utf-8")
    assert "两轮差分" in doc and "环路" in doc
    assert "GE2/0/4" in doc and "MAC_FLAPPING" in doc
    assert "password" not in doc.lower()


def test_alerts_to_html_with_no_alerts(tmp_path):
    out = tmp_path / "empty.html"
    res = RA.analyze_samples({"192.0.2.10": fd.device_sample(ts=0)},
                             {"192.0.2.10": fd.device_sample(ts=60)},
                             enabled=["D1"], interval_seconds=60)
    RA.alerts_to_html(res, str(out))
    assert "未发现告警" in out.read_text(encoding="utf-8")


# ══════════════════════════════════════════════════════════════════
# 命令行入口
# ══════════════════════════════════════════════════════════════════

def test_cli_offline_mode_with_exports(tmp_path, capsys):
    r1 = write_report(tmp_path / "report_20260917_145530.csv", report_rows("192.0.2.10"))
    r2 = write_report(tmp_path / "report_20260917_150530.csv",
                      report_rows("192.0.2.10", port="GE2/0/5", eth_trunk_in_errors=500000))
    html, csv_out = tmp_path / "a.html", tmp_path / "a.csv"
    rc = RA._main([r1, r2, "--device-class", "aggregation",
                   "--out", str(html), "--csv", str(csv_out)])
    printed = capsys.readouterr().out
    assert rc == 0
    assert "两轮差分" in printed and "D5" in printed
    assert html.exists() and csv_out.exists()


def test_cli_all_rules_flag(tmp_path, capsys):
    r1 = write_report(tmp_path / "report_20260917_145530.csv", report_rows("192.0.2.10"))
    rc = RA._main([r1, "--all-rules"])
    printed = capsys.readouterr().out
    assert rc == 0 and "启用规则" in printed and "D9" in printed

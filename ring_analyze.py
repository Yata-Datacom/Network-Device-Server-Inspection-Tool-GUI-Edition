#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ring_analyze.py —— 分析编排层（报告文件 → 告警清单）

这一层把「解析」和「判据」串起来，给界面（`ring_analyzer.py`）和命令行共用，
所以 GUI 只负责收集参数 + 展示结果，逻辑不散在界面代码里。

职责
----
1. 选文件：第一轮报告（必需）、第二轮报告（可选，给了就是**两轮差分**模式）；
2. 算间隔：优先从文件名 `report_YYYYmmdd_HHMMSS.csv` 推出两轮实际间隔（差分必须用时差
   换算速率，猜不得），失败则用调用方给的秒数，再不行给 300 秒并在 warnings 里说明；
3. 逐设备跑判据：`ring_rules.analyze_pair(第一轮, 第二轮, ...)`；
4. 跨设备关联（**仅完整版**）：`ring_rules.analyze_cross(pairs, ...)` —— 阉割版的
   `ring_rules.py` 里根本没有这两个函数，`analyze_reports` 会自动跳过（`allow_cross`
   也会先判一次）；
5. 汇总 + 统计 + 未支持命令清单（哪些设备没有哪些检测能力，得让用户看得见）。

两种模式
--------
* **单轮**（只给第一轮）：能判「关键字类」（D7 日志事件）、「绝对值类」（D10 光功率越界、
  D11 温度、D12 组件状态）、以及**历史累计量**（可看但要人工判断是否"正在增长"）；
* **两轮**（两份报告）：额外能判「增长类」（D1 MAC 漂移、D2 TC 增量、D4 广播速率、
  D5 CRC/错误增长、D6 链路震荡、D8 BPDU、D10 趋势）——**环路检测的主力**。

⚠️ 间隔很重要：两轮间隔 10 分钟和 24 小时，同样的增量算出来差 144 倍。所以界面上
   会显示"实际间隔"，并允许手工覆盖。

命令行用法::

    python ring_analyze.py report_20260917_145530.csv
    python ring_analyze.py r1.csv r2.csv --device-class core --out alerts.html
"""

from __future__ import annotations

import csv
import html
import os
import re
from datetime import datetime
from typing import Any, Callable, Dict, Iterable, List, Optional, Sequence

import ring_parsers as RP
import ring_rules as RR

try:
    import ring_events as RE      # 故障事件层（把多条告警合成"一个故障"）
except Exception:                 # 缺模块时降级：只出告警明细，不崩
    RE = None

# ══════════════════════════════════════════════════════════════════
# 规则清单（给界面做勾选框；按"当前引擎里真的存在哪些规则"动态算）
# ══════════════════════════════════════════════════════════════════

SEVERITY_ORDER = {"high": 0, "medium": 1, "low": 2}
SEVERITY_CN = {"high": "高危", "medium": "一般", "low": "提示"}


def available_rules() -> "Dict[str, Dict[str, str]]":
    """
    返回当前引擎可用的规则表 `{规则号: 描述}`。

    动态计算的原因：阉割版（V4）的 `ring_rules.py` 里删掉了 D8/D9 的函数，
    这里自然就不会列出来 —— **界面不用改代码**，勾选框自动少两项。
    """
    single = set(getattr(RR, "_SINGLE_PAIR_RULES", {}).keys())
    if hasattr(RR, "rule_d7_log_keywords"):
        single.add("D7")
    cross = {"D9"} if hasattr(RR, "rule_d9_cross_device") else set()
    exist = single | cross
    out: "Dict[str, Dict[str, str]]" = {}
    for c in getattr(RR, "RULE_CATALOG", []):
        if c.get("id") in exist:
            out[c["id"]] = c
    return out


def default_enabled(rules: "Dict[str, Dict[str, str]]" = None) -> List[str]:
    """
    默认勾选项：**基础项全开，深度项（D8 BPDU / D9 跨设备）默认关**。

    D9 默认关的理由：它需要"同一轮里所有设备的数据"，只有完整版才有，且
    聚合口/堆叠场景容易误报（已在解析层标记 `is_aggregate` 排除，但仍保守默认关）。
    """
    rules = rules if rules is not None else available_rules()
    return [rid for rid in rules if rid not in ("D8", "D9")]


def _round_ts_from_name(path: str) -> Optional[float]:
    """从报告文件名 `report_YYYYmmdd_HHMMSS.csv` 解析采样时间戳（秒）。"""
    m = re.search(r"(\d{8})_(\d{6})", os.path.basename(path or ""))
    if not m:
        return None
    try:
        return datetime.strptime(m.group(1) + m.group(2), "%Y%m%d%H%M%S").timestamp()
    except ValueError:
        return None


def _fmt_dt(ts: Optional[float]) -> str:
    return datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S") if ts else "未知"


def _fmt_interval(sec: Optional[float]) -> str:
    """把秒数写成人话（界面和报告都要用）。"""
    if not sec or sec <= 0:
        return "未知"
    if sec < 90:
        return f"{sec:.0f} 秒"
    if sec < 5400:
        return f"{sec / 60:.1f} 分钟"
    return f"{sec / 3600:.1f} 小时"


# ══════════════════════════════════════════════════════════════════
# 主流程
# ══════════════════════════════════════════════════════════════════

def analyze_samples(s1: Dict[str, Dict[str, Any]],
                    s2: Optional[Dict[str, Dict[str, Any]]] = None,
                    rules: Optional[Dict[str, Any]] = None,
                    enabled: Optional[Iterable[str]] = None,
                    device_class: str = "aggregation",
                    interval_seconds: Optional[float] = None,
                    allow_cross: bool = True,
                    progress: Optional[Callable[[str, int, int], None]] = None,
                    meta: Optional[Dict[str, Any]] = None) -> Dict[str, Any]:
    """
    分析**已在内存里的采样**（在线两轮采样走这里，不落盘）。

    :param s1: `{设备: sample}` 第一轮。
    :param s2: `{设备: sample}` 第二轮；None → 单轮模式。
    :param rules: 规则表（`ring_parsers.load_rules()`）。
    :param enabled: 启用的规则号；None → `default_enabled()`。
    :param device_class: 设备角色档（core/aggregation/access）。
    :param interval_seconds: 两轮实际间隔（秒）——在线模式必须传真实耗时！
    :param allow_cross: 是否跑跨设备关联（阉割版引擎没有该能力，自动失效）。
    :param progress: 进度回调 `fn(阶段, 当前, 总数)`。
    :param meta: 附加上下文（报告路径/采样时间等），会合并进 summary 与结果。
    :return: 与 `analyze_reports` 同结构的结果 dict。
    """
    warnings: List[str] = list((meta or {}).get("warnings") or [])
    rules = rules if rules is not None else RP.load_rules()
    warnings.extend(rules.get("_warnings") or [])
    all_rules = available_rules()
    ids = list(enabled) if enabled is not None else default_enabled(all_rules)
    ids = [i for i in ids if i in all_rules]
    single_ids = [i for i in ids if all_rules[i].get("scope") == "single"]
    cross_ids = [i for i in ids if all_rules[i].get("scope") == "cross"]

    def tick(msg: str, cur: int, total: int) -> None:
        if progress:
            try:
                progress(msg, cur, total)
            except Exception:
                pass

    two_round = bool(s2)
    if not two_round:
        interval_seconds = interval_seconds or 0.0
    elif not interval_seconds or interval_seconds <= 0:
        interval_seconds = 300.0
        warnings.append("两轮间隔缺失或为 0，已回退为 300 秒计算速率（请核实实际间隔）")

    # ── 逐设备判据 ────────────────────────────────────────────────
    devices = list(s1.keys())
    alerts: List[Dict[str, Any]] = []
    by_device: Dict[str, List[Dict[str, Any]]] = {}
    pairs: List[List[Dict[str, Any]]] = []
    for n, dev in enumerate(devices, 1):
        tick(f"分析 {dev} …", n, len(devices))
        a1 = s1.get(dev) or {}
        a2 = (s2 or {}).get(dev) if two_round else a1
        if two_round and a2 is None:
            warnings.append(f"设备 {dev} 只有第一轮数据，按单轮分析")
            a2 = a1
        dev_alerts: List[Dict[str, Any]] = []
        if single_ids:
            # 单轮时 a2 = a1：D10/D11/D12 判的是"本轮绝对值"，D7 判本轮日志关键字，
            # 所以单轮照样出结果；不要再单独跑一遍（会重复告警）。
            dev_alerts += RR.analyze_pair(a1, a2, rules=rules, enabled=single_ids,
                                          interval_seconds=interval_seconds)
        by_device[dev] = dev_alerts
        alerts += dev_alerts
        if two_round:
            pairs.append([a1, a2])

    # ── 跨设备关联（仅完整版引擎有）──────────────────────────────
    allow_cross = allow_cross and hasattr(RR, "analyze_cross")
    if allow_cross and cross_ids:
        if two_round and len(pairs) >= 2:
            tick("跨设备关联分析…", 0, 1)
            try:
                alerts += _collect_cross(RR.analyze_cross(pairs, rules=rules, enabled=cross_ids,
                                                          interval_seconds=interval_seconds),
                                         by_device)
            except Exception as e:
                warnings.append(f"跨设备关联异常: {e}")
        # 单轮也能查"同一 MAC 出现在两台设备"（不需要两轮）
        if not two_round and hasattr(RR, "rule_d9_cross_device"):
            try:
                alerts += _collect_cross(RR.rule_d9_cross_device(list(s1.values()), rules),
                                         by_device)
            except Exception as e:
                warnings.append(f"跨设备 MAC 冲突判定异常: {e}")
    elif cross_ids and not allow_cross:
        warnings.append("当前为精简版：跨设备关联能力不可用，已跳过")

    alerts = RR.sort_alerts(alerts) if hasattr(RR, "sort_alerts") else alerts
    # ── 故障事件层：把逐条告警聚合成"故障"（谁的问题 + 怎么处理）──
    faults: List[Dict[str, Any]] = []
    if RE is not None:
        try:
            _sm = dict(s1 or {})
            if s2:
                for _k, _v in (s2 or {}).items():
                    _sm[_k] = _v
            faults = RE.build_faults(alerts, _sm)
        except Exception as exc:                 # 故障层异常不能影响告警明细
            warnings.append(f"故障事件聚合异常：{exc}")

    # ── 统计 ──────────────────────────────────────────────────────
    sig_count: Dict[str, int] = {}
    sev_count: Dict[str, int] = {"high": 0, "medium": 0, "low": 0}
    for a in alerts:
        sig_count[a.get("signal", "?")] = sig_count.get(a.get("signal", "?"), 0) + 1
        sev_count[a.get("severity", "low")] = sev_count.get(a.get("severity", "low"), 0) + 1
    unsupported: Dict[str, Dict[str, str]] = {}
    for dev, smp in list(s1.items()) + list((s2 or {}).items()):
        if smp.get("unsupported"):
            unsupported.setdefault(dev, {}).update(smp["unsupported"])

    summary = {
        "total": len(alerts),
        "high": sev_count["high"], "medium": sev_count["medium"], "low": sev_count["low"],
        "devices": len(devices),
        "devices_with_alerts": len([x for x, v in by_device.items() if v]),
        "two_round": two_round,
        "interval_seconds": interval_seconds,
        "interval_text": _fmt_interval(interval_seconds) if two_round else "—",
        "round1_time": (meta or {}).get("round1_time", "—"),
        "round2_time": (meta or {}).get("round2_time", "—") if two_round else "—",
        "rules_enabled": sorted(ids),
        "device_class": device_class,
        "signals": sig_count,
        "generated_at": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
        "round1_path": (meta or {}).get("round1_path", "（在线采样）"),
        "round2_path": (meta or {}).get("round2_path", "（在线采样）") if two_round else "",
    }
    summary["faults_total"] = len(faults)
    summary["faults_high"] = sum(1 for f in faults if f.get("severity") == "high")
    summary["faults_medium"] = sum(1 for f in faults if f.get("severity") == "medium")
    summary["faults_low"] = sum(1 for f in faults if f.get("severity") == "low")
    return {"alerts": alerts, "faults": faults, "by_device": by_device, "summary": summary,
            "unsupported": unsupported, "warnings": warnings,
            "samples1": s1, "samples2": s2}


def _collect_cross(cross_alerts: List[Dict[str, Any]],
                   by_device: Dict[str, List[Dict[str, Any]]]) -> List[Dict[str, Any]]:
    """把跨设备告警挂到 `（跨设备）` 分组下，同时返回以便并入总表。"""
    if cross_alerts:
        by_device.setdefault("（跨设备）", []).extend(cross_alerts)
    return list(cross_alerts)


def analyze_reports(round1_path: str,
                    round2_path: Optional[str] = None,
                    rules: Optional[Dict[str, Any]] = None,
                    enabled: Optional[Iterable[str]] = None,
                    device_class: str = "aggregation",
                    interval_seconds: Optional[float] = None,
                    allow_cross: bool = True,
                    progress: Optional[Callable[[str, int, int], None]] = None) -> Dict[str, Any]:
    """
    分析一份或两份**报告文件**（离线模式），返回告警清单与统计。

    :param round1_path: 第一期报告 CSV（巡检工具导出）。
    :param round2_path: 第二期报告 CSV；给了就是**两轮差分**模式。
    :param rules: 规则表（`ring_parsers.load_rules()` 的结果）。
    :param enabled: 启用的规则号集合；None → `default_enabled()`。
    :param device_class: 设备角色（core/aggregation/access），决定阈值档。
    :param interval_seconds: 两轮间隔（秒）；None → 优先从文件名时间戳推算。
    :param allow_cross: 是否跑跨设备关联。
    :param progress: 进度回调 `fn(阶段文字, 当前, 总数)`。
    :return: 结果 dict（alerts/summary/by_device/unsupported/warnings/samples1/samples2）。
    """
    warnings: List[str] = []

    def tick(msg: str, cur: int, total: int) -> None:
        if progress:
            try:
                progress(msg, cur, total)
            except Exception:
                pass

    tick("读取第一期报告…", 0, 1)
    # 路径打错 / 文件被挪走也要降级成 warnings（与「解析不出设备」的处理风格一致，
    # 不再把 FileNotFoundError 整个抛给调用方 —— GUI 只需展示提示，不必弹异常）
    try:
        s1 = RP.parse_report(round1_path, device_class=device_class)
    except Exception as e:
        warnings.append(f"第一期报告读取失败（{e}）：{round1_path}")
        s1 = {}
    if not s1:
        warnings.append(f"第一期报告没有解析出任何设备：{round1_path}")
    s2 = None
    two_round = bool(round2_path)
    if two_round:
        tick("读取第二期报告…", 0, 1)
        try:
            s2 = RP.parse_report(round2_path, device_class=device_class)
        except Exception as e:
            warnings.append(f"第二期报告读取失败（{e}）：{round2_path}")
            s2 = {}
        if not s2:
            warnings.append(f"第二期报告没有解析出任何设备：{round2_path}")
            two_round = False

    # 两轮间隔：差分判据的命门。优先用文件名时间戳（report_YYYYmmdd_HHMMSS.csv）。
    ts1, ts2 = _round_ts_from_name(round1_path), _round_ts_from_name(round2_path or "")
    if two_round and interval_seconds is None:
        if ts1 and ts2:
            interval_seconds = abs(ts2 - ts1)
        else:
            interval_seconds = 300.0
            warnings.append("无法从文件名推算两轮间隔，暂用 300 秒计算速率（请手工指定实际间隔）")
    meta = {"round1_path": round1_path, "round2_path": round2_path or "",
            "round1_time": _fmt_dt(ts1), "round2_time": _fmt_dt(ts2),
            "warnings": warnings}
    return analyze_samples(s1, s2 if two_round else None, rules=rules, enabled=enabled,
                           device_class=device_class, interval_seconds=interval_seconds,
                           allow_cross=allow_cross, progress=progress, meta=meta)


# ══════════════════════════════════════════════════════════════════
# 结果导出
# ══════════════════════════════════════════════════════════════════

def alerts_to_csv(result: Dict[str, Any], path: str) -> str:
    """
    把告警清单写成 CSV（UTF-8 BOM，Excel 直接双击不乱码）。

    列：`Severity,Signal,Rule,Device,Interface,Evidence,Advice`
    """
    sev_cn = SEVERITY_CN
    with open(path, "w", encoding="utf-8-sig", newline="") as f:
        w = csv.writer(f)
        w.writerow(["Severity", "Signal", "Rule", "Device", "Interface", "Evidence", "Advice"])
        for a in result["alerts"]:
            w.writerow([
                sev_cn.get(a.get("severity"), a.get("severity")),
                a.get("signal", ""), a.get("rule_id", ""), a.get("device", ""),
                a.get("interface", ""), a.get("evidence", ""), a.get("advice", ""),
            ])
    return path


def alerts_to_html(result: Dict[str, Any], path: str, tool_name: str = "环路/异常告警分析") -> str:
    """
    把结果写成单文件 HTML（配色与巡检工具一致：红=高危 / 橙=一般 / 黄=提示）。

    包含：概要卡片、按信号统计、逐条告警表（含证据与建议原样保留）、
    未支持命令清单、警告信息。**不写任何凭证**（解析层就丢弃了）。
    """
    s = result["summary"]
    sev_color = {"high": "#d32f2f", "medium": "#e65100", "low": "#f9a825"}
    # ── 故障清单（人话，放在技术明细之前；不懂网络的人看这一段就够）──
    fault_html = ""
    if RE is not None:
        try:
            fault_html = RE.faults_to_html(result.get("faults") or [])
        except Exception:
            fault_html = ""

    rows = []
    for a in result["alerts"]:
        c = sev_color.get(a.get("severity"), "#555")
        rows.append(
            "<tr>"
            f'<td style="color:{c};font-weight:600">{html.escape(SEVERITY_CN.get(a.get("severity"), ""))}</td>'
            f'<td>{html.escape(str(a.get("signal", "")))}</td>'
            f'<td>{html.escape(str(a.get("device", "")))}</td>'
            f'<td>{html.escape(str(a.get("interface", "")))}</td>'
            f'<td class="ev">{html.escape(str(a.get("evidence", "")))}</td>'
            f'<td class="ad">{html.escape(str(a.get("advice", "")))}</td>'
            "</tr>"
        )
    unsup = "".join(
        f"<li><b>{html.escape(d)}</b>：{html.escape('；'.join(v.keys()))}</li>"
        for d, v in result["unsupported"].items()
    ) or "<li>无</li>"
    warn = "".join(f"<li>{html.escape(w)}</li>" for w in result["warnings"]) or "<li>无</li>"
    sig = "".join(f"<li>{html.escape(k)}：{v} 条</li>" for k, v in sorted(
        s["signals"].items(), key=lambda kv: -kv[1])) or "<li>无</li>"

    doc = f"""<!DOCTYPE html>
<html lang="zh-CN"><head><meta charset="utf-8">
<title>{html.escape(tool_name)} {html.escape(s['generated_at'])}</title>
<style>
 body{{font-family:"Microsoft YaHei",Arial,sans-serif;margin:24px;color:#1f2937;background:#f3f5f9}}
 h1{{font-size:20px;margin:0 0 4px}} h2{{font-size:15px;margin:22px 0 8px;color:#1f4e79}}
 .cards{{display:flex;gap:12px;flex-wrap:wrap;margin:14px 0}}
 .card{{background:#fff;border:1px solid #dbe2ea;border-radius:8px;padding:10px 16px;min-width:110px}}
 .card b{{display:block;font-size:22px}} .k{{color:#5b6b7c;font-size:12px}}
 table{{border-collapse:collapse;width:100%;background:#fff;font-size:13px}}
 th{{background:#d6e4f0;text-align:left;padding:7px 9px;border:1px solid #c3d4e6}}
 td{{padding:7px 9px;border:1px solid #e2e8ef;vertical-align:top}}
 .ev{{font-family:Consolas,monospace;font-size:12px;color:#37474f;max-width:520px;word-break:break-all}}
 .ad{{color:#37474f;max-width:240px}}
 ul{{margin:4px 0 0 18px;padding:0}} li{{margin:2px 0;font-size:13px}}
</style></head><body>
<h1>{html.escape(tool_name)}</h1>
<div class="k">生成时间 {html.escape(s['generated_at'])} ｜ 模式：{'两轮差分' if s['two_round'] else '单轮快照'}
 ｜ 间隔 {html.escape(str(s['interval_text']))} ｜ 设备角色档 {html.escape(str(s['device_class']))}</div>
<div class="cards">
 <div class="card"><span class="k">设备数</span><b>{s['devices']}</b></div>
 <div class="card"><span class="k">有告警设备</span><b>{s['devices_with_alerts']}</b></div>
 <div class="card"><span class="k" style="color:#d32f2f">高危</span><b style="color:#d32f2f">{s['high']}</b></div>
 <div class="card"><span class="k" style="color:#e65100">一般</span><b style="color:#e65100">{s['medium']}</b></div>
 <div class="card"><span class="k" style="color:#f9a825">提示</span><b style="color:#f9a825">{s['low']}</b></div>
</div>
{fault_html}

<h2>告警明细（{s['total']} 条）</h2>
<table><tr><th>级别</th><th>信号</th><th>设备</th><th>接口</th><th>证据（原始）</th><th>建议动作</th></tr>
{''.join(rows) or '<tr><td colspan="6">未发现告警</td></tr>'}
</table>
<h2>按信号统计</h2><ul>{sig}</ul>
<h2>检测能力提示（设备不支持的检测项）</h2><ul>{unsup}</ul>
<h2>过程提示</h2><ul>{warn}</ul>
<div class="k" style="margin-top:18px">本报告只含设备地址与命令输出片段，不含任何登录凭证。</div>
</body></html>"""
    with open(path, "w", encoding="utf-8") as f:
        f.write(doc)
    return path


# ══════════════════════════════════════════════════════════════════
# 命令行入口（便于不打开界面时跑、也便于交付方做回归验证）
# ══════════════════════════════════════════════════════════════════

def _main(argv: Sequence[str]) -> int:
    import argparse
    ap = argparse.ArgumentParser(description="环路/异常告警分析（离线报告模式）")
    ap.add_argument("round1", help="第一期报告 CSV")
    ap.add_argument("round2", nargs="?", help="第二期报告 CSV（给了就是两轮差分）")
    ap.add_argument("--device-class", default="aggregation",
                    choices=["core", "aggregation", "access"])
    ap.add_argument("--interval", type=float, default=None, help="两轮间隔（秒）")
    ap.add_argument("--rules", default=None, help="rules.yaml 路径")
    ap.add_argument("--out", default=None, help="导出 HTML 报告路径")
    ap.add_argument("--csv", dest="out_csv", default=None, help="导出 CSV 路径")
    ap.add_argument("--all-rules", action="store_true", help="启用全部规则（含深度项）")
    args = ap.parse_args(list(argv))

    rules = RP.load_rules(args.rules)
    ids = list(available_rules()) if args.all_rules else default_enabled()
    res = analyze_reports(args.round1, args.round2, rules=rules, enabled=ids,
                          device_class=args.device_class,
                          interval_seconds=args.interval)
    s = res["summary"]
    print(f"模式: {'两轮差分' if s['two_round'] else '单轮'}   设备: {s['devices']}   "
          f"间隔: {s['interval_text']}   告警: {s['total']} "
          f"(高危 {s['high']} / 一般 {s['medium']} / 提示 {s['low']})")
    print(f"启用规则: {','.join(s['rules_enabled'])}")
    for a in res["alerts"][:40]:
        print(f"  [{a['severity']:>6}] {a['rule_id']} {a['signal']:<20} {a['device']:<16} "
              f"{a.get('interface','')[:22]:<22} {a['evidence'][:90]}")
    if len(res["alerts"]) > 40:
        print(f"  … 还有 {len(res['alerts']) - 40} 条")
    print(f"按信号: {s['signals']}")
    for w in res["warnings"]:
        print(f"  ⚠ {w}")
    if args.out:
        alerts_to_html(res, args.out)
        print(f"HTML 已导出: {args.out}")
    if args.out_csv:
        alerts_to_csv(res, args.out_csv)
        print(f"CSV 已导出: {args.out_csv}")
    return 0


if __name__ == "__main__":
    import sys
    sys.exit(_main(sys.argv[1:]))

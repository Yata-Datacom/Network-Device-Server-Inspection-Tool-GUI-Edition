#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
ring_events.py —— 故障事件层 / fault-event layer（把"多条告警"合成"一个故障"）

为什么要有这一层
----------------
判据引擎（`ring_rules.py`）输出的是**逐条技术告警**：一次真实的二层环路会让十几个端口
同时越阈，用户看到的是上百条散点告警，例如::

    10.21.11.193  XGigabitEthernet0/0/2  广播风暴 7244 pps
    10.21.11.193  XGigabitEthernet0/0/3  广播风暴 7243 pps
    ...（还有 110 条）

**懂网络的人**能看出"这是同一个环路"，但本工具要交给**不会数通的人**操作，他需要的是:

    ❗ 故障：10.21.11.193 出现二层环路（网络有一根线接成了圈）
       源头：MAC f033-e508-0567 在 GE1/0/1 与 GE1/0/2 两口上同时出现
       处理：① 拔掉 GE1/0/2 的网线，观察广播是否降下来 ② 顺着这根线找对端…

本模块负责这次"翻译"：
  1. **聚合**：按「故障类型 + 设备 + MAC」把告警归并成故障事件；
  2. **根因打分**：按证据强弱给每个故障打分（谁最可能是故障点、置信度多少）；
  3. **人话输出**：标题 / 现象 / 判断 / 处理步骤（不超过 3 步、只含"不会数通也敢做"的动作）。

对外接口
--------
* ``build_faults(alerts, samples=None) -> List[dict]`` —— 主入口
* ``faults_to_text(faults) -> str`` —— 纯文本卡片（界面 Text 控件直接贴）
* ``faults_to_html(faults) -> str`` —— HTML 片段（报告里放在告警明细之前）

数据约定
--------
告警（alert）来自 `ring_rules`，除标准字段外可能带：
``mac`` / ``vlan`` / ``ports`` / ``port_count`` / ``peer`` / ``grouped`` /
``event`` / ``matched_keyword`` / ``fault_hint``（规则类型：loop|storm|log|phy|hw|stp）。
"""

from __future__ import annotations

from collections import defaultdict
from typing import Any, Dict, Iterable, List, Optional, Sequence

# ── 故障类型 → 展示信息（标题用大白话，术语后加括号解释）────────────────
KIND_INFO: Dict[str, Dict[str, str]] = {
    "loop": {
        "title": "二层环路（网络里有一根线接成了圈）",
        "why": "接成圈之后，广播帧会在圈里不停地打转并成倍增长，导致整个网段变慢甚至瘫痪。",
        "steps": [
            "按下面列出的端口顺序，**依次拔掉一根网线**，每拔一根等 1 分钟看广播量是否降下来",
            "广播量降下来的那一根，就是环路的接入点；顺着这根线找到另一端（多半接了台小交换机/路由器）",
            "把两端设备的关系拍照回传，交给懂网络的人确认后再恢复",
        ],
    },
    "loop_cross": {
        "title": "两台设备之间形成环路",
        "why": "同一个 MAC（设备身份）同时出现在两台交换机的端口上，通常说明这两台之间被接了第二根线，形成了圈。",
        "steps": [
            "核对下面列出的 A 设备端口 与 B 设备端口 之间有几根线连着",
            "如果发现有两根及以上，**先拔掉后接的那一根**，观察广播是否下降",
            "检查这条链路上是否私接了未管理的小交换机",
        ],
    },
    "storm": {
        "title": "广播风暴（多端口同时猛发广播）",
        "why": "多个端口的广播量同时飙升到正常值的数倍，通常是环路的典型表现，少数情况是某台设备故障乱发包。",
        "steps": [
            "先看「现象」里列出的端口，按顺序逐个拔线观察广播量",
            "若拔掉某个端口后恢复正常，该端口下面的线路/设备就是问题源",
            "若全部拔完仍不降，请联系网络管理员处理上联链路",
        ],
    },
    "storm_single": {
        "title": "终端广播异常（大概率不是环路）",
        "why": "只有一个端口的广播量略超阈值，且没有 MAC 漂移、没有设备自检环路日志，多半是某个终端/摄像头在猛发广播。",
        "steps": [
            "先观察，多数会自行恢复",
            "若持续增长，把该端口下面的设备（摄像头/NVR/终端）重启一次",
            "仍不恢复再报网络管理员",
        ],
    },
    "phy": {
        "title": "线路质量差 / 接口不稳定",
        "why": "接口出现 CRC 校验错误或反复 up/down，说明网线、水晶头或光模块有问题，会造成卡顿与丢包。",
        "steps": [
            "把该端口的两端网线重新插拔一次（或换一根已知好的网线）",
            "若端口是光口，检查光模块与光纤是否插紧、有无灰尘",
            "处理后仍报错，报网络管理员更换模块/跳线",
        ],
    },
    "hw": {
        "title": "硬件告警（光衰 / 温度 / 电源）",
        "why": "设备的硬件指标超出正常范围，长期运行可能宕机。",
        "steps": [
            "记录下面列出的部件与读数，拍照",
            "检查机房/机柜温度、风扇是否正常运转",
            "联系设备维保或管理员处理（不要自行拆机）",
        ],
    },
    "stp": {
        "title": "生成树拓扑变动（网络结构在变化）",
        "why": "生成树（STP）反复重新计算拓扑，通常伴随链路抖动或环路，会导致短时断网。",
        "steps": [
            "结合本次其它故障一起看（多数由环路或链路抖动引起）",
            "确认最近有没有人改动线路/增加设备",
            "若持续反复，报网络管理员检查上联链路",
        ],
    },
    "log": {
        "title": "设备告警日志",
        "why": "设备自己的日志里出现了需要关注的告警事件。",
        "steps": [
            "先看下面列出的日志原文，判断是否与本次其它故障相关",
            "若同一事件反复出现，报网络管理员",
        ],
    },
}

# 打分权重：证据越"直接"，分越高（决定谁是故障点、置信度多少）
SCORE = {
    "D13": 35,   # 同设备同 MAC 多端口 → 该设备就是故障点
    "D9": 30,    # 跨设备同 MAC → 两台之间成环
    "D1": 15,    # MAC 漂移
    "D7_LOOP": 30,   # 设备自检到环路（MFLP / loop detect）
    "D7": 8,     # 一般日志命中
    "D4_GROUP": 15,  # 多端口同速率
    "D4": 5,     # 单端口高广播
    "D5": 10, "D6": 10, "D10": 10, "D11": 10, "D12": 10,
    "D2": 6, "D3": 6, "D8": 8,
}
LOOP_LOG_HINT = ("mflp", "loop", "flapping", "mac_move", "mac/move")


def _f(v, default=0.0):
    """安全转 float / safe float cast."""
    try:
        return float(v)
    except (TypeError, ValueError):
        return default


def _kind_of(a: Dict[str, Any]) -> str:
    """从告警推出故障类型（优先用规则给的 fault_hint）。"""
    k = (a.get("fault_hint") or "").strip()
    if k:
        return k
    rid = str(a.get("rule_id") or "")
    return {"D1": "loop", "D9": "loop", "D13": "loop", "D4": "storm",
            "D5": "phy", "D6": "phy", "D7": "log", "D2": "stp", "D3": "stp", "D8": "stp",
            "D10": "hw", "D11": "hw", "D12": "hw"}.get(rid, "log")


def _is_loop_log(a: Dict[str, Any]) -> bool:
    """这条日志告警是不是"环路自检"类（MFLP / loop detect / MAC 漂移）。"""
    blob = " ".join(str(a.get(k) or "") for k in ("signal", "event", "matched_keyword", "evidence")).lower()
    return any(h in blob for h in LOOP_LOG_HINT)


def _alert_score(a: Dict[str, Any]) -> int:
    rid = str(a.get("rule_id") or "")
    if rid == "D7":
        return SCORE["D7_LOOP"] if _is_loop_log(a) else SCORE["D7"]
    if rid == "D4":
        return SCORE["D4_GROUP"] if a.get("grouped") else SCORE["D4"]
    return SCORE.get(rid, 5)


def _sev_value(a: Dict[str, Any]) -> int:
    return {"high": 3, "medium": 2, "low": 1}.get(str(a.get("severity") or "low"), 1)


def _uniq(seq: Iterable[Any]) -> List[Any]:
    out: List[Any] = []
    for x in seq:
        if x not in (None, "", []) and x not in out:
            out.append(x)
    return out


def build_faults(alerts: Sequence[Dict[str, Any]],
                 samples: Optional[Dict[str, Any]] = None) -> List[Dict[str, Any]]:
    """
    把逐条告警聚合成**故障事件** / merge raw alerts into incidents.

    聚合规则（按优先级）：
      1. `loop` 类且同一设备 → 一个故障；`D9`（跨设备）单独成一个"设备之间成环"故障；
      2. 同一设备若已有 `loop` 故障，则把它的 `storm` 告警与"环路类日志"**并入**该故障
         （风暴是环路的症状，不是独立问题）；
      3. 其余按「类型 + 设备」归组（硬件/线路/生成树/普通日志）；
      4. `storm` 只有单端口命中时归为 `storm_single`（终端异常，**不升级**为环路）。

    :return: 故障列表，按 严重度 → 分数 排序。每个故障含
             `kind/title/severity/confidence/score/device/devices/macs/vlans/ports/
              counts/summary/symptoms/cause/steps/alerts`。
    """
    alerts = [a for a in (alerts or []) if isinstance(a, dict)]
    if not alerts:
        return []

    buckets: Dict[Any, List[Dict[str, Any]]] = defaultdict(list)
    for a in alerts:
        kind = _kind_of(a)
        dev = str(a.get("device") or "?")
        if kind == "loop" and dev in ("多设备", "（跨设备）", "cross"):
            key = ("loop_cross", str(a.get("mac") or "?"))
        elif kind == "storm":
            # 强风暴（≥3 口同速率，或速率远超阈值）才算"故障"；其余归入"轻微"合并项
            strong = bool(a.get("grouped")) and (
                int(a.get("port_count") or len(a.get("ports") or [])) >= 3
                or _f(a.get("delta")) >= _f(a.get("threshold")) * 5)
            key = ("storm", dev) if (strong and a.get("grouped")) else ("mild", "多处")
        else:
            key = (kind, dev)
        buckets[key].append(a)

    # 归并：某设备有 loop 时，吸收它的 storm / 环路日志
    dev_has_loop = {k[1] for k in buckets if k[0] == "loop"}
    merged: Dict[Any, List[Dict[str, Any]]] = {}
    for key, items in buckets.items():
        kind, dev = key
        if kind in ("storm", "log", "stp") and dev in dev_has_loop:
            target = ("loop", dev)
            merged.setdefault(target, []).extend(items)
        else:
            merged.setdefault(key, []).extend(items)

    faults: List[Dict[str, Any]] = []
    for (kind, dev), items in merged.items():
        score = min(100, sum(_alert_score(a) for a in items))
        # 严重度由**证据分数**决定（避免"轻微双口广播"被当成严重环路吓人）
        sev = "high" if score >= 55 else ("medium" if score >= 25 else "low")
        if kind in ("mild", "storm_single"):
            sev, score = "low", min(score, 20)
        conf = "high" if score >= 55 else ("medium" if score >= 25 else "low")
        counts: Dict[str, int] = defaultdict(int)
        for a in items:
            counts[str(a.get("rule_id") or "?")] += 1
        macs = _uniq([a.get("mac") for a in items])
        vlans = _uniq([a.get("vlan") for a in items])
        ports = _uniq([p for a in items for p in (a.get("ports") or ([a.get("interface")] if a.get("interface") else []))])
        devices = _uniq([a.get("device") for a in items])
        if kind in ("mild", "storm_single"):
            devs = _uniq([a.get("device") for a in items])
            info = dict(KIND_INFO["storm_single"])
            items_txt = "、".join(f"{a.get('device')}:{a.get('interface')}" for a in items[:8])
            extra_mild = [f"共 {len(items)} 处轻微超标（多为终端/摄像头发广播，非环路）：{items_txt}"
                          + ("…" if len(items) > 8 else "")]
            kind = "mild"
        else:
            extra_mild = []
        info = info if kind == "mild" else KIND_INFO.get(kind, KIND_INFO["log"])

        # ── 人话措辞 ──
        pps = None
        for a in items:
            if a.get("rule_id") in ("D4",) and isinstance(a.get("delta"), (int, float)):
                pps = max(pps or 0, float(a["delta"]))
        if kind in ("loop", "storm", "loop_cross"):
            port_txt = "、".join(ports[:8]) + ("…" if len(ports) > 8 else "")
            symptoms = [f"涉及端口 {len(ports)} 个：{port_txt}"] if ports else []
            if pps:
                symptoms.append(f"广播量最高约 {pps:.0f} pps（正常应低于 1000，属于异常飙升）")
            if macs:
                symptoms.append("源头 MAC（设备的网卡身份）：" + "、".join(str(m) for m in macs[:3]))
            if vlans:
                symptoms.append("涉及 VLAN（网段）：" + "、".join(str(v) for v in vlans[:4]))
            cause = ("同一个 MAC 同时出现在这些端口上 → 这些端口之间被线路环接了。"
                     if any(a.get("rule_id") in ("D13", "D9") for a in items)
                     else "多个端口的广播量同时飙升，符合环路环流的特征。")
            if any(a.get("rule_id") == "D7" and _is_loop_log(a) for a in items):
                cause += "（设备自己的日志里也报告了环路事件）"
        else:
            symptoms = [str(a.get("evidence") or "")[:160] for a in items[:3]]
            cause = info["why"]

        steps = list(info["steps"])
        if ports and kind in ("loop", "storm", "loop_cross"):
            first = ports[0]
            second = ports[1] if len(ports) > 1 else ports[0]
            steps[0] = f"先拔掉 **{second}** 的网线，等 1 分钟看广播量有没有降下来"
            if len(ports) > 2:
                steps.insert(1, f"若没降，继续依次拔 {'、'.join(ports[2:6])}，每次拔一根、等 1 分钟")

        if extra_mild:
            symptoms = extra_mild + symptoms
            devices = ["多处（轻微）"]
            dev = "多处（轻微）"
        faults.append({
            "kind": kind,
            "title": info["title"],
            "severity": sev,
            "confidence": conf,
            "score": score,
            "device": dev,
            "devices": devices,
            "macs": macs,
            "vlans": vlans,
            "ports": ports,
            "counts": dict(counts),
            "summary": f"{dev} 上出现「{info['title']}」",
            "symptoms": symptoms,
            "cause": cause,
            "why": info["why"],
            "steps": steps,
            "alerts": items,
        })

    rank = {"high": 0, "medium": 1, "low": 2}
    faults.sort(key=lambda f: (rank.get(f["severity"], 9), -f["score"], str(f["device"])))
    for i, f in enumerate(faults, 1):
        f["id"] = f"F{i}"
        f["first"] = (i == 1 and f["severity"] == "high")
    return faults


# ── 输出渲染 ─────────────────────────────────────────────────────────

_SEV_CN = {"high": "严重", "medium": "一般", "low": "提示"}
_SEV_ICON = {"high": "❗", "medium": "⚠️", "low": "ℹ️"}


def fault_to_text(f: Dict[str, Any], index: Optional[int] = None) -> str:
    """把一个故障渲染成纯文本卡片（给 tkinter Text / 控制台用）。"""
    idx = f" {index}" if index else ""
    head = f"{_SEV_ICON.get(f['severity'], '·')} 故障{idx}｜{f['title']}"
    if f.get("first"):
        head += "   ← 先处理这个"
    lines = [head, "─" * 62,
             f"故障设备：{f['device']}      置信度：{'高' if f['confidence'] == 'high' else ('中' if f['confidence'] == 'medium' else '低')}",
             f"涉及告警：{len(f['alerts'])} 条（" + "、".join(f"{k}×{v}" for k, v in sorted(f["counts"].items())) + "）"]
    if f.get("symptoms"):
        lines.append("")
        lines.append("【现象】")
        lines += [f"  · {s}" for s in f["symptoms"]]
    lines.append("")
    lines.append("【判断】")
    lines.append(f"  {f['cause']}")
    lines.append("")
    lines.append("【怎么处理】")
    lines += [f"  {s}" for s in f["steps"]]
    return "\n".join(lines)


def faults_to_text(faults: Sequence[Dict[str, Any]], header: str = "") -> str:
    """把故障列表渲染成完整的纯文本（界面默认视图用）。"""
    if not faults:
        return (header + "\n" if header else "") + "✅ 未发现故障级问题。"
    out = [header] if header else []
    out.append(f"❗ 共发现 {len(faults)} 个故障"
               f"（严重 {sum(1 for f in faults if f['severity'] == 'high')} / "
               f"一般 {sum(1 for f in faults if f['severity'] == 'medium')} / "
               f"提示 {sum(1 for f in faults if f['severity'] == 'low')}）")
    out.append("=" * 62)
    for i, f in enumerate(faults, 1):
        out.append(fault_to_text(f, i))
        out.append("")
    out.append("说明：术语解释 —— MAC＝设备的网卡身份（相当于网线的身份证）；"
               "端口＝设备上插网线的口；VLAN＝网段。")
    return "\n".join(out)


def faults_to_html(faults: Sequence[Dict[str, Any]]) -> str:
    """把故障列表渲染成 HTML 片段（放在告警明细表之前）。"""
    if not faults:
        return '<p style="color:#2e7d32;font-weight:600">✅ 未发现故障级问题。</p>'
    color = {"high": "#d32f2f", "medium": "#e65100", "low": "#f9a825"}
    bg = {"high": "#ffebee", "medium": "#fff3e0", "low": "#fffde7"}
    parts = [f'<h2>🚨 故障清单（{len(faults)} 个）</h2>',
             '<p class="k">按"先处理哪个"排序；点开每条故障可见原始告警证据。</p>']
    for i, f in enumerate(faults, 1):
        c = color.get(f["severity"], "#555")
        parts.append(
            f'<div style="border:1px solid {c};border-left:6px solid {c};background:{bg.get(f["severity"], "#fff")};'
            f'border-radius:8px;padding:10px 14px;margin:10px 0">'
            f'<div style="font-size:15px;font-weight:700;color:{c}">'
            f'{_SEV_ICON.get(f["severity"], "")} 故障 {i}｜{f["title"]}'
            f'{"　← 先处理这个" if f.get("first") else ""}</div>'
            f'<div style="margin:6px 0 2px"><b>故障设备：</b>{f["device"]}　'
            f'<span class="k">置信度：{f["confidence"]}｜证据 {len(f["alerts"])} 条</span></div>')
        if f.get("symptoms"):
            parts.append("<div><b>现象：</b><ul style='margin:4px 0 4px 18px'>"
                         + "".join(f"<li>{s}</li>" for s in f["symptoms"]) + "</ul></div>")
        parts.append(f'<div><b>判断：</b>{f["cause"]}</div>')
        parts.append("<div><b>怎么处理：</b><ol style='margin:4px 0 4px 18px'>"
                     + "".join(f"<li>{s}</li>" for s in f["steps"]) + "</ol></div>")
        ev = "<br>".join(
            f'<span class="ev">[{a.get("rule_id")}] {a.get("signal")}｜'
            f'{str(a.get("evidence") or "")[:200]}</span>' for a in f["alerts"][:12])
        more = f'<div class="k">…还有 {len(f["alerts"]) - 12} 条</div>' if len(f["alerts"]) > 12 else ""
        parts.append(f'<details><summary class="k">原始告警证据（{len(f["alerts"])} 条）</summary>{ev}{more}</details>')
        parts.append("</div>")
    return "\n".join(parts)


if __name__ == "__main__":     # 自检
    demo = [
        {"rule_id": "D4", "signal": "BROADCAST_STORM", "severity": "high", "device": "10.21.11.193",
         "interface": "XGE0/0/2", "evidence": "8 个端口同速率", "grouped": True, "ports":
         ["XGE0/0/2", "XGE0/0/3", "XGE0/0/4"], "delta": 7244, "fault_hint": "storm"},
        {"rule_id": "D13", "signal": "MAC_MULTI_PORT", "severity": "high", "device": "10.21.11.193",
         "interface": "GE1/0/1", "evidence": "MAC x 同时在两端口", "mac": "f033-e508-0567", "vlan": 1000,
         "ports": ["GE1/0/1", "GE1/0/2"], "fault_hint": "loop"},
        {"rule_id": "D7", "signal": "MAC_FLAPPING", "severity": "high", "device": "10.21.11.193",
         "interface": "", "evidence": "命中 MFLPVLAN", "matched_keyword": "MFLPVLAN", "fault_hint": "log"},
        {"rule_id": "D4", "signal": "BROADCAST_STORM", "severity": "medium", "device": "172.18.2.148",
         "interface": "GE0/0/5", "evidence": "单口 1200 pps", "grouped": False, "fault_hint": "storm"},
    ]
    fs = build_faults(demo)
    print(faults_to_text(fs))
    print(f"\n（HTML 片段 {len(faults_to_html(fs))} 字节）")

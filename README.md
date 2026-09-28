<div align="center">

<img src="app_icon.ico" width="96" alt="Network Inspection Tool" />

# Network Inspection Tool

**SSH-based automated inspection tool for network devices and servers** — multi-vendor inspection, anomaly flagging, config backup, traffic test, security audit, active probes, and **ring/health alerting** (loop detection, optical/temperature/power).<br/>
<sub>[**English**](README.md) · [**简体中文**](README.zh-CN.md)</sub>

<a href="https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/actions/workflows/ci.yml"><img src="https://img.shields.io/github/actions/workflow/status/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/ci?style=for-the-badge&label=CI&color=5E81AC&logo=githubactions&logoColor=white" alt="CI" /></a>
<a href="https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/actions/workflows/build.yml"><img src="https://img.shields.io/github/actions/workflow/status/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/build?style=for-the-badge&label=Build%20EXE&color=5E81AC&logo=githubactions&logoColor=white" alt="Build EXE" /></a>
<a href="https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/releases"><img src="https://img.shields.io/github/v/release/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition?style=for-the-badge&color=5E81AC&label=Download" alt="Download" /></a>
<a href="pyproject.toml"><img src="https://img.shields.io/badge/python-3.10%2B-5E81AC?style=for-the-badge&logo=python&logoColor=white" alt="Python 3.10+" /></a>
<img src="https://img.shields.io/badge/platform-Windows-81A1C1?style=for-the-badge&logo=windows11&logoColor=white" alt="Platform: Windows" />
<a href="LICENSE"><img src="https://img.shields.io/badge/License-MIT-8FBCBB?style=for-the-badge" alt="License: MIT" /></a>

</div>

> An SSH inspection tool for network operations and on-site engineers: one Windows PC and one device list are enough to run multi-vendor inspection, config backup, traffic tests and ring alerting in one pass.

---

## ⬇️ Download

**⬇️ Download:** [Releases](https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/releases) — single-file Windows exe, no install needed, no Python required.

**v5.1.2** · [CHANGELOG](CHANGELOG.md) · [Development & Tests](#开发与测试--development--tests)

---

## 🧭 Version lines

| Version | Role | Features |
|---|---|---|
| **V5** `net_inspect_gui_v5.py` | Personal, full-featured | Inspection + config backup + traffic test + security audit + active probes + **ring alert (12 checks, incl. cross-device correlation)** |
| **V3** `net_inspect_gui.py` | Personal, basic | Same as V5 but 10 ring checks (no BPDU self-loop / cross-device correlation) ※ trunk source, actively evolving |
| **V2** | Colleague build | Inspection + config backup (no heavy features such as traffic test); **source not in this repository** (internal delivery V4 = V2 + ring alert) |

> V4 (colleague build + ring alert, trimmed) is an internal delivery and is not published in this repository.

---

## 🚨 Fault view (new in v5.2.0, for people who don't do networking)

Ring Alert results **show the "fault view" by default**: no longer hundreds of scattered alerts, but **a few faults**,
each one answering the four things an operator cares about most:

```
❗ Fault 1 | Layer-2 loop (somewhere a cable was patched into a ring)   ← handle this one first
──────────────────────────────────────────────
Faulty device: 10.21.11.193      Confidence: high
Alerts involved: 4 (D13×1, D4×1, D7×2)

[What is seen]
  · 10 ports involved: XGE0/0/2, XGE0/0/3 …
  · Peak broadcast ≈ 7244 pps (normally it should stay below 1000)
  · Source MAC: f033-e508-0567   VLAN: 1000
[Diagnosis]
  The same MAC shows up on all these ports → these ports are looped together by the cabling.
[What to do]
  Unplug the cable on **XGE0/0/3** first, wait 1 minute and see whether the broadcast rate drops
  If it does not, keep unplugging XGE0/0/4, 0/0/5 … in turn
  The one that drops the rate is the access point of the loop; follow it to the other end (most likely an unmanaged switch someone patched in privately)
```

- **Aggregation**: "multi-port equal-rate broadcast + loop log + same MAC on several ports" on one device → merged into **one** fault
- **Root-cause scoring**: same device, same MAC on several ports (★★★) · cross-device same MAC (★★★) · device self-check loop log (★★★) ·
  several ports at equal rate (★★) · MAC flapping (★) → ranks the "most likely fault point" and marks the first one "handle this one first"
- **A single port with light broadcast** never escalates into a fault; it is folded into one "terminal broadcast anomaly (most likely not a loop)"
- Need technical detail? Switch to "**Alert details**" in the top right for the per-item evidence (the original table view is unchanged)
- An exported HTML report likewise puts the **fault list on top and the details below**

**New check D13 | same-device MAC multi-port conflict**: the same MAC (same VLAN) appearing on ≥2 non-aggregated ports of one device
→ a single round is enough to decide it, and it names directly "which two ports are looped together" (D4 also changed from "report each port" to "loop-group aggregation").

**Sampling health check**: every sampling round records each command's bytes/lines/whether it errored, to tell
"the command got no data (device unsupported / large table truncated)" apart from "data came back but no loop was found"; the tab offers a **large-table mode** (bigger quiet window and timeout).

---

## 🚀 Quick Start

| Way | How to do it |
|------|------|
| Standalone exe (recommended) | Download from [Releases](https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/releases), double-click, no Python install |
| Run from source | `pip install paramiko openpyxl pyyaml` → `python net_inspect_gui_v5.py` |
| Launcher script | Double-click `启动巡检工具.bat` (runs from source) |

Put the device list next to the program — `devices.xlsx` (recommended, five columns) or `devices.txt` — and start.

## ✨ Features

| | Feature |
| :-- | :-- |
| 🔎 | **Multi-vendor inspection** — Huawei / H3C / Cisco / Ruijie / Linux in one pass |
| 🔴 | **Anomaly flagging** — CPU / memory / disk / interface over threshold highlighted |
| 💾 | **Config backup** — batch backup of `running-config` / `current-configuration` |
| 🚦 | **Traffic test** *(V5)* — UDP / ICMP / TCP / TCP-SYN generators + built-in TCP receiver |
| 🛡️ | **Security audit** *(V5)* — read-only DHCP snooping / DAI / DNS / port isolation / port security checks |
| 📡 | **Active probes** *(V5)* — ICMP / DNS / DHCP / ARP / VLAN probes for on-site fault location |
| 🔁 | **Ring alert** *(V5)* — two-round sampling diff, raw evidence line, confidence and suggested action |
| 🚨 | **Fault view** *(v5.2.0)* — collapses scattered alerts into a few faults, each with clear actions |
| 📄 | **Report export** — HTML / CSV, fault list on top and details below |

## 📋 Feature list

| # | Feature | Description |
|---|---------|-------------|
| 1 | Single Host | Inspect one device with editable command set |
| 2 | Batch Inspection | Parallel multi-device inspection + anomaly detection + HTML/CSV export |
| 3 | Config Backup | Backup `running-config` / `current-configuration` |
| 4 | Profiles | Manage saved connections via `profiles.json` |
| 5 | Anomaly Detection | Flag CPU / memory / disk exceeding thresholds |
| 6 | Compact Output | Only show key metrics (CPU%, mem%, …) |
| 7 | Quick Inspection | Core commands only (cpu/mem/alarm/device/stack) |
| 8 | Status Column | Live Running/OK/FAILED status in batch mode |
| 9 | Ping Pre-check | Ping before SSH, skip unreachable devices |
| 10 | Output Search | Keyword highlight + ↑/↓ navigation + match count |
| 11 | Anomaly Jump | Jump to next **/ previous** flagged line |
| 12 | Presets | Save/load custom command sets |
| 13 | Traffic Test (V5) | UDP / ICMP / TCP / TCP-SYN generators + built-in TCP receiver |
| 14 | Security Audit (V5) | DHCP snooping / DAI / DNS / port isolation / port security checks |
| 15 | Active Test (V5) | ICMP / DNS / DHCP / ARP / VLAN probes for on-site fault location |
| 16 | **Ring Alert (V5)** | **Loop & hardware-health alerting — see below** |

## 🔁 Ring alert tab (V5)

Loop and hardware-health alerting is a tab inside the inspection tool: every alert carries the **raw evidence line**,
a confidence level and a suggested action — the tool would rather report "suspicious" for a human to judge than
jump to a conclusion.

**Two ways to use it**

| Mode | What it does |
|------|------|
| **A. Online two-round sampling** (primary) | The tool logs in twice itself (interval configurable, default 30 min) and **diffs the two samples** — this is the only way to see *what is changing* |
| **B. Offline report analysis** | Analyse 1~2 exported inspection reports (CSV); good for after-the-fact review, or when you have no access to the devices |

**Why two rounds are mandatory**: counters such as CRC are **cumulative historical values** (possibly left over from
years ago), so a single snapshot cannot tell whether it "is still getting worse". Diff-based checks (MAC flapping,
CRC growth, broadcast rate, link flapping, TC delta) **require two rounds**. A single round can only produce
keyword-based results (log events) and absolute-value results (optical power out of range, temperature, component state).

**Checks**

| ID | Check | Basis | Source |
|---|---|---|---|
| D1 | MAC flapping | Same MAC+VLAN moved port between rounds | `display mac-address` |
| D2 | STP topology change | Topology-change delta per minute over threshold (access 5 / aggregation 15 / core 30) | `display stp` |
| D3 | Root bridge change | Root bridge ID / root port changed | `display stp` |
| D4 | Broadcast/multicast storm | Broadcast+multicast packet rate over threshold | `display interface` |
| D5 | Interface errors growing | CRC / input-error delta per minute over threshold | `display interface [brief]` |
| D6 | Link flapping | up/down count per hour over threshold | `display interface` |
| D7 | Vendor log keywords | Log event-name mapping | `display logbuffer` / `display alarm active` |
| D10 | Optical degradation | Rx power too low / dropping more than 3 dB between rounds / module self-reported alarm | `display interface` (Rx/Tx Power lines) |
| D11 | Temperature | Over threshold or rising fast | `display temperature` |
| D12 | Power / component | Any component not `Normal`; healthy count dropping (redundancy lost) | `display device` |
| D8 * | BPDU anomaly | Abnormal BPDU rate; receiving a BPDU carrying this device's own Bridge ID = **self-loop signature** | `display stp interface` |
| D9 * | Cross-device correlation | **The same MAC on two devices at once**; TC jumping on several devices in the same window | multi-device comparison |

\* deep checks, off by default.

**Changing the rules touches one file**: `rules.yaml` next to the program (auto-created on first run) — thresholds + log keywords.
Edit it and click **Reload rules** in the tab for it to take effect immediately, **no repackaging needed**.

> ⚠️ Keywords are **regex** (case-insensitive). **Do not use bare words**: `Alarm` matches
> `alarmID=0x…` in the logs of healthy devices (256 false hits measured). Write the **full event name**, e.g.
> `MSTP/4/PORT_STATE_DISCARDING`, `MAC/4/MAC_MOVE`.
>
> How to find event names: capture a chunk of logs and count with the regex `%%\d+([A-Za-z0-9_]+)/(\d)/([A-Za-z0-9_()\-]+)`.
> High-volume events that every healthy device has (such as user-side link up/down) are noise — do not collect them.

**Result area**: alert table red = high risk / orange = medium / yellow = info; double-click for the full evidence + suggested action;
"⚠ Previous anomaly / Next anomaly" jumps straight there; severity filter + keyword search; export HTML/CSV to a path of your choice.

**Known limitations**
1. A single round cannot show "currently growing"; deciding whether it is worsening requires two rounds.
2. A device may not support some commands (for example `display transceiver` / `display temperature`
   return `Unrecognized command` on some BRAS) → the tool records it as a "capability note" and **does not raise a false alert**.
3. Log keywords will also hit routine events (link up/down and so on), so always judge from the evidence line — do not look at the red dot alone.
4. Optical power prefers the alarm threshold reported by the device itself; when the module model is unknown only the trend is trusted.
5. The parsers are currently **fully implemented for Huawei**; other vendors' commands run, but are recorded as "capability notes" and can be extended once real output is available.

## ⌨️ Keyboard shortcuts

| Shortcut | Action |
|----------|--------|
| **Enter** | Press inside the Single Host input → start the single-host inspection |
| **Ctrl+Enter** | Start the operation for the current tab |
| **Esc** | Stop all running tasks |

## 🔍 Output search

Type a keyword into the search bar above the output area: every match is highlighted **yellow**; **Enter** / **↓** for the next one,
**↑** for the previous one; the current match is **orange**; the match count (e.g. `15 match(es)`) is shown on the right.

## 📏 Anomaly detection rules

| Device type | Metric | Threshold | Source |
|----------|---------|------|------|
| Linux | CPU Load (5min) | > 4.0 | `uptime` |
| Linux | Disk usage | > 80% | `df -h` |
| Cisco | CPU 5sec Utilization | > 80% | `show processes cpu sorted` |
| Huawei | CPU Usage | > 80% | `display cpu-usage` |
| Huawei | Memory Usage | > 80% | `display memory-usage` |

## 📑 Device list format

**`devices.txt`** (backwards compatible)
```
# Format: IP:user:password:[type]:"command1,command2,..."
# type is optional (linux/cisco/huawei/h3c/ruijie), default cisco; # comment lines are supported
192.0.2.1:admin:yourpass:cisco:"show version,show ip int brief"
192.0.2.2:root:yourpass:linux:"hostnamectl --static,uname -r"
192.0.2.3:admin:yourpass:huawei:"display version,display ip int brief"
```

**`devices.xlsx`** (recommended, easy copy-paste) — five columns, row 1 is the header:

| A | B | C | D | E |
|---|---|---|---|---|
| IP | Username | Password | Type | Commands (comma or newline separated) |

> When both files exist in the same directory, **xlsx is read first**. The batch tab has a "→ Excel" button
> that converts an existing txt into a styled xlsx in one click.

## 🗂️ Tabs

| Tab | What it does |
|---|---|
| **Single Host** | Single-host inspection: anomaly detection / compact output / quick inspection / ping pre-check are all optional |
| **Batch Inspection** | Parallel inspection: concurrency 1~10 (default 3); Status column `---` → `Running...` → `OK` / `UNREACHABLE` / `FAILED` / `WARNING`; anomaly statistics grouped per device |
| **Config Backup** | Backs up configurations to `backups/<类型>/<IP>/<IP>_<时间>.cfg`; Linux devices are excluded |
| **Profiles** | Saved connection management; after Save the single-host dropdown is populated |
| **Traffic Test** *(V5)* | UDP / ICMP / TCP / TCP-SYN generators + built-in receiver. ⚠ `rate=0` sends at full unthrottled speed (about 97k packets/s single-threaded) — **never use 0 on localhost/loopback** |
| **Security Test** *(V5)* | Read-only checks: DHCP snooping / DAI / DNS / port isolation / port security, with fix suggestions, pushing no configuration at all |
| **Active Test** *(V5)* | ICMP / DNS / DHCP / ARP / VLAN active probes for locating intermittent faults on site |
| **Ring Alert** *(V5)* | Loop / health alerting (see the section above) |

## ❓ FAQ

**Q: Huawei devices report "SSH session not active"?**
Fixed — Cisco/Huawei use an interactive `invoke_shell()` channel.

**Q: Network device output is truncated / paged?**
The tool automatically sends the paging-off command: Cisco/Ruijie `terminal length 0`, Huawei/H3C `screen-length 0 temporary`.

**Q: Old devices will not connect (`no acceptable host key` / algorithm mismatch)?**
Old models only offer the `ssh-rsa` host key and sha1 kex. The tool already puts these algorithms back into the preference list at startup;
**package/run with paramiko 3.5.x** (paramiko 4/5 removed the `ssh-rsa` implementation entirely, so putting it back into the preferences has no effect either).

**Q: Batch inspection is slow?**
Raise the concurrency to 5~10 (batch tab).

**Q: Where did the reports / configurations go?**
The program writes `profiles.json` / `presets.json` / `backups/` / `reports/` **next to the program (exe)** —
when frozen into a single-file exe, `__file__` points at a temporary unpack directory, and early versions therefore wrote into `%TEMP%\_MEIxxxx` (lost on restart). Fixed.

**Q: After running "A. Online two-round sampling" with no alerts, how do I tell "really no problem" from "never connected"?**
Look at the **status bar** of the result page: it says "data: round 1 x/y devices with data; round 2 x/y devices with data" —
if both rounds ran and both have data, the sampling itself was fine (no alerts = nothing changed between the two rounds, which is good).
If one round shows `0 台有数据`, a popup lists the failure reasons directly (connection timeout / authentication failure / command not supported on that platform).
The wording for a single-round snapshot and for the two-round diff is **separate**, so it can no longer mislead you by saying "single round" when you actually ran two.

> Fix record (2026-09-17): early versions called the inspection tool's SSH helper **without the `client` argument**
> (treating `_ssh_connect`, which connects in place and returns None, as if it returned a connection object), so **every device
> failed to connect**, both rounds came back empty, and no matter how many rounds were run it said "a single round cannot show…". It now does:
> `_create_ssh_client()` → `_ssh_connect(client, host, 22, user, pwd, timeout=…)` →
> `_run_commands_via_shell(client, devtype, {标题: 命令})` (paging-off and legacy-algorithm fallback are both handled inside the latter).

**Q: How do I change the anomaly thresholds?**
Edit `ANOMALY_RULES` in `net_inspect_gui.py`; the ring alert thresholds live in `rules.yaml` (no repackaging needed).

**Q: How do I rebuild the exe?**
```bash
# V5 (personal build)
../.venv-build/Scripts/python -m PyInstaller --clean --noconfirm NetworkInspectionV5.spec
# legacy (V3)
pyinstaller --noconfirm NetworkInspectionV3.spec
```
Close the running exe first — a locked file makes packaging fail.

## 📁 Project layout

```
network_A/
├── net_inspect_gui.py          # V3 main program (trunk source)
├── ring_panel.py               # ring alert tab (UI + online two-round sampling + offline analysis)
├── ring_analyze.py             # orchestration layer: parse → run checks → aggregate/export
├── ring_rules.py               # check engine (12 rules, pure functions, vendor-agnostic)
├── ring_parsers.py             # parser layer: each vendor's command output → structured data
├── rules.yaml                  # thresholds + log keywords (extend as you like)
├── test_ring_rules.py          # regression tests for the check engine
├── v5/                         # V5 personal build (self-contained: main program + the modules above + README)
├── 启动巡检工具.bat             # source launcher script
├── NetworkInspectionV3.spec    # packaging spec
└── 环路检测-规则清单.md          # check specification (commands / thresholds / false-positive scenarios)
```

---

## 📄 License & Disclaimer

Personal/educational tool. Use it only on devices you are authorized to access —
all inspection commands are read-only queries, but **do confirm authorization before running**.
The licence is **MIT** (see [LICENSE](LICENSE)).

**Third-party:** the runtime depends on `paramiko` / `openpyxl` / `PyYAML` (see `pyproject.toml`);
their copyright and licences belong to their respective authors. Every command sent to a device is a read-only query — the tool pushes no configuration.

---

<a id="开发与测试--development--tests"></a>

## 🛠️ Development & Tests

```bash
# install (with dev dependencies: pytest / ruff / openpyxl / PyYAML)
python -m pip install -e ".[dev]"

# run the tests (12 check-engine rules, parser layer, two-round diff in the orchestration layer, v5 mirror consistency)
python -m pytest -q

# static checks
ruff check .

# build the exe (Windows; for V5 run it inside the v5/ directory)
python -m PyInstaller --clean --noconfirm NetworkInspectionV3.spec
cd v5 && python -m PyInstaller --clean --noconfirm NetworkInspectionV5.spec
```

- Once installed you can also start it via the console entry point: `net-inspect`
- ⚠️ **The dependency must be pinned to `paramiko>=3.5,<4`**: old devices only support `ssh-rsa`, and paramiko 4/5 removed that implementation
- Ring alert thresholds/keywords live in `rules.yaml` (no repackaging needed); the detection logic is in `ring_rules.py`
- CI: `.github/workflows/ci.yml` (pytest on Windows, ruff on Linux);
  `.github/workflows/build.yml` (push a tag or run it manually → V3/V5 exe artifacts)
- The version number lives in **two places**, `pyproject.toml` and `net_inspect_gui.__version__`, and the two must stay in sync

---

<div align="center">
<sub>MIT License · © 2026 Yata-Datacom · Network Inspection Tool</sub>
</div>

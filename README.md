# Network Inspection Tool / 网络设备巡检工具

[![CI](https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/actions/workflows/ci.yml/badge.svg)](https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/actions/workflows/ci.yml)
[![Build EXE](https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/actions/workflows/build.yml/badge.svg)](https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/actions/workflows/build.yml)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](LICENSE)
[![Python 3.10+](https://img.shields.io/badge/python-3.10%2B-blue.svg)](pyproject.toml)
[![Platform: Windows](https://img.shields.io/badge/platform-Windows-lightgrey.svg)](#)

**v5.1.2** · [CHANGELOG](CHANGELOG.md) · [开发与测试](#开发与测试--development--tests)

SSH-based automated inspection tool for network devices and servers — multi-vendor
inspection, anomaly flagging, config backup, traffic test, security audit, active probes,
and **ring/health alerting (loop detection, optical/temperature/power)**.

> 基于 SSH 的自动化网络设备 / 服务器巡检工具：多厂商巡检、异常标红、配置备份、
> 流量测试、安全核查、主动探测，以及**环路 / 健康告警**（环路特征、光衰、温度、电源）。

**⬇️ 下载 / Downloads:** [Releases](https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/releases)
（Windows 单文件 exe，免安装、无需 Python）

---

## 版本线 / Version lines

| 版本 | 定位 | 功能 |
|---|---|---|
| **V5** `net_inspect_gui_v5.py` | 个人版（全功能） | 巡检 + 配置备份 + 流量测试 + 安全核查 + 主动探测 + **环路告警（12 条判据，含跨设备关联）** |
| **V3** `net_inspect_gui.py` | 个人版（基础） | 同 V5 但环路判据为 10 条（无 BPDU 自环 / 跨设备关联）※ 主干源码，持续演进 |
| **V2** | 同事版 | 巡检 + 配置备份（无流量测试等重功能）；**源码不在本仓库**（另有内部交付版本 V4 = V2 + 环路告警）|

> V4（同事版 + 环路告警的裁剪版）为内部交付版本，不在本仓库公开。

---

## English

### Quick Start

1. Download the exe from [Releases](https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/releases) and run it (no install needed), **or**
2. Run from source: `pip install paramiko openpyxl pyyaml` then `python net_inspect_gui_v5.py`
3. Put a device list next to the program (`devices.xlsx` or `devices.txt`) and start.

### Features

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

### Ring Alert tab (V5)

Detects loop symptoms and hardware degradation. Every alert carries the **raw evidence line**,
a confidence level, and a suggested action — human decides, the tool never guesses silently.

**Two ways to use it**

| Mode | What it does |
|---|---|
| **A. Online two-round sampling** | The tool logs in twice (interval configurable, default 30 min) and **diffs the two samples** — this is the only way to see *what is changing* |
| **B. Offline report analysis** | Analyse 1–2 exported inspection reports (CSV); good for after-the-fact review |

**Checks**

| ID | Check | Basis |
|---|---|---|
| D1 | MAC flapping | Same MAC+VLAN moved port between rounds |
| D2 | STP topology change | Topology-change delta per minute over threshold |
| D3 | Root bridge change | Root ID / root port changed |
| D4 | Broadcast storm | Broadcast+multicast packet rate over threshold |
| D5 | Interface errors growing | CRC / input-error delta per minute |
| D6 | Link flapping | up/down count per hour |
| D7 | Vendor log keywords | Event-name mapping (full event names, not bare words) |
| D10 | Optical degradation | Rx power low / dropping > 3 dB / module self-reported alarm |
| D11 | Temperature | Over threshold or fast rise |
| D12 | Power / component | Any component not `Normal`; redundancy lost |
| D8 * | BPDU anomaly | BPDU rate; receiving own Bridge ID on a port = self-loop |
| D9 * | Cross-device | Same MAC on two devices; simultaneous TC burst |

\* deep checks, off by default.

**Thresholds & keywords** live in `rules.yaml` (auto-created next to the program on first run).
Edit it and click **Reload rules** — no rebuild needed.

> ⚠️ Keyword patterns are **regex, case-insensitive**. Never use bare words: `Alarm` matches
> `alarmID=0x…` on healthy devices (256 false hits measured). Use full event names, e.g.
> `MSTP/4/PORT_STATE_DISCARDING`, `MAC/4/MAC_MOVE`.

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| **Enter** | Start inspection when focused in Single Host input |
| **Ctrl+Enter** | Start operation based on current tab |
| **Esc** | Stop all running tasks |

---

## 中文说明

### 快速开始

| 方式 | 做法 |
|------|------|
| 独立 exe（推荐） | 到 [Releases](https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/releases) 下载，双击即用，无需装 Python |
| 源码运行 | `pip install paramiko openpyxl pyyaml` → `python net_inspect_gui_v5.py` |
| 启动脚本 | 双击 `启动巡检工具.bat`（走源码） |

设备清单放在程序同目录：`devices.xlsx`（推荐，五列）或 `devices.txt`。

### 功能列表

| # | 功能 | 说明 |
|---|------|------|
| 1 | 单机巡检 | 连接单台设备，命令集可编辑 |
| 2 | 批量巡检 | 并行多设备 + 异常检测 + HTML/CSV 报告导出 |
| 3 | 配置备份 | 备份 `running-config` / `current-configuration` |
| 4 | 连接信息 | `profiles.json` 管理常用连接 |
| 5 | 异常检测 | CPU / 内存 / 磁盘超阈值自动标红 |
| 6 | 紧凑输出 | 仅保留关键指标行 |
| 7 | 快速巡检 | 仅核心命令（cpu/mem/alarm/device/stack） |
| 8 | 状态列 | 批量巡检实时 Running / OK / FAILED |
| 9 | Ping 预检 | SSH 前预检，不可达直接跳过 |
| 10 | 输出搜索 | 关键词高亮 + ↑↓ 跳转 + 匹配计数 |
| 11 | 异常跳转 | 「⚠ 上一异常 / 下一异常」直接跳，不用从头翻 |
| 12 | 预设方案 | 保存/加载自定义命令集 |
| 13 | 流量测试 *(V5)* | UDP / ICMP / TCP / TCP-SYN 压测 + 内置 TCP 接收端 |
| 14 | 安全核查 *(V5)* | DHCP snooping / DAI / DNS / 端口隔离 / 端口安全 只读核查 |
| 15 | 主动探测 *(V5)* | ICMP / DNS / DHCP / ARP / VLAN 探测，用于现场故障定位 |
| 16 | **环路告警** *(V5)* | **环路特征 + 硬件健康告警，见下节** |

### 🔁 环路告警页签（V5 新增）

把「环路 / 异常告警」做成巡检工具的一个页签：每条告警都带**原始证据行** + 置信度 +
建议动作 —— 宁可报“可疑”让人工判断，也不武断下结论。

**两种用法**

| 模式 | 说明 |
|------|------|
| **A. 在线两轮采样**（主力） | 工具自己连设备跑两遍（间隔可设，默认 30 分钟），**对两轮结果做差分**：只有这样才能看出“正在变化” |
| **B. 离线分析报告** | 选 1~2 份巡检导出的报告 CSV 分析；适合事后复盘、或没有设备访问权限时 |

**为什么必须两轮**：CRC 等计数器是**历史累计值**（可能是几年前留下的），单看一次快照
无法判断“是否还在恶化”。差分类判据（MAC 漂移、CRC 增长、广播速率、链路震荡、TC 增量）
**必须两轮**。单轮只能出关键字类（日志事件）和绝对值类（光功率越界、温度、组件状态）。

**检测项**

| 编号 | 名称 | 判据要点 | 数据来源 |
|---|---|---|---|
| D1 | MAC 漂移 | 同一 MAC+VLAN 两轮间换了端口 | `display mac-address` |
| D2 | STP 拓扑变化 | 每分钟 TC 增量超阈值（接入 5 / 汇聚 15 / 核心 30） | `display stp` |
| D3 | 根桥变更 | 根桥 ID / 根端口变化 | `display stp` |
| D4 | 广播/组播风暴 | 广播+组播包速率超阈值 | `display interface` |
| D5 | 接口误码增长 | CRC / 输入错误每分钟增量超阈值 | `display interface [brief]` |
| D6 | 链路震荡 | 每小时 up/down 次数超阈值 | `display interface` |
| D7 | 厂家日志关键字 | 日志事件名映射 | `display logbuffer` / `display alarm active` |
| D10 | 光衰 | 收光功率过低 / 两轮下降 > 3 dB / 模块自报越界 | `display interface`（Rx/Tx Power 行） |
| D11 | 温度 | 超阈值或快速升温 | `display temperature` |
| D12 | 电源 / 组件 | 任一组件状态非 `Normal`；正常数减少（冗余丢失） | `display device` |
| D8 * | BPDU 异常 | BPDU 速率异常；收到本机 Bridge ID 的 BPDU = **自环特征** | `display stp interface` |
| D9 * | 跨设备关联 | **同一 MAC 同时出现在两台设备**；多台设备同一窗口 TC 同时跳增 | 多设备比对 |

\* 深度检测项，默认不勾选。

**改规则只改一个文件**：程序同目录的 `rules.yaml`（首次运行自动生成）——阈值 + 日志关键字。
改完点页签里的「重新加载规则」即时生效，**不用重新打包**。

> ⚠️ 关键字是**正则**（大小写不敏感）。**不要用裸词**：`Alarm` 会命中健康设备日志里的
> `alarmID=0x…`（实测误报 256 次）。要写**完整事件名**，如 `MSTP/4/PORT_STATE_DISCARDING`、
> `MAC/4/MAC_MOVE`。
>
> 找事件名的方法：抓一段日志，用正则 `%%\d+([A-Za-z0-9_]+)/(\d)/([A-Za-z0-9_()\-]+)` 统计。
> 量大但每个健康设备都有的（如用户侧上下线）属噪声，不要收。

**结果区**：告警表红=高危 / 橙=一般 / 黄=提示；双击看完整证据 + 建议；
「⚠ 上一异常 / 下一异常」快速跳转；支持级别筛选 + 关键字搜索；导出 HTML/CSV 可自选路径。

**已知限制**
1. 单轮看不出“正在增长”，要判断是否恶化必须两轮。
2. 设备可能不支持某些命令（例如某些 BRAS 上 `display transceiver` / `display temperature`
   会报 `Unrecognized command`）→ 程序记入「检测能力提示」，**不会误报告警**。
3. 日志关键字会命中例行事件（链路 up/down 等），所以必须看证据行判断，别只看红点。
4. 光功率优先采用设备自报的告警门限；模块型号未知时只信趋势。
5. 解析器目前**完整实现华为**；其他厂商命令能跑但会记入「检测能力提示」，拿到真实输出后可扩展。

### 快捷键

| 快捷键 | 作用 |
|--------|------|
| **Enter** | Single Host 输入框内按 → 启动单机巡检 |
| **Ctrl+Enter** | 根据当前标签页启动对应操作 |
| **Esc** | 停止所有正在执行的任务 |

### 输出区搜索

在输出区上方搜索栏输入关键词：所有匹配**黄色**高亮；**Enter** / **↓** 下一个，
**↑** 上一个；当前项**橙色**；右侧显示匹配数量（如 `15 match(es)`）。

### 异常检测规则

| 设备类型 | 检测指标 | 阈值 | 来源 |
|----------|---------|------|------|
| Linux | CPU Load (5min) | > 4.0 | `uptime` |
| Linux | 磁盘使用率 | > 80% | `df -h` |
| Cisco | CPU 5sec Utilization | > 80% | `show processes cpu sorted` |
| Huawei | CPU Usage | > 80% | `display cpu-usage` |
| Huawei | Memory Usage | > 80% | `display memory-usage` |

### 设备列表格式

**`devices.txt`**（向后兼容）
```
# 格式: IP:用户名:密码:[类型]:"命令1,命令2,..."
# 类型可选 (linux/cisco/huawei/h3c/ruijie)，默认 cisco；支持 # 注释行
192.0.2.1:admin:yourpass:cisco:"show version,show ip int brief"
192.0.2.2:root:yourpass:linux:"hostnamectl --static,uname -r"
192.0.2.3:admin:yourpass:huawei:"display version,display ip int brief"
```

**`devices.xlsx`**（推荐，方便复制粘贴）——五列，第 1 行表头：

| A | B | C | D | E |
|---|---|---|---|---|
| IP | 用户名 | 密码 | 类型 | 命令（逗号或换行分隔）|

> 同目录同时存在两种文件时，**优先读 xlsx**。批量页有「→ Excel」按钮可把
> 现有 txt 一键转成带样式的 xlsx。

### 标签页说明

| 页签 | 说明 |
|---|---|
| **Single Host** | 单机巡检：异常检测 / 紧凑输出 / 快速巡检 / Ping 预检 均可勾选 |
| **Batch Inspection** | 批量巡检：并发 1~10（默认 3）；Status 列 `---` → `Running...` → `OK` / `UNREACHABLE` / `FAILED` / `WARNING`；异常统计按设备分组显示 |
| **Config Backup** | 备份配置到 `backups/<类型>/<IP>/<IP>_<时间>.cfg`；Linux 设备不参与 |
| **Profiles** | 连接信息管理，Save 后单机页下拉框可用 |
| **Traffic Test** *(V5)* | UDP / ICMP / TCP / TCP-SYN 压测 + 内置接收端。⚠ `rate=0` 为不限速全速发（实测单线程约 9.7 万包/秒），**别在本机/环回开 0** |
| **Security Test** *(V5)* | 只读核查：DHCP snooping / DAI / DNS / 端口隔离 / 端口安全，给修复建议，不下发任何配置 |
| **Active Test** *(V5)* | ICMP / DNS / DHCP / ARP / VLAN 主动探测，用于现场定位间歇性故障 |
| **Ring Alert** *(V5)* | 环路 / 健康告警（见上节） |

### 常见问题

**Q: 华为设备报 "SSH session not active"？**
已修复，Cisco/Huawei 使用 `invoke_shell()` 交互式通道。

**Q: 网络设备输出被截断/分页？**
自动发送禁用分页命令：Cisco/Ruijie `terminal length 0`，Huawei/H3C `screen-length 0 temporary`。

**Q: 老设备连不上（`no acceptable host key` / 算法不匹配）？**
老型号只提供 `ssh-rsa` host key 与 sha1 kex。本工具已在启动时把这些算法加回偏好列表；
**打包/运行请用 paramiko 3.5.x**（paramiko 4/5 已彻底移除 `ssh-rsa` 实现，加回偏好也无效）。

**Q: 批量巡检速度慢？**
把并发数调到 5~10（批量页）。

**Q: 报告/配置怎么找不到了？**
程序把 `profiles.json` / `presets.json` / `backups/` / `reports/` 写在**程序（exe）同目录**——
打包成单文件 exe 时，`__file__` 指向临时解包目录，早期版本曾因此落在 `%TEMP%\_MEIxxxx`（重启即丢），已修复。

**Q: 环路告警「A. 在线两轮采样」跑完没告警，怎么区分"真没问题"和"根本没连上"？**
看结果页的**状态栏**，它会写「数据：第1轮 x/y 台有数据；第2轮 x/y 台有数据」——
两轮都跑到了、且都有数据，说明采样本身正常（没告警 = 两轮之间没有变化，是好事）。
若某一轮是 `0 台有数据`，弹窗会直接列出失败原因（连接超时 / 认证失败 / 命令不被该平台支持）。
单轮快照与两轮差分的提示文案是**分开**的，不会再出现"明明跑了两轮却说单轮"的误导。

> 修复记录（2026-09-17）：早期版本调用巡检工具的 SSH 帮助函数时**漏传 `client` 参数**
> （把"就地连接、返回 None"的 `_ssh_connect` 当成返回连接对象用），导致**每台设备都连接
> 失败**、两轮均为空数据，并且无论几轮都提示"单轮时看不出…"。现改为：
> `_create_ssh_client()` → `_ssh_connect(client, host, 22, user, pwd, timeout=…)` →
> `_run_commands_via_shell(client, devtype, {标题: 命令})`（关分页与老设备算法降级由后者内部处理）。

**Q: 如何修改异常阈值？**
改 `net_inspect_gui.py` 里的 `ANOMALY_RULES`；环路告警的阈值改 `rules.yaml`（不用重打包）。

**Q: 如何重新打包 exe？**
```bash
# V5（个人版）
../.venv-build/Scripts/python -m PyInstaller --clean --noconfirm NetworkInspectionV5.spec
# 旧版（V3）
pyinstaller --noconfirm NetworkInspectionV3.spec
```
打包前先关掉正在运行的 exe（文件被占用会失败）。

### 项目结构

```
network_A/
├── net_inspect_gui.py          # V3 主程序（主干源码）
├── ring_panel.py               # 环路告警页签（界面 + 在线两轮采样 + 离线分析）
├── ring_analyze.py             # 编排层：解析 → 跑判据 → 汇总/导出
├── ring_rules.py               # 判据引擎（12 条规则，纯函数，厂商无关）
├── ring_parsers.py             # 解析层：各厂商命令输出 → 结构化数据
├── rules.yaml                  # 阈值 + 日志关键字（可自行扩展）
├── test_ring_rules.py          # 判据引擎回归测试
├── v5/                         # V5 个人版（自包含：主程序 + 上述模块 + README）
├── 启动巡检工具.bat             # 源码启动脚本
├── NetworkInspectionV3.spec    # 打包配置
└── 环路检测-规则清单.md          # 判据规格书（命令 / 阈值 / 误报场景）
```

---

## License

Personal/educational tool. Use only on devices you are authorized to access —
all inspection commands are read-only queries, but **do confirm authorization before running**.

---

## 开发与测试 / Development & Tests

```bash
# 安装（含开发依赖：pytest / ruff / openpyxl / PyYAML）
python -m pip install -e ".[dev]"

# 跑测试（判据引擎 12 条规则、解析层、编排层两轮差分、v5 镜像一致性）
python -m pytest -q

# 静态检查
ruff check .

# 打包 exe（Windows；V5 需要在 v5/ 目录里执行）
python -m PyInstaller --clean --noconfirm NetworkInspectionV3.spec
cd v5 && python -m PyInstaller --clean --noconfirm NetworkInspectionV5.spec
```

- 装好后也可用命令入口启动：`net-inspect`
- ⚠️ **依赖必须锁 `paramiko>=3.5,<4`**：老设备只支持 `ssh-rsa`，paramiko 4/5 已移除该实现
- 环路告警的阈值/关键字改 `rules.yaml`（不用重打包）；检测逻辑在 `ring_rules.py`
- CI：`.github/workflows/ci.yml`（Windows 跑 pytest、Linux 跑 ruff）；
  `.github/workflows/build.yml`（打 tag 或手动触发 → V3/V5 两个 exe artifact）
- 版本号在 `pyproject.toml` 与 `net_inspect_gui.__version__` **两处**，必须保持一致

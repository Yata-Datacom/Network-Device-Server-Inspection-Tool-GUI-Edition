# Network Inspection Tool / 网络设备巡检工具

Automated SSH-based inspection tool for Linux servers, Cisco, and Huawei network devices. Supports anomaly detection, config backup, report export, and connection profile management.

> 基于 SSH 的自动化网络设备/服务器巡检工具，支持 Linux 服务器、思科 (Cisco) 和华为 (Huawei) 设备。具备异常检测、配置备份、报告导出和连接信息管理功能。

---

## English

### Quick Start

| Method | Command |
|--------|---------|
| Executable (recommended) | Double-click `dist/Network巡检工具.exe` |
| Launch script | Double-click `启动巡检工具.bat` |
| Command line | `python net_inspect_gui.py` |

### Dependencies

```bash
pip install paramiko          # Required
pip install openpyxl          # Optional (Excel export)
```

### Features

| # | Feature | Description |
|---|---------|-------------|
| 1 | Single Host | Inspect one device with editable command set |
| 2 | Batch Inspection | Parallel multi-device inspection + anomaly detection + report export |
| 3 | Config Backup | Backup running-config / current-configuration |
| 4 | Profiles | Manage saved connections via profiles.json |
| 5 | Anomaly Detection | Red flag CPU/memory/disk exceeding thresholds |
| 6 | Compact Output | Only show key metrics (CPU%, mem%, etc.) |
| 7 | Quick Inspection | Core commands only (cpu/mem/alarm/device/stack) |
| 8 | Status Column | Live Running/OK/FAILED status in batch mode |
| 9 | Ping Pre-check | Ping before SSH, skip unreachable devices |
| 10 | Keyboard Shortcuts | Enter to start / Esc to stop / Ctrl+Enter |
| 11 | Output Search | Keyword highlight + arrow key navigation + match count |
| 12 | Presets | Save/load custom command sets, one-click switch |

### Keyboard Shortcuts

| Shortcut | Action |
|----------|--------|
| **Enter** | Start inspection when focused in Single Host input |
| **Ctrl+Enter** | Start operation based on current tab |
| **Esc** | Stop all running tasks |

### Output Search

Type in the search bar above output area:
- All matches highlighted in **yellow**
- **Enter** / **↓** to jump to next match
- **↑** to jump to previous match
- Current match highlighted in **orange**
- Match count shown on the right (e.g. `15 match(es)`)

### File Structure

```
network_A/
├── net_inspect_gui.py          # Main program
├── dist/
│   └── Network巡检工具.exe      # Standalone exe
├── 启动巡检工具.bat              # Launch script
├── devices.txt                 # Device list
├── profiles.json               # Connection profiles (auto-generated)
├── backups/                    # Config backups
├── reports/                    # HTML/CSV reports
├── README.txt                  # Documentation
└── README.md                   # Markdown documentation
```

### Device List Format (devices.txt)

```
# Format: IP:username:password:[type]:"cmd1,cmd2,..."
# Type optional (linux/cisco/huawei), default cisco
# Lines starting with # are comments

192.168.1.1:admin:mypwd:cisco:"show version,show ip int brief"
10.0.0.1:root:pass123:linux:"hostnamectl --static,uname -r"
192.168.1.3:admin:pass123:huawei:"display version,display ip int brief"
```

### Tabs

**1. Single Host** - Connect to one device with editable commands.
- `Anomaly Detection` — detect anomalies (default on)
- `Compact Output` — compact mode, key metrics only (default on)
- `Quick Inspection` — core commands only (default off, locks editing)
- `Pre-check (ping)` — ping before SSH (default on)

**2. Batch Inspection** - Parallel multi-device check with anomaly detection + HTML/CSV export.
- Concurrency: 1~10 (default 3)
- Status column: `---` → `Running...` → `OK` / `UNREACHABLE` / `FAILED` / `WARNING`

**3. Config Backup** - Backup `running-config` / `current-configuration`.
- Path: `backups/<type>/<IP>/<IP>_<datetime>.cfg`
- Linux devices excluded from backup

**4. Profiles** - Manage saved device connection info (IP/port/user/pwd/type).

### Anomaly Detection Rules

| Device | Metric | Threshold | Source |
|--------|--------|-----------|--------|
| Linux | CPU Load (5min) | > 4.0 | uptime |
| Linux | Disk Usage | > 80% | df -h |
| Cisco | CPU 5sec Utilization | > 80% | show processes cpu sorted |
| Huawei | CPU Usage | > 80% | display cpu-usage |
| Huawei | Memory Usage | > 80% | display memory-usage |

### Default Commands

**Linux Server:** Hostname, OS Release, Kernel, Uptime, CPU Info, CPU Cores, CPU Load, Memory, Swap, Disk Usage, Top 10 CPU, Top 10 Memory

**Cisco Device:** Show Version, Running Config, IP Interface Brief, Interfaces Status, VLAN Brief, MAC Address Table, CPU Usage, Memory, Logging, Environment

**Huawei Device:** Display Version, Current Config, IP Interface Brief, Interface Brief, VLAN, MAC Address, CPU Usage, Memory, Logbuffer, Environment

### Quick Inspection Commands

| Type | Commands |
|------|----------|
| Linux | CPU Load, CPU Cores, Memory, Disk Usage, Top 5 CPU |
| Cisco | CPU, Memory, Alarm, Device (inventory), Stack |
| Huawei | CPU, Memory, Alarm Active, Device, CSS Status, Stack |

### FAQ

**Q: Huawei device shows "SSH session not active"?**  
A: Fixed. Cisco/Huawei use `invoke_shell()` interactive channel.

**Q: Device output truncated/paginated?**  
A: Auto-sends pagination disable: Cisco `terminal length 0`, Huawei `screen-length 0 temporary`.

**Q: Batch inspection too slow?**  
A: Increase concurrency to 5~10.

**Q: How to disable ping pre-check?**  
A: Uncheck "Pre-check (ping)" checkbox.

**Q: How to repackage exe?**
```bash
pip install pyinstaller
pyinstaller --noconfirm Network巡检工具.spec
```

**Q: Custom anomaly thresholds?**  
A: Edit `ANOMALY_RULES` dict in `net_inspect_gui.py`.

---

## 中文说明

### 快速开始

| 方式 | 命令 |
|------|------|
| 独立 exe（推荐） | 双击 `dist/Network巡检工具.exe` |
| 启动脚本 | 双击 `启动巡检工具.bat` |
| 命令行 | `python net_inspect_gui.py` |

### 依赖

```bash
pip install paramiko          # 必需
pip install openpyxl          # 可选（Excel 导出）
```

### 功能列表

| # | 功能 | 说明 |
|---|------|------|
| 1 | 单机巡检 | 连接单台设备，可编辑命令集 |
| 2 | 批量巡检 | 并行多设备巡检 + 异常检测 + 报告导出 |
| 3 | 配置备份 | 备份 running-config / current-configuration |
| 4 | 连接信息 | profiles.json 管理常用连接 |
| 5 | 异常检测 | CPU/内存/磁盘超阈值标红告警 |
| 6 | 紧凑模式 | 仅保留关键指标行（CPU%、内存% 等） |
| 7 | 快速巡检 | 仅核心命令（cpu/mem/alarm/device/stack） |
| 8 | 状态列 | 批量巡检实时显示 Running/OK/FAILED |
| 9 | Ping 预检 | SSH 前 ping 预检，不可达直接跳过 |
| 10 | 快捷键 | Enter 启动 / Esc 停止 / Ctrl+Enter |
| 11 | 输出搜索 | 关键词高亮 + ↑↓ 跳转 + 匹配计数 |
| 12 | 预设方案 | 保存/加载自定义命令集，一键切换 |

### 快捷键

| 快捷键 | 作用 |
|--------|------|
| **Enter** | Single Host 输入框内按 → 启动单机巡检 |
| **Ctrl+Enter** | 根据当前标签页启动对应操作 |
| **Esc** | 停止所有正在执行的任务 |

### 输出区搜索

在输出区上方搜索栏输入关键词：
- 自动高亮所有匹配（**黄色**背景）
- **Enter** 或 **↓** 跳转到下一个匹配
- **↑** 跳转到上一个匹配
- 当前匹配项 **橙色** 高亮
- 右侧实时显示匹配数量（如 `15 match(es)`）

### 文件结构

```
network_A/
├── net_inspect_gui.py          # 主程序
├── dist/
│   └── Network巡检工具.exe      # 独立 exe，无需 Python
├── 启动巡检工具.bat              # 启动脚本
├── devices.txt                 # 设备列表
├── profiles.json               # 连接信息（自动生成）
├── backups/                    # 配置备份
├── reports/                    # HTML/CSV 报告
├── README.txt                  # 说明文档
└── README.md                   # Markdown 文档
```

### 设备列表格式 (devices.txt)

```
# 格式: IP:用户名:密码:[类型]:"命令1,命令2,..."
# 类型可选 (linux/cisco/huawei)，默认 cisco
# 支持 # 开头的注释行

192.168.1.1:admin:mypwd:cisco:"show version,show ip int brief"
10.0.0.1:root:pass123:linux:"hostnamectl --static,uname -r"
192.168.1.3:admin:pass123:huawei:"display version,display ip int brief"
```

### 四个标签页

**1. Single Host（单机巡检）** — 连接单台设备，执行可编辑命令集。
- `Anomaly Detection` — 异常检测（默认开）
- `Compact Output` — 紧凑模式（默认开）
- `Quick Inspection` — 快速巡检（默认关，开启后锁定编辑）
- `Pre-check (ping)` — SSH 前 ping 预检（默认开）

**2. Batch Inspection（批量巡检）** — 并行检查多台设备，支持异常检测 + HTML/CSV 导出。
- 并发数 1~10（默认 3）
- Status 列实时更新：`---` → `Running...` → `OK` / `UNREACHABLE` / `FAILED` / `WARNING`

**3. Config Backup（配置备份）** — 备份网络设备配置。
- 存储路径：`backups/<类型>/<IP>/<IP>_<日期时间>.cfg`
- Linux 设备不参与备份

**4. Profiles（连接信息管理）** — 保存常用设备连接信息，Save 后在 Single Host 页下拉框可用。

### 异常检测规则

| 设备类型 | 检测指标 | 阈值 | 来源 |
|----------|---------|------|------|
| Linux | CPU Load (5min) | > 4.0 | uptime |
| Linux | 磁盘使用率 | > 80% | df -h |
| Cisco | CPU 5sec Utilization | > 80% | show processes cpu sorted |
| Huawei | CPU Usage | > 80% | display cpu-usage |
| Huawei | Memory Usage | > 80% | display memory-usage |

### 默认命令集

**Linux Server:** Hostname, OS Release, Kernel, Uptime, CPU Info, CPU Cores, CPU Load, Memory, Swap, Disk Usage, Top 10 CPU, Top 10 Memory

**Cisco Device:** Show Version, Running Config, IP Interface Brief, Interfaces Status, VLAN Brief, MAC Address Table, CPU Usage, Memory, Logging, Environment

**Huawei Device:** Display Version, Current Config, IP Interface Brief, Interface Brief, VLAN, MAC Address, CPU Usage, Memory, Logbuffer, Environment

### 常见问题

**Q: 华为设备报 "SSH session not active" 错误？**  
已修复，Cisco/Huawei 使用 `invoke_shell()` 交互式通道。

**Q: 网络设备输出被截断/分页？**  
自动发送禁用分页命令：Cisco `terminal length 0`，Huawei `screen-length 0 temporary`。

**Q: 批量巡检速度慢？**  
增加并发数，建议 5~10。

**Q: 如何禁用 Ping 预检？**  
取消勾选 "Pre-check (ping)" 复选框。

**Q: 如何重新打包 exe？**
```bash
pip install pyinstaller
pyinstaller --noconfirm Network巡检工具.spec
```

**Q: 如何自定义异常检测阈值？**  
修改 `net_inspect_gui.py` 中 `ANOMALY_RULES` 字典的 `threshold` 值。

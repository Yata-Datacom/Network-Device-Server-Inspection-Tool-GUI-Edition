================================================================================
  Network Inspection Tool — 网络设备/服务器巡检工具
================================================================================

【概述 / Overview】
  本工具通过 SSH 连接 Linux 服务器、思科(Cisco)设备、华为(Huawei)设备，
  自动执行巡检命令，支持异常检测、配置备份、报告导出和连接信息管理。

  运行方式 / Run:
    方法1: 双击 dist/巡检Network Inspection System V2 - For GCC.exe       (独立exe，无需Python环境)
    方法2: 双击 启动巡检工具.bat               (自动装依赖+启动)
    方法3: python net_inspect_gui.py          (命令行直接运行)

  依赖: pip install paramiko
  可选: pip install openpyxl  (Excel 报告导出)

================================================================================
【文件说明 / Files】
================================================================================

  文件                      说明
  ────────────────────────  ──────────────────────────────────────────────
  net_inspect_gui.py        主程序（图形界面），中英双语注释
  dist/巡检Network Inspection System V2 - For GCC.exe  独立可执行文件，双击即用，无需 Python
  启动巡检工具.bat           启动脚本（自动安装 paramiko，不弹黑窗）
  devices.txt               设备列表文件（批量巡检/备份时读取）
  profiles.json             保存的常用连接信息（通过 Profiles 页管理）
  backups/                  配置备份存放目录（自动创建）
  reports/                  HTML/CSV 报告存放目录（自动创建）

  以下为早期命令行版本，GUI 版不依赖它们：
  import paramiko.py        单机 Linux 巡检（命令行版）
  net_inspect.py            批量设备巡检（命令行版）

================================================================================
【功能列表 / Features】
================================================================================

  1. 单机巡检       Single Host      — SSH 连接单台设备，可编辑命令集
  2. 批量巡检       Batch Inspect    — 并行多线程 + 异常检测 + 报告导出
  3. 配置备份       Config Backup    — 备份 running-config / current-config
  4. 连接信息管理   Profiles         — profiles.json 保存常用连接
  5. 异常检测       Anomaly Detect   — CPU/内存/磁盘超阈值标红告警
  6. 紧凑输出       Compact Output   — 仅保留关键指标行（CPU%、内存% 等）
  7. 简短巡检       Quick Inspect    — 仅 cpu/mem/alarm/device/stack
  8. 运行状态栏     Status Column    — 批量巡检实时显示 Running/OK/FAILED
  9. Ping 预检      Pre-check        — SSH 前先 ping，不可达直接跳过
 10. 键盘快捷键     Shortcuts        — Enter 启动 / Esc 停止 / Ctrl+Enter
 11. 输出区搜索     Output Search    — 关键词高亮，↑↓ 跳转匹配项
 12. 巡检预设方案   Presets          — 保存/加载自定义命令集，一键切换

================================================================================
【键盘快捷键 / Keyboard Shortcuts】
================================================================================

  快捷键             作用
  ────────────────   ──────────────────────────────────────────
  Enter              在 Single Host 输入框中按 → 启动单机巡检
  Ctrl+Enter         全局 → 根据当前标签页启动对应操作
                      单机页→巡检 / 批量页→巡检 / 备份页→备份
     Esc                全局 → 停止所有正在执行的任务

  输出区搜索:
    在输出区上方搜索栏输入关键词 → 自动高亮所有匹配（黄色）
    Enter → 下一个 / ↑↓ 按钮 → 上下跳转（当前匹配橙色）
    右侧实时显示匹配数量

  巡检预设方案:
    在命令编辑区上方 Presets 栏:
      Save — 弹出对话框，输入名称保存当前命令集
      Load — 从下拉框选择预设，自动加载命令并切换设备类型
      Del  — 删除选中的预设（确认后删除）
    数据文件: presets.json

================================================================================
【功能标签页说明】
================================================================================

一、Single Host (单机巡检)
  ────────────────────────
  用途：连接单台设备，执行自定义命令集，输出巡检结果。

  复选框:
    Anomaly Detection  — 异常检测开关（默认开启）
    Compact Output     — 紧凑模式，只显示关键指标（默认开启）
    Quick Inspection   — 简短巡检，仅核心命令（默认关闭，开启后锁定编辑）
    Pre-check (ping)   — SSH 前 ping 预检，不可达跳过（默认开启，禁 ping 的设备可关闭）

  操作步骤：
    1. 顶部 "Load Profile" 下拉框选择已保存的连接信息（可选）
    2. 选择设备类型 (Linux Server / Cisco Device / Huawei Device)
    3. 输入 IP 地址、端口、用户名、密码（任一输入框按 Enter 直接启动）
    4. 命令编辑区可增删改命令，格式: 标题::命令
    5. 点击 "Start Inspection" 或按 Enter，随时点击 "Stop" 或按 Esc 中断

  输出区颜色:
    红色 = 严重告警 (critical)，如 CPU/磁盘使用率 > 80%
    橙色 = 警告 (warning)

二、Batch Inspection (批量巡检)
  ─────────────────────────────
  用途：批量检查多台设备，支持并行执行、异常检测、报告导出。

  设备文件格式 (devices.txt):
    IP:用户名:密码:[linux|cisco|huawei]:"命令1,命令2,..."
    type 字段可选，不写默认 cisco。支持 # 注释行和空行。

  示例:
    192.168.1.1:admin:mypwd:cisco:"show version,show ip int brief"
    10.0.0.1:root:mypwd:linux:"hostnamectl --static,uname -r"
    192.168.1.3:admin:pass123:huawei:"display version,display ip int brief"

  操作步骤：
    1. 选择设备文件 → Load（或 Browse... 选择其他）
    2. 勾选要巡检的设备（不选则默认全部）
    3. 设置并发数 Parallel (1~10)，建议 3~5
    4. 复选框: Anomaly Detection / Compact Output / Quick Inspection / Pre-check
    5. 点击 "Inspect Selected"，Status 列实时显示运行状态
       (--- → Running... → OK / UNREACHABLE / FAILED / WARNING)
    6. 巡检完成后点击 "Export HTML" 或 "Export CSV" 导出报告
    7. 随时可点击 "Stop" 或按 Esc 中断

三、Config Backup (配置备份)
  ──────────────────────────
  用途：备份网络设备的 running-config / current-configuration。
  注意：Linux 设备不参与备份。

  操作步骤：
    1. 选择设备文件 → Load
    2. 选择备份目录（默认 backups/）
    3. 选中设备 → "Backup Selected"
    4. 按路径存储: backups/<类型>/<IP>/<IP>_<日期时间>.cfg

四、Profiles (连接信息管理)
  ─────────────────────────
  用途：保存常用设备的连接信息，在 Single Host 页快速加载。

  操作步骤：
    1. 填写 Name / Host / Port / Type / User / Password
    2. 点击 Save 保存
    3. 选中列表中的 profile 可编辑/删除
    4. 保存后在 Single Host 页的 "Load Profile" 下拉框中可用

  数据文件: profiles.json（明文存储密码，请注意安全）

================================================================================
【异常检测规则 / Anomaly Rules】
================================================================================

  设备类型    检测指标                阈值      来源
  ────────    ───────────────        ────      ────────────
  Linux       CPU Load (5min)        > 4.0     uptime
  Linux       Disk Usage             > 80%     df -h
  Cisco       CPU 5sec Utilization   > 80%     show processes cpu sorted
  Huawei      CPU Usage              > 80%     display cpu-usage
  Huawei      Memory Usage           > 80%     display memory-usage

  异常信息在输出区颜色高亮，并计入 HTML/CSV 报告。

================================================================================
【默认命令集 / Default Commands】
================================================================================

  Linux Server:
    Hostname, OS Release, Kernel, Uptime, CPU Info, CPU Cores, CPU Load,
    Memory, Swap, Disk Usage, Top 10 CPU, Top 10 Memory

  Cisco Device:
    Show Version, Running Config, IP Interface Brief, Interfaces Status,
    VLAN Brief, MAC Address Table, CPU Usage, Memory, Logging, Environment

  Huawei Device:
    Display Version, Current Config, IP Interface Brief, Interface Brief,
    VLAN, MAC Address, CPU Usage, Memory, Logbuffer, Environment

================================================================================
【简短巡检命令 / Quick Inspection Commands】
================================================================================

  Linux:   CPU Load, CPU Cores, Memory, Disk Usage, Top 5 CPU
  Cisco:   CPU, Memory, Alarm, Device (inventory), Stack
  Huawei:  CPU, Memory, Alarm Active, Device, CSS Status, Stack

================================================================================
【常见问题 / FAQ】
================================================================================

  Q: 连接失败？
  A: 检查 IP/端口/用户名/密码；确认目标设备 SSH 服务开启、防火墙放行。

  Q: 华为设备报 "SSH session not active" 错误？
  A: 已修复。对 Cisco/Huawei 使用 invoke_shell() 交互式通道。

  Q: 网络设备输出被截断/分页卡住？
  A: 程序自动发送禁用分页命令
     (Cisco: terminal length 0, Huawei: screen-length 0 temporary)。

  Q: 批量巡检速度慢？
  A: 增加并发数 (Parallel 数值，建议 5~10)。

  Q: Excel 导出报错？
  A: 安装 openpyxl: pip install openpyxl。HTML/CSV 无需额外依赖。

  Q: Compact Output 过滤了什么？
  A: 每种命令有预定义正则规则，只保留含关键指标的行。
     规则在 OUTPUT_FILTERS 字典中，可按需修改。

  Q: Ping 预检怎么关？
  A: 取消勾选 "Pre-check (ping)" 复选框。禁 ping 的设备可关闭。

  Q: 如何自定义异常检测阈值？
  A: 在 net_inspect_gui.py 的 ANOMALY_RULES 字典中修改 threshold 值。

  Q: 如何重新打包 exe？
  A: pip install pyinstaller
     pyinstaller --noconfirm NetworkInspectionV2.spec

================================================================================

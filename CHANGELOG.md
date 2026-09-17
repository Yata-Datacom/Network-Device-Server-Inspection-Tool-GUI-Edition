# Changelog

本项目遵循 [语义化版本](https://semver.org/lang/zh-CN/) 与
[Keep a Changelog](https://keepachangelog.com/zh-CN/1.1.0/) 格式。

> 3.x 及更早版本早于本 CHANGELOG 建立，详见 git 提交历史与 Releases 页。

## [5.1.2] - 2026-09-17

清掉最后一个已知问题，至此「已知问题」清单为**空**。

### Fixed

- `analyze_reports()` 在报告路径打错 / 文件被挪走时会把 `FileNotFoundError` 整个抛给调用方，
  与同函数对「解析不出设备」的处理风格不一致。现在降级为 `warnings`（GUI 只需展示提示，不必弹异常）；
  第二期报告读不到时同样降级，并退回单轮模式

### Tests

- 原 characterization 用例改为验证修复后的行为；用例总数 -1 项，全绿

## [5.1.1] - 2026-09-17

三个「不报错但结果错」的静默缺陷（由新增测试发现并修复）。

### Fixed

- **`rules.yaml` 里改阈值完全不生效**：文件用 `thresholds:` 嵌套写法，而引擎 `_th()` 只读**顶层键** →
  一律回退内置默认值（用户按文档调阈值实为无效，例：广播风暴阈值调到 100000 仍按 1000 判）。
  现在顶层优先、其次读 `thresholds` 子键（两种写法都生效）
- **`parse_huawei_temperature` 取到的「温度」是槽位号**：固定宽度槽位表里第一个 -20~120 的数字被当成温度
  → D11 温度告警永远拿 1~N 度比较，**真实过温静默漏报**。现在按表头定位 `Temperature(C)` 列取值
  （字符位置切片 → 词序号 → 启发式 三级降级）
- **首次运行自动释放 `rules.yaml` 后没有回读** → 本次调用缺 `signals`，D7 日志关键字静默失效
  （新装 exe 或删掉 rules.yaml 后才会遇到）。现在写出后立刻解析回读

### Tests

- 两个原 xfail 用例（温度列取值、释放后回读）转为正式断言；阈值用例从「锁定缺陷」改为「验证生效」
- 测试总数 250 → 253

## [5.1.0] - 2026-09-17

工程化改造 + 修一个影响环路告警可用性的真 bug。

### Added

- `LICENSE`（MIT）
- `pyproject.toml`：PEP 621 元数据 + 命令入口 `net-inspect` + ruff/pytest 配置，
  现在可以 `pip install -e .`；依赖锁定 `paramiko>=3.5,<4`（老设备 ssh-rsa 的硬要求）
- `tests/`：pytest 测试套件（判据引擎 12 条规则正负例、解析层华为两种排版、
  编排层两轮差分、`v5/` 镜像文件一致性）
- GitHub Actions：`.github/workflows/ci.yml`（Windows 跑 pytest、Linux 跑 ruff）、
  `.github/workflows/build.yml`（打 tag 或手动触发 → V3 与 V5 两个 exe artifact）
- 本 CHANGELOG；README 增加徽章与「开发与测试」章节

### Fixed

- **环路告警页签「A. 在线两轮采样」连不上任何设备**：调用宿主的 SSH 帮助函数时漏传 `client`
  参数（`_ssh_connect()` 是**就地连接、返回 `None`**），导致每台设备都抛异常、两轮采样全是空数据；
  而结果提示不管几轮都写「单轮时看不出…」，用户会以为「只跑了一轮」
- 结果提示按「单轮快照 / 两轮差分」分开；新增采样数据统计（第 1 轮 / 第 2 轮各几台有数据）；
  失败原因（连接超时 / 认证失败 / 命令不被该平台支持）直接列进弹窗

### Changed

- 主程序新增 `main()` 入口与 `__version__`；`__main__` 守卫改为调用 `main()`

## [5.0.0] - 2026-09-17

### Added

- **环路告警页签（Ring Alert）**：12 条判据 —— MAC 漂移 / STP 拓扑变化 / 根桥变更 / 广播与组播风暴 /
  接口误码增长 / 链路震荡 / 厂家日志关键字 / BPDU 收发异常 / 跨设备关联 / 光衰 / 温度 / 电源状态；
  支持**在线两轮采样**（工具自己连设备跑两遍做差分）与**离线报告分析**（1~2 份巡检 CSV）
- V5（个人版，含全部功能）与 V3（基础版）两个入口

## [3.4.0] - 2026-09-08

### Changed

- 153 个函数补齐中文 docstring（教学 / 交接版），AST 对比验证零逻辑改动

## [3.3.0] - 2026-09-02

### Added

- 主动探测页签：ICMP 连通性 / DNS 解析与重定向 / DHCP 私接检测 / ARP 欺骗与跨网段判定 / VLAN 隔离检查

## [3.2.0] - 2026-09-02

### Added

- 安全配置核查页签：DHCP snooping / DAI / DNS / VLAN 隔离 / 端口安全（只查询配置，不下发）

## [3.1.0] - 2026-08-31

### Added

- 流量测试页签（UDP / ICMP / TCP / TCP SYN，内置接收端，实时 PPS 与带宽）
- 攻击日志检测（SQLi / XSS / 路径穿越 / 命令注入 / WebShell / SSH 爆破，按行类型门控防误报）
- IP 情报查询（ip-api，含机房 / 代理特征标记）

## [3.0.0] - 2026-08-31

### Added

- 单机 / 批量 SSH 巡检（华为 / 新华三 / 锐捷 / 思科 / Linux），异常严重性着色与跳转
- 按设备异常统计、设备清单 txt + Excel 双格式、导出报告

[5.1.0]: https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/releases/tag/v5.1.0
[5.0.0]: https://github.com/Yata-Datacom/Network-Device-Server-Inspection-Tool-GUI-Edition/releases/tag/v5.0

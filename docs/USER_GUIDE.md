# Network Inspection Studio 6.0 — User Guide

> Applies to **v6.0.0**. The UI mixes Chinese navigation with the proven V5 inspection panels.
> All examples use synthetic documentation addresses (`192.0.2.0/24`, `198.51.100.0/24`) and fake MACs.

> **Privacy:** do not commit real device lists, `profiles.json`, screenshots or exported reports to a
> public repository. Keep `devices.xlsx`, `profiles.json` and `reports/` private.

---

## 1. What changed in 6.0

V6 is a **UI/architecture refresh** around the V5 engine:

- dark navy header, left workspace rail and page headers
- one workspace per task (no more eight flat tabs)
- an Overview dashboard with profiles, reports, backups and presets
- Chinese navigation and translated common controls
- a separate launcher so the V5 engine stays intact as a legacy fallback

The SSH, anomaly, report, backup, traffic, security, probe and ring-detection code is still the V5 engine.

---

## 2. Install and launch

### Windows exe

Download the single-file exe from Releases and run it. No Python required.

### From source

```bash
python -m pip install "paramiko>=3.5,<4" openpyxl pyyaml
python net_inspect_v6.py
```

Optional install:

```bash
python -m pip install -e ".[excel,yaml]"
net-inspect
```

Legacy: `python net_inspect_gui_v5.py` or `python net_inspect_gui.py` still start the old UIs.

---

## 3. Workspaces

| Workspace | Purpose |
| :-- | :-- |
| 总览 Overview | counts, quick actions, recent reports |
| 单机巡检 Single | one device, editable command set |
| 批量巡检 Batch | parallel inspection, anomaly marking, CSV/HTML/Excel export |
| 配置备份 Backup | batch `running-config` / `current-configuration` backup |
| 流量测试 Traffic | UDP / ICMP / TCP / TCP-SYN generator and TCP receiver |
| 安全核查 Security | read-only DHCP snooping / DAI / DNS / port isolation / port security checks |
| 主动探测 Probes | ICMP / DNS / DHCP / ARP / VLAN probes |
| 环路告警 Ring | two-round sampling diff, fault view, optical/temperature/power alerts |
| 连接档案 Profiles | saved connections and command presets |

Keyboard: `Ctrl+1…9` switches workspace, `Esc` stops, `Ctrl+Enter` starts the current single/batch/backup page.

![Overview](../assets/studio-v6-dashboard.png)

---

## 4. Device lists and profiles

### 4.1 `devices.txt`

One device per line:

```text
# IP:username:password:[type]:"command1,command2,..."
192.0.2.10:demo:DEMO-PASSWORD:huawei:"display version,display cpu-usage"
192.0.2.11:demo:DEMO-PASSWORD:h3c:"display version,display cpu-usage"
```

Supported types: `linux`, `cisco`, `huawei`, `h3c`, `ruijie` (case-insensitive), plus Chinese aliases.

### 4.2 `devices.xlsx`

Recommended columns: IP / username / password / type / commands. It is read with `openpyxl`; install the
`excel` extra if needed.

### 4.3 Profiles

The **连接档案** workspace stores named connections and command presets. Passwords are written through the
legacy obfuscation path; treat `profiles.json` as a secret file and never commit it.

---

## 5. Single-host inspection

1. Pick a device type (Linux / Huawei / H3C / Ruijie / Cisco).
2. Enter IP, port (usually 22), username and password.
3. Edit the command set (`标题::命令` per line) or load a preset.
4. Use **Ping 预检** to skip unreachable devices.
5. Click **开始巡检** (`Ctrl+Enter`).
6. Use **异常检测** and **紧凑输出** to reduce noise; search/highlight and “上一异常 / 下一异常” navigate results.

The output pane keeps colors for critical/warning/anomaly lines and supports search highlighting.

---

## 6. Batch inspection and reports

1. Load `devices.txt` or `devices.xlsx`.
2. Select target devices (or use select-all).
3. Set parallelism, anomaly detection, compact output and quick mode.
4. Click **开始巡检**; the status column shows Running / OK / FAILED.
5. Export CSV, HTML or Excel. HTML includes the anomaly summary; reports go to `reports/`.

Use **IP 情报** on a host for a quick intelligence summary.

---

## 7. Config backup

1. Load the device list.
2. Choose the backup directory (default `backups/`).
3. Select devices and click **备份选中设备**.
4. Files are written as `backups/<type>/<ip>/<ip>_<timestamp>.cfg`.

Backup runs in a worker thread; **停止** sends the shared stop event.

---

## 8. Traffic test

- Target IP / port / protocol: UDP, ICMP, TCP, TCP-SYN.
- Concurrency, packet size and rate are configurable.
- A built-in TCP receiver can listen on a local port for end-to-end checks.
- Real-time PPS, Mbps, packets, bytes and elapsed time are displayed.
- Use a lab or maintenance window: this generates real traffic.

---

## 9. Security checks

Read-only checks:

- DHCP snooping
- DAI / ARP protection
- DNS anti-spoofing / DHCP DNS
- port isolation / cross-VLAN ACL
- port security / MAC limit

Enter a target device and run. The report is informational; verify vendor syntax and business intent before
changing production configuration.

---

## 10. Active probes

Use these when a new machine is on site and basic connectivity works:

- **DHCP probe**: detect a rogue DHCP server / private router answering requests.
- **DNS probe**: compare expected vs. actual resolution (redirection check).
- **ARP probe**: detect ARP conflict / spoofing.
- **VLAN probe**: test cross-VLAN reachability.

These are diagnostic tools, not attacks. Use them only on networks you are authorized to test.

---

## 11. Ring alert (环路告警)

Two modes:

1. **Online two-round sampling** — connect to the device list, sample twice, diff the results.
2. **Offline report analysis** — compare two exported CSV reports.

The result defaults to the **fault view**:

- one fault card per suspected loop
- confidence, involved alerts, affected ports/VLAN/MAC
- recommended action (“unplug this port first”)
- switch to **告警明细** for raw evidence

Checks include MAC flapping, STP topology changes, root bridge changes, broadcast storms, CRC/input errors,
link flapping, vendor loop logs, BPDU self-loop, optical Rx power, temperature, power supply and cross-device
MAC conflicts.

![Ring alert](../assets/studio-v6-ring.png)

---

## 12. Data, reports and security

| Path | Contents |
| :-- | :-- |
| `backups/` | device configuration backups |
| `reports/` | CSV / HTML / Excel reports |
| `profiles.json` | saved connections and presets (secret) |
| `presets.json` | command presets |
| `rules.yaml` | ring-detection rules |

- Do not commit `devices.xlsx`, `devices.txt`, `profiles.json`, `backups/`, `reports/` or `samples/`.
- Exported HTML/CSV can contain hostnames, IPs, logs and config fragments; treat them as sensitive.
- Test generated reports and ring findings before acting on production devices.

---

## 13. Troubleshooting

| Symptom | Check |
| :-- | :-- |
| SSH authentication fails | username/password, device SSH enablement, ACL |
| `Unable to open channel` | device VTY sessions are full; close other sessions and retry |
| Old device negotiation fails | use the bundled Paramiko 3.5 compatibility path |
| Excel list not loading | install `openpyxl`; check header row and sheet |
| No report file | check write permission on `reports/` |
| Ring view empty | verify two rounds captured data; check sampling health messages |
| Wrong data directory | V6 stores user data next to the launcher; legacy V5 uses `v5/` |
| UI cuts off | minimum 1180×740; maximize for ring/traffic panels |

## 14. Version lines

| Version | Entry | Role |
| :-- | :-- | :-- |
| V6.0.0 | `net_inspect_v6.py` | Studio shell + V5 engine |
| V5.2.2 | `v5/net_inspect_gui_v5.py` | Legacy V5 UI |
| V3 | `net_inspect_gui.py` | Legacy basic UI |

See the repository [CHANGELOG](../CHANGELOG.md) for details.

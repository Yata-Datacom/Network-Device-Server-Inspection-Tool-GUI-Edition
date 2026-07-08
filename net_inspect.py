"""
批量网络设备巡检工具
从 devices.txt 读取设备列表（IP、用户名、密码、命令），
通过 SSH 逐台连接并执行指定命令，输出巡检报告。

devices.txt 格式:
    IP:用户名:密码:"命令1,命令2,..."
    支持 # 开头的注释行和空行
"""

import paramiko
import sys
import re
from typing import List, Tuple


def read_devices(filepath: str) -> List[Tuple[str, str, str, List[str]]]:
    """
    从文件中解析设备列表

    :param filepath: 设备列表文件的路径
    :return: 设备信息列表，每项为 (host, user, password, [cmd1, cmd2, ...])
    """
    devices: List[Tuple[str, str, str, List[str]]] = []

    try:
        f = open(filepath, "r", encoding="utf-8")
    except FileNotFoundError:
        print(f"[!] File not found: {filepath}")
        sys.exit(1)

    with f:
        for line in f:
            line = line.strip()
            # 跳过空行和注释行
            if not line or line.startswith("#"):
                continue

            # 匹配格式: IP:用户名:密码:"命令1,命令2,..."
            m = re.match(r'^([^:]+):([^:]+):([^:]+):"([^"]*)"$', line)
            if not m:
                print(f"[!] Invalid format, skipping: {line}")
                continue

            host, user, pwd, cmds_str = m.groups()
            cmds = [c.strip() for c in cmds_str.split(",") if c.strip()]
            if cmds:
                devices.append((host, user, pwd, cmds))

    return devices


def inspect_device(host: str, user: str, pwd: str, cmds: List[str]) -> None:
    """
    连接到单台网络设备，执行巡检命令并打印输出

    :param host: 设备 IP 地址
    :param user: SSH 登录用户名
    :param pwd:  SSH 登录密码
    :param cmds: 要执行的命令列表
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    print(f"\n{'=' * 60}")
    print(f"  Device: {host}")
    print(f"{'=' * 60}")

    try:
        client.connect(
            host,
            username=user,
            password=pwd,
            timeout=10,
            look_for_keys=False,
            allow_agent=False,
        )
    except Exception as e:
        print(f"  [FAILED] Connection error: {e}")
        return

    # 逐条执行命令并输出结果
    for cmd in cmds:
        print(f"\n--- [{cmd}] ---")
        stdin, stdout, stderr = client.exec_command(cmd, timeout=15)
        output = stdout.read().decode(errors="replace")
        err = stderr.read().decode(errors="replace")
        if output:
            print(output.rstrip())
        if err:
            print(f"[STDERR] {err.rstrip()}")

    client.close()


def main() -> None:
    """主入口：从 devices.txt 加载设备列表，逐个执行巡检"""
    filepath = "devices.txt"
    devices = read_devices(filepath)

    if not devices:
        print("No valid device entries found.")
        sys.exit(1)

    print(f"Loaded {len(devices)} device(s) from {filepath}\n")
    print("=" * 60)
    print("  Network Device Inspection Report")
    print("=" * 60)

    for host, user, pwd, cmds in devices:
        inspect_device(host, user, pwd, cmds)

    print(f"\n{'=' * 60}")
    print("  Inspection complete.")
    print(f"{'=' * 60}")
    input("\nPress any key to exit...")


if __name__ == "__main__":
    main()

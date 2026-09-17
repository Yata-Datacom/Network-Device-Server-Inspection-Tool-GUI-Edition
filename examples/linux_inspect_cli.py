"""
Linux 系统巡检工具
通过 SSH 连接到远程 Linux 服务器，自动执行预定义的检查命令并输出巡检报告。
"""

import paramiko
import getpass
import sys


# ============================================================
# 预定义的巡检命令：标题 -> Shell 命令
# ============================================================
INSPECTION_COMMANDS = {
    "Hostname": "hostnamectl --static",
    "OS Release": "cat /etc/os-release | grep PRETTY_NAME | cut -d= -f2",
    "Kernel": "uname -r",
    "Uptime": "uptime -p",
    "CPU Info": "lscpu | grep 'Model name' | sed 's/Model name:[[:space:]]*//'",
    "CPU Cores": "nproc",
    "CPU Load": "uptime | awk -F'load average:' '{print $2}'",
    "Memory": (
        "free -h | awk 'NR==2{printf \"total: %s  used: %s  free: %s  available: %s\", $2,$3,$4,$7}'"
    ),
    "Swap": "free -h | awk 'NR==3{printf \"total: %s  used: %s  free: %s\", $2,$3,$4}'",
    "Disk Usage": (
        "df -h --total | awk '/^total/{printf \"total: %s  used: %s  avail: %s  use%%: %s\", $2,$3,$4,$5}'"
    ),
    "Top 10 by CPU": "ps -eo pid,pcpu,pmem,user,comm --sort=-pcpu --no-headers | head -10",
    "Top 10 by Memory": "ps -eo pid,pcpu,pmem,user,comm --sort=-pmem --no-headers | head -10",
}


def run_ssh(host: str, port: int, user: str, password: str) -> None:
    """
    通过 SSH 连接到远程主机，依次执行巡检命令并打印结果

    :param host:     目标主机的 IP 地址
    :param port:     SSH 端口号
    :param user:     SSH 登录用户名
    :param password: SSH 登录密码
    """
    client = paramiko.SSHClient()
    client.set_missing_host_key_policy(paramiko.AutoAddPolicy())

    try:
        client.connect(host, port=port, username=user, password=password, timeout=10)
    except Exception as e:
        print(f"Connection failed: {e}")
        sys.exit(1)

    # 打印报告头部
    print("\n" + "=" * 60)
    print(f"  System Inspection Report — {host}:{port}")
    print("=" * 60)

    # 逐项执行并输出
    for title, cmd in INSPECTION_COMMANDS.items():
        stdin, stdout, stderr = client.exec_command(cmd)
        output = stdout.read().decode().strip()
        if output:
            print(f"\n[{title}]")
            print(output)

    client.close()


def main() -> None:
    """主入口：交互式获取连接信息，然后执行系统巡检"""
    print("=== Linux System Inspection Tool ===\n")

    host = input("IP address: ").strip()
    port = int(input("Port (default 22): ").strip() or "22")
    user = input("Username: ").strip()
    password = getpass.getpass("Password: ")

    if not host or not user:
        print("IP and username are required.")
        sys.exit(1)

    run_ssh(host, port, user, password)

    print("\n" + "=" * 60)
    input("Press any key to exit...")


if __name__ == "__main__":
    main()

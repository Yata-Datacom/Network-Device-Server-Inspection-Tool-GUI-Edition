# -*- coding: utf-8 -*-
"""
提示符提前收工（2026-09-18 性能优化）回归测试。

背景：原来判断"一条命令输出读完"只能死等 3 秒静默，11 条命令 = 35 秒/台，
用户实测"太慢了"。改为：从登录 banner 认出设备提示符（<SW-1> / [SW-1]），
每读到一次的结尾是提示符就立刻收工；认不出提示符则退回静默判定（行为不变）。
"""
import os
import sys
import threading
import time as _time

HERE = os.path.dirname(os.path.abspath(__file__))
V5 = os.path.join(os.path.dirname(HERE), "v5")
if V5 not in sys.path:
    sys.path.insert(0, V5)

import net_inspect_gui_v5 as M  # noqa: E402


def test_extract_prompt_from_huawei_banner():
    banner = ("Info: The max number of VTY users is 10.\r\n"
              "Info: Lastest accessed IP: 10.0.0.1\r\n"
              "\r\n<2J_3FX_48WXHJ>")
    assert M._extract_prompt(banner) == "<2J_3FX_48WXHJ>"


def test_extract_prompt_system_view_and_empty():
    assert M._extract_prompt("...\r\n[SW-CORE-01]") == "[SW-CORE-01]"
    assert M._extract_prompt("") == ""
    assert M._extract_prompt("no prompt here\njust text") == ""


def test_prompt_like_line_inside_table_is_not_confused():
    """MAC 表里出现 <...> 的行不应该被当提示符（要求整行就是提示符）。"""
    table = "MAC Address    VLAN  Port\r\n  <00e0-fc12-3456>  hmm\r\n<SW-1>"
    assert M._extract_prompt(table) == "<SW-1>"


class _FakeChannel:
    """假设备：send 之后把"回显 + 输出 + 提示符"排队，recv 依次吐出。"""

    def __init__(self, prompt="<SW-1>"):
        self.q = []
        self.prompt = prompt
        self.closed = False
        self.sent = []

    def settimeout(self, t):
        pass

    def recv_ready(self):
        return bool(self.q)

    def recv(self, n):
        return self.q.pop(0)

    def send(self, s):
        self.sent.append(s)
        self.q.append(s.encode())                                    # 回显
        self.q.append(b"Huawei Versatile Routing Platform\r\n" * 3)  # 输出
        self.q.append(("\r\n" + self.prompt).encode())               # 提示符

    def close(self):
        self.closed = True


class _FakeClient:
    def __init__(self, prompt="<SW-1>"):
        self.chan = _FakeChannel(prompt)

    def invoke_shell(self, width=200, height=100):
        return self.chan


def _app():
    app = M.NetworkInspectGUI.__new__(M.NetworkInspectGUI)
    app.stop_event = threading.Event()
    return app


def test_prompt_makes_commands_finish_immediately(monkeypatch):
    """看到提示符立刻收工：不应等满 3 秒静默。"""
    monkeypatch.setattr(M.time, "sleep", lambda *_: None)     # 去掉固定等待，只看逻辑
    app = _app()
    client = _FakeClient()
    t0 = _time.time()
    out = app._run_commands_via_shell(client, "huawei", {"a": "display stp", "b": "display version"})
    dt = _time.time() - t0
    assert dt < 0.5, f"应当靠提示符提前收工，实际耗时 {dt:.2f}s"
    assert "Huawei Versatile" in out["a"] and "Huawei Versatile" in out["b"]
    assert client.chan.closed, "通道必须被关闭"


def test_without_prompt_falls_back_to_silence(monkeypatch):
    """认不出提示符（老设备）→ 退回静默判定，行为不变，且不会卡死。"""
    monkeypatch.setattr(M.time, "sleep", lambda *_: None)
    app = _app()
    client = _FakeClient(prompt="")            # 没有提示符
    out = app._run_commands_via_shell(client, "huawei", {"a": "display stp"})
    assert "Huawei Versatile" in out["a"]
    assert client.chan.closed

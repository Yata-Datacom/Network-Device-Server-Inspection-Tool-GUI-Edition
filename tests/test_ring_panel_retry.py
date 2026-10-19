# -*- coding: utf-8 -*-
"""
Ring Alert 面板连接层回归测试（2026-09-18 加）。

背景（真实故障）：
  * 用户侧报「第1轮/第2轮 0/37 台有数据」，弹窗里全是 Unable to open channel /
    Authentication failed；
  * 排查发现两条独立问题：
      1) 宿主 _run_commands_via_shell 的 channel.close() 只写在成功路径上 →
         异常/超时/被停止时通道不释放，设备的 VTY 会话被挂住（实测挂了 3 小时），
         后续连接就被设备回 "Unable to open channel"；
      2) 面板 _ssh_run 只要失败一次就直接放弃，而这类"通道被拒"多为瞬时故障
         （另一个实例在连同一台设备、上一轮会话还没释放等），重试一次大概率就好。

本文件锁住修复后的行为：
  * 瞬时故障 → 换一条新连接重试一次，成功则正常返回；
  * 认证失败 → 不重试（重试只是白撞，还可能触发设备锁定），直接给中文提示；
  * 连续瞬时故障 → 抛 RuntimeError，且文案含"怎么办"的中文指导；
  * _friendly_session_error 的四类映射。
"""
import os
import sys

import pytest
from paramiko.ssh_exception import AuthenticationException, SSHException

HERE = os.path.dirname(os.path.abspath(__file__))
ROOT = os.path.dirname(HERE)
V5 = os.path.join(ROOT, "v5")
if V5 not in sys.path:
    sys.path.insert(0, V5)

import ring_panel as RPa  # noqa: E402


class _FakeClient:
    def close(self):
        return None


class _FakeApp:
    """只实现面板用到的三个宿主帮助函数，并可指定第 N 次调用抛什么错。"""

    def __init__(self, failures=()):
        self.failures = list(failures)
        self.create_calls = 0
        self.run_calls = 0

    def _create_ssh_client(self):
        self.create_calls += 1
        return _FakeClient()

    def _ssh_connect(self, client, host, port, user, pwd, timeout=10):
        idx = self.create_calls - 1
        if idx < len(self.failures) and self.failures[idx] is not None:
            raise self.failures[idx]

    def _run_commands_via_shell(self, client, devtype, cmds, timeout=30, silence_rounds=20):
        self.run_calls += 1
        idx = self.create_calls - 1
        if idx < len(self.failures) and self.failures[idx] is not None:
            raise self.failures[idx]
        return {k: f"output-of-{v}" for k, v in cmds.items()}


def _panel(app, monkeypatch, tmp_path):
    """造一个不起界面的面板哑实例（只需要 app / _stop / _note_health）。"""
    p = RPa.RingAlertPanel.__new__(RPa.RingAlertPanel)
    p.app = app
    p._stop = __import__("threading").Event()
    p._health = {}
    p._note_health = lambda host, out: p._health.__setitem__(host, out)
    return p


def test_transient_error_retries_once_and_succeeds(monkeypatch):
    """第 1 次 'Unable to open channel'，重试后成功 → 返回数据且共连 2 次。"""
    app = _FakeApp([SSHException("Unable to open channel."), None])
    panel = _panel(app, monkeypatch, None)
    monkeypatch.setattr("time.sleep", lambda *_: None)          # 别真等 2.5 秒
    out = panel._ssh_run("192.0.2.1", "u", "p", "huawei", ["display stp"])
    assert app.create_calls == 2, "瞬时故障必须换新连接重试一次"
    assert out == {"display stp": "output-of-display stp"}


def test_transient_error_twice_raises_friendly_message(monkeypatch):
    """连续两次瞬时故障 → 抛 RuntimeError，文案要说清"为什么 + 怎么办"。"""
    app = _FakeApp([SSHException("Unable to open channel."), SSHException("Unable to open channel.")])
    panel = _panel(app, monkeypatch, None)
    monkeypatch.setattr("time.sleep", lambda *_: None)
    with pytest.raises(RuntimeError) as ei:
        panel._ssh_run("192.0.2.1", "u", "p", "huawei", ["display stp"])
    msg = str(ei.value)
    assert app.create_calls == 2
    assert "会话" in msg and ("等 30 秒" in msg or "只开了一个" in msg)


def test_auth_failure_is_not_retried(monkeypatch):
    """认证失败不重试（重试无意义且可能触发设备锁定），且文案直指账号密码。"""
    app = _FakeApp([AuthenticationException("Authentication failed.")])
    panel = _panel(app, monkeypatch, None)
    with pytest.raises(RuntimeError) as ei:
        panel._ssh_run("192.0.2.1", "u", "p", "huawei", ["display stp"])
    assert app.create_calls == 1, "认证失败不应重试"
    assert "用户名或密码" in str(ei.value)


def test_friendly_session_error_mapping():
    """四类常见报错 → 对应的中文指导。"""
    f = RPa._friendly_session_error
    assert "会话" in f("SSHException: Unable to open channel.")
    assert "用户名或密码" in f("AuthenticationException: Authentication failed.")
    assert "超时" in f("TimeoutError: timed out")
    assert "22 端口" in f("ConnectionRefusedError: [WinError 10061] refused")
    assert f("some other boom") == "some other boom"


def test_looks_transient_classification():
    lt = RPa._looks_transient
    assert lt(SSHException("Unable to open channel."))
    assert lt(TimeoutError("timed out"))
    assert lt(ConnectionResetError("Connection reset by peer"))
    assert not lt(AuthenticationException("Authentication failed."))

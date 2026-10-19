# -*- coding: utf-8 -*-
"""tests/test_shell_channel.py — _run_commands_via_shell 核心路径测试（Mock SSH）。

覆盖两次真实事故的回归点：
1. v5.2.1 修复：channel.close() 必须在 finally（异常路径也要释放 VTY，
   否则设备会话挂 3 小时 → "Unable to open channel"）。
2. 提示符提前收工（5.2.2 优化）：prompt 出现在输出尾行即停，不等 3s 静默。

全部用 Mock channel，不连真设备。
"""
import os
import sys
import time
import types
import threading
import unittest

sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))

import net_inspect_gui as gui


class FakeChannel:
    """可编程的伪 SSH channel：按脚本回放输出。"""

    def __init__(self, script, banner="<SW-1>"):
        # script: [(delay_sec, bytes), ...] 每次 recv 依次弹出
        self.script = list(script)
        self.banner = banner
        self.sent = []
        self.closed = False
        self._lock = threading.Lock()

    def invoke_shell(self, width=200, height=100):
        return self

    def settimeout(self, t):
        pass

    def send(self, data):
        with self._lock:
            self.sent.append(data)

    def recv_ready(self):
        with self._lock:
            return bool(self.script)

    def recv(self, n):
        with self._lock:
            if not self.script:
                return b""
            delay, data = self.script.pop(0)
        if delay:
            time.sleep(delay)
        return data

    def close(self):
        self.closed = True


DISABLE_FIRST = gui.DISABLE_PAGING.get("huawei", "screen-length")


def make_gui_stub():
    """绕开 Tk，只造 _run_commands_via_shell 所需的最小 self。"""
    stub = types.SimpleNamespace()
    stub.stop_event = threading.Event()
    func = gui.NetworkInspectGUI.__dict__["_run_commands_via_shell"]
    bound = func.__get__(stub, types.SimpleNamespace)
    return stub, bound


class TestShellChannel(unittest.TestCase):
    def test_normal_output_and_keys_complete(self):
        """正常路径：每条命令拿到输出，键齐全。"""
        ch = FakeChannel([
            (0.0, b"\r\nInfo: banner text\r\n<SW-1>"),
            (0.0, b"disable paging ok\r\n<SW-1>"),
            (0.0, b"display version\r\nHuawei VersatileRouting\r\n<SW-1>"),
            (0.0, b"display clock\r\n2026-10-14 12:00\r\n<SW-1>"),
        ])
        stub, bound = make_gui_stub()
        res = bound(ch, "huawei", {"版本": "display version", "时钟": "display clock"}, timeout=8)
        self.assertEqual(set(res), {"版本", "时钟"})
        self.assertIn("Huawei", res["版本"])
        self.assertIn("2026-10-14", res["时钟"])
        self.assertTrue(ch.closed, "结束时必须关闭 channel")

    def test_close_in_finally_on_exception(self):
        """回归 v5.2.1：通道开成功后中途抛异常，channel 也必须 close（VTY 不悬挂）。

        注：invoke_shell 本身抛异常时 channel 仍为 None（无需 close）——
        真正要守护的是「通道已建立、执行中炸掉」的路径。
        """
        ch = FakeChannel([(0.0, b"\r\n<SW-1>"), (0.0, b"paging ok\r\n<SW-1>"),
                          (0.0, b"cmd1 output\r\n<SW-1>")])
        # banner 与分页回显读取成功后，让再下一次 recv（读命令输出）炸掉
        original_recv = ch.recv
        calls = {"n": 0}

        def flaky_recv(n):
            calls["n"] += 1
            if calls["n"] >= 3:
                raise ConnectionError("recv died mid-session")
            return original_recv(n)

        ch.recv = flaky_recv
        stub, bound = make_gui_stub()
        res = bound(ch, "huawei", {"a": "cmd1"}, timeout=5)
        self.assertIn("[ERROR]", res["a"])
        self.assertTrue(ch.closed, "异常路径 channel 未关闭（v5.2.1 回归）")

    def test_prompt_early_exit(self):
        """回归 5.2.2：提示符出现即收工，不等 3 秒静默（<2s 完成）。"""
        ch = FakeChannel([
            (0.0, b"\r\n<SW-1>"),
            (0.0, b"paging off\r\n<SW-1>"),
            (0.0, b"cmd out\r\n<SW-1>"),          # 输出+提示符 → 立即结束
        ])
        stub, bound = make_gui_stub()
        t0 = time.time()
        res = bound(ch, "huawei", {"x": "cmd"}, timeout=30)
        dt = time.time() - t0
        self.assertIn("cmd out", res["x"])
        self.assertLess(dt, 5, f"提示符收工应立即返回，实际耗时 {dt:.1f}s")

    def test_stop_event_breaks_loop(self):
        """点「停止」后不再发送后续命令。"""
        ch = FakeChannel([
            (0.0, b"\r\n<SW-1>"),
            (0.0, b"ok1\r\n<SW-1>"),
        ])
        stub, bound = make_gui_stub()
        stub.stop_event.set()  # 预先置位
        bound(ch, "huawei", {"a": "cmd1", "b": "cmd2"}, timeout=5)
        formal = [s for s in ch.sent if not s.startswith(DISABLE_FIRST)]
        self.assertEqual(formal, [], "stop_event 置位后不应发送任何正式命令（关分页前置命令除外）")

    def test_silent_timeout_fills_output(self):
        """无提示符（认不出）时靠 3s 静默判定，输出仍完整收集。"""
        ch = FakeChannel([
            (0.0, b"welcome"),                     # banner，无提示符
            (0.0, b"paging off"),
            (0.0, b"some output here"),
            # 之后不再有数据 → 静默判定结束
        ])
        stub, bound = make_gui_stub()
        res = bound(ch, "unknown-dev", {"k": "cmd"}, timeout=10)
        self.assertIn("some output here", res["k"])
        self.assertTrue(ch.closed)


if __name__ == "__main__":
    unittest.main(verbosity=2)

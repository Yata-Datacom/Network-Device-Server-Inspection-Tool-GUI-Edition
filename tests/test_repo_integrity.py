#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
test_repo_integrity.py —— 仓库级一致性检查（v5 镜像 / 只读约束 / 公开性）

覆盖：
1. `v5/` 下与根目录同名的文件是否**逐字节一致**（sha256）——防止镜像漂移；
2. 默认调用 `load_rules()` 不会往仓库目录写盘（repo 文件清单前后一致）；
3. rules.yaml 缺失时的自动释放可以用 tmp_path + monkeypatch 重定向（测试不落盘仓库）；
4. tests/ 里不出现内部交付版 `v4/` 的引用（v4 不进公开仓库）。

注意：`v4/` 目录**不读取、不导入**，本文件只做「不得引用」的静态检查。
"""

from __future__ import annotations

import hashlib
import pathlib
import re

import pytest

import ring_parsers as RP

# 根目录与 v5/ 应当一致的文件集合（同一套逻辑两份镜像）
MIRROR_FILES = ["ring_rules.py", "ring_parsers.py", "ring_analyze.py",
                "ring_panel.py", "rules.yaml", "test_ring_rules.py"]

ROOT = pathlib.Path(__file__).resolve().parents[1]
TESTS_DIR = pathlib.Path(__file__).resolve().parent


def sha256(path: pathlib.Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def test_v5_files_exist_in_both_places():
    missing = [f for f in MIRROR_FILES
               if not (ROOT / f).is_file() or not (ROOT / "v5" / f).is_file()]
    assert missing == [], f"镜像文件缺失: {missing}"


@pytest.mark.parametrize("name", MIRROR_FILES)
def test_v5_mirror_is_byte_identical(name):
    a, b = ROOT / name, ROOT / "v5" / name
    da, db = sha256(a), sha256(b)
    assert da == db, (f"v5 镜像与根目录不一致: {name}\n"
                      f"  root sha256 = {da}\n  v5   sha256 = {db}")


def test_v5_mirror_importable_as_a_separate_copy():
    """v5 的 ring_parsers 单独 import 时也能自洽（不依赖根目录的模块路径）。"""
    src = (ROOT / "v5" / "ring_parsers.py").read_text(encoding="utf-8")
    assert "from ring_rules import DEFAULTS" in src      # 规则表合并依赖同目录模块


def test_default_load_rules_does_not_write_into_repo():
    """仓库自带 rules.yaml 时 load_rules() 只读：仓库清单与文件内容都不变。"""
    def snapshot():
        return {str(p.relative_to(ROOT)) for p in ROOT.rglob("*")
                if "__pycache__" not in p.parts and p.is_file()}

    before_files = snapshot()
    before_hash = sha256(ROOT / "rules.yaml")
    RP.load_rules()
    assert snapshot() == before_files, "load_rules() 往仓库目录写了新文件"
    assert sha256(ROOT / "rules.yaml") == before_hash


def test_missing_rules_auto_release_can_be_redirected_to_tmp(tmp_path, monkeypatch):
    """缺规则表时确实会写盘 —— 用 monkeypatch 把默认路径重定向到 tmp_path。"""
    target = tmp_path / "rules.yaml"
    monkeypatch.setattr(RP, "default_rules_path", lambda: str(target))
    assert not target.exists()
    rules = RP.load_rules()                       # path=None → 走被重定向的默认路径
    assert target.exists()
    assert "已释放默认规则表" in " ".join(rules["_warnings"])
    assert not (ROOT / "rules.yaml_new").exists()


def test_tests_do_not_reference_internal_v4_tree():
    """tests/ 不得出现 v4（内部交付版）的引用——它不进公开仓库。"""
    offenders = {}
    for p in sorted(TESTS_DIR.glob("*.py")):
        if p.name == pathlib.Path(__file__).name:      # 本文件描述规则本身
            continue
        text = p.read_text(encoding="utf-8")
        for m in re.finditer(r"\bv4\b", text):
            offenders.setdefault(p.name, []).append(text[:m.start()].count("\n") + 1)
    assert offenders == {}, f"tests/ 里出现 v4 引用: {offenders}"


def test_fake_samples_are_fictional():
    """测试样本不含真实内网/公网地址与真实单位名（仓库是公开的）。"""
    text = (TESTS_DIR / "fake_data.py").read_text(encoding="utf-8")
    ips = set(re.findall(r"\b\d{1,3}\.\d{1,3}\.\d{1,3}\.\d{1,3}\b", text))
    assert ips, "fake_data.py 里应当有设备地址"
    for ip in ips:
        assert ip.startswith(("192.0.2.", "10.0.0.")), f"非虚构地址: {ip}"

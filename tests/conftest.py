#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
conftest.py —— 测试公共配置

职责只有两件（刻意保持最小）：
1. 把**仓库根目录**加进 `sys.path`，这样任何工作目录下都能 `import ring_rules`
   （测试本身不回写任何仓库文件）；
2. 把 **tests/ 目录**也加进去，方便 `import fake_data`（虚构样本模块）。

注意：内部交付版目录不进公开仓库（.gitignore 里已排除），测试**不读取、不导入**它。
"""

from __future__ import annotations

import pathlib
import sys

import pytest

ROOT = pathlib.Path(__file__).resolve().parents[1]
TESTS = pathlib.Path(__file__).resolve().parent

for _p in (str(TESTS), str(ROOT)):
    if _p not in sys.path:
        sys.path.insert(0, _p)


@pytest.fixture(scope="session")
def repo_root() -> pathlib.Path:
    return ROOT


@pytest.fixture(scope="session")
def rules_yaml_path() -> str:
    """仓库自带的 rules.yaml（只读使用）。"""
    return str(ROOT / "rules.yaml")

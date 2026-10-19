"""Tests for connectivity/baseline helpers."""
from __future__ import annotations

from netinspect_tests import baseline_compare, baseline_name, config_hash


def test_baseline_new_same_and_changed():
    assert baseline_compare("", "a\nb\n")[0] == "新基线"
    assert baseline_compare("a\nb\n", "a\nb\n") == ("一致", 0, 0)
    status, added, deleted = baseline_compare("a\nb\n", "a\nc\nd\n")
    assert status == "已变更"
    assert added == 2
    assert deleted == 1


def test_baseline_name_is_safe():
    assert "/" not in baseline_name("10.0.0.1/edge")
    assert ":" not in baseline_name("fe80::1")


def test_config_hash_stable():
    assert config_hash("sysname demo\n") == config_hash("sysname demo\n")
    assert config_hash("a") != config_hash("b")

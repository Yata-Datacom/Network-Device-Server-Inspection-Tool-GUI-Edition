"""Credential vault tests: DPAPI round-trip and no plaintext on disk."""
from __future__ import annotations

import tkinter as tk

import net_inspect_v6 as v6
import netinspect_secrets as vault


def test_vault_roundtrip():
    token = vault.protect("demo-secret")
    assert token.startswith(("dpapi:1:", "plain:1:"))
    assert vault.unprotect(token) == "demo-secret"
    assert vault.unprotect("") == ""


def test_profiles_are_encrypted_on_disk(tmp_path, monkeypatch):
    root = tk.Tk()
    root.withdraw()
    try:
        app = v6.InspectionStudio(root)
        target = tmp_path / "profiles.json"
        monkeypatch.setattr(v6.base, "PROFILES_FILE", str(target))
        profiles = [
            {"name": "demo", "host": "192.0.2.10", "port": 22,
             "user": "demo", "password": "SECRET-VALUE", "devtype": "huawei"},
        ]
        app._write_profiles(profiles)
        text = target.read_text(encoding="utf-8")
        assert "SECRET-VALUE" not in text
        loaded = app._load_profiles()
        assert loaded[0]["password"] == "SECRET-VALUE"
    finally:
        root.destroy()

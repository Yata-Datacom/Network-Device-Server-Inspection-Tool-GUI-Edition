"""V6 shell smoke: pages, navigation and version."""
from __future__ import annotations

import tkinter as tk

import net_inspect_v6


def test_v6_shell_pages():
    root = tk.Tk()
    root.withdraw()
    try:
        app = net_inspect_v6.InspectionStudio(root)
        expected = {"dashboard", "single", "batch", "backup", "testing",
                    "traffic", "security", "active", "ring", "profiles"}
        assert set(app.pages) == expected
        assert app.current_page == "dashboard"
        app._show_page("ring")
        assert app.current_page == "ring"
        assert net_inspect_v6.__version__.startswith("6.")
    finally:
        root.destroy()

from __future__ import annotations
import sys

def platform_name() -> str:
    # Normalized platform name.
    if sys.platform.startswith("win"):
        return "windows"
    if sys.platform.startswith("linux"):
        return "linux"
    if sys.platform.startswith("darwin"):
        return "darwin"
    return "other"

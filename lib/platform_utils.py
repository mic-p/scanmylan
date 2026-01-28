from __future__ import annotations
import platform

def platform_key() -> str:
    sys = platform.system().lower()
    if "windows" in sys:
        return "windows"
    if "linux" in sys:
        return "linux"
    if "darwin" in sys or "mac" in sys:
        return "darwin"
    return "other"

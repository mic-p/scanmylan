"""OS detection utilities."""

from __future__ import annotations
import platform


def get_os() -> str:
    sysname = platform.system().lower()
    if "windows" in sysname:
        return "windows"
    if "linux" in sysname:
        return "linux"
    if "darwin" in sysname or "mac" in sysname:
        return "darwin"
    return "other"

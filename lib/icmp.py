from __future__ import annotations

import subprocess
from typing import List

from .platform_utils import platform_name

# ICMP is performed by calling the OS "ping" command (no raw sockets).
# Settings required by spec:
# - timeout: 3 seconds
# - echo count: 2

DEFAULT_TIMEOUT_SEC = 3
DEFAULT_ECHO_COUNT = 2

def _ping_cmd(ip: str, timeout_sec: int = DEFAULT_TIMEOUT_SEC, echo_count: int = DEFAULT_ECHO_COUNT) -> List[str]:
    plat = platform_name()
    if plat == "windows":
        # -n count, -w timeout_ms (per reply)
        return ["ping", "-n", str(echo_count), "-w", str(int(timeout_sec * 1000)), ip]
    if plat == "linux":
        # -c count, -W timeout_sec (per reply)
        return ["ping", "-c", str(echo_count), "-W", str(timeout_sec), ip]
    # Placeholder for future OS support (e.g. macOS options differ).
    return ["ping", ip]

def popen_ping(ip: str, timeout_sec: int = DEFAULT_TIMEOUT_SEC, echo_count: int = DEFAULT_ECHO_COUNT) -> subprocess.Popen:
    cmd = _ping_cmd(ip, timeout_sec, echo_count)
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)

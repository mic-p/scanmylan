"""ICMP scanning via OS 'ping' command (subprocess).

We intentionally avoid raw sockets to keep it usable without admin/root.
The OS command is invoked with arguments that work on Windows and Linux.

Important: we return the Popen object so the caller can terminate/kill it on Stop.
"""

from __future__ import annotations

import subprocess
from dataclasses import dataclass
from typing import List

from .platform_utils import get_os


DEFAULT_TIMEOUT_SEC = 3
DEFAULT_ECHO_COUNT = 2


@dataclass
class PingResult:
    ip: str
    ok: bool
    returncode: int


def build_ping_command(ip: str, timeout_sec: int = DEFAULT_TIMEOUT_SEC, echo_count: int = DEFAULT_ECHO_COUNT) -> List[str]:
    os_name = get_os()

    if os_name == "windows":
        # -n count, -w timeout_in_ms (per reply)
        return ["ping", "-n", str(echo_count), "-w", str(timeout_sec * 1000), ip]

    if os_name == "linux":
        # -c count, -W timeout_in_sec (per reply)
        return ["ping", "-c", str(echo_count), "-W", str(timeout_sec), ip]

    # Placeholder for other OSes (e.g. macOS uses different flags: -c, -W is different)
    # We'll try a Linux-like default, but the caller should handle failures gracefully.
    return ["ping", "-c", str(echo_count), ip]


def popen_ping(ip: str, timeout_sec: int = DEFAULT_TIMEOUT_SEC, echo_count: int = DEFAULT_ECHO_COUNT) -> subprocess.Popen:
    cmd = build_ping_command(ip, timeout_sec=timeout_sec, echo_count=echo_count)
    # stdout/stderr are suppressed; we only care about the return code.
    return subprocess.Popen(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)


def run_ping(ip: str, timeout_sec: int = DEFAULT_TIMEOUT_SEC, echo_count: int = DEFAULT_ECHO_COUNT) -> PingResult:
    p = popen_ping(ip, timeout_sec=timeout_sec, echo_count=echo_count)
    rc = p.wait()
    return PingResult(ip=ip, ok=(rc == 0), returncode=rc)

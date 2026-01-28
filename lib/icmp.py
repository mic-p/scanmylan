from __future__ import annotations
import subprocess
from typing import List, Tuple
from .platform_utils import platform_key

DEFAULT_TIMEOUT_SECONDS = 3
DEFAULT_ECHO_COUNT = 2

def build_ping_command(ip: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, echo_count: int = DEFAULT_ECHO_COUNT) -> List[str]:
    pk = platform_key()
    if pk == "windows":
        return ["ping", "-n", str(echo_count), "-w", str(int(timeout_seconds * 1000)), ip]
    if pk == "linux":
        return ["ping", "-c", str(echo_count), "-W", str(int(timeout_seconds)), ip]
    if pk == "darwin":
        # placeholder: not officially supported yet
        return ["ping", "-c", str(echo_count), ip]
    return ["ping", ip]

def popen_ping(ip: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, echo_count: int = DEFAULT_ECHO_COUNT) -> subprocess.Popen:
    cmd = build_ping_command(ip, timeout_seconds=timeout_seconds, echo_count=echo_count)
    creationflags = 0
    if platform_key() == "windows":
        creationflags = getattr(subprocess, "CREATE_NO_WINDOW", 0)
    return subprocess.Popen(
        cmd,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
        text=True,
        creationflags=creationflags,
    )

def ping_once(ip: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, echo_count: int = DEFAULT_ECHO_COUNT) -> Tuple[bool, int, str]:
    p = popen_ping(ip, timeout_seconds=timeout_seconds, echo_count=echo_count)
    out, err = p.communicate()
    rc = p.returncode if p.returncode is not None else 1
    combined = (out or "") + (err or "")
    return (rc == 0), rc, combined

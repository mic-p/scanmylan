"""ARP table reader.

Requirements:
- Windows: parse `arp -a`
- Linux: parse `/proc/net/arp`
- Other OS: do nothing (return empty results)

We normalize MAC to uppercase with ':' separators: AA:BB:CC:DD:EE:FF
"""

from __future__ import annotations

import re
import subprocess
from pathlib import Path
from typing import Dict, Optional

from .platform_utils import get_os


_MAC_RE = re.compile(r"([0-9a-fA-F]{2}[:-]){5}([0-9a-fA-F]{2})")


def _normalize_mac(mac: str) -> str:
    mac = mac.strip().replace("-", ":").upper()
    return mac


def read_arp_table() -> Dict[str, str]:
    os_name = get_os()
    if os_name == "windows":
        return _read_windows_arp()
    if os_name == "linux":
        return _read_linux_proc_arp()
    return {}


def get_mac_for_ip(ip: str) -> str:
    # Simple implementation: read the full ARP table and return matching IP.
    # This is called after a successful ping, which should populate ARP/neighbor cache.
    table = read_arp_table()
    return table.get(ip, "")


def _read_windows_arp() -> Dict[str, str]:
    try:
        p = subprocess.run(["arp", "-a"], capture_output=True, text=True, check=False)
        out = p.stdout or ""
    except Exception:
        return {}

    result: Dict[str, str] = {}
    # Lines look like: 192.168.88.11         0c-c4-7a-43-12-d8     dynamic
    for line in out.splitlines():
        line = line.strip()
        if not line:
            continue
        parts = re.split(r"\s+", line)
        if len(parts) >= 2 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
            ip = parts[0]
            mac = parts[1]
            if _MAC_RE.search(mac):
                result[ip] = _normalize_mac(mac)
    return result


def _read_linux_proc_arp() -> Dict[str, str]:
    path = Path("/proc/net/arp")
    if not path.exists():
        return {}
    try:
        text = path.read_text(encoding="utf-8", errors="ignore")
    except Exception:
        return {}

    result: Dict[str, str] = {}
    lines = text.splitlines()
    if not lines:
        return result

    # Skip header line
    for line in lines[1:]:
        line = line.strip()
        if not line:
            continue
        parts = re.split(r"\s+", line)
        # IP address HW type Flags HW address Mask Device
        if len(parts) >= 4 and re.match(r"^\d+\.\d+\.\d+\.\d+$", parts[0]):
            ip = parts[0]
            mac = parts[3]
            if _MAC_RE.search(mac):
                result[ip] = _normalize_mac(mac)
    return result

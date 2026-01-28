from __future__ import annotations

import os
import re
import subprocess
from typing import Dict

from .platform_utils import platform_name

# ARP lookup:
# - Windows: `arp -a`
# - Linux: `/proc/net/arp`
# Other OS: return {} (placeholder).

_MAC_RE_WIN = re.compile(r"(?P<ip>\d+\.\d+\.\d+\.\d+)\s+(?P<mac>[0-9a-fA-F\-]{11,17})")
_MAC_RE_LINUX = re.compile(r"^(?P<ip>\d+\.\d+\.\d+\.\d+)\s+\S+\s+\S+\s+(?P<mac>[0-9a-fA-F:]{17})\s+", re.M)

def _norm_mac(mac: str) -> str:
    mac = mac.strip().lower().replace("-", ":")
    parts = mac.split(":")
    if len(parts) == 6:
        return ":".join(p.zfill(2).upper() for p in parts)
    return mac.upper()

def read_arp_table() -> Dict[str, str]:
    plat = platform_name()
    out: Dict[str, str] = {}
    try:
        if plat == "windows":
            p = subprocess.run(["arp", "-a"], capture_output=True, text=True, timeout=3)
            txt = p.stdout or ""
            for m in _MAC_RE_WIN.finditer(txt):
                out[m.group("ip")] = _norm_mac(m.group("mac"))
            return out

        if plat == "linux":
            path = "/proc/net/arp"
            if not os.path.exists(path):
                return {}
            with open(path, "r", encoding="utf-8", errors="ignore") as f:
                txt = f.read()
            for m in _MAC_RE_LINUX.finditer(txt):
                out[m.group("ip")] = _norm_mac(m.group("mac"))
            return out
    except Exception:
        return {}
    return {}

def get_mac_for_ip(ip: str) -> str:
    # Read full table and return MAC for a single IP.
    return read_arp_table().get(ip, "")

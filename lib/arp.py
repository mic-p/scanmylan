from __future__ import annotations
import re
import subprocess
from typing import Dict
from .platform_utils import platform_key

_MAC_RE = re.compile(r"([0-9a-fA-F]{2}[-:]){5}[0-9a-fA-F]{2}")
_IP_RE = re.compile(r"\b(\d{1,3}(?:\.\d{1,3}){3})\b")

def _normalize_mac(mac: str) -> str:
    return mac.strip().replace("-", ":").upper()

def read_arp_table() -> Dict[str, str]:
    pk = platform_key()
    if pk == "windows":
        return _read_arp_windows()
    if pk == "linux":
        return _read_arp_linux()
    # placeholder for other OS
    return {}

def _read_arp_windows() -> Dict[str, str]:
    try:
        p = subprocess.run(["arp", "-a"], capture_output=True, text=True)
        text = (p.stdout or "") + "\n" + (p.stderr or "")
    except Exception:
        return {}
    out: Dict[str, str] = {}
    for line in text.splitlines():
        ipm = _IP_RE.search(line)
        macm = _MAC_RE.search(line)
        if not ipm or not macm:
            continue
        out[ipm.group(1)] = _normalize_mac(macm.group(0))
    return out

def _read_arp_linux() -> Dict[str, str]:
    try:
        with open("/proc/net/arp", "r", encoding="utf-8", errors="ignore") as f:
            lines = f.read().splitlines()
    except Exception:
        return {}
    out: Dict[str, str] = {}
    for line in lines[1:]:
        parts = line.split()
        if len(parts) < 4:
            continue
        ip = parts[0].strip()
        mac = parts[3].strip()
        if mac and mac != "00:00:00:00:00:00":
            out[ip] = _normalize_mac(mac)
    return out

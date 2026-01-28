from __future__ import annotations
import requests
from typing import Optional

DEFAULT_TIMEOUT_SECONDS = 3
DEFAULT_RETRY = 1

def vendor_from_mac(mac_text: str, timeout_seconds: int = DEFAULT_TIMEOUT_SECONDS, retry: int = DEFAULT_RETRY) -> str:
    mac_text = (mac_text or "").strip()
    if not mac_text:
        return ""
    url = f"https://www.macvendorlookup.com/api/v2/{mac_text}"
    last_exc: Optional[Exception] = None
    for _ in range(retry + 1):
        try:
            r = requests.get(url, timeout=timeout_seconds)
            if r.status_code != 200:
                return ""
            data = r.json()
            if isinstance(data, list) and data:
                item = data[0]
                if isinstance(item, dict):
                    return str(item.get("company") or "")
            return ""
        except Exception as e:
            last_exc = e
            continue
    return ""

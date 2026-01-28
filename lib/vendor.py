from __future__ import annotations

import requests

# Vendor lookup via https://www.macvendorlookup.com/api/v2/<mac>
# Requirements:
# - timeout 3s
# - 1 retry
# - on errors (server down, rate limit, bad JSON): return empty string (no exception)

DEFAULT_TIMEOUT = 3

def vendor_from_mac(mac_text: str, timeout: int = DEFAULT_TIMEOUT) -> str:
    mac_text = (mac_text or "").strip().lower()
    if not mac_text:
        return ""
    url = f"https://www.macvendorlookup.com/api/v2/{mac_text}"
    for attempt in range(2):
        try:
            r = requests.get(url, timeout=timeout)
            if r.status_code != 200:
                return ""
            data = r.json()
            if isinstance(data, list) and data and isinstance(data[0], dict):
                return str(data[0].get("company", "") or "")
            return ""
        except Exception:
            if attempt == 0:
                continue
            return ""
    return ""

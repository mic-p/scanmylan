"""Vendor lookup via macvendorlookup.com API.

Requirements:
- Always call remote (no cache).
- Timeout 3 seconds and 1 retry.
- Any error -> return empty string (no exception to caller).
"""

from __future__ import annotations

import requests

DEFAULT_TIMEOUT_SEC = 3
DEFAULT_RETRIES = 1


def lookup_vendor(mac: str, timeout_sec: int = DEFAULT_TIMEOUT_SEC, retries: int = DEFAULT_RETRIES) -> str:
    mac_text = (mac or "").strip().lower()
    if not mac_text:
        return ""

    url = f"https://www.macvendorlookup.com/api/v2/{mac_text}"

    last_exc = None
    for attempt in range(retries + 1):
        try:
            r = requests.get(url, timeout=timeout_sec)
            if r.status_code != 200:
                return ""
            data = r.json()
            if isinstance(data, list) and data:
                company = data[0].get("company", "")
                return (company or "").strip()
            return ""
        except Exception as e:
            last_exc = e
            continue
    return ""

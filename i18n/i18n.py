from __future__ import annotations

import json
import locale
import os
from typing import Dict

# Loads UI strings from a JSON file.
# Language is selected from OS locale; if unavailable, it falls back to English.

_STRINGS: Dict[str, Dict[str, str]] | None = None

def _load_strings() -> Dict[str, Dict[str, str]]:
    global _STRINGS
    if _STRINGS is not None:
        return _STRINGS
    here = os.path.dirname(__file__)
    path = os.path.join(here, "strings.json")
    with open(path, "r", encoding="utf-8") as f:
        _STRINGS = json.load(f)
    return _STRINGS

def get_lang() -> str:
    # Try multiple locale APIs for best portability.
    lang = None
    try:
        lang = locale.getlocale()[0]
    except Exception:
        lang = None
    if not lang:
        try:
            lang = locale.getdefaultlocale()[0]
        except Exception:
            lang = None
    if not lang:
        return "en"
    lang = lang.lower()
    if lang.startswith("it"):
        return "it"
    return "en"

def tr(key: str, lang: str | None = None) -> str:
    strings = _load_strings()
    lang = lang or get_lang()
    if lang not in strings:
        lang = "en"
    return strings.get(lang, {}).get(key, strings.get("en", {}).get(key, key))

"""Internationalization helper.

- Loads translations from i18n/strings.json.
- Picks language from OS locale:
  - If it starts with 'it' -> Italian
  - Otherwise -> English
- Fallback: English
"""

from __future__ import annotations

import json
import locale
import os
from pathlib import Path
from typing import Any, Dict


def _detect_lang() -> str:
    # Try Python locale first
    try:
        loc = locale.getdefaultlocale()[0] or ""
    except Exception:
        loc = ""

    # Fallback to environment on Unix
    if not loc:
        loc = os.environ.get("LANG", "")

    loc = (loc or "").lower()
    if loc.startswith("it"):
        return "it"
    return "en"


class I18N:
    def __init__(self, base_dir: Path):
        self.lang = _detect_lang()
        self._data: Dict[str, Dict[str, str]] = {}
        self._load(base_dir)

    def _load(self, base_dir: Path) -> None:
        path = base_dir / "i18n" / "strings.json"
        with path.open("r", encoding="utf-8") as f:
            self._data = json.load(f)

    def tr(self, key: str, **kwargs: Any) -> str:
        entry = self._data.get(key, {})
        text = entry.get(self.lang) or entry.get("en") or key
        try:
            return text.format(**kwargs)
        except Exception:
            return text

"""Tarjima: o‘zbekcha matn asosiy (kalitning o‘zi), inglizchasi ``i18n/en.json`` da.

Shablonlarda ``t("Boshqaruv paneli")`` yoziladi. Ingliz tili tanlansa, matn
``en.json`` dan olinadi; tarjima topilmasa o‘zbekcha qoladi (test buni
tekshiradi).
"""

from __future__ import annotations

import json
from functools import lru_cache
from pathlib import Path

LANGS = ("uz", "en")
_DIR = Path(__file__).resolve().parent / "i18n"


@lru_cache(maxsize=1)
def english() -> dict[str, str]:
    data = json.loads((_DIR / "en.json").read_text(encoding="utf-8"))
    return {str(k): str(v) for k, v in data.items()}


def translate(text: str, lang: str) -> str:
    if lang == "en":
        return english().get(text, text)
    return text

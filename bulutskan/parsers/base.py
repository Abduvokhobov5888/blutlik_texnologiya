"""Parserlar uchun umumiy yordamchilar."""

from __future__ import annotations

import json
from collections.abc import Mapping
from pathlib import Path
from typing import Any

#: Bitta hisobot faylining eng katta hajmi. Real hisobotlar 8 MB atrofida,
#: zaxira bilan 256 MB: undan kattasi xotirani to‘ldirish urinishi bo‘lishi mumkin.
MAX_REPORT_BYTES = 256 * 1024 * 1024


class ParseError(ValueError):
    """Hisobotni o‘qib yoki tushunib bo‘lmadi."""


def load_json(path: str | Path, max_bytes: int = MAX_REPORT_BYTES) -> Any:
    """JSON faylni o‘qiydi (UTF-8, BOM bo‘lsa ham).

    PowerShell yozgan fayllar ko‘pincha BOM bilan boshlanadi, shuning uchun
    ``utf-8-sig`` ishlatiladi.
    """
    p = Path(path)
    try:
        size = p.stat().st_size
    except OSError as exc:
        raise ParseError(f"Fayl topilmadi: {p.name}") from exc
    if size == 0:
        raise ParseError(f"Fayl bo‘sh: {p.name}")
    if size > max_bytes:
        raise ParseError(f"Fayl juda katta: {p.name} ({size} bayt)")
    try:
        with p.open(encoding="utf-8-sig") as fh:
            return json.load(fh)
    except (UnicodeDecodeError, json.JSONDecodeError) as exc:
        raise ParseError(f"JSON xato: {p.name}: {exc}") from exc


def as_mapping(value: Any, what: str) -> Mapping[str, Any]:
    """Qiymat lug‘at ekanini tekshiradi."""
    if not isinstance(value, Mapping):
        raise ParseError(f"{what}: JSON obyekt kutilgan")
    return value


def sub(mapping: Mapping[str, Any], key: str) -> dict[str, Any]:
    """Ichki obyekt; u lug‘at bo‘lmasa (yoki yo‘q bo‘lsa) bo‘sh lug‘at."""
    value = mapping.get(key)
    return dict(value) if isinstance(value, Mapping) else {}


def items(value: Any) -> list[Any]:
    """``None`` yoki ro‘yxat bo‘lmagan qiymatni bo‘sh ro‘yxatga aylantiradi."""
    return list(value) if isinstance(value, list) else []


def text(value: Any) -> str:
    """Qiymatni satrga keltiradi (``None`` → bo‘sh satr)."""
    return "" if value is None else str(value)


def optional_int(value: Any) -> int | None:
    """Butun son yoki ``None``."""
    if isinstance(value, bool):
        return None
    if isinstance(value, int):
        return value
    try:
        return int(str(value))
    except (TypeError, ValueError):
        return None

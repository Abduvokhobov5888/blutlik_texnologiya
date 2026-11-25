"""Parollar: bcrypt bilan xeshlash va tekshirish."""

from __future__ import annotations

import bcrypt

MIN_LENGTH = 12
#: bcrypt faqat birinchi 72 baytni hisobga oladi (5.x versiya undan uzunini rad etadi).
MAX_BYTES = 72
_ROUNDS = 12
# Mavjud bo‘lmagan foydalanuvchi uchun ham bir xil vaqt sarflash (vaqt bo‘yicha sizib chiqishni oldini olish).
_DUMMY_HASH = bcrypt.hashpw(b"bulutskan-dummy-password", bcrypt.gensalt(rounds=_ROUNDS))


class WeakPassword(ValueError):
    """Parol talablarga javob bermaydi."""


def check_policy(password: str) -> None:
    """Parol uzunligi: kamida 12 belgi, ko‘pi bilan 72 bayt (UTF-8)."""
    if len(password) < MIN_LENGTH:
        raise WeakPassword(f"Parol kamida {MIN_LENGTH} belgidan iborat bo‘lishi kerak")
    if len(password.encode("utf-8")) > MAX_BYTES:
        raise WeakPassword(f"Parol {MAX_BYTES} baytdan oshmasligi kerak")
    if password.strip() != password or not password.strip():
        raise WeakPassword("Parol bo‘shliq bilan boshlanmasligi va tugamasligi kerak")


def hash_password(password: str) -> str:
    check_policy(password)
    return bcrypt.hashpw(password.encode("utf-8"), bcrypt.gensalt(rounds=_ROUNDS)).decode("ascii")


def verify_password(password: str, password_hash: str | None) -> bool:
    """Parolni tekshiradi; xesh bo‘lmasa ham bcrypt bajariladi (bir xil vaqt)."""
    data = password.encode("utf-8")[:MAX_BYTES]
    if not password_hash:
        bcrypt.checkpw(data, _DUMMY_HASH)
        return False
    try:
        return bcrypt.checkpw(data, password_hash.encode("ascii"))
    except ValueError:
        return False

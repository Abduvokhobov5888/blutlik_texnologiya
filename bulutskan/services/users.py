"""Foydalanuvchilar: yaratish, o‘chirish, parol almashtirish, kirish."""

from __future__ import annotations

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from bulutskan.security.passwords import hash_password, verify_password
from bulutskan.storage.db import utcnow
from bulutskan.storage.tables import ROLE_ADMIN, ROLES, User

USERNAME_RE = r"^[a-z][a-z0-9_.-]{2,31}$"


class UserError(ValueError):
    """Foydalanuvchi amali bajarilmadi."""


def normalize_username(name: str) -> str:
    import re

    n = name.strip().lower()
    if not re.fullmatch(USERNAME_RE, n):
        raise UserError("Login 3–32 belgi: kichik lotin harfi bilan boshlanadi, harf, raqam, _ . - bo‘lishi mumkin")
    return n


def get_user(session: Session, username: str) -> User | None:
    return session.scalar(select(User).where(User.username == username.strip().lower()))


def count_users(session: Session) -> int:
    return int(session.scalar(select(func.count()).select_from(User)) or 0)


def add_user(session: Session, username: str, password: str, role: str) -> User:
    if role not in ROLES:
        raise UserError(f"Rol: {', '.join(ROLES)}")
    name = normalize_username(username)
    if get_user(session, name) is not None:
        raise UserError(f"Bunday foydalanuvchi bor: {name}")
    user = User(username=name, password_hash=hash_password(password), role=role)
    session.add(user)
    session.flush()
    return user


def set_password(session: Session, user: User, password: str) -> None:
    user.password_hash = hash_password(password)
    user.session_epoch += 1  # eski sessiyalar bekor


def disable_user(session: Session, user: User) -> None:
    user.is_active = False
    user.session_epoch += 1


def enable_user(session: Session, user: User) -> None:
    user.is_active = True


def authenticate(session: Session, username: str, password: str) -> User | None:
    """Login va parolni tekshiradi; muvaffaqiyatda ``last_login_at`` yangilanadi."""
    user = get_user(session, username)
    ok = verify_password(password, user.password_hash if user else None)
    if not ok or user is None or not user.is_active:
        return None
    user.last_login_at = utcnow()
    return user


def bootstrap_admin(session: Session, username: str | None, password: str | None) -> User | None:
    """Server rejimi: ``.env`` dagi qiymatlardan birinchi administratorni bir marta yaratadi."""
    if not username or not password:
        return None
    exists = session.scalar(select(User).where(User.role == ROLE_ADMIN))
    if exists is not None:
        return None
    return add_user(session, username, password, ROLE_ADMIN)

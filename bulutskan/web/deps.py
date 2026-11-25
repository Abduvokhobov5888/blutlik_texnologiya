"""Veb uchun umumiy holat va bog‘liqliklar: joriy foydalanuvchi, rollar, CSRF."""

from __future__ import annotations

import ipaddress
import time
from dataclasses import dataclass, field
from typing import Any

from fastapi import HTTPException, Request
from fastapi.templating import Jinja2Templates

from bulutskan.config import Settings
from bulutskan.core.ahp import AhpModel
from bulutskan.storage.db import Database
from bulutskan.storage.tables import ROLE_ADMIN, ROLE_ANALYST, ROLE_GUEST, User
from bulutskan.web.security import LoginLimiter, csrf_valid


@dataclass
class AppState:
    settings: Settings
    db: Database
    templates: Jinja2Templates
    login_limiter: LoginLimiter
    ahp: AhpModel
    demo_images: list[str]
    extra: dict[str, Any] = field(default_factory=dict)


class LoginRequired(Exception):
    """Kirish talab qilinadi (yo‘naltirish)."""


class FirstRunRequired(Exception):
    """Lokal rejim: hali administrator yo‘q."""


def state(request: Request) -> AppState:
    st: AppState = request.app.state.bulutskan
    return st


def is_loopback(request: Request) -> bool:
    host = request.client.host if request.client else ""
    if host in {"testclient", "localhost"}:
        return True
    try:
        return ipaddress.ip_address(host).is_loopback
    except ValueError:
        return False


def current_user(request: Request) -> User | None:
    """Sessiyadagi foydalanuvchi (har so‘rovda bazadan qayta o‘qiladi)."""
    if "user" in request.state._state:
        cached: User | None = request.state.user
        return cached
    st = state(request)
    uid = request.session.get("u")
    user: User | None = None
    if isinstance(uid, int):
        now = time.time()
        iat = float(request.session.get("iat", 0))
        seen = float(request.session.get("seen", 0))
        s = st.settings
        if now - iat > s.session_hours * 3600 or now - seen > s.session_idle_min * 60:
            request.session.clear()
        else:
            with st.db.session() as session:
                row = session.get(User, uid)
                if row is not None and row.is_active and row.session_epoch == request.session.get("e"):
                    user = row
                else:
                    request.session.clear()
            if user is not None and now - seen > 30:
                request.session["seen"] = now
    request.state.user = user
    return user


def login_required(request: Request) -> User:
    user = current_user(request)
    if user is None:
        raise LoginRequired()
    return user


def admin_required(request: Request) -> User:
    user = login_required(request)
    if user.role != ROLE_ADMIN:
        raise HTTPException(status_code=403, detail="Bu sahifa faqat administrator uchun")
    return user


def can_scan(user: User) -> bool:
    return user.role in (ROLE_ADMIN, ROLE_ANALYST, ROLE_GUEST)


def is_guest(user: User) -> bool:
    return user.role == ROLE_GUEST


async def csrf_protect(request: Request) -> None:
    """POST so‘rovlar uchun: ``X-CSRF-Token`` sarlavhasi yoki ``csrf_token`` maydoni."""
    token = request.headers.get("X-CSRF-Token")
    if not token:
        form = await request.form()
        value = form.get("csrf_token")
        token = value if isinstance(value, str) else None
    if not csrf_valid(request, token):
        raise HTTPException(status_code=403, detail="CSRF token noto‘g‘ri yoki eskirgan. Sahifani yangilang.")

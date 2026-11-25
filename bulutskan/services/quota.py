"""Kvota va navbat cheklovlari (``docs/arxitektura.md``, 17.5-bo‘lim)."""

from __future__ import annotations

import ipaddress
from datetime import datetime, timedelta, timezone

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from bulutskan.config import Settings
from bulutskan.security.validators import ImageReference
from bulutskan.services import jobs
from bulutskan.storage.db import utcnow
from bulutskan.storage.tables import ROLE_ADMIN, ROLE_GUEST, Scan, User

#: O‘zbekiston vaqti (UTC+5, yozgi vaqt yo‘q) — "kunlik" kvota shu bo‘yicha.
UZT = timezone(timedelta(hours=5), "UTC+5")


class QuotaExceeded(Exception):
    """Cheklov oshdi: foydalanuvchiga tushunarli xabar."""


def day_start_utc(now: datetime | None = None) -> datetime:
    local = (now or datetime.now(UZT)).astimezone(UZT)
    start = local.replace(hour=0, minute=0, second=0, microsecond=0)
    return start.astimezone(timezone.utc).replace(tzinfo=None)


def daily_limit(user: User, settings: Settings) -> int | None:
    if user.role == ROLE_ADMIN:
        return None
    return settings.quota_guest if user.role == ROLE_GUEST else settings.quota_analyst


def used_today(session: Session, user: User) -> int:
    return int(session.scalar(
        select(func.count()).select_from(Scan).where(Scan.user_id == user.id, Scan.created_at >= day_start_utc())
    ) or 0)


def remaining_today(session: Session, user: User, settings: Settings) -> int | None:
    limit = daily_limit(user, settings)
    return None if limit is None else max(0, limit - used_today(session, user))


def check_can_submit(session: Session, user: User, settings: Settings) -> None:
    """Tekshiruv yuborishdan oldingi barcha cheklovlar."""
    limit = daily_limit(user, settings)
    if limit is not None and used_today(session, user) >= limit:
        raise QuotaExceeded(f"Kunlik kvota tugadi ({limit} ta). Ertaga qayta urinib ko‘ring.")
    if settings.scan_min_interval_s and user.role != ROLE_ADMIN:
        last = session.scalar(select(func.max(Scan.created_at)).where(Scan.user_id == user.id))
        if last is not None and utcnow() - last < timedelta(seconds=settings.scan_min_interval_s):
            raise QuotaExceeded(f"Tekshiruvlar orasida kamida {settings.scan_min_interval_s} soniya bo‘lishi kerak.")
    if jobs.active_count(session) >= settings.queue_max:
        raise QuotaExceeded("Navbat to‘lgan. Birozdan keyin qayta urinib ko‘ring.")
    if jobs.active_count(session, user) >= settings.queue_per_user:
        raise QuotaExceeded(f"Sizda navbatda {settings.queue_per_user} ta tekshiruv bor. Ular tugashini kuting.")


def registry_allowed(ref: ImageReference, settings: Settings) -> bool:
    """Server rejimi: faqat ruxsat etilgan registrlar; IP va ichki nomlar rad etiladi (SSRF)."""
    if not settings.is_server:
        return True
    domain = (ref.domain or "docker.io").split(":", 1)[0].lower()
    if domain in {"localhost"} or domain.endswith((".local", ".internal", ".lan")):
        return False
    try:
        ipaddress.ip_address(domain)
        return False
    except ValueError:
        pass
    allowed = {d.lower() for d in settings.allowed_registries}
    return domain in allowed or (domain == "registry-1.docker.io" and "docker.io" in allowed)

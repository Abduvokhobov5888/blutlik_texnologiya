"""Kirish va audit jurnali."""

from __future__ import annotations

import json
import logging
from datetime import timedelta
from typing import Any

from sqlalchemy import delete
from sqlalchemy.orm import Session

from bulutskan.storage.db import utcnow
from bulutskan.storage.tables import AuditLog, User

log = logging.getLogger("bulutskan.audit")

#: Jurnalga hech qachon yozilmaydigan kalitlar.
_SECRET_KEYS = {"password", "parol", "token", "secret", "proxy", "csrf"}


def _clean(detail: dict[str, Any] | None) -> dict[str, Any]:
    out: dict[str, Any] = {}
    for k, v in (detail or {}).items():
        if any(s in k.lower() for s in _SECRET_KEYS):
            continue
        out[k] = v if isinstance(v, (int, float, bool, type(None))) else str(v)[:500]
    return out


def record(
    session: Session,
    action: str,
    *,
    user: User | None = None,
    username: str | None = None,
    ip: str | None = None,
    target: str | None = None,
    result: str = "ok",
    detail: dict[str, Any] | None = None,
) -> AuditLog:
    """Audit yozuvini qo‘shadi va JSON qator sifatida jurnalga chiqaradi."""
    entry = AuditLog(
        ts=utcnow(),
        user_id=user.id if user else None,
        username=(user.username if user else username),
        role=user.role if user else None,
        ip=ip,
        action=action,
        target=(target or None) and target[:512],
        result=result,
        detail=_clean(detail),
    )
    session.add(entry)
    log.info(json.dumps({"audit": action, "user": entry.username, "ip": ip, "target": entry.target,
                         "result": result}, ensure_ascii=False))
    return entry


def purge(session: Session, days: int) -> int:
    """``days`` kundan eski audit yozuvlarini o‘chiradi."""
    cutoff = utcnow() - timedelta(days=days)
    res = session.execute(delete(AuditLog).where(AuditLog.ts < cutoff))
    return int(getattr(res, "rowcount", 0) or 0)

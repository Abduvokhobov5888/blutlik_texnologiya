"""SQLite navbati: veb vazifa qo‘shadi, worker uni atomar oladi.

Navbat — ``scans`` jadvalining o‘zi. Veb va worker boshqa yo‘l bilan
gaplashmaydi (``docs/arxitektura.md``, 17.3-bo‘lim).
"""

from __future__ import annotations

from datetime import timedelta
from typing import Any

from sqlalchemy import func, select, update
from sqlalchemy.orm import Session

from bulutskan.storage.db import Database, utcnow
from bulutskan.storage.tables import Scan, User

ACTIVE = ("queued", "running")


def enqueue(
    session: Session,
    *,
    uid: str,
    kind: str,
    target: str,
    request: dict[str, Any],
    user: User | None = None,
    source: str = "web",
) -> Scan:
    """Yangi vazifa (``queued``)."""
    scan = Scan(uid=uid, kind=kind, target=target[:512], request=request, user_id=user.id if user else None,
                source=source, status="queued")
    session.add(scan)
    session.flush()
    return scan


def claim_next(db: Database, worker_id: str) -> int | None:
    """Navbatdagi eng eski vazifani atomar oladi (bitta ``UPDATE … RETURNING``)."""
    now = utcnow()
    oldest = (
        select(Scan.id).where(Scan.status == "queued").order_by(Scan.created_at, Scan.id).limit(1).scalar_subquery()
    )
    stmt = (
        update(Scan)
        .where(Scan.id == oldest, Scan.status == "queued")
        .values(status="running", worker_id=worker_id, started_at=now, heartbeat_at=now, attempts=Scan.attempts + 1)
        .returning(Scan.id)
        .execution_options(synchronize_session=False)
    )
    with db.engine.begin() as conn:
        row = conn.execute(stmt).fetchone()
    return int(row[0]) if row else None


def heartbeat(db: Database, scan_id: int) -> None:
    with db.engine.begin() as conn:
        conn.execute(update(Scan).where(Scan.id == scan_id, Scan.status == "running").values(heartbeat_at=utcnow()))


def requeue_stale(db: Database, max_age_s: int = 120, max_attempts: int = 2) -> tuple[int, int]:
    """Yurak urishi to‘xtagan vazifalar: bir marta qayta navbatga, keyin ``failed``."""
    cutoff = utcnow() - timedelta(seconds=max_age_s)
    stale = (Scan.status == "running", Scan.heartbeat_at < cutoff)
    with db.engine.begin() as conn:
        requeued = conn.execute(
            update(Scan).where(*stale, Scan.attempts < max_attempts).values(status="queued", worker_id=None)
        ).rowcount
        failed = conn.execute(
            update(Scan)
            .where(*stale, Scan.attempts >= max_attempts)
            .values(status="failed", finished_at=utcnow(), error="Worker to‘xtab qoldi: tekshiruv yakunlanmadi")
        ).rowcount
    return int(requeued or 0), int(failed or 0)


def queue_position(session: Session, scan: Scan) -> int:
    """Navbatdagi o‘rni (1 — keyingi); navbatda bo‘lmasa 0."""
    if scan.status != "queued":
        return 0
    ahead = session.scalar(
        select(func.count()).select_from(Scan).where(Scan.status == "queued", Scan.created_at <= scan.created_at,
                                                     Scan.id < scan.id)
    )
    return int(ahead or 0) + 1


def active_count(session: Session, user: User | None = None) -> int:
    q = select(func.count()).select_from(Scan).where(Scan.status.in_(ACTIVE))
    if user is not None:
        q = q.where(Scan.user_id == user.id)
    return int(session.scalar(q) or 0)


def active_uids(session: Session) -> set[str]:
    return set(session.scalars(select(Scan.uid).where(Scan.status.in_(ACTIVE))))

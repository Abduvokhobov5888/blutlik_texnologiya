"""SQLite ulanishi.

Veb va worker jarayonlari bitta faylni ochadi (server rejimida — umumiy
katalog orqali ikki konteyner). WAL rejimi o‘qish va yozishni bir vaqtda
bajarishga, ``busy_timeout`` esa qisqa blokirovkalarni kutishga imkon beradi.
"""

from __future__ import annotations

from collections.abc import Iterator
from contextlib import contextmanager
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from sqlalchemy import Engine, create_engine, event
from sqlalchemy.orm import Session, sessionmaker


def utcnow() -> datetime:
    """Joriy vaqt, UTC (bazada vaqt mintaqasisiz saqlanadi)."""
    return datetime.now(UTC).replace(tzinfo=None)


def make_engine(path: Path) -> Engine:
    """SQLite engine (WAL, busy_timeout, foreign_keys)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    engine = create_engine(
        f"sqlite:///{path.as_posix()}",
        connect_args={"timeout": 30, "check_same_thread": False},
    )

    @event.listens_for(engine, "connect")
    def _pragmas(dbapi_conn: Any, _record: Any) -> None:
        cur = dbapi_conn.cursor()
        cur.execute("PRAGMA journal_mode=WAL")
        cur.execute("PRAGMA busy_timeout=30000")
        cur.execute("PRAGMA foreign_keys=ON")
        cur.execute("PRAGMA synchronous=NORMAL")
        cur.close()

    return engine


class Database:
    """Engine va sessiyalar fabrikasi."""

    def __init__(self, path: Path) -> None:
        self.path = path
        self.engine = make_engine(path)
        self.sessionmaker = sessionmaker(self.engine, expire_on_commit=False)

    def init_schema(self) -> None:
        """Jadvallarni yaratadi (mavjud bo‘lsa tegmaydi)."""
        from bulutskan.storage.tables import Base

        Base.metadata.create_all(self.engine)

    @contextmanager
    def session(self) -> Iterator[Session]:
        """Tranzaksiyali sessiya: xato bo‘lsa orqaga qaytariladi."""
        session = self.sessionmaker()
        try:
            yield session
            session.commit()
        except BaseException:
            session.rollback()
            raise
        finally:
            session.close()

    def dispose(self) -> None:
        """Ulanishlarni yopadi (Windows: fayl band bo‘lib qolmasligi uchun)."""
        self.engine.dispose()

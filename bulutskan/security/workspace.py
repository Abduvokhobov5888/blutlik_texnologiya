"""Har bir tekshiruv uchun alohida vaqtinchalik katalog.

Tuzilma::

    data/workdir/{uid}/
        input/    — tekshiriladigan fayllar (konteynerga faqat o‘qish uchun ulanadi)
        out/      — KICS natija fayli (bo‘sh holda ochiladi)
        scratch/  — Grype vaqtinchalik fayllari, kerak bo‘lsa baza nusxasi

Katalog kontekst menejeri tugashi bilan (xato bo‘lsa ham) o‘chiriladi.
"""

from __future__ import annotations

import os
import secrets
import shutil
import stat
import sys
import time
from collections.abc import Callable
from pathlib import Path
from types import TracebackType


def new_uid() -> str:
    """Tasodifiy 32 belgili identifikator (URL va katalog nomi uchun)."""
    return secrets.token_hex(16)


def _make_writable_and_retry(func: Callable[[str], object], path: str) -> None:
    # Windows’da faqat o‘qish uchun belgilangan fayllar o‘chmaydi: belgini olib, qayta urinamiz.
    try:
        os.chmod(path, stat.S_IWRITE | stat.S_IREAD)
        func(path)
    except OSError:
        pass


def remove_tree(path: Path) -> None:
    """Katalogni butunlay o‘chiradi (Windows’dagi read-only fayllar bilan ham)."""
    if not path.exists():
        return
    if sys.version_info >= (3, 12):
        shutil.rmtree(path, onexc=lambda func, p, _exc: _make_writable_and_retry(func, p))
    else:  # pragma: no cover - Python 3.11
        shutil.rmtree(path, onerror=lambda func, p, _exc: _make_writable_and_retry(func, p))


class Workspace:
    """Tekshiruvning vaqtinchalik katalogi."""

    def __init__(self, root: Path, uid: str | None = None) -> None:
        self.uid = uid or new_uid()
        if not self.uid.isalnum():
            raise ValueError("uid faqat harf va raqamlardan iborat bo‘lishi kerak")
        self.root = Path(root).resolve()
        self.path = self.root / self.uid
        self.input = self.path / "input"
        self.out = self.path / "out"
        self.scratch = self.path / "scratch"

    def create(self) -> Workspace:
        """Kataloglarni yaratadi (mavjud bo‘lsa xato)."""
        self.root.mkdir(parents=True, exist_ok=True)
        self.path.mkdir(mode=0o700)
        for d in (self.input, self.out, self.scratch):
            d.mkdir(mode=0o700)
        return self

    def cleanup(self) -> None:
        """Katalogni o‘chiradi."""
        remove_tree(self.path)

    def __enter__(self) -> Workspace:
        return self.create()

    def __exit__(
        self,
        exc_type: type[BaseException] | None,
        exc: BaseException | None,
        tb: TracebackType | None,
    ) -> None:
        self.cleanup()


def purge_stale(root: Path, max_age_s: float = 6 * 3600) -> list[str]:
    """Eski (masalan, server to‘xtab qolganda qolib ketgan) kataloglarni o‘chiradi."""
    removed: list[str] = []
    base = Path(root)
    if not base.is_dir():
        return removed
    now = time.time()
    for child in base.iterdir():
        if child.is_dir() and child.name.isalnum() and now - child.stat().st_mtime > max_age_s:
            remove_tree(child)
            removed.append(child.name)
    return removed

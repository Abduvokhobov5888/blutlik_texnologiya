"""Har bir tekshiruv uchun alohida vaqtinchalik katalog.

Tuzilma::

    data/workdir/{uid}/
        input/    — tekshiriladigan fayllar (konteynerga faqat o‘qish uchun ulanadi)
        out/      — Checkov va KICS natija fayllari (bo‘sh holda ochiladi)
        scratch/  — Grype vaqtinchalik fayllari, kerak bo‘lsa baza nusxasi

Katalog kontekst menejeri tugashi bilan (xato bo‘lsa ham) o‘chiriladi.
"""

from __future__ import annotations

import logging
import os
import secrets
import shutil
import stat
import sys
import time
from collections.abc import Callable
from pathlib import Path
from types import TracebackType

log = logging.getLogger(__name__)


def new_uid() -> str:
    """Tasodifiy 32 belgili identifikator (URL va katalog nomi uchun)."""
    return secrets.token_hex(16)


def _clear_readonly_and_retry(func: Callable[..., object], path: str, exc: BaseException) -> None:
    """``rmtree`` xato ishlovchisi.

    Windows’da faqat o‘qish uchun belgilangan fayl o‘chmaydi (WinError 5):
    belgini olib, bir marta qayta urinamiz. Boshqa xatolar (masalan, fayl
    boshqa jarayonda ochiq — WinError 32) yuqoriga uzatiladi va
    :func:`remove_tree` ularni kutib, qayta urinadi.
    """
    # Faqat o‘chirish amallari qayta uriniladi. ``os.scandir``, ``os.open`` va
    # ``os.lstat`` ni qayta chaqirish xatoni jimgina yutib yuborardi.
    if not isinstance(exc, PermissionError) or func not in (os.unlink, os.remove, os.rmdir):
        raise exc
    try:
        # Joriy ruxsatlarga faqat yozish biti qo‘shiladi. Katalogdan bajarish
        # (x) biti olib tashlansa, Linux’da (root bo‘lmagan foydalanuvchida)
        # uning ichidagi fayllarni o‘chirib bo‘lmay qoladi.
        mode = stat.S_IMODE(os.lstat(path).st_mode)
        os.chmod(path, mode | stat.S_IWRITE | stat.S_IREAD)
    except OSError:
        raise exc from None
    func(path)


def remove_tree(path: Path, attempts: int = 5, delay_s: float = 0.2) -> bool:
    """Katalogni butunlay o‘chiradi.

    Windows’da fayl antivirus yoki Docker Desktop tomonidan bir lahza band
    bo‘lib qolishi mumkin (WinError 32). Shuning uchun xato bo‘lsa, bir
    necha marta ortib boruvchi pauza bilan qayta urinadi.

    Returns:
        Katalog o‘chirildi (yoki umuman yo‘q edi) — ``True``; barcha
        urinishlardan keyin ham qolgan bo‘lsa — ``False``. Qolgan katalogni
        keyinroq :func:`purge_stale` tozalaydi.
    """
    for attempt in range(attempts):
        if not path.exists():
            return True
        try:
            if sys.version_info >= (3, 12):
                shutil.rmtree(path, onexc=_clear_readonly_and_retry)
            else:  # pragma: no cover - Python 3.11
                shutil.rmtree(path, onerror=lambda f, p, ei: _clear_readonly_and_retry(f, p, ei[1]))
            return True
        except OSError as exc:
            if attempt == attempts - 1:
                log.warning("Katalogni o‘chirib bo‘lmadi: %s (%s)", path, exc)
                break
            time.sleep(delay_s * (2**attempt))
    return not path.exists()


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
        self.cleaned = False

    def create(self) -> Workspace:
        """Kataloglarni yaratadi (mavjud bo‘lsa xato)."""
        self.root.mkdir(parents=True, exist_ok=True)
        self.path.mkdir(mode=0o700)
        for d in (self.input, self.out, self.scratch):
            d.mkdir(mode=0o700)
        return self

    def cleanup(self) -> bool:
        """Katalogni o‘chiradi.

        Windows’da fayl band bo‘lsa ham tekshiruv natijasi yo‘qolmasligi
        uchun xato ko‘tarilmaydi: o‘chmay qolgan katalogni keyingi ishga
        tushishda :func:`purge_stale` tozalaydi.
        """
        self.cleaned = remove_tree(self.path)
        return self.cleaned

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
            if remove_tree(child, attempts=2, delay_s=0.1):
                removed.append(child.name)
    return removed

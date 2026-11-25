"""Linux’da Windows fayl qoidasini taqlid qilish.

Windows ochiq turgan faylni o‘chirishga, nomini o‘zgartirishga va u turgan
katalogni o‘chirishga ruxsat bermaydi (``PermissionError: [WinError 32]``).
Linux esa bunga ruxsat beradi, shuning uchun bunday xatolar bulutli testlarda
ko‘rinmaydi. :func:`install` ``io.open`` orqali ochilgan fayllarni kuzatadi
va ``os.unlink``, ``os.remove``, ``os.rmdir``, ``os.rename``, ``os.replace``
ochiq fayl ustida chaqirilsa, Windows’dagi kabi xato beradi.

Faqat ``root`` (test katalogi) ichidagi fayllar kuzatiladi: pytest va boshqa
kutubxonalarning o‘z fayllariga ta’sir qilmaydi.
"""

from __future__ import annotations

import builtins
import io
import os
from collections.abc import Callable
from pathlib import Path
from typing import Any

import pytest


class OpenFileRegistry:
    """``root`` ichida ochilgan fayllar ro‘yxati."""

    def __init__(self, root: Path) -> None:
        self.root = os.path.realpath(root)
        self._files: list[tuple[str, Any]] = []

    def track(self, file: object, handle: Any) -> None:
        if not isinstance(file, (str, os.PathLike)):
            return
        try:
            path = os.path.realpath(os.fspath(file))
        except TypeError:
            return
        if path == self.root or path.startswith(self.root + os.sep):
            self._files.append((path, handle))

    def busy(self, path: str) -> bool:
        """Fayl (yoki katalog ichidagi biror fayl) hozir ochiqmi."""
        target = os.path.realpath(path)
        self._files = [(p, h) for p, h in self._files if not h.closed]
        return any(p == target or p.startswith(target + os.sep) for p, _ in self._files)


def _resolve(path: Any, dir_fd: int | None) -> str:
    p = os.fspath(path)
    if dir_fd is not None and not os.path.isabs(p):
        try:
            base = os.readlink(f"/proc/self/fd/{dir_fd}")
        except OSError:
            return p
        return os.path.join(base, p)
    return p


def _locked(path: str) -> PermissionError:
    return PermissionError(
        13, f"[WinError 32] Jarayon faylga kira olmaydi, chunki u boshqa jarayon tomonidan band: {path!r}"
    )


def install(monkeypatch: pytest.MonkeyPatch, root: Path) -> OpenFileRegistry:
    """Windows qoidasini ``monkeypatch`` orqali yoqadi."""
    registry = OpenFileRegistry(root)
    real_open = io.open

    def tracking_open(file: Any, *args: Any, **kwargs: Any) -> Any:
        handle = real_open(file, *args, **kwargs)
        registry.track(file, handle)
        return handle

    def guard_one(real: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(path: Any, *args: Any, dir_fd: int | None = None, **kwargs: Any) -> Any:
            if registry.busy(_resolve(path, dir_fd)):
                raise _locked(os.fspath(path))
            if dir_fd is not None:
                return real(path, *args, dir_fd=dir_fd, **kwargs)
            return real(path, *args, **kwargs)

        return wrapper

    def guard_two(real: Callable[..., Any]) -> Callable[..., Any]:
        def wrapper(src: Any, dst: Any, *args: Any, **kwargs: Any) -> Any:
            for p in (src, dst):
                if registry.busy(os.fspath(p)):
                    raise _locked(os.fspath(p))
            return real(src, dst, *args, **kwargs)

        return wrapper

    monkeypatch.setattr(io, "open", tracking_open)
    monkeypatch.setattr(builtins, "open", tracking_open)
    for name in ("unlink", "remove", "rmdir"):
        monkeypatch.setattr(os, name, guard_one(getattr(os, name)))
    for name in ("rename", "replace"):
        monkeypatch.setattr(os, name, guard_two(getattr(os, name)))
    return registry

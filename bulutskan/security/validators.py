"""Obraz nomini qat’iy tekshirish.

Regex Docker havola grammatikasiga (distribution/reference) asoslangan::

    [registr[:port]/]nom[/nom...][:teg][@sha256:64_hex]

Nom harf yoki raqam bilan boshlanadi, shuning uchun ``-`` bilan boshlanuvchi
qiymat (``--privileged`` kabi) buyruq bayrog‘i sifatida talqin qilinmaydi.
Bo‘shliq, nuqta-vergul, ``$``, qo‘shtirnoq va boshqa qobiq belgilari regexga
kirmaydi.
"""

from __future__ import annotations

import re
from dataclasses import dataclass

MAX_REFERENCE_LENGTH = 255

_DOMAIN_COMPONENT = r"(?:[a-zA-Z0-9]|[a-zA-Z0-9][a-zA-Z0-9-]*[a-zA-Z0-9])"
_DOMAIN = rf"{_DOMAIN_COMPONENT}(?:\.{_DOMAIN_COMPONENT})*(?::[0-9]{{1,5}})?"
_PATH_COMPONENT = r"[a-z0-9]+(?:(?:[._]|__|-+)[a-z0-9]+)*"
_TAG = r"[A-Za-z0-9_][A-Za-z0-9_.-]{0,127}"
_DIGEST = r"sha256:[a-f0-9]{64}"

_REFERENCE = re.compile(
    rf"(?:(?P<domain>{_DOMAIN})/)?"
    rf"(?P<path>{_PATH_COMPONENT}(?:/{_PATH_COMPONENT})*)"
    rf"(?::(?P<tag>{_TAG}))?"
    rf"(?:@(?P<digest>{_DIGEST}))?"
)


class InvalidImageReference(ValueError):
    """Obraz nomi qoidalarga mos emas."""


@dataclass(frozen=True)
class ImageReference:
    """Tekshirilgan obraz havolasi."""

    raw: str
    domain: str | None
    path: str
    tag: str | None
    digest: str | None

    @property
    def name(self) -> str:
        """Repozitoriy nomi (registr bilan)."""
        return f"{self.domain}/{self.path}" if self.domain else self.path

    @property
    def file_stem(self) -> str:
        """Fayl nomi uchun xavfsiz ko‘rinish: ``nginx_1.21``."""
        return re.sub(r"[^A-Za-z0-9_.-]", "_", self.raw)


def parse_image_reference(value: str) -> ImageReference:
    """Obraz nomini tekshiradi va qismlarga ajratadi.

    Raises:
        InvalidImageReference: nom grammatikaga mos kelmasa.
    """
    if not isinstance(value, str) or not value:
        raise InvalidImageReference("Obraz nomi bo‘sh")
    if len(value) > MAX_REFERENCE_LENGTH:
        raise InvalidImageReference("Obraz nomi juda uzun")
    m = _REFERENCE.fullmatch(value)
    if m is None:
        raise InvalidImageReference(f"Obraz nomi noto‘g‘ri: {value!r}")
    domain = m.group("domain")
    path = m.group("path")
    # Birinchi qism registr bo‘lishi uchun unda nuqta yoki port bo‘lishi, yoki
    # u ``localhost`` bo‘lishi kerak; aks holda u yo‘lning bir qismi.
    if domain and not ("." in domain or ":" in domain or domain == "localhost"):
        if not re.fullmatch(_PATH_COMPONENT, domain):
            raise InvalidImageReference(f"Obraz nomi noto‘g‘ri: {value!r}")
        path = f"{domain}/{path}"
        domain = None
    return ImageReference(
        raw=value,
        domain=domain,
        path=path,
        tag=m.group("tag"),
        digest=m.group("digest"),
    )


def is_valid_image_reference(value: str) -> bool:
    """Obraz nomi to‘g‘rimi."""
    try:
        parse_image_reference(value)
    except InvalidImageReference:
        return False
    return True

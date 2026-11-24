"""Qo‘llab-quvvatlash muddati tugagan (EOL) bazaviy obrazni aniqlash.

Manbalar:

1. Trivy: ``Metadata.OS.EOSL == true``.
2. Trivy ``Metadata.OS`` va Grype ``distro`` maydonidagi distributiv nomi va
   versiyasi ichki ro‘yxatda (``resources/eol.json``).
3. Obraz nomi va tegi ichki ro‘yxatdagi runtime’ga mos (``node:16-alpine``,
   ``python:3.9-slim``).
4. Grype ``binary`` artefaktlari orasida ro‘yxatdagi runtime versiyasi bor.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bulutskan.core.models import ToolReport

DEFAULT_EOL_LIST = Path(__file__).resolve().parent.parent / "resources" / "eol.json"

#: Ogohlantirish matni (talabdagi aniq so‘zlar).
EOL_WARNING_UZ = (
    "Bazaviy obrazning qo‘llab-quvvatlash muddati tugagan. "
    "Skanerlar natijalari to‘liq emas, obrazni almashtiring."
)
EOL_WARNING_EN = (
    "The base image has reached end of life. "
    "Scanner results are incomplete; replace the image."
)


@dataclass(frozen=True)
class EolEntry:
    """Ichki ro‘yxatning bitta yozuvi."""

    id: str
    name: str
    kind: str  # distro yoki runtime
    products: tuple[str, ...]
    versions: tuple[str, ...]
    eol: str

    def matches(self, product: str | None, version: str | None) -> bool:
        """Mahsulot nomi va versiyasi shu yozuvga mos keladimi."""
        if not product or not version:
            return False
        if product.strip().lower() not in self.products:
            return False
        return any(version_matches(version, v) for v in self.versions)


@dataclass(frozen=True)
class EolReason:
    """EOL aniqlangan manba."""

    source: str  # trivy-eosl, trivy-os, grype-distro, image-ref, grype-binary
    detail: str
    entry_id: str | None = None


@dataclass
class EolResult:
    """EOL tekshiruvi natijasi."""

    reasons: list[EolReason] = field(default_factory=list)
    entries: list[EolEntry] = field(default_factory=list)

    @property
    def is_eol(self) -> bool:
        """Kamida bitta manba EOL deb topgan."""
        return bool(self.reasons)

    def to_dict(self) -> dict[str, Any]:
        """Saqlash va eksport uchun lug‘at."""
        return {
            "is_eol": self.is_eol,
            "reasons": [r.__dict__ for r in self.reasons],
            "entries": [{"id": e.id, "name": e.name, "eol": e.eol} for e in self.entries],
        }


def version_matches(version: str, prefix: str) -> bool:
    """``11.11`` → ``11`` ga mos, ``110`` esa mos emas."""
    v = version.strip().lower().lstrip("v")
    return v == prefix or (v.startswith(prefix) and not v[len(prefix)].isdigit())


def load_eol_list(path: str | Path = DEFAULT_EOL_LIST) -> list[EolEntry]:
    """Ichki EOL ro‘yxatini o‘qiydi."""
    data = json.loads(Path(path).read_text(encoding="utf-8"))
    return [
        EolEntry(
            id=e["id"],
            name=e["name"],
            kind=e["kind"],
            products=tuple(p.lower() for p in e["products"]),
            versions=tuple(e["versions"]),
            eol=e["eol"],
        )
        for e in data["entries"]
    ]


_TAG_VERSION = re.compile(r"^v?(\d+(?:\.\d+)*)")


def split_image_ref(ref: str) -> tuple[str, str | None]:
    """Obraz havolasidan (repo nomining oxirgi qismi, teg) juftligini ajratadi."""
    base = ref.split("@", 1)[0]
    last = base.rsplit("/", 1)[-1]
    if ":" in last:
        name, tag = last.split(":", 1)
        return name.lower(), tag
    return last.lower(), None


def detect_eol(
    image_ref: str | None,
    trivy: ToolReport | None,
    grype: ToolReport | None,
    entries: list[EolEntry] | None = None,
) -> EolResult:
    """Barcha manbalar bo‘yicha EOL tekshiruvi."""
    entries = entries if entries is not None else load_eol_list()
    result = EolResult()

    def add(source: str, detail: str, entry: EolEntry | None = None) -> None:
        result.reasons.append(EolReason(source=source, detail=detail, entry_id=entry.id if entry else None))
        if entry is not None and entry not in result.entries:
            result.entries.append(entry)

    distros = [e for e in entries if e.kind == "distro"]
    runtimes = [e for e in entries if e.kind == "runtime"]

    if trivy is not None:
        family = trivy.metadata.get("os_family")
        name = trivy.metadata.get("os_name")
        if trivy.metadata.get("eosl"):
            add("trivy-eosl", f"Trivy: {family} {name} (Metadata.OS.EOSL = true)")
        for e in distros:
            if e.matches(family, name):
                add("trivy-os", f"Trivy: {family} {name}", e)

    if grype is not None:
        dname = grype.metadata.get("distro_name")
        dver = grype.metadata.get("distro_version")
        for e in distros:
            if e.matches(dname, dver):
                add("grype-distro", f"Grype distro: {dname} {dver}", e)
        for bname, bver in grype.metadata.get("binaries") or []:
            for e in runtimes:
                if e.matches(bname, bver):
                    add("grype-binary", f"Grype binary: {bname} {bver}", e)

    if image_ref:
        name, tag = split_image_ref(image_ref)
        m = _TAG_VERSION.match(tag or "")
        if m:
            for e in runtimes:
                if e.matches(name, m.group(1)):
                    add("image-ref", f"Obraz nomi: {image_ref}", e)
    return result

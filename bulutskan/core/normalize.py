"""Vositalar qiymatlarini yagona ko‘rinishga keltirish.

Bu yerdagi qoidalar dissertatsiya tahlil skriptlaridan (``analyze.py``,
``stats3.py``) aynan ko‘chirilgan, shuning uchun platforma natijalari III bob
raqamlari bilan bir xil chiqadi.
"""

from __future__ import annotations

import re
from collections.abc import Iterable, Mapping
from typing import Any

from bulutskan.core.models import FindingStatus, Severity

_SEVERITY_MAP: dict[str, Severity] = {
    "CRITICAL": Severity.CRITICAL,
    "HIGH": Severity.HIGH,
    "MEDIUM": Severity.MEDIUM,
    "LOW": Severity.LOW,
    # Grype: Negligible. analyze.py uni LOW ustuniga qo‘shib sanaydi.
    "NEGLIGIBLE": Severity.LOW,
    "INFO": Severity.INFO,
    # KICS: TRACE — eng past axborot darajasi.
    "TRACE": Severity.INFO,
    "UNKNOWN": Severity.UNKNOWN,
}


def normalize_severity(value: Any) -> Severity:
    """Vosita jiddiylik qiymatini :class:`Severity` ga keltiradi.

    ``None`` yoki bo‘sh qiymat (Checkov’ning ochiq kodli versiyasida ko‘p
    uchraydi) UNKNOWN bo‘ladi: platforma darajani to‘qib chiqarmaydi.
    """
    if value is None:
        return Severity.UNKNOWN
    return _SEVERITY_MAP.get(str(value).strip().upper(), Severity.UNKNOWN)


_TRIVY_WONT_FIX = {"will_not_fix", "fix_deferred", "end_of_life"}


def trivy_status(status: str | None, fixed_version: str | None) -> FindingStatus:
    """Trivy zaifligi holati.

    ``stats3.py`` dagi kabi tuzatish mavjudligi ``FixedVersion`` bo‘sh
    emasligi bilan aniqlanadi.
    """
    if fixed_version:
        return FindingStatus.FIX_AVAILABLE
    s = (status or "").strip().lower()
    if s in _TRIVY_WONT_FIX:
        return FindingStatus.WONT_FIX
    if s == "affected":
        return FindingStatus.NO_FIX
    return FindingStatus.UNKNOWN


_GRYPE_STATES: dict[str, FindingStatus] = {
    "fixed": FindingStatus.FIX_AVAILABLE,
    "not-fixed": FindingStatus.NO_FIX,
    "wont-fix": FindingStatus.WONT_FIX,
}


def grype_status(state: str | None) -> FindingStatus:
    """Grype ``vulnerability.fix.state`` qiymatidan holat."""
    return _GRYPE_STATES.get((state or "").strip().lower(), FindingStatus.UNKNOWN)


def _related_ids(related: Iterable[Any] | None) -> Iterable[str]:
    for item in related or ():
        if isinstance(item, Mapping):
            yield str(item.get("id", ""))
        else:
            yield str(item)


def vuln_key(vuln_id: str, related: Iterable[Any] | None = None) -> str:
    """Zaiflikning vositalararo kaliti (``stats3.cve`` funksiyasi).

    ID ``CVE-`` bilan boshlansa, o‘zi; aks holda bog‘liq ID lar
    (Grype ``relatedVulnerabilities``) orasidagi birinchi CVE; u ham
    bo‘lmasa, asl ID katta harflarda (masalan, GHSA, DLA, TEMP).
    """
    vid = (vuln_id or "").upper()
    if vid.startswith("CVE-"):
        return vid
    for rid in _related_ids(related):
        if rid.upper().startswith("CVE-"):
            return rid.upper()
    return vid


def extract_cve(vuln_id: str, related: Iterable[Any] | None = None) -> str | None:
    """Faqat haqiqiy CVE identifikatorini qaytaradi, bo‘lmasa ``None``."""
    key = vuln_key(vuln_id, related)
    return key if key.startswith("CVE-") else None


_LEADING_RELATIVE = re.compile(r"^(?:\./|\.\./)+")


def canonical_path(path: str | None, mount: str | None = None) -> str:
    """Skaner ko‘rsatgan fayl yo‘lini tekshiruv ildiziga nisbatan yo‘lga keltiradi.

    Vositalar yo‘lni turlicha yozadi: Checkov ``/iac/x.tf``, KICS
    ``../../iac/x.tf``, Trivy ``x.tf``. Natija hamma uchun ``x.tf``
    bo‘ladi. ``mount`` — konteyner ichidagi ulanish katalogi nomi
    (masalan, ``scan`` yoki ``iac``).
    """
    p = (path or "").replace("\\", "/")
    p = _LEADING_RELATIVE.sub("", p).lstrip("/")
    if mount:
        prefix = mount.strip("/") + "/"
        if p.startswith(prefix):
            p = p[len(prefix) :]
    return p


def match_path(path: str | None) -> str:
    """``analyze.norm`` bilan bir xil: solishtirish uchun kichik harfli yo‘l."""
    return (path or "").replace("\\", "/").lstrip("./").lower()

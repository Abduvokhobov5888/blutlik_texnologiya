"""Bitta vosita ichidagi takroriy topilmalarni birlashtirish.

Masalan, Grype bitta paketdagi bitta CVE ni har bir joylashuv uchun, Trivy
esa bir xil kutubxonaning bir nechta nusxasi uchun alohida qaytaradi.
Birlashtirish kaliti :attr:`Finding.fingerprint` (6.4-bo‘lim).
"""

from __future__ import annotations

from collections.abc import Iterable

from bulutskan.core.models import Finding


def dedup_findings(findings: Iterable[Finding]) -> list[Finding]:
    """Bir xil kalitli topilmalarni bittaga birlashtiradi.

    Birinchi uchragan yozuv asos bo‘ladi. Qolganlaridan joylashuvlar
    qo‘shiladi, jiddiylik eng yuqorisi olinadi. ``cpe_based`` faqat barcha
    nusxalar CPE orqali topilgan bo‘lsa rost qoladi (``stats3.py`` dagi
    ``all(...)`` mantiqi), ``known_exploited`` esa bittasida bo‘lsa yetarli.
    Kirish tartibi saqlanadi.
    """
    merged: dict[str, Finding] = {}
    for f in findings:
        key = f.fingerprint
        current = merged.get(key)
        if current is None:
            merged[key] = f.model_copy(deep=True)
            continue
        for loc in f.locations:
            if loc not in current.locations:
                current.locations.append(loc)
        if f.severity.rank > current.severity.rank:
            current.severity = f.severity
        current.cpe_based = current.cpe_based and f.cpe_based
        current.known_exploited = current.known_exploited or f.known_exploited
        if not current.fixed_version and f.fixed_version:
            current.fixed_version = f.fixed_version
            current.status = f.status
        if not current.title and f.title:
            current.title = f.title
    return list(merged.values())

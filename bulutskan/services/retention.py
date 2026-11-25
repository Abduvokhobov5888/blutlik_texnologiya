"""Saqlash muddati: hisobotlar va topilmalar ``N`` kundan keyin o‘chiriladi.

``SCAN`` qatori (kim, qachon, nimani tekshirgani va xulosa sonlari) audit
uchun qoladi; namoyish tekshiruvlari o‘chirilmaydi.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import delete, select
from sqlalchemy.orm import Session

from bulutskan.config import Settings
from bulutskan.security.workspace import remove_tree
from bulutskan.storage.db import utcnow
from bulutskan.storage.tables import FindingGroupRow, FindingRow, Scan, ToolRunRow


def purge_expired(session: Session, settings: Settings) -> int:
    """Muddati o‘tgan tekshiruvlar tafsilotlarini o‘chiradi; nechta tekshiruv tozalanganini qaytaradi."""
    days = settings.effective_retention_days
    if days <= 0:
        return 0
    cutoff = utcnow() - timedelta(days=days)
    scans = list(
        session.scalars(
            select(Scan).where(Scan.is_demo.is_(False), Scan.purged_at.is_(None), Scan.finished_at.is_not(None),
                               Scan.finished_at < cutoff)
        )
    )
    for scan in scans:
        session.execute(delete(FindingGroupRow).where(FindingGroupRow.scan_id == scan.id))
        session.execute(delete(FindingRow).where(FindingRow.scan_id == scan.id))
        for run in session.scalars(select(ToolRunRow).where(ToolRunRow.scan_id == scan.id)):
            run.raw_report_path = None
        remove_tree(settings.reports_dir / scan.uid, attempts=2, delay_s=0.1)
        scan.purged_at = utcnow()
    return len(scans)

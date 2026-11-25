"""CLI natijasini tarixga yozish va DOCX hisobot yaratish.

DOCX hisobot bazadagi yozuvdan quriladi (veb-interfeys bilan bir xil). CLI
``--save`` siz ishlaganda vaqtinchalik bazadan foydalaniladi: tarixga hech
narsa yozilmaydi.
"""

from __future__ import annotations

import tempfile
from pathlib import Path
from typing import Any

from bulutskan.reporting.docx_report import build_docx
from bulutskan.reporting.scan_view import load_view
from bulutskan.security.workspace import new_uid
from bulutskan.services.pipeline import ScanOutcome
from bulutskan.storage.db import Database
from bulutskan.storage.repo import save_outcome, scan_by_uid
from bulutskan.storage.tables import Scan


def record_outcome(db: Database, outcome: ScanOutcome, source: str = "cli",
                   request: dict[str, Any] | None = None) -> str:
    """Natijani ``scans`` jadvaliga yozadi va uning ``uid`` sini qaytaradi."""
    with db.session() as s:
        scan = Scan(uid=new_uid(), kind=outcome.kind.value, target=outcome.target[:512], source=source,
                    status="running", request=request or {})
        s.add(scan)
        s.flush()
        save_outcome(s, scan, outcome)
        return scan.uid


def docx_for(db: Database, uid: str) -> bytes:
    """Bazadagi tekshiruv bo‘yicha DOCX hisobot."""
    with db.session() as s:
        scan = scan_by_uid(s, uid)
        if scan is None:
            raise KeyError(uid)
        return build_docx(load_view(s, scan))


def docx_from_outcome(outcome: ScanOutcome) -> bytes:
    """Tarixga yozmasdan DOCX: vaqtinchalik baza ichida quriladi."""
    with tempfile.TemporaryDirectory(prefix="bulutskan-docx-", ignore_cleanup_errors=True) as tmp:
        db = Database(Path(tmp) / "hisobot.db")
        try:
            db.init_schema()
            return docx_for(db, record_outcome(db, outcome))
        finally:
            db.dispose()  # Windows: ochiq baza faylini o‘chirib bo‘lmaydi


def write_docx(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_bytes(data)

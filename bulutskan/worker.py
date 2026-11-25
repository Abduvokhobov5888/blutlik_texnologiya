"""Navbatdan tekshiruvlarni olib bajaruvchi worker.

Lokal rejimda u ``bulutskan serve`` ichidagi oqim, server rejimida alohida
``bulutskan worker`` jarayoni. Docker’ga faqat worker murojaat qiladi; veb
bilan aloqa faqat SQLite navbati orqali (``services.jobs``).
"""

from __future__ import annotations

import logging
import os
import socket
import threading
import time
from collections.abc import Callable
from pathlib import Path
from typing import Any

from bulutskan.config import Settings
from bulutskan.core.categories import DEFAULT_IAC_ROOT
from bulutskan.scanner.docker import DockerClient
from bulutskan.scanner.tools import IntegrityError
from bulutskan.security.upload_guard import UploadRejected, stage_directory
from bulutskan.security.workspace import Workspace, purge_stale
from bulutskan.services import audit, jobs, retention
from bulutskan.services.pipeline import Scanner, ScanOutcome
from bulutskan.storage.db import Database, utcnow
from bulutskan.storage.repo import save_outcome
from bulutskan.storage.tables import Scan

log = logging.getLogger(__name__)

HEARTBEAT_S = 15
POLL_S = 1.0
HOUSEKEEPING_S = 3600


class _Heartbeat:
    """Vazifa bajarilayotganda har 15 soniyada ``heartbeat_at`` ni yangilaydi."""

    def __init__(self, db: Database, scan_id: int, interval: float = HEARTBEAT_S) -> None:
        self.db, self.scan_id, self.interval = db, scan_id, interval
        self._stop = threading.Event()
        self._thread = threading.Thread(target=self._run, daemon=True)

    def _run(self) -> None:
        while not self._stop.wait(self.interval):
            try:
                jobs.heartbeat(self.db, self.scan_id)
            except Exception:  # noqa: BLE001 - yurak urishi tekshiruvni to‘xtatmasligi kerak
                log.exception("heartbeat")

    def __enter__(self) -> _Heartbeat:
        self._thread.start()
        return self

    def __exit__(self, *exc: object) -> None:
        self._stop.set()
        self._thread.join(timeout=5)


class Worker:
    """Navbat ishchisi."""

    def __init__(
        self,
        settings: Settings,
        db: Database,
        client_factory: Callable[[], DockerClient] | None = None,
        worker_id: str | None = None,
    ) -> None:
        self.settings = settings
        self.db = db
        self.client_factory = client_factory or (lambda: DockerClient(docker_bin=settings.docker_bin))
        self.worker_id = worker_id or f"{socket.gethostname()}:{os.getpid()}"
        self._last_housekeeping = 0.0

    # ------------------------------------------------------------ bitta vazifa

    def process_one(self) -> bool:
        """Navbatdan bitta vazifani olib bajaradi; vazifa bo‘lmasa ``False``."""
        scan_id = jobs.claim_next(self.db, self.worker_id)
        if scan_id is None:
            return False
        with _Heartbeat(self.db, scan_id):
            self._run(scan_id)
        return True

    def _run(self, scan_id: int) -> None:
        with self.db.session() as s:
            scan = s.get(Scan, scan_id)
            assert scan is not None
            uid, kind, target, request, source = scan.uid, scan.kind, scan.target, dict(scan.request), scan.source
            audit.record(s, "scan_started", username=scan.user.username if scan.user else None, target=target,
                         detail={"uid": uid, "kind": kind})
        ws = Workspace(self.settings.workdir, uid=uid)
        if not ws.path.exists():
            ws.create()
        try:
            outcome = self._execute(ws, kind, target, request, source)
        except (IntegrityError, UploadRejected, ValueError, RuntimeError, OSError) as exc:
            self._fail(scan_id, str(exc))
            return
        except Exception as exc:  # noqa: BLE001 - kutilmagan xato ham vazifani yopishi kerak
            log.exception("Tekshiruv xatosi")
            self._fail(scan_id, f"Kutilmagan xato: {exc}")
            return
        finally:
            ws.cleanup()  # yuklangan fayllar va .tar tekshiruvdan keyin o‘chiriladi
        with self.db.session() as s:
            scan = s.get(Scan, scan_id)
            assert scan is not None
            save_outcome(s, scan, outcome)
            audit.record(s, "scan_finished" if outcome.status != "failed" else "scan_failed",
                         username=scan.user.username if scan.user else None, target=target,
                         result="ok" if outcome.status == "done" else "failed",
                         detail={"uid": uid, "status": outcome.status})

    def _execute(self, ws: Workspace, kind: str, target: str, request: dict[str, Any], source: str) -> ScanOutcome:
        scanner = Scanner(self.settings, self.client_factory())
        if kind == "iac":
            files = [str(f) for f in request.get("files") or []]
            skipped = [str(f) for f in request.get("skipped") or []]
            if request.get("demo"):
                accepted = stage_directory(DEFAULT_IAC_ROOT, ws.input)
                files, skipped = accepted.files, accepted.skipped
            return scanner.scan_iac_workspace(ws, target, files, skipped, source=source)
        if request.get("image"):
            return scanner.scan_image(str(request["image"]), source=source, ws=ws)
        if request.get("tar"):
            name = request.get("image_name")
            return scanner.scan_image_workspace(ws, str(request["tar"]), str(name) if name else None, source=source)
        raise ValueError("Vazifada obraz nomi ham, .tar fayl ham yo‘q")

    def _fail(self, scan_id: int, message: str) -> None:
        with self.db.session() as s:
            scan = s.get(Scan, scan_id)
            assert scan is not None
            scan.status = "failed"
            scan.error = message[:4000]
            scan.finished_at = utcnow()
            audit.record(s, "scan_failed", username=scan.user.username if scan.user else None, target=scan.target,
                         result="failed", detail={"uid": scan.uid, "error": message[:300]})

    # ------------------------------------------------------------ xizmat

    def housekeeping(self) -> None:
        """Eski kataloglar, to‘xtab qolgan vazifalar, saqlash muddati."""
        jobs.requeue_stale(self.db)
        with self.db.session() as s:
            active = jobs.active_uids(s)
        root = Path(self.settings.workdir)
        if root.is_dir():
            for child in root.iterdir():
                if child.name in active:
                    os.utime(child)  # navbatdagi vazifa katalogi o‘chirilmasin
        purge_stale(root)
        with self.db.session() as s:
            purged = retention.purge_expired(s, self.settings)
            removed = audit.purge(s, self.settings.audit_retention_days)
            if purged or removed:
                audit.record(s, "retention_cleanup", detail={"scans": purged, "audit_rows": removed})

    def run_forever(self, stop: threading.Event, slots: int | None = None) -> None:
        """``slots`` ta parallel oqim bilan navbatni kuzatadi."""
        n = slots or self.settings.effective_worker_slots

        def loop() -> None:
            while not stop.is_set():
                try:
                    if not self.process_one():
                        stop.wait(POLL_S)
                except Exception:  # noqa: BLE001
                    log.exception("Worker oqimi xatosi")
                    stop.wait(5)

        threads = [threading.Thread(target=loop, name=f"bulutskan-worker-{i}", daemon=True) for i in range(n)]
        for t in threads:
            t.start()
        while not stop.is_set():
            if time.monotonic() - self._last_housekeeping > HOUSEKEEPING_S:
                try:
                    self.housekeeping()
                except Exception:  # noqa: BLE001
                    log.exception("Housekeeping xatosi")
                self._last_housekeeping = time.monotonic()
            stop.wait(5)
        for t in threads:
            t.join(timeout=30)

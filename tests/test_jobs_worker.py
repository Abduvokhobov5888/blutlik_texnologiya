"""Navbat va worker: atomar olish, yurak urishi, to‘liq tekshiruv soxta docker bilan."""

import threading

from bulutskan.scanner.docker import DockerClient
from bulutskan.security.workspace import Workspace, new_uid
from bulutskan.services import jobs
from bulutskan.storage.repo import scan_by_uid
from bulutskan.storage.tables import AuditLog, Scan
from bulutskan.worker import Worker
from sqlalchemy import select
from tests.conftest import ch3_row
from tests.fakes import FakeDocker


def _enqueue(db, **kw):
    uid = kw.pop("uid", new_uid())
    with db.session() as s:
        jobs.enqueue(s, uid=uid, **kw)
    return uid


def test_claim_is_atomic_and_fifo(db) -> None:
    a = _enqueue(db, kind="image", target="a", request={"image": "alpine:3.20"})
    b = _enqueue(db, kind="image", target="b", request={"image": "alpine:3.18"})
    claimed: list[int] = []
    lock = threading.Lock()

    def claim() -> None:
        scan_id = jobs.claim_next(db, "w")
        if scan_id is not None:
            with lock:
                claimed.append(scan_id)

    threads = [threading.Thread(target=claim) for _ in range(8)]
    for t in threads:
        t.start()
    for t in threads:
        t.join()
    assert len(claimed) == 2 and len(set(claimed)) == 2
    with db.session() as s:
        first = scan_by_uid(s, a)
        assert first is not None and first.status == "running" and first.attempts == 1
        assert scan_by_uid(s, b) is not None
    assert jobs.claim_next(db, "w") is None


def test_stale_jobs_are_requeued_then_failed(db) -> None:
    uid = _enqueue(db, kind="image", target="a", request={"image": "alpine:3.20"})
    jobs.claim_next(db, "w1")
    assert jobs.requeue_stale(db, max_age_s=-1) == (1, 0)
    jobs.claim_next(db, "w2")
    assert jobs.requeue_stale(db, max_age_s=-1) == (0, 1)
    with db.session() as s:
        scan = scan_by_uid(s, uid)
        assert scan is not None and scan.status == "failed" and "to‘xtab qoldi" in (scan.error or "")


def _worker(settings, db, fake):
    return Worker(settings, db, client_factory=lambda: DockerClient(fake), worker_id="test")


def test_worker_runs_image_job_and_cleans_up(settings, db) -> None:
    fake = FakeDocker(settings)
    fake.install_tools()
    fake.install_databases()
    uid = _enqueue(db, kind="image", target="nginx:1.21", request={"image": "nginx:1.21"})
    assert _worker(settings, db, fake).process_one() is True
    with db.session() as s:
        scan = scan_by_uid(s, uid)
        assert scan is not None and scan.status == "done"
        assert abs(scan.jaccard["trivy|grype"] - ch3_row("nginx:1.21")["j"]) < 1e-12
        actions = [a.action for a in s.scalars(select(AuditLog).order_by(AuditLog.id))]
        assert actions == ["scan_started", "scan_finished"]
    assert not (settings.workdir / uid).exists()


def test_worker_runs_uploaded_iac_job(settings, db) -> None:
    fake = FakeDocker(settings)
    fake.install_tools()
    fake.install_databases()
    ws = Workspace(settings.workdir).create()
    (ws.input / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    _enqueue(db, uid=ws.uid, kind="iac", target="main.tf", request={"files": ["main.tf"], "skipped": []})
    assert _worker(settings, db, fake).process_one()
    with db.session() as s:
        scan = scan_by_uid(s, ws.uid)
        assert scan is not None and scan.status == "done" and scan.files == ["main.tf"]
    assert not ws.path.exists()  # yuklangan fayllar tekshiruvdan keyin o‘chirildi


def test_worker_demo_iac_job_matches_experiment(settings, db, summary) -> None:
    fake = FakeDocker(settings)
    fake.install_tools()
    fake.install_databases()
    uid = _enqueue(db, kind="iac", target="Namoyish", request={"demo": True})
    assert _worker(settings, db, fake).process_one()
    with db.session() as s:
        scan = scan_by_uid(s, uid)
        assert scan is not None and scan.status == "done"
        assert scan.ground_truth["tools"]["KICS"]["tp"] == summary["iac_summary"]["KICS"]["tp"]


def test_integrity_problem_fails_job_with_message(settings, db) -> None:
    fake = FakeDocker(settings)
    fake.install_databases()  # vositalar o‘rnatilmagan
    uid = _enqueue(db, kind="image", target="nginx:1.21", request={"image": "nginx:1.21"})
    assert _worker(settings, db, fake).process_one()
    with db.session() as s:
        scan = scan_by_uid(s, uid)
        assert scan is not None and scan.status == "failed" and "bloklandi" in (scan.error or "")
    assert fake.runs() == []
    assert not (settings.workdir / uid).exists()


def test_worker_housekeeping_keeps_queued_workspaces(settings, db) -> None:
    import os

    ws = Workspace(settings.workdir).create()
    os.utime(ws.path, (0, 0))
    _enqueue(db, uid=ws.uid, kind="iac", target="x", request={"files": []})
    orphan = Workspace(settings.workdir).create()
    os.utime(orphan.path, (0, 0))
    _worker(settings, db, FakeDocker(settings)).housekeeping()
    assert ws.path.exists() and not orphan.path.exists()


def test_run_forever_stops(settings, db) -> None:
    stop = threading.Event()
    w = _worker(settings, db, FakeDocker(settings))
    w._last_housekeeping = float("inf")  # housekeeping’ni o‘tkazib yuborish
    t = threading.Thread(target=w.run_forever, args=(stop, 2))
    t.start()
    stop.set()
    t.join(timeout=15)
    assert not t.is_alive()


def test_queue_position(db) -> None:
    a = _enqueue(db, kind="image", target="a", request={})
    b = _enqueue(db, kind="image", target="b", request={})
    with db.session() as s:
        sa, sb = scan_by_uid(s, a), scan_by_uid(s, b)
        assert sa is not None and sb is not None
        assert jobs.queue_position(s, sa) == 1 and jobs.queue_position(s, sb) == 2
        assert jobs.active_count(s) == 2
        assert isinstance(sa, Scan)

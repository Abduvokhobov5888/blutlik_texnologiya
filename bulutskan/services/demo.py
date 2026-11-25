"""Namoyish ma’lumotlarini import qilish (``bulutskan demo-import``).

III bob eksperimentining real hisobotlari (``demo/sinov/natijalar``) Docker
va internetsiz bazaga yoziladi: 15 ta obraz va namoyish IaC fayllari. Vaqtlar
ham o‘ylab topilmaydi: hisobot yaratilgan vaqt (``CreatedAt``) va
``timings.csv`` dagi birinchi takror davomiyligi olinadi.
"""

from __future__ import annotations

import csv
import json
import logging
from datetime import datetime
from pathlib import Path
from typing import Any

from sqlalchemy import delete, select

from bulutskan.config import RESOURCES, demo_root
from bulutskan.core.categories import DEFAULT_IAC_ROOT, load_sources
from bulutskan.core.models import ScanKind, Tool, ToolReport
from bulutskan.parsers import load_json, parse_checkov, parse_grype, parse_kics, parse_trivy_config, parse_trivy_image
from bulutskan.scanner.tools import load_tool_digests
from bulutskan.services.pipeline import ScanOutcome, outcome_from_reports
from bulutskan.storage.db import Database
from bulutskan.storage.repo import save_outcome
from bulutskan.storage.tables import Scan
from bulutskan.security.workspace import new_uid

log = logging.getLogger(__name__)

IAC_TARGET = "Namoyish IaC fayllari (III bob)"


def demo_available(root: Path | None = None) -> bool:
    r = root or demo_root()
    return (r / "natijalar" / "tahlil" / "ch3.json").is_file()


def demo_images(root: Path) -> list[str]:
    """Eksperimentdagi obrazlar (``stats3.py`` guruhlari tartibida)."""
    data = json.loads((root / "natijalar" / "tahlil" / "ch3.json").read_text(encoding="utf-8"))
    return [r["image"] for r in data["images"]]


def _stem(image: str) -> str:
    return image.replace("/", "_").replace(":", "_")


def _timings(root: Path) -> dict[tuple[str, str], float]:
    """``timings.csv``: oxirgi to‘liq ishga tushirishning 1-takrori (``analyze.py`` mantig‘i)."""
    path = root / "natijalar" / "timings.csv"
    if not path.is_file():
        return {}
    with path.open(encoding="utf-8-sig", newline="") as fh:
        rows = list(csv.DictReader(fh, delimiter=";"))
    starts = [i for i, r in enumerate(rows) if r["tool"].strip() == "checkov" and r["run"].strip() == "1"]
    if starts:
        rows = rows[starts[-1]:]
    out: dict[tuple[str, str], float] = {}
    for r in rows:
        if r["run"].strip() == "1":
            try:
                out[(r["tool"].strip(), r["target"].strip())] = float(r["seconds"])
            except ValueError:
                continue
    return out


def _image_digests(root: Path) -> dict[str, str]:
    path = root / "natijalar" / "image_digests.txt"
    out: dict[str, str] = {}
    if path.is_file():
        for line in path.read_text(encoding="utf-8-sig").splitlines():
            if "->" in line:
                left, right = (x.strip() for x in line.split("->", 1))
                out[left] = right
    return out


def _parse_ts(raw: object) -> datetime | None:
    """``2026-11-24T18:23:26.4255Z`` → UTC vaqt (soniyagacha)."""
    try:
        return datetime.fromisoformat(str(raw)[:19])
    except ValueError:
        return None


def _created(report: ToolReport) -> datetime | None:
    raw = report.metadata.get("created_at")
    return _parse_ts(raw) if raw else None


def _tool_refs() -> dict[Tool, str]:
    reg = load_tool_digests(RESOURCES / "tool_digests.txt")
    refs = {t: img.digest_ref for t, img in reg.images.items()}
    refs[Tool.CHECKOV] = f"{reg.checkov_tag} (mahalliy obraz)"
    return refs


def build_demo_outcomes(root: Path | None = None) -> list[tuple[ScanOutcome, datetime | None]]:
    """Namoyish natijalari (bazaga yozmasdan)."""
    r = root or demo_root()
    nat = r / "natijalar"
    timings = _timings(r)
    refs = _tool_refs()
    digests = _image_digests(r)
    out: list[tuple[ScanOutcome, datetime | None]] = []

    run1 = nat / "iac" / "run1"
    iac_reports = {
        Tool.CHECKOV: parse_checkov(load_json(run1 / "checkov" / "results_json.json"), mount="iac"),
        Tool.KICS: parse_kics(load_json(run1 / "kics" / "results.json"), mount="iac"),
        Tool.TRIVY: parse_trivy_config(load_json(run1 / "trivy_config.json"), mount="iac"),
    }
    targets = sorted({f.target for rep in iac_reports.values() for f in rep.findings})
    iac = outcome_from_reports(ScanKind.IAC, IAC_TARGET, iac_reports, sources=load_sources(DEFAULT_IAC_ROOT, targets))
    names = {Tool.CHECKOV: "checkov", Tool.KICS: "kics", Tool.TRIVY: "trivy-config"}
    for run in iac.tool_runs:
        run.duration_s = timings.get((names[run.tool], "iac"), 0.0)
        run.image_ref = refs[run.tool]
    try:
        iac_created = _parse_ts(json.loads((run1 / "trivy_config.json").read_text(encoding="utf-8-sig"))["CreatedAt"])
    except (KeyError, json.JSONDecodeError):
        iac_created = None
    out.append((iac, iac_created))

    for image in demo_images(r):
        trivy = parse_trivy_image(load_json(nat / "images" / f"trivy_{_stem(image)}_run1.json"))
        grype = parse_grype(load_json(nat / "images" / f"grype_{_stem(image)}_run1.json"))
        outcome = outcome_from_reports(ScanKind.IMAGE, image, {Tool.TRIVY: trivy, Tool.GRYPE: grype}, image_ref=image)
        outcome.image = {"reference": image, "repo_digests": [digests[image]] if image in digests else [],
                         "archive_type": "docker-archive"}
        for run in outcome.tool_runs:
            run.duration_s = timings.get((run.tool.value, image), 0.0)
            run.image_ref = refs[run.tool]
        out.append((outcome, _created(trivy)))
    return out


def import_demo(db: Database, force: bool = False, root: Path | None = None) -> int:
    """Namoyish tekshiruvlarini bazaga yozadi; yozilganlar sonini qaytaradi.

    Allaqachon import qilingan bo‘lsa, ``force`` bo‘lmasa hech narsa qilmaydi.
    """
    r = root or demo_root()
    if not demo_available(r):
        log.warning("Namoyish ma’lumotlari topilmadi: %s", r)
        return 0
    with db.session() as s:
        existing = s.scalar(select(Scan.id).where(Scan.is_demo.is_(True)).limit(1))
        if existing is not None and not force:
            return 0
        if force:
            for scan in s.scalars(select(Scan).where(Scan.is_demo.is_(True))):
                s.delete(scan)
    count = 0
    for outcome, created in build_demo_outcomes(r):
        with db.session() as s:
            scan = Scan(uid=new_uid(), kind=outcome.kind.value, target=outcome.target, source="demo",
                        status="running", is_demo=True, request={"demo": True})
            if created is not None:
                scan.created_at = created
                scan.started_at = created
            s.add(scan)
            s.flush()
            save_outcome(s, scan, outcome)
            scan.integrity = {"demo": True, "note": "III bob eksperimenti hisobotlari (run1)"}
            if created is not None:
                scan.finished_at = created
        count += 1
    return count


def demo_scan_count(db: Database) -> int:
    with db.session() as s:
        return len(list(s.scalars(select(Scan.id).where(Scan.is_demo.is_(True)))))


def delete_demo(db: Database) -> None:
    with db.session() as s:
        s.execute(delete(Scan).where(Scan.is_demo.is_(True)))


def demo_summary_rows(db: Database) -> list[dict[str, Any]]:
    """Test va panel uchun: namoyish tekshiruvlari xulosasi."""
    with db.session() as s:
        return [
            {"target": sc.target, "kind": sc.kind, "jaccard": sc.jaccard, "consensus": sc.consensus}
            for sc in s.scalars(select(Scan).where(Scan.is_demo.is_(True)).order_by(Scan.id))
        ]

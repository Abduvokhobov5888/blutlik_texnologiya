"""Tekshiruv quvuri: skaner → parser → dedup → konsensus → EOL.

Veb-interfeys va CLI bir xil funksiyalarni chaqiradi. Tahlil qismi
(:func:`analyze_iac`, :func:`analyze_image`) Docker’siz ham ishlaydi va
testlarda hamda ``demo-import`` da real hisobotlar bilan ishlatiladi.
"""

from __future__ import annotations

from collections import Counter
from collections.abc import Mapping
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from bulutskan.config import Settings
from bulutskan.core.categories import (
    DEFAULT_IAC_ROOT,
    GroundTruth,
    GroundTruthEvaluation,
    build_block_maps,
    evaluate_ground_truth,
    load_sources,
)
from bulutskan.core.consensus import ConsensusResult, iac_consensus, image_consensus, tool_order
from bulutskan.core.dedup import dedup_findings
from bulutskan.core.eol import EolResult, detect_eol
from bulutskan.core.models import SEVERITY_ORDER, ScanKind, Severity, Tool, ToolReport
from bulutskan.core.normalize import match_path
from bulutskan.scanner.docker import DockerClient
from bulutskan.scanner.iac import run_iac_tools
from bulutskan.scanner.image import ImageInput, existing_tar, pull_and_save, run_image_tools
from bulutskan.scanner.runs import ToolRun
from bulutskan.scanner.tools import IntegrityError, IntegrityReport, load_tool_digests, verify_tools
from bulutskan.security.upload_guard import UploadLimits, stage_directory
from bulutskan.security.validators import parse_image_reference
from bulutskan.security.workspace import Workspace, new_uid


class ScanStatus:
    """Tekshiruv holatlari (bazada ham shu qiymatlar)."""

    QUEUED = "queued"
    RUNNING = "running"
    DONE = "done"
    PARTIAL = "partial"
    FAILED = "failed"


@dataclass
class ScanOutcome:
    """Bitta tekshiruvning to‘liq natijasi."""

    uid: str
    kind: ScanKind
    target: str
    status: str
    tool_runs: list[ToolRun] = field(default_factory=list)
    consensus: ConsensusResult | None = None
    eol: EolResult | None = None
    gt_evaluation: GroundTruthEvaluation | None = None
    files: list[str] = field(default_factory=list)
    skipped_files: list[str] = field(default_factory=list)
    image: dict[str, Any] = field(default_factory=dict)
    integrity: dict[str, Any] = field(default_factory=dict)
    started_at: str = field(default_factory=lambda: _now())
    finished_at: str | None = None
    error: str | None = None
    source: str = "cli"

    @property
    def reports(self) -> dict[Tool, ToolReport]:
        """Muvaffaqiyatli ishlagan vositalar hisobotlari."""
        return {r.tool: r.report for r in self.tool_runs if r.ok and r.report is not None}

    def severity_table(self) -> dict[str, dict[str, int]]:
        """Vosita × daraja jadvali (takrorlar birlashtirilgan topilmalar)."""
        table: dict[str, dict[str, int]] = {}
        for tool, report in self.reports.items():
            counts = Counter(f.severity for f in report.findings)
            table[tool.value] = {s.value: counts.get(s, 0) for s in SEVERITY_ORDER}
        return table


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _status(runs: list[ToolRun]) -> str:
    ok = sum(1 for r in runs if r.ok)
    if ok == len(runs) and runs:
        return ScanStatus.DONE
    return ScanStatus.PARTIAL if ok else ScanStatus.FAILED


# ------------------------------------------------------------------ tahlil


def deduplicated(reports: Mapping[Tool, ToolReport]) -> dict[Tool, ToolReport]:
    """Har bir hisobot topilmalarini birlashtiradi (asl hisobotlar o‘zgarmaydi)."""
    out: dict[Tool, ToolReport] = {}
    for tool in tool_order(reports):
        rep = reports[tool]
        out[tool] = rep.model_copy(update={"findings": dedup_findings(rep.findings)})
    return out


def _gt_applicable(sources: Mapping[str, str], gt: GroundTruth, iac_root: Path) -> bool:
    """Tekshirilgan fayllar orasida ground truth fayllari aynan (o‘zgarishsiz) bormi."""
    gt_files = {r.insecure_file for r in gt.rules} | {r.secure_file for r in gt.rules}
    for path, text in sources.items():
        for gt_file in gt_files:
            if match_path(path).endswith(match_path(gt_file)):
                ref = iac_root / gt_file
                if ref.is_file() and ref.read_text(encoding="utf-8") == text:
                    return True
    return False


def analyze_iac(
    raw_reports: Mapping[Tool, ToolReport],
    sources: Mapping[str, str],
    gt: GroundTruth | None = None,
    iac_root: Path = DEFAULT_IAC_ROOT,
) -> tuple[dict[Tool, ToolReport], ConsensusResult, GroundTruthEvaluation | None]:
    """IaC hisobotlari tahlili.

    Returns:
        (birlashtirilgan hisobotlar, konsensus, GT baholash yoki ``None``).
        GT baholash faqat namoyish fayllari o‘zgarishsiz tekshirilganda
        hisoblanadi va ``analyze.py`` kabi asl (birlashtirilmagan) topilmalarda.
    """
    gt = gt or GroundTruth.load()
    reports = deduplicated(raw_reports)
    block_maps = build_block_maps(sources)
    consensus = iac_consensus({t: r.findings for t, r in reports.items()}, gt, block_maps)
    evaluation = None
    if _gt_applicable(sources, gt, iac_root):
        names = {Tool.CHECKOV: "Checkov", Tool.KICS: "KICS", Tool.TRIVY: "Trivy (config)"}
        evaluation = evaluate_ground_truth(
            {names[t]: raw_reports[t].findings for t in tool_order(raw_reports)}, gt
        )
    return reports, consensus, evaluation


def analyze_image(
    raw_reports: Mapping[Tool, ToolReport],
    image_ref: str | None,
) -> tuple[dict[Tool, ToolReport], ConsensusResult, EolResult]:
    """Obraz hisobotlari tahlili: konsensus va EOL."""
    reports = deduplicated(raw_reports)
    consensus = image_consensus({t: r.findings for t, r in reports.items()})
    eol = detect_eol(image_ref, raw_reports.get(Tool.TRIVY), raw_reports.get(Tool.GRYPE))
    return reports, consensus, eol


# ---------------------------------------------------------------- skaner


class Scanner:
    """Docker orqali haqiqiy tekshiruvni bajaruvchi xizmat."""

    def __init__(self, settings: Settings, client: DockerClient | None = None) -> None:
        self.settings = settings
        self.client = client or DockerClient(docker_bin=settings.docker_bin)
        self.registry = load_tool_digests(settings.tool_digests_file)

    def verify(self) -> IntegrityReport:
        """Vositalar yaxlitligi (har bir tekshiruvdan oldin chaqiriladi)."""
        return verify_tools(self.client, self.registry, self.settings.tool_lock_file)

    def _require_integrity(self) -> IntegrityReport:
        report = self.verify()
        if not report.ok:
            problems = "; ".join(f"{c.tool.value}: {c.message}" for c in report.checks if c.status.value != "ok")
            raise IntegrityError(f"Tekshiruv bloklandi — vositalar yaxlitligi tasdiqlanmadi. {problems}")
        return report

    def limits(self) -> UploadLimits:
        s = self.settings
        return UploadLimits(
            max_upload_bytes=s.max_upload_bytes,
            max_unzipped_bytes=s.max_unzipped_bytes,
            max_entries=s.max_zip_entries,
            max_file_bytes=s.max_file_bytes,
        )

    def scan_iac_directory(self, src: Path, source: str = "cli") -> ScanOutcome:
        """Mahalliy katalogdagi IaC fayllarini tekshiradi."""
        integrity = self._require_integrity()
        with Workspace(self.settings.workdir) as ws:
            accepted = stage_directory(Path(src), ws.input, self.limits())
            return self._scan_iac_staged(ws, str(src), accepted.files, accepted.skipped, integrity, source)

    def scan_iac_workspace(self, ws: Workspace, target: str, files: list[str], skipped: list[str],
                           source: str = "web") -> ScanOutcome:
        """Fayllari allaqachon ``ws.input`` ga xavfsiz joylangan IaC tekshiruvi."""
        integrity = self._require_integrity()
        return self._scan_iac_staged(ws, target, files, skipped, integrity, source)

    def _scan_iac_staged(self, ws: Workspace, target: str, files: list[str], skipped: list[str],
                         integrity: IntegrityReport, source: str) -> ScanOutcome:
        outcome = ScanOutcome(uid=ws.uid, kind=ScanKind.IAC, target=target, status=ScanStatus.RUNNING,
                              files=files, skipped_files=skipped, integrity=integrity.to_dict(), source=source)
        if not files:
            outcome.status = ScanStatus.FAILED
            outcome.error = "Tekshiriladigan IaC fayli topilmadi (Terraform, Kubernetes YAML yoki Dockerfile)"
            outcome.finished_at = _now()
            return outcome
        runs = run_iac_tools(self.client, integrity, self.settings, ws, self.settings.reports_dir / ws.uid)
        sources = load_sources(ws.input, files)
        raw = {r.tool: r.report for r in runs if r.ok and r.report is not None}
        reports, consensus, evaluation = analyze_iac(raw, sources)
        for run in runs:
            if run.ok and run.tool in reports:
                run.report = reports[run.tool]
        outcome.tool_runs = runs
        outcome.consensus = consensus
        outcome.gt_evaluation = evaluation
        outcome.status = _status(runs)
        outcome.finished_at = _now()
        return outcome

    def scan_image(self, reference: str, source: str = "cli") -> ScanOutcome:
        """Obraz nomi bo‘yicha: pull → save → Trivy, Grype."""
        ref = parse_image_reference(reference)
        integrity = self._require_integrity()
        with Workspace(self.settings.workdir) as ws:
            image = pull_and_save(self.client, self.settings, ws, ref)
            return self._scan_image_input(ws, ref.raw, image, integrity, source)

    def scan_image_tar(self, tar_path: Path, source: str = "cli", image_name: str | None = None) -> ScanOutcome:
        """Tayyor ``.tar`` arxivni tekshiradi (arxiv faqat o‘qish uchun ulanadi)."""
        name = parse_image_reference(image_name).raw if image_name else None
        integrity = self._require_integrity()
        image = existing_tar(tar_path, self.settings)
        image.reference = name
        with Workspace(self.settings.workdir) as ws:
            return self._scan_image_input(ws, name or Path(tar_path).name, image, integrity, source)

    def scan_image_workspace(self, ws: Workspace, tar_name: str, image_name: str | None = None,
                             source: str = "web") -> ScanOutcome:
        """Yuklangan ``.tar`` (``ws.input`` ichida) tekshiruvi."""
        name = parse_image_reference(image_name).raw if image_name else None
        integrity = self._require_integrity()
        image = existing_tar(ws.input / tar_name, self.settings)
        image.reference = name
        return self._scan_image_input(ws, name or tar_name, image, integrity, source)

    def _scan_image_input(self, ws: Workspace, target: str, image: ImageInput,
                          integrity: IntegrityReport, source: str) -> ScanOutcome:
        outcome = ScanOutcome(uid=ws.uid, kind=ScanKind.IMAGE, target=target, status=ScanStatus.RUNNING,
                              image=image.to_dict(), integrity=integrity.to_dict(), source=source)
        runs = run_image_tools(self.client, integrity, self.settings, ws, image, self.settings.reports_dir / ws.uid)
        raw = {r.tool: r.report for r in runs if r.ok and r.report is not None}
        reports, consensus, eol = analyze_image(raw, image.reference)
        for run in runs:
            if run.ok and run.tool in reports:
                run.report = reports[run.tool]
        outcome.tool_runs = runs
        outcome.consensus = consensus
        outcome.eol = eol
        outcome.status = _status(runs)
        outcome.finished_at = _now()
        return outcome


def outcome_from_reports(
    kind: ScanKind,
    target: str,
    raw_reports: Mapping[Tool, ToolReport],
    sources: Mapping[str, str] | None = None,
    image_ref: str | None = None,
    source: str = "demo",
) -> ScanOutcome:
    """Tayyor hisobotlardan natija yasaydi (Docker’siz: demo-import va testlar)."""
    outcome = ScanOutcome(uid=new_uid(), kind=kind, target=target, status=ScanStatus.DONE, source=source)
    if kind is ScanKind.IAC:
        reports, consensus, evaluation = analyze_iac(raw_reports, sources or {})
        outcome.gt_evaluation = evaluation
        outcome.files = sorted(sources or {})
    else:
        reports, consensus, eol = analyze_image(raw_reports, image_ref)
        outcome.eol = eol
    outcome.consensus = consensus
    outcome.tool_runs = [
        ToolRun(tool=t, image_ref="", ok=True, report=reports[t], returncode=0, duration_s=0.0)
        for t in tool_order(reports)
    ]
    outcome.finished_at = _now()
    return outcome


def unknown_severity_tools(outcome: ScanOutcome) -> list[str]:
    """Darajasi noma’lum topilma bergan vositalar (hisobot izohi uchun)."""
    return [
        t.value for t, r in outcome.reports.items() if any(f.severity is Severity.UNKNOWN for f in r.findings)
    ]

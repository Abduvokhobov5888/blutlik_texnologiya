"""Tekshiruv natijasini bazaga saqlash va o‘qish."""

from __future__ import annotations

from collections import Counter
from typing import Any

from sqlalchemy import func, select
from sqlalchemy.orm import Session

from bulutskan.core.consensus import ConsensusLabel
from bulutskan.core.models import SEVERITY_ORDER, Finding, Severity
from bulutskan.services.pipeline import ScanOutcome
from bulutskan.storage.db import utcnow
from bulutskan.storage.tables import FindingGroupRow, FindingRow, Scan, ToolRunRow

_RANK = {s.value: s.rank for s in Severity}


def _summary(outcome: ScanOutcome) -> dict[str, Any]:
    """Xulosa: vositalar × daraja, jami, konsensus sonlari (tafsilotlar o‘chirilganda ham qoladi)."""
    table = outcome.severity_table()
    consensus = outcome.consensus
    groups_by_sev: Counter[str] = Counter()
    if consensus is not None:
        for g in consensus.groups:
            groups_by_sev[g.severity.value] += 1
    return {
        "severity_table": table,
        "groups_by_severity": {s.value: groups_by_sev.get(s.value, 0) for s in SEVERITY_ORDER},
        "findings_total": sum(sum(v.values()) for v in table.values()),
        "groups_total": len(consensus.groups) if consensus else 0,
        "confirmed": consensus.count(ConsensusLabel.CONFIRMED) if consensus else 0,
        "needs_review": consensus.count(ConsensusLabel.NEEDS_REVIEW) if consensus else 0,
        "cpe_suspect": consensus.cpe_suspect_count if consensus else 0,
        "tools_ok": [r.tool.value for r in outcome.tool_runs if r.ok],
        "tools_failed": [r.tool.value for r in outcome.tool_runs if not r.ok],
    }


def _finding_row(scan_id: int, run_id: int, f: Finding) -> FindingRow:
    return FindingRow(
        scan_id=scan_id,
        tool_run_id=run_id,
        tool=f.tool.value,
        kind=f.kind.value,
        target=f.target[:512],
        resource=(f.resource or None) and f.resource[:512],
        rule_id=f.rule_id[:128],
        title=f.title,
        severity=f.severity.value,
        cve=f.cve,
        fixed_version=(f.fixed_version or None) and f.fixed_version[:256],
        installed_version=(f.installed_version or None) and f.installed_version[:256],
        status=f.status.value,
        package_type=f.package_type,
        category=f.category,
        cpe_based=f.cpe_based,
        known_exploited=f.known_exploited,
        line_start=f.line_start,
        line_end=f.line_end,
        primary_url=(f.primary_url or None) and f.primary_url[:512],
        fingerprint=f.fingerprint,
    )


def save_outcome(session: Session, scan: Scan, outcome: ScanOutcome) -> None:
    """``outcome`` ni ``scan`` qatoriga va bog‘liq jadvallarga yozadi."""
    scan.status = outcome.status
    scan.error = outcome.error
    scan.finished_at = utcnow()
    scan.summary = _summary(outcome)
    consensus = outcome.consensus
    scan.jaccard = dict(consensus.jaccard) if consensus else {}
    scan.jaccard_core = consensus.jaccard_core if consensus else None
    scan.consensus = (
        {
            "confirmed": consensus.count(ConsensusLabel.CONFIRMED),
            "needs_review": consensus.count(ConsensusLabel.NEEDS_REVIEW),
            "cpe_suspect": consensus.cpe_suspect_count,
            "key_sets": {t.value: len(k) for t, k in consensus.key_sets.items()},
            "common": len(set.intersection(*consensus.key_sets.values())) if consensus.key_sets else 0,
        }
        if consensus
        else {}
    )
    scan.eol = outcome.eol.to_dict() if outcome.eol else {}
    ev = outcome.gt_evaluation
    scan.ground_truth = (
        {
            "tools": {
                n: {"tp": t.tp, "fp": t.fp, "gt": t.gt, "recall": t.recall, "precision": t.precision,
                    "f1": t.f1, "detected_ids": list(t.detected_ids)}
                for n, t in ev.tools.items()
            },
            "overlap": ev.overlap,
            "missed_by_all": list(ev.missed_by_all),
            "complete": not outcome.failed_tools,
        }
        if ev
        else {}
    )
    scan.image = dict(outcome.image)
    scan.integrity = dict(outcome.integrity)
    scan.files = list(outcome.files)
    scan.skipped_files = list(outcome.skipped_files)
    scan.failures = [
        {"tool": r.tool.value, "reason_code": r.reason_code or "exit_code", "returncode": r.returncode,
         "error": r.error}
        for r in outcome.tool_runs
        if not r.ok
    ]
    session.flush()

    by_identity: dict[int, FindingRow] = {}
    for run in outcome.tool_runs:
        report = run.report
        row = ToolRunRow(
            scan_id=scan.id,
            tool=run.tool.value,
            tool_version=report.tool_version if report else None,
            image_ref=run.image_ref,
            ok=run.ok,
            returncode=run.returncode,
            reason_code=run.reason_code,
            duration_s=run.duration_s,
            error=run.error,
            notes=list(run.notes),
            raw_report_path=str(run.raw_path) if run.raw_path else None,
            finding_count=len(report.findings) if report else 0,
            raw_count=int(report.metadata.get("raw_count", len(report.findings))) if report else 0,
            passed_count=report.passed_count if report else None,
            metadata_json={k: v for k, v in (report.metadata if report else {}).items() if k != "db"},
        )
        session.add(row)
        session.flush()
        if report is None:
            continue
        rows = [_finding_row(scan.id, row.id, f) for f in report.findings]
        session.add_all(rows)
        session.flush()
        for f, r in zip(report.findings, rows, strict=True):
            by_identity[id(f)] = r

    if consensus is not None:
        for g in consensus.groups:
            grow = FindingGroupRow(
                scan_id=scan.id,
                key=g.key[:600],
                kind=g.kind.value,
                title=g.title,
                category=g.category,
                description=g.description,
                severity=g.severity.value,
                severity_rank=g.severity.rank,
                tools=",".join(t.value for t in g.tools),
                tool_count=g.tool_count,
                consensus=g.label.value,
                cpe_suspect=g.cpe_suspect,
                uncategorized=g.uncategorized,
                fix_available=g.fix_available,
                known_exploited=g.known_exploited,
                fixed_versions=g.fixed_versions[:10],
                targets=g.targets[:20],
                severity_by_tool={t.value: s.value for t, s in g.severity_by_tool().items()},
            )
            grow.members = [by_identity[id(m)] for m in g.members if id(m) in by_identity]
            session.add(grow)
    session.flush()


def scan_by_uid(session: Session, uid: str) -> Scan | None:
    return session.scalar(select(Scan).where(Scan.uid == uid))


def severity_rank(value: str) -> int:
    return _RANK.get(value, 0)


def count_groups(session: Session, scan_id: int) -> int:
    return int(session.scalar(select(func.count()).select_from(FindingGroupRow).where(
        FindingGroupRow.scan_id == scan_id)) or 0)

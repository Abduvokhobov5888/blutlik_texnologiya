"""Bazadagi tekshiruvni hisobot va eksport uchun bitta ko‘rinishga yig‘ish."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from bulutskan import __version__
from bulutskan.core.eol import EOL_WARNING_EN, EOL_WARNING_UZ
from bulutskan.core.gate import DEFAULT_UNKNOWN_POLICY, UnknownSeverityPolicy, ci_severity, severity_label
from bulutskan.core.models import SEVERITY_ORDER, Severity
from bulutskan.scanner.runs import FAILURE_CODES
from bulutskan.storage.tables import FindingGroupRow, FindingRow, Scan, ToolRunRow

STATUS_UZ = {"queued": "Navbatda", "running": "Bajarilmoqda", "done": "Tugadi", "partial": "Qisman", "failed": "Xato"}
CONSENSUS_UZ = {"confirmed": "Tasdiqlangan", "needs_review": "Tekshirish talab etiladi"}
CPE_UZ = "CPE asosida, soxta bo‘lishi mumkin"


@dataclass
class ScanView:
    scan: Scan
    tool_runs: list[ToolRunRow]
    groups: list[FindingGroupRow] = field(default_factory=list)
    fixes: list[dict[str, Any]] = field(default_factory=list)
    owner: str | None = None

    @property
    def severity_table(self) -> dict[str, dict[str, int]]:
        return dict((self.scan.summary or {}).get("severity_table", {}))

    @property
    def is_eol(self) -> bool:
        return bool((self.scan.eol or {}).get("is_eol"))

    @property
    def groups_by_severity(self) -> dict[str, int]:
        return dict((self.scan.summary or {}).get("groups_by_severity", {}))


def load_view(session: Session, scan: Scan, max_groups: int | None = None) -> ScanView:
    runs = list(session.scalars(select(ToolRunRow).where(ToolRunRow.scan_id == scan.id).order_by(ToolRunRow.id)))
    q = (select(FindingGroupRow).where(FindingGroupRow.scan_id == scan.id)
         .order_by(FindingGroupRow.severity_rank.desc(), FindingGroupRow.tool_count.desc(), FindingGroupRow.key))
    if max_groups:
        q = q.limit(max_groups)
    groups = list(session.scalars(q))
    fixes: list[dict[str, Any]] = []
    if scan.kind == "image":
        rows = session.execute(
            select(FindingRow.target, FindingRow.installed_version, FindingRow.fixed_version, FindingRow.severity,
                   FindingRow.cve, FindingRow.rule_id)
            .where(FindingRow.scan_id == scan.id, FindingRow.fixed_version.is_not(None))
        ).all()
        by_pkg: dict[tuple[str, str], dict[str, Any]] = {}
        rank = {s.value: s.rank for s in Severity}
        for target, installed, fixed, sev, cve, rule in rows:
            key = (target, installed or "")
            entry = by_pkg.setdefault(key, {"package": target, "installed": installed, "fixed": set(),
                                            "ids": set(), "severity": "UNKNOWN"})
            entry["fixed"].add(fixed)
            entry["ids"].add(cve or rule)
            if rank.get(sev, 0) > rank.get(entry["severity"], 0):
                entry["severity"] = sev
        fixes = sorted(
            ({**e, "fixed": sorted(e["fixed"]), "ids": sorted(e["ids"])} for e in by_pkg.values()),
            key=lambda e: (-rank.get(e["severity"], 0), -len(e["ids"]), e["package"]),
        )
    owner = scan.user.username if scan.user else None
    return ScanView(scan=scan, tool_runs=runs, groups=groups, fixes=fixes, owner=owner)


def export_dict(session: Session, scan: Scan, policy: UnknownSeverityPolicy = DEFAULT_UNKNOWN_POLICY,
                lang: str = "uz") -> dict[str, Any]:
    """JSON eksport (CLI ``--json`` bilan bir xil tuzilma, bazadan)."""
    view = load_view(session, scan)

    def sev(value: str) -> dict[str, Any]:
        s = Severity(value)
        ci = ci_severity(s, policy)
        return {"severity": s.value, "severity_ci": ci.value if ci else None,
                "severity_label": severity_label(s, policy, lang)}

    findings = [
        {
            "tool": f.tool, "kind": f.kind, "target": f.target, "resource": f.resource, "rule_id": f.rule_id,
            "title": f.title, "cve": f.cve, "fixed_version": f.fixed_version,
            "installed_version": f.installed_version, "status": f.status, "category": f.category,
            "cpe_based": f.cpe_based, "known_exploited": f.known_exploited, "line_start": f.line_start,
            "line_end": f.line_end, "primary_url": f.primary_url, "fingerprint": f.fingerprint, **sev(f.severity),
        }
        for f in session.scalars(select(FindingRow).where(FindingRow.scan_id == scan.id).order_by(FindingRow.id))
    ]
    data: dict[str, Any] = {
        "schema_version": 1,
        "generator": f"BulutSkan {__version__}",
        "scan": {
            "uid": scan.uid, "kind": scan.kind, "target": scan.target, "status": scan.status, "source": scan.source,
            "is_demo": scan.is_demo, "owner": view.owner,
            "created_at": scan.created_at.isoformat() if scan.created_at else None,
            "finished_at": scan.finished_at.isoformat() if scan.finished_at else None,
            "error": scan.error, "files": scan.files, "skipped_files": scan.skipped_files, "image": scan.image,
            "purged": scan.purged_at is not None,
        },
        "tools": [
            {"tool": r.tool, "version": r.tool_version, "image_ref": r.image_ref, "ok": r.ok,
             "returncode": r.returncode, "reason_code": r.reason_code, "duration_s": round(r.duration_s, 2),
             "error": r.error, "findings": r.finding_count, "raw_count": r.raw_count, "notes": r.notes,
             "db": (r.metadata_json or {}).get("db")}
            for r in view.tool_runs
        ],
        "failures": [
            {**f, "reason_title": FAILURE_CODES.get(f.get("reason_code") or "exit_code", "")} for f in scan.failures or []
        ],
        "integrity": scan.integrity,
        "severity_table": view.severity_table,
        "unknown_severity_policy": policy.value,
        "consensus": {
            **(scan.consensus or {}),
            "jaccard": scan.jaccard,
            "jaccard_core": scan.jaccard_core,
            "groups": [
                {"key": g.key, "kind": g.kind, "title": g.title, "category": g.category, "consensus": g.consensus,
                 "tools": g.tools.split(",") if g.tools else [], "tool_count": g.tool_count,
                 "cpe_suspect": g.cpe_suspect, "uncategorized": g.uncategorized, "fix_available": g.fix_available,
                 "known_exploited": g.known_exploited, "fixed_versions": g.fixed_versions, "targets": g.targets,
                 "severity_by_tool": g.severity_by_tool, **sev(g.severity)}
                for g in view.groups
            ],
        },
        "findings": findings,
    }
    if scan.eol:
        eol = dict(scan.eol)
        if eol.get("is_eol"):
            eol["warning"] = EOL_WARNING_UZ if lang == "uz" else EOL_WARNING_EN
        data["eol"] = eol
    if scan.ground_truth:
        data["ground_truth"] = scan.ground_truth
    return data


def severity_order() -> list[str]:
    return [s.value for s in SEVERITY_ORDER]

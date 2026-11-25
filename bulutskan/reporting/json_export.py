"""Tekshiruv natijasini JSON ga eksport qilish.

Noma’lum jiddiylik ma’lumotda "UNKNOWN" bo‘lib qoladi. CI qarori uchun
olingan daraja alohida maydonda (``severity_ci``) va izoh bilan beriladi,
masalan: ``noma’lum (CI uchun medium deb olindi)``.
"""

from __future__ import annotations

import json
from pathlib import Path
from typing import Any

from bulutskan import __version__
from bulutskan.core.consensus import ConsensusGroup, ConsensusLabel
from bulutskan.core.eol import EOL_WARNING_EN, EOL_WARNING_UZ
from bulutskan.core.gate import GateDecision, UnknownSeverityPolicy, ci_severity, severity_label
from bulutskan.core.models import Finding, Severity
from bulutskan.services.pipeline import ScanOutcome

SCHEMA_VERSION = 1

LABEL_TEXT = {
    "uz": {
        ConsensusLabel.CONFIRMED: "Tasdiqlangan",
        ConsensusLabel.NEEDS_REVIEW: "Tekshirish talab etiladi",
        "cpe": "CPE asosida, soxta bo‘lishi mumkin",
        "uncategorized": "Toifalanmagan",
    },
    "en": {
        ConsensusLabel.CONFIRMED: "Confirmed",
        ConsensusLabel.NEEDS_REVIEW: "Needs review",
        "cpe": "CPE-based, may be a false positive",
        "uncategorized": "Uncategorized",
    },
}


def _severity_fields(sev: Severity, policy: UnknownSeverityPolicy, lang: str) -> dict[str, Any]:
    ci = ci_severity(sev, policy)
    return {
        "severity": sev.value,
        "severity_ci": ci.value if ci else None,
        "severity_label": severity_label(sev, policy, lang),
    }


def _finding(f: Finding, policy: UnknownSeverityPolicy, lang: str) -> dict[str, Any]:
    data = f.model_dump(mode="json", exclude={"severity"})
    data.update(_severity_fields(f.severity, policy, lang))
    data["fingerprint"] = f.fingerprint
    return data


def _group(g: ConsensusGroup, policy: UnknownSeverityPolicy, lang: str) -> dict[str, Any]:
    texts = LABEL_TEXT[lang]
    badges = [texts[g.label]]
    if g.cpe_suspect:
        badges.append(texts["cpe"])
    if g.uncategorized:
        badges.append(texts["uncategorized"])
    return {
        "key": g.key,
        "kind": g.kind.value,
        "title": g.title,
        "category": g.category,
        "description": g.description,
        "consensus": g.label.value,
        "badges": badges,
        "tools": [t.value for t in g.tools],
        "tool_count": g.tool_count,
        "cpe_suspect": g.cpe_suspect,
        "uncategorized": g.uncategorized,
        "known_exploited": g.known_exploited,
        "fix_available": g.fix_available,
        "fixed_versions": g.fixed_versions,
        "targets": g.targets,
        "severity_by_tool": {t.value: s.value for t, s in g.severity_by_tool().items()},
        **_severity_fields(g.severity, policy, lang),
    }


def build_export(
    outcome: ScanOutcome,
    policy: UnknownSeverityPolicy,
    gate: GateDecision | None = None,
    lang: str = "uz",
) -> dict[str, Any]:
    """Eksport uchun lug‘at."""
    consensus = outcome.consensus
    data: dict[str, Any] = {
        "schema_version": SCHEMA_VERSION,
        "generator": f"BulutSkan {__version__}",
        "scan": {
            "uid": outcome.uid,
            "kind": outcome.kind.value,
            "target": outcome.target,
            "status": outcome.status,
            "source": outcome.source,
            "started_at": outcome.started_at,
            "finished_at": outcome.finished_at,
            "error": outcome.error,
            "files": outcome.files,
            "skipped_files": outcome.skipped_files,
            "image": outcome.image,
        },
        "tools": [r.to_dict() for r in outcome.tool_runs],
        "integrity": outcome.integrity,
        "severity_table": outcome.severity_table(),
        "unknown_severity_policy": policy.value,
    }
    if consensus is not None:
        data["consensus"] = {
            "confirmed": consensus.count(ConsensusLabel.CONFIRMED),
            "needs_review": consensus.count(ConsensusLabel.NEEDS_REVIEW),
            "cpe_suspect": consensus.cpe_suspect_count,
            "jaccard": consensus.jaccard,
            "jaccard_core": consensus.jaccard_core,
            "groups": [_group(g, policy, lang) for g in consensus.groups],
        }
    if outcome.eol is not None:
        eol = outcome.eol.to_dict()
        if outcome.eol.is_eol:
            eol["warning"] = EOL_WARNING_UZ if lang == "uz" else EOL_WARNING_EN
        data["eol"] = eol
    if outcome.gt_evaluation is not None:
        ev = outcome.gt_evaluation
        data["ground_truth"] = {
            "tools": {
                name: {
                    "tp": t.tp, "fp": t.fp, "gt": t.gt, "recall": t.recall, "precision": t.precision,
                    "f1": t.f1, "detected_ids": list(t.detected_ids), "fp_ids": list(t.fp_ids),
                }
                for name, t in ev.tools.items()
            },
            "overlap": ev.overlap,
            "missed_by_all": list(ev.missed_by_all),
            # Biror vosita ishlamagan bo‘lsa, natija III bob bilan solishtirilmaydi.
            "complete": not outcome.failed_tools,
            "tools_failed": [t.value for t in outcome.failed_tools],
        }
    if gate is not None:
        data["gate"] = {
            "failed": gate.failed,
            "fail_on": gate.threshold.value if gate.threshold else None,
            "fixable_only": gate.fixable_only,
            "unknown_severity": gate.policy.value,
            "counted": len(gate.counted),
            "counted_unknown": gate.unknown_counted,
            "notes": gate.notes,
        }
    data["findings"] = [
        _finding(f, policy, lang) for r in outcome.tool_runs if r.report is not None for f in r.report.findings
    ]
    return data


def write_export(path: Path, data: dict[str, Any]) -> None:
    """JSON faylga yozadi (UTF-8, o‘zbekcha belgilar saqlanadi)."""
    path.parent.mkdir(parents=True, exist_ok=True)
    path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")

"""Checkov JSON hisoboti (``-o json``) parseri."""

from __future__ import annotations

from typing import Any

from bulutskan.core.models import Finding, FindingKind, FindingStatus, ScanKind, Tool, ToolReport
from bulutskan.core.normalize import canonical_path, normalize_severity
from bulutskan.parsers.base import ParseError, as_mapping, items, optional_int, text


def parse_checkov(data: Any, mount: str | None = "scan") -> ToolReport:
    """Checkov hisobotini o‘qiydi.

    Checkov bitta framework uchun obyekt, bir nechtasi uchun obyektlar
    ro‘yxatini qaytaradi. Faqat ``failed_checks`` topilma sifatida olinadi.
    Fayl yo‘li ``file_abs_path`` dan (konteyner ichidagi aniq yo‘l) olinadi,
    u bo‘lmasa ``file_path`` dan.
    """
    if not isinstance(data, (list, dict)):
        raise ParseError("Checkov: noma’lum hisobot tuzilmasi")
    blocks = data if isinstance(data, list) else [data]
    findings: list[Finding] = []
    passed = failed = 0
    version: str | None = None
    frameworks: list[str] = []
    for raw in blocks:
        block = as_mapping(raw, "Checkov bloki")
        results = block.get("results")
        if results is None:
            # Checkov hech narsa topmaganda qisqa xulosa qaytaradi.
            continue
        results = as_mapping(results, "Checkov results")
        summary = block.get("summary") or {}
        if isinstance(summary, dict):
            passed += int(summary.get("passed") or 0)
            failed += int(summary.get("failed") or 0)
            version = version or (text(summary.get("checkov_version")) or None)
        frameworks.append(text(block.get("check_type")))
        for fc in items(results.get("failed_checks")):
            fc = as_mapping(fc, "Checkov failed_check")
            path = fc.get("file_abs_path") or fc.get("file_path")
            if fc.get("file_abs_path"):
                target = canonical_path(text(path), mount)
            else:
                target = canonical_path(text(path))
            lines = items(fc.get("file_line_range"))
            resource = text(fc.get("resource")) or None
            findings.append(
                Finding(
                    tool=Tool.CHECKOV,
                    kind=FindingKind.MISCONFIGURATION,
                    target=target,
                    resource=resource,
                    resource_name=resource,
                    rule_id=text(fc.get("check_id")),
                    title=text(fc.get("check_name")),
                    severity=normalize_severity(fc.get("severity")),
                    status=FindingStatus.FAILED,
                    line_start=optional_int(lines[0]) if lines else None,
                    line_end=optional_int(lines[1]) if len(lines) > 1 else None,
                    primary_url=text(fc.get("guideline")) or None,
                )
            )
    return ToolReport(
        tool=Tool.CHECKOV,
        kind=ScanKind.IAC,
        tool_version=version,
        findings=findings,
        passed_count=passed,
        failed_count=failed,
        metadata={"frameworks": frameworks, "raw_count": len(findings)},
    )

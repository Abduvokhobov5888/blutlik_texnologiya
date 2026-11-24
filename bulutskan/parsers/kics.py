"""KICS JSON hisoboti (``--report-formats json``) parseri."""

from __future__ import annotations

from typing import Any

from bulutskan.core.models import Finding, FindingKind, FindingStatus, ScanKind, Tool, ToolReport
from bulutskan.core.normalize import canonical_path, normalize_severity
from bulutskan.parsers.base import as_mapping, items, optional_int, text


def parse_kics(data: Any, mount: str | None = "scan") -> ToolReport:
    """KICS hisobotini o‘qiydi.

    KICS natijasi so‘rovlar (``queries``) bo‘yicha guruhlangan; har bir
    so‘rov ichidagi har bir fayl yozuvi alohida topilma bo‘ladi.
    """
    doc = as_mapping(data, "KICS hisoboti")
    findings: list[Finding] = []
    for q in items(doc.get("queries")):
        q = as_mapping(q, "KICS query")
        for fl in items(q.get("files")):
            fl = as_mapping(fl, "KICS file")
            search_key = text(fl.get("search_key")) or None
            line = optional_int(fl.get("line"))
            findings.append(
                Finding(
                    tool=Tool.KICS,
                    kind=FindingKind.MISCONFIGURATION,
                    target=canonical_path(text(fl.get("file_name")), mount),
                    resource=search_key,
                    resource_name=text(fl.get("resource_name")) or None,
                    rule_id=text(q.get("query_id")),
                    title=text(q.get("query_name")),
                    severity=normalize_severity(q.get("severity")),
                    status=FindingStatus.FAILED,
                    line_start=line,
                    line_end=line,
                    primary_url=text(q.get("query_url")) or None,
                )
            )
    counters = doc.get("severity_counters")
    return ToolReport(
        tool=Tool.KICS,
        kind=ScanKind.IAC,
        tool_version=text(doc.get("kics_version")) or None,
        findings=findings,
        failed_count=optional_int(doc.get("total_counter")),
        metadata={
            "raw_count": len(findings),
            "files_scanned": doc.get("files_scanned"),
            "queries_total": doc.get("queries_total"),
            "severity_counters": counters if isinstance(counters, dict) else {},
        },
    )

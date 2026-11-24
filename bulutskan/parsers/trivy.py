"""Trivy JSON hisoboti parserlari: obraz (zaifliklar) va config (IaC)."""

from __future__ import annotations

from typing import Any

from bulutskan.core.models import Finding, FindingKind, FindingStatus, ScanKind, Tool, ToolReport
from bulutskan.core.normalize import (
    canonical_path,
    extract_cve,
    normalize_severity,
    trivy_status,
)
from bulutskan.parsers.base import as_mapping, items, sub, optional_int, text


def _version(doc: dict[str, Any]) -> str | None:
    info = doc.get("Trivy")
    if isinstance(info, dict):
        return text(info.get("Version")) or None
    return None


def parse_trivy_image(data: Any) -> ToolReport:
    """``trivy image --format json`` hisobotini o‘qiydi.

    CVE kaliti ``stats3.py`` dagi kabi faqat ``VulnerabilityID`` dan
    olinadi: Trivy CVE bo‘lmagan ID larni (TEMP, DLA, GHSA) o‘zgarishsiz
    qaytaradi va ular Grype bilan solishtirishda alohida kalit bo‘ladi.
    """
    doc = dict(as_mapping(data, "Trivy hisoboti"))
    findings: list[Finding] = []
    for result in items(doc.get("Results")):
        result = as_mapping(result, "Trivy Result")
        result_target = text(result.get("Target"))
        package_type = text(result.get("Type")) or None
        for v in items(result.get("Vulnerabilities")):
            v = as_mapping(v, "Trivy Vulnerability")
            vid = text(v.get("VulnerabilityID"))
            fixed = text(v.get("FixedVersion")) or None
            findings.append(
                Finding(
                    tool=Tool.TRIVY,
                    kind=FindingKind.VULNERABILITY,
                    target=text(v.get("PkgName")),
                    resource=text(v.get("PkgPath")) or result_target or None,
                    rule_id=vid,
                    title=text(v.get("Title")),
                    severity=normalize_severity(v.get("Severity") or "UNKNOWN"),
                    cve=extract_cve(vid),
                    fixed_version=fixed,
                    status=trivy_status(text(v.get("Status")), fixed),
                    installed_version=text(v.get("InstalledVersion")) or None,
                    package_type=package_type,
                    primary_url=text(v.get("PrimaryURL")) or None,
                    locations=[result_target] if result_target else [],
                )
            )
    metadata = sub(doc, "Metadata")
    os_info = sub(metadata, "OS")
    return ToolReport(
        tool=Tool.TRIVY,
        kind=ScanKind.IMAGE,
        tool_version=_version(doc),
        findings=findings,
        metadata={
            "raw_count": len(findings),
            "os_family": text(os_info.get("Family")) or None,
            "os_name": text(os_info.get("Name")) or None,
            "eosl": bool(os_info.get("EOSL")),
            "image_id": text(metadata.get("ImageID")) or None,
            "repo_tags": [text(t) for t in items(metadata.get("RepoTags"))],
            "repo_digests": [text(t) for t in items(metadata.get("RepoDigests"))],
            "reference": text(metadata.get("Reference")) or None,
            "created_at": text(doc.get("CreatedAt")) or None,
        },
    )


def parse_trivy_config(data: Any, mount: str | None = "scan") -> ToolReport:
    """``trivy config --format json`` hisobotini o‘qiydi.

    Faqat ``Status == FAIL`` bo‘lgan noto‘g‘ri sozlamalar olinadi
    (``analyze.parse_trivy_config`` bilan bir xil).
    """
    doc = dict(as_mapping(data, "Trivy config hisoboti"))
    findings: list[Finding] = []
    passed = failed = 0
    for result in items(doc.get("Results")):
        result = as_mapping(result, "Trivy Result")
        summary = result.get("MisconfSummary")
        if isinstance(summary, dict):
            passed += int(summary.get("Successes") or 0)
            failed += int(summary.get("Failures") or 0)
        target = canonical_path(text(result.get("Target")), mount)
        for m in items(result.get("Misconfigurations")):
            m = as_mapping(m, "Trivy Misconfiguration")
            if text(m.get("Status") or "FAIL") != "FAIL":
                continue
            cm = sub(m, "CauseMetadata")
            resource = text(cm.get("Resource")) or None
            findings.append(
                Finding(
                    tool=Tool.TRIVY,
                    kind=FindingKind.MISCONFIGURATION,
                    target=target,
                    resource=resource,
                    resource_name=resource,
                    rule_id=text(m.get("ID")),
                    title=text(m.get("Title")),
                    severity=normalize_severity(m.get("Severity")),
                    status=FindingStatus.FAILED,
                    line_start=optional_int(cm.get("StartLine")),
                    line_end=optional_int(cm.get("EndLine")),
                    primary_url=text(m.get("PrimaryURL")) or None,
                )
            )
    return ToolReport(
        tool=Tool.TRIVY,
        kind=ScanKind.IAC,
        tool_version=_version(doc),
        findings=findings,
        passed_count=passed,
        failed_count=failed,
        metadata={"raw_count": len(findings)},
    )

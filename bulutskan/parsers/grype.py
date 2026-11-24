"""Grype JSON hisoboti (``-o json``) parseri."""

from __future__ import annotations

from typing import Any

from bulutskan.core.models import Finding, FindingKind, ScanKind, Tool, ToolReport
from bulutskan.core.normalize import extract_cve, grype_status, normalize_severity
from bulutskan.parsers.base import as_mapping, items, sub, text


def is_cpe_based(vulnerability: dict[str, Any], artifact: dict[str, Any]) -> bool:
    """Grype topilmasi CPE yoki binar fayl orqali topilganmi.

    ``stats3.py`` mezoni: ``namespace`` ``nvd:cpe`` bilan boshlanadi yoki
    artefakt turi ``binary``. Bunday mosliklar soxta bo‘lishi mumkin.
    """
    namespace = text(vulnerability.get("namespace"))
    return namespace.startswith("nvd:cpe") or text(artifact.get("type")) == "binary"


def parse_grype(data: Any) -> ToolReport:
    """Grype hisobotini o‘qiydi."""
    doc = dict(as_mapping(data, "Grype hisoboti"))
    findings: list[Finding] = []
    for match in items(doc.get("matches")):
        match = as_mapping(match, "Grype match")
        v = dict(as_mapping(match.get("vulnerability") or {}, "Grype vulnerability"))
        a = dict(as_mapping(match.get("artifact") or {}, "Grype artifact"))
        fix = sub(v, "fix")
        versions = [text(x) for x in items(fix.get("versions")) if x]
        vid = text(v.get("id"))
        locations = [
            text(loc.get("path"))
            for loc in items(a.get("locations"))
            if isinstance(loc, dict) and loc.get("path")
        ]
        findings.append(
            Finding(
                tool=Tool.GRYPE,
                kind=FindingKind.VULNERABILITY,
                target=text(a.get("name")),
                resource=locations[0] if locations else None,
                rule_id=vid,
                title=vid,
                severity=normalize_severity(v.get("severity") or "Unknown"),
                cve=extract_cve(vid, match.get("relatedVulnerabilities")),
                fixed_version=", ".join(versions) or None,
                status=grype_status(text(fix.get("state"))),
                installed_version=text(a.get("version")) or None,
                package_type=text(a.get("type")) or None,
                cpe_based=is_cpe_based(v, a),
                known_exploited=bool(items(v.get("knownExploited"))),
                primary_url=text(v.get("dataSource")) or None,
                locations=locations,
            )
        )
    distro = sub(doc, "distro")
    descriptor = sub(doc, "descriptor")
    source = sub(doc, "source")
    src_target = sub(source, "target")
    db = sub(descriptor, "db")
    binaries = sorted(
        {
            (text(m["artifact"].get("name")), text(m["artifact"].get("version")))
            for m in items(doc.get("matches"))
            if isinstance(m, dict)
            and isinstance(m.get("artifact"), dict)
            and text(m["artifact"].get("type")) == "binary"
        }
    )
    return ToolReport(
        tool=Tool.GRYPE,
        kind=ScanKind.IMAGE,
        tool_version=text(descriptor.get("version")) or None,
        findings=findings,
        metadata={
            "raw_count": len(findings),
            "distro_name": text(distro.get("name")) or None,
            "distro_version": text(distro.get("version")) or None,
            "binaries": [list(b) for b in binaries],
            "user_input": text(src_target.get("userInput")) or None,
            "tags": [text(t) for t in items(src_target.get("tags"))],
            "image_id": text(src_target.get("imageID")) or None,
            "manifest_digest": text(src_target.get("manifestDigest")) or None,
            "db": db,
            "timestamp": text(descriptor.get("timestamp")) or None,
        },
    )

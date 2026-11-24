"""Takroriy topilmalarni birlashtirish."""

from bulutskan.core.dedup import dedup_findings
from bulutskan.core.models import Finding, FindingKind, FindingStatus, Severity, Tool
from tests.conftest import grype_report


def _f(**kw: object) -> Finding:
    data: dict[str, object] = {
        "tool": Tool.GRYPE,
        "kind": FindingKind.VULNERABILITY,
        "target": "libssl",
        "rule_id": "CVE-2024-0001",
        "cve": "CVE-2024-0001",
        "installed_version": "1.0",
    }
    data.update(kw)
    return Finding(**data)  # type: ignore[arg-type]


def test_merges_locations_and_keeps_strongest_values() -> None:
    merged = dedup_findings(
        [
            _f(locations=["/a"], severity=Severity.MEDIUM, cpe_based=True),
            _f(
                locations=["/b", "/a"],
                severity=Severity.HIGH,
                cpe_based=False,
                fixed_version="1.1",
                status=FindingStatus.FIX_AVAILABLE,
                known_exploited=True,
            ),
        ]
    )
    assert len(merged) == 1
    m = merged[0]
    assert m.locations == ["/a", "/b"]
    assert m.severity is Severity.HIGH
    assert m.cpe_based is False
    assert m.known_exploited is True
    assert m.fixed_version == "1.1" and m.status is FindingStatus.FIX_AVAILABLE


def test_different_versions_are_not_merged() -> None:
    assert len(dedup_findings([_f(), _f(installed_version="2.0")])) == 2


def test_input_is_not_mutated() -> None:
    a = _f(locations=["/a"])
    dedup_findings([a, _f(locations=["/b"])])
    assert a.locations == ["/a"]


def test_real_report_dedup() -> None:
    findings = grype_report("centos:7").findings
    merged = dedup_findings(findings)
    assert len(merged) <= len(findings)
    assert len({f.fingerprint for f in merged}) == len(merged)

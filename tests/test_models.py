"""Yagona model: jiddiylik tartibi va takrorlar kaliti."""

from bulutskan.core.models import (
    SEVERITY_ORDER,
    Finding,
    FindingKind,
    FindingStatus,
    Severity,
    Tool,
)


def _vuln(**overrides: object) -> Finding:
    data: dict[str, object] = {
        "tool": Tool.GRYPE,
        "kind": FindingKind.VULNERABILITY,
        "target": "openssl",
        "rule_id": "CVE-2023-0286",
        "cve": "CVE-2023-0286",
        "installed_version": "1.1.1n-0+deb11u3",
        "severity": Severity.HIGH,
        "status": FindingStatus.FIX_AVAILABLE,
    }
    data.update(overrides)
    return Finding(**data)  # type: ignore[arg-type]


def test_severity_order_is_strictly_descending() -> None:
    ranks = [s.rank for s in SEVERITY_ORDER]
    assert ranks == sorted(ranks, reverse=True)
    assert len(set(ranks)) == len(ranks)


def test_unknown_severity_never_meets_threshold() -> None:
    assert not Severity.UNKNOWN.at_least(Severity.LOW)
    assert Severity.CRITICAL.at_least(Severity.HIGH)
    assert Severity.HIGH.at_least(Severity.HIGH)
    assert not Severity.MEDIUM.at_least(Severity.HIGH)


def test_fingerprint_ignores_location_but_not_version() -> None:
    a = _vuln(locations=["/usr/lib/x86_64-linux-gnu/libssl.so.1.1"])
    b = _vuln(locations=["/usr/share/doc/openssl/copyright"])
    c = _vuln(installed_version="1.1.1w-0+deb11u1")
    assert a.fingerprint == b.fingerprint
    assert a.fingerprint != c.fingerprint


def test_fingerprint_differs_between_tools() -> None:
    assert _vuln().fingerprint != _vuln(tool=Tool.TRIVY).fingerprint


def test_vuln_key_falls_back_to_rule_id() -> None:
    f = _vuln(cve=None, rule_id="ghsa-xxxx-yyyy-zzzz")
    assert f.vuln_key == "GHSA-XXXX-YYYY-ZZZZ"


def test_misconfiguration_fingerprint_uses_line() -> None:
    base = {
        "tool": Tool.CHECKOV,
        "kind": FindingKind.MISCONFIGURATION,
        "target": "main.tf",
        "resource": "aws_s3_bucket.data",
        "rule_id": "CKV_AWS_20",
        "status": FindingStatus.FAILED,
    }
    assert (
        Finding(**base, line_start=1).fingerprint  # type: ignore[arg-type]
        != Finding(**base, line_start=9).fingerprint  # type: ignore[arg-type]
    )

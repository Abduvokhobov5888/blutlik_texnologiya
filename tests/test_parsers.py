"""Parserlar: real hisobotlardagi sonlar analyze.py natijalari bilan bir xil."""

from collections import Counter
from pathlib import Path

import pytest

from bulutskan.core.models import FindingKind, FindingStatus, Severity, Tool
from bulutskan.parsers import ParseError, load_json, parse_checkov, parse_grype, parse_kics
from tests.conftest import IMAGES, ch3_row, grype_report, iac_reports, summary_row, trivy_report


@pytest.mark.parametrize("image", IMAGES)
@pytest.mark.parametrize("tool", ["Trivy", "Grype"])
def test_image_counts_match_analyze(image: str, tool: str) -> None:
    report = trivy_report(image) if tool == "Trivy" else grype_report(image)
    expected = summary_row(image)
    sev = Counter(f.severity for f in report.findings)
    assert len(report.findings) == expected[f"{tool}_findings"]
    assert sev[Severity.CRITICAL] == expected[f"{tool}_critical"]
    assert sev[Severity.HIGH] == expected[f"{tool}_high"]
    assert sev[Severity.MEDIUM] == expected[f"{tool}_medium"]
    # analyze.py: LOW + NEGLIGIBLE
    assert sev[Severity.LOW] == expected[f"{tool}_low"]
    fixable = sum(1 for f in report.findings if f.status is FindingStatus.FIX_AVAILABLE)
    assert fixable == expected[f"{tool}_fixable"]


@pytest.mark.parametrize("image", IMAGES)
def test_trivy_os_metadata_matches_stats3(image: str) -> None:
    md = trivy_report(image).metadata
    row = ch3_row(image)
    assert f"{md['os_family']} {md['os_name']}" == row["os"]
    assert md["eosl"] is row["eosl"]


def test_versions_are_read_from_reports() -> None:
    assert trivy_report("nginx:1.21").tool_version == "0.76.1"
    assert grype_report("nginx:1.21").tool_version == "0.121.0"
    reports = iac_reports()
    assert reports["Checkov"].tool_version == "3.3.26"
    assert reports["KICS"].tool_version == "v2.2.0"
    assert reports["Trivy (config)"].tool_version == "0.76.1"


def test_grype_ghsa_is_mapped_to_cve_through_related() -> None:
    findings = grype_report("bkimminich/juice-shop:v15.0.0").findings
    ghsa = [f for f in findings if f.rule_id.startswith("GHSA-")]
    assert ghsa, "juice-shop hisobotida GHSA yozuvlari bo‘lishi kerak"
    mapped = next(f for f in ghsa if f.rule_id == "GHSA-35jh-r3h4-6jhm")
    assert mapped.cve == "CVE-2021-23337"
    assert mapped.vuln_key == "CVE-2021-23337"
    for f in ghsa:
        assert f.cve is None or f.cve.startswith("CVE-")


def test_grype_cpe_flag_and_binaries() -> None:
    report = grype_report("node:16-alpine")
    assert any(f.cpe_based and f.package_type == "binary" for f in report.findings)
    assert ["node", "16.20.2"] in report.metadata["binaries"]
    assert report.metadata["distro_name"] == "alpine"
    assert report.metadata["distro_version"] == "3.18.3"


def test_trivy_image_findings_shape() -> None:
    f = trivy_report("nginx:1.21").findings[0]
    assert f.tool is Tool.TRIVY
    assert f.kind is FindingKind.VULNERABILITY
    assert f.target and f.installed_version and f.rule_id


def test_iac_counts_match_analyze(summary: dict) -> None:
    for name, report in iac_reports().items():
        assert len(report.findings) == summary["iac_summary"][name]["findings_total"], name
        assert all(f.kind is FindingKind.MISCONFIGURATION for f in report.findings)
        assert all(f.status is FindingStatus.FAILED for f in report.findings)


def test_iac_paths_are_canonical_across_tools() -> None:
    paths = {name: {f.target for f in r.findings} for name, r in iac_reports().items()}
    for name, ps in paths.items():
        for p in ps:
            assert not p.startswith(("/", ".", "iac/")), (name, p)
    # Uchala vosita xatoli fayllarni bir xil yo‘l bilan yozadi.
    insecure = {
        "terraform/insecure/main.tf",
        "kubernetes/insecure/deployment.yaml",
        "docker/insecure/Dockerfile",
    }
    for name, ps in paths.items():
        assert insecure <= ps, name


def test_checkov_open_source_has_no_severity() -> None:
    """Checkov OSS jiddiylik bermaydi: platforma uni to‘qib chiqarmaydi."""
    report = iac_reports()["Checkov"]
    assert {f.severity for f in report.findings} == {Severity.UNKNOWN}
    assert report.passed_count == 335
    assert report.failed_count == 102


def test_kics_severity_counters_are_consistent() -> None:
    report = iac_reports()["KICS"]
    counters = report.metadata["severity_counters"]
    sev = Counter(f.severity for f in report.findings)
    assert sev[Severity.CRITICAL] == counters["CRITICAL"]
    assert sev[Severity.HIGH] == counters["HIGH"]
    assert sev[Severity.INFO] == counters["INFO"] + counters["TRACE"]


def test_load_json_rejects_empty_and_invalid(tmp_path: Path) -> None:
    empty = tmp_path / "empty.json"
    empty.write_text("", encoding="utf-8")
    with pytest.raises(ParseError):
        load_json(empty)
    bad = tmp_path / "bad.json"
    bad.write_text("{not json", encoding="utf-8")
    with pytest.raises(ParseError):
        load_json(bad)
    with pytest.raises(ParseError):
        load_json(tmp_path / "missing.json")
    big = tmp_path / "big.json"
    big.write_text("[" + "1," * 100 + "1]", encoding="utf-8")
    with pytest.raises(ParseError):
        load_json(big, max_bytes=10)


def test_load_json_accepts_bom(tmp_path: Path) -> None:
    p = tmp_path / "bom.json"
    p.write_bytes("﻿{\"matches\": []}".encode("utf-8"))
    assert parse_grype(load_json(p)).findings == []


def test_parsers_reject_wrong_structure() -> None:
    with pytest.raises(ParseError):
        parse_checkov("matn")
    with pytest.raises(ParseError):
        parse_kics([1, 2, 3])
    with pytest.raises(ParseError):
        parse_grype({"matches": ["satr"]})


def test_checkov_empty_result_block_is_tolerated() -> None:
    report = parse_checkov({"passed": 0, "failed": 0, "skipped": 0})
    assert report.findings == []

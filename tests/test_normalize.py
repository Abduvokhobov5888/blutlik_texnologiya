"""Normallashtirish qoidalari."""

import pytest

from bulutskan.core.models import FindingStatus, Severity
from bulutskan.core.normalize import (
    canonical_path,
    extract_cve,
    grype_status,
    match_path,
    normalize_severity,
    trivy_status,
    vuln_key,
)


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("CRITICAL", Severity.CRITICAL),
        ("High", Severity.HIGH),
        ("medium", Severity.MEDIUM),
        ("Low", Severity.LOW),
        ("Negligible", Severity.LOW),
        ("INFO", Severity.INFO),
        ("TRACE", Severity.INFO),
        ("Unknown", Severity.UNKNOWN),
        (None, Severity.UNKNOWN),
        ("", Severity.UNKNOWN),
        ("bema'ni", Severity.UNKNOWN),
    ],
)
def test_normalize_severity(raw: object, expected: Severity) -> None:
    assert normalize_severity(raw) is expected


def test_vuln_key_follows_stats3() -> None:
    assert vuln_key("cve-2023-0286") == "CVE-2023-0286"
    related = [{"id": "CVE-2021-23337"}]
    assert vuln_key("GHSA-35jh-r3h4-6jhm", related) == "CVE-2021-23337"
    # Bog‘liq CVE bo‘lmasa, asl ID katta harflarda qoladi.
    assert vuln_key("ghsa-5mrr-rgp6-x4gr", [{"id": "GHSA-x"}]) == "GHSA-5MRR-RGP6-X4GR"
    assert vuln_key("TEMP-0841856-B18BAF") == "TEMP-0841856-B18BAF"
    assert extract_cve("TEMP-0841856-B18BAF") is None
    assert extract_cve("GHSA-35jh-r3h4-6jhm", ["CVE-2021-23337"]) == "CVE-2021-23337"


@pytest.mark.parametrize(
    ("raw", "mount", "expected"),
    [
        ("/kubernetes/insecure/deployment.yaml", None, "kubernetes/insecure/deployment.yaml"),
        ("/iac/terraform/insecure/main.tf", "iac", "terraform/insecure/main.tf"),
        ("../../iac/terraform/insecure/main.tf", "iac", "terraform/insecure/main.tf"),
        ("../../scan/infra/main.tf", "scan", "infra/main.tf"),
        ("docker/insecure/Dockerfile", "scan", "docker/insecure/Dockerfile"),
        ("infra\\prod\\main.tf", None, "infra/prod/main.tf"),
        ("./main.tf", "scan", "main.tf"),
    ],
)
def test_canonical_path(raw: str, mount: str | None, expected: str) -> None:
    assert canonical_path(raw, mount) == expected


def test_match_path_is_analyze_norm() -> None:
    assert match_path("../../iac/Terraform/Insecure/main.tf") == "iac/terraform/insecure/main.tf"


def test_trivy_status_uses_fixed_version_first() -> None:
    assert trivy_status("affected", "1.2.3") is FindingStatus.FIX_AVAILABLE
    assert trivy_status("affected", None) is FindingStatus.NO_FIX
    assert trivy_status("will_not_fix", None) is FindingStatus.WONT_FIX
    assert trivy_status("fix_deferred", "") is FindingStatus.WONT_FIX
    assert trivy_status(None, None) is FindingStatus.UNKNOWN


def test_grype_status() -> None:
    assert grype_status("fixed") is FindingStatus.FIX_AVAILABLE
    assert grype_status("not-fixed") is FindingStatus.NO_FIX
    assert grype_status("wont-fix") is FindingStatus.WONT_FIX
    assert grype_status("unknown") is FindingStatus.UNKNOWN
    assert grype_status(None) is FindingStatus.UNKNOWN

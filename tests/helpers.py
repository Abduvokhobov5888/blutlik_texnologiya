"""Testlar uchun umumiy yordamchilar: real hisobotlardan natija yasash."""

from __future__ import annotations

from bulutskan.core.categories import DEFAULT_IAC_ROOT, load_sources
from bulutskan.core.models import ScanKind, Tool
from bulutskan.services.pipeline import ScanOutcome, outcome_from_reports
from tests.conftest import grype_report, iac_reports, trivy_report

IAC_NAME_TOOL = {"Checkov": Tool.CHECKOV, "KICS": Tool.KICS, "Trivy (config)": Tool.TRIVY}


def iac_outcome(only: tuple[Tool, ...] | None = None) -> ScanOutcome:
    """Namoyish fayllari bo‘yicha eksperiment hisobotlaridan IaC natijasi."""
    reports = {IAC_NAME_TOOL[n]: r for n, r in iac_reports().items()}
    if only is not None:
        reports = {t: r for t, r in reports.items() if t in only}
    targets = sorted({f.target for r in reports.values() for f in r.findings})
    return outcome_from_reports(ScanKind.IAC, "namoyish", reports, sources=load_sources(DEFAULT_IAC_ROOT, targets))


def image_outcome(image: str) -> ScanOutcome:
    """Obraz bo‘yicha eksperiment hisobotlaridan natija."""
    return outcome_from_reports(
        ScanKind.IMAGE, image, {Tool.TRIVY: trivy_report(image), Tool.GRYPE: grype_report(image)}, image_ref=image
    )

"""Yagona topilma modeli.

Checkov, KICS, Trivy va Grype hisobotlari turlicha tuzilgan. Parserlar
ularning har birini shu moduldagi :class:`Finding` ko‘rinishiga keltiradi,
shundan keyin konsensus, hisobot va solishtirish vositadan qat’i nazar bir
xil ishlaydi. Maydonlar ``docs/arxitektura.md`` ning 6-bo‘limiga mos.
"""

from __future__ import annotations

import hashlib
from enum import StrEnum
from typing import Any

from pydantic import BaseModel, ConfigDict, Field


class Tool(StrEnum):
    """Platforma ishlatadigan skanerlar."""

    CHECKOV = "checkov"
    KICS = "kics"
    TRIVY = "trivy"
    GRYPE = "grype"


class ScanKind(StrEnum):
    """Tekshiruv turi."""

    IAC = "iac"
    IMAGE = "image"


class FindingKind(StrEnum):
    """Topilma turi: obrazdagi zaiflik yoki IaC dagi noto‘g‘ri sozlama."""

    VULNERABILITY = "vulnerability"
    MISCONFIGURATION = "misconfiguration"


class Severity(StrEnum):
    """Normallashtirilgan jiddiylik darajasi."""

    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"
    UNKNOWN = "UNKNOWN"

    @property
    def rank(self) -> int:
        """Taqqoslash uchun daraja: qancha katta bo‘lsa, shuncha jiddiy.

        UNKNOWN eng past o‘rinda turadi: noma’lum darajani yuqori deb
        hisoblash natijani to‘qib chiqarish bo‘lardi.
        """
        return _SEVERITY_RANK[self]

    def at_least(self, threshold: Severity) -> bool:
        """Daraja ``threshold`` dan past emasligini tekshiradi."""
        return self.rank >= threshold.rank


_SEVERITY_RANK: dict[Severity, int] = {
    Severity.UNKNOWN: 0,
    Severity.INFO: 1,
    Severity.LOW: 2,
    Severity.MEDIUM: 3,
    Severity.HIGH: 4,
    Severity.CRITICAL: 5,
}

#: Hisobot va interfeysda ishlatiladigan tartib (eng jiddiysi birinchi).
SEVERITY_ORDER: tuple[Severity, ...] = (
    Severity.CRITICAL,
    Severity.HIGH,
    Severity.MEDIUM,
    Severity.LOW,
    Severity.INFO,
    Severity.UNKNOWN,
)


class FindingStatus(StrEnum):
    """Topilmaning normallashtirilgan holati."""

    FIX_AVAILABLE = "fix_available"  # Tuzatish mavjud
    NO_FIX = "no_fix"  # Tuzatish yo‘q
    WONT_FIX = "wont_fix"  # Tuzatilmaydi
    UNKNOWN = "unknown"  # Noma’lum
    FAILED = "failed"  # IaC: qoidaga zid


class Finding(BaseModel):
    """Bitta vositaning bitta topilmasi, yagona ko‘rinishda."""

    model_config = ConfigDict(frozen=False, extra="forbid")

    # --- Talab qilingan asosiy maydonlar ---
    tool: Tool
    target: str = Field(description="Fayl (IaC) yoki paket nomi (obraz)")
    resource: str | None = Field(default=None, description="Resurs yoki paket joylashuvi")
    rule_id: str = Field(description="Qoida ID yoki zaiflik ID")
    title: str = Field(default="", description="Topilma nomi")
    severity: Severity = Severity.UNKNOWN
    cve: str | None = Field(default=None, description="Normallashtirilgan CVE")
    fixed_version: str | None = None
    status: FindingStatus = FindingStatus.UNKNOWN

    # --- Yordamchi maydonlar ---
    kind: FindingKind
    installed_version: str | None = None
    package_type: str | None = None
    resource_name: str | None = Field(
        default=None, description="IaC: resurs nomi (KICS resource_name va h.k.), toifalash uchun"
    )
    category: str | None = Field(default=None, description="IaC xato toifasi")
    cpe_based: bool = Field(default=False, description="Grype: CPE yoki binar orqali topilgan")
    known_exploited: bool = Field(default=False, description="CISA KEV ro‘yxatida bor (Grype)")
    line_start: int | None = None
    line_end: int | None = None
    primary_url: str | None = None
    locations: list[str] = Field(default_factory=list)

    @property
    def vuln_key(self) -> str:
        """Zaiflikning vositalararo kaliti: CVE bo‘lsa CVE, aks holda asl ID."""
        return (self.cve or self.rule_id).upper()

    @property
    def fingerprint(self) -> str:
        """Bitta vosita ichidagi takrorlarni aniqlash kaliti (6.4-bo‘lim)."""
        if self.kind is FindingKind.VULNERABILITY:
            parts: tuple[Any, ...] = (
                self.tool,
                self.vuln_key,
                self.target,
                self.installed_version or "",
            )
        else:
            parts = (
                self.tool,
                self.rule_id,
                self.target,
                self.resource or "",
                self.line_start if self.line_start is not None else "",
            )
        raw = "\x1f".join(str(p) for p in parts)
        return hashlib.sha256(raw.encode("utf-8")).hexdigest()[:32]


class ToolReport(BaseModel):
    """Bitta vosita hisobotining parser natijasi."""

    model_config = ConfigDict(extra="forbid")

    tool: Tool
    kind: ScanKind
    tool_version: str | None = None
    findings: list[Finding] = Field(default_factory=list)
    passed_count: int | None = Field(default=None, description="IaC: o‘tgan tekshiruvlar soni")
    failed_count: int | None = Field(default=None, description="IaC: muvaffaqiyatsiz tekshiruvlar soni")
    metadata: dict[str, Any] = Field(
        default_factory=dict,
        description="Vositaga xos qo‘shimcha ma’lumot (OS, distro, baza versiyasi va h.k.)",
    )

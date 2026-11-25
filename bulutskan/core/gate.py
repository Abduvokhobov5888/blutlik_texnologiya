"""CI/CD rejimi uchun ``--fail-on`` qarori.

Qaror konsensus guruhlari bo‘yicha qabul qilinadi: bir xil xatoni uchta
vosita topgan bo‘lsa ham, u bitta marta sanaladi.

Checkov’ning ochiq kodli versiyasi jiddiylik bermaydi. Agar xatoni faqat
Checkov topgan bo‘lsa, guruh darajasi UNKNOWN bo‘ladi va u hech qachon
chegaraga yetmaydi. III bob natijalarida Checkov 36 ta xatodan 4 tasini
yolg‘iz o‘zi topgan, shuning uchun ``--unknown-severity`` sozlamasi
noma’lum darajani faqat shu qaror uchun qaysi daraja deb olishni belgilaydi.
Ma’lumotlar va interfeysda daraja baribir "noma’lum" bo‘lib qoladi.
"""

from __future__ import annotations

from dataclasses import dataclass, field
from enum import StrEnum

from bulutskan.core.consensus import ConsensusGroup, ConsensusResult
from bulutskan.core.models import FindingKind, Severity


class UnknownSeverityPolicy(StrEnum):
    """Noma’lum darajani CI qarorida qanday hisoblash."""

    IGNORE = "ignore"
    LOW = "low"
    MEDIUM = "medium"
    HIGH = "high"


DEFAULT_UNKNOWN_POLICY = UnknownSeverityPolicy.MEDIUM

_POLICY_SEVERITY: dict[UnknownSeverityPolicy, Severity | None] = {
    UnknownSeverityPolicy.IGNORE: None,
    UnknownSeverityPolicy.LOW: Severity.LOW,
    UnknownSeverityPolicy.MEDIUM: Severity.MEDIUM,
    UnknownSeverityPolicy.HIGH: Severity.HIGH,
}

#: ``--fail-on`` qabul qiladigan darajalar.
FAIL_ON_LEVELS: tuple[str, ...] = ("critical", "high", "medium", "low")


def parse_fail_on(value: str) -> Severity:
    """``--fail-on`` qiymatini darajaga aylantiradi."""
    v = value.strip().lower()
    if v not in FAIL_ON_LEVELS:
        raise ValueError(f"--fail-on: {', '.join(FAIL_ON_LEVELS)} dan biri bo‘lishi kerak")
    return Severity(v.upper())


def ci_severity(severity: Severity, policy: UnknownSeverityPolicy) -> Severity | None:
    """CI qarori uchun daraja: noma’lum bo‘lsa siyosat bo‘yicha, ``ignore`` da ``None``."""
    if severity is Severity.UNKNOWN:
        return _POLICY_SEVERITY[policy]
    return severity


def severity_label(severity: Severity, policy: UnknownSeverityPolicy, lang: str = "uz") -> str:
    """Hisobot uchun daraja yozuvi.

    Masalan: ``noma’lum (CI uchun medium deb olindi)``.
    """
    if severity is not Severity.UNKNOWN:
        return severity.value
    if lang == "en":
        if policy is UnknownSeverityPolicy.IGNORE:
            return "unknown (ignored for CI)"
        return f"unknown (treated as {policy.value} for CI)"
    if policy is UnknownSeverityPolicy.IGNORE:
        return "noma’lum (CI uchun hisobga olinmadi)"
    return f"noma’lum (CI uchun {policy.value} deb olindi)"


@dataclass
class GateDecision:
    """``--fail-on`` qarori."""

    failed: bool
    threshold: Severity | None
    policy: UnknownSeverityPolicy
    fixable_only: bool
    counted: list[ConsensusGroup] = field(default_factory=list)
    unknown_counted: int = 0
    notes: list[str] = field(default_factory=list)

    @property
    def exit_code(self) -> int:
        """CLI chiqish kodi: 1 — chegaradan oshdi, 0 — yo‘q."""
        return 1 if self.failed else 0


def evaluate_gate(
    consensus: ConsensusResult,
    fail_on: Severity | None,
    fixable_only: bool = False,
    unknown_policy: UnknownSeverityPolicy = DEFAULT_UNKNOWN_POLICY,
) -> GateDecision:
    """Chegaradan oshgan guruhlarni sanaydi.

    ``fixable_only`` faqat zaifliklarga taalluqli: tuzatilgan versiyasi bor
    guruhlar sanaladi. IaC topilmalari uchun u e’tiborga olinmaydi.
    """
    decision = GateDecision(
        failed=False, threshold=fail_on, policy=unknown_policy, fixable_only=fixable_only
    )
    if fail_on is None:
        return decision
    has_misconfig = any(g.kind is FindingKind.MISCONFIGURATION for g in consensus.groups)
    if fixable_only and has_misconfig:
        decision.notes.append("--fixable-only faqat zaifliklarga qo‘llanadi; IaC topilmalari to‘liq sanaldi")
    for group in consensus.groups:
        if fixable_only and group.kind is FindingKind.VULNERABILITY and not group.fix_available:
            continue
        effective = ci_severity(group.severity, unknown_policy)
        if effective is None or not effective.at_least(fail_on):
            continue
        decision.counted.append(group)
        if group.severity is Severity.UNKNOWN:
            decision.unknown_counted += 1
    decision.failed = bool(decision.counted)
    return decision


@dataclass(frozen=True)
class ExitDecision:
    """CLI chiqish kodi va uning sababi."""

    code: int
    reason: str
    partial: bool
    allow_partial: bool


def decide_exit(
    status: str,
    failed_tools: list[str],
    gate: GateDecision | None,
    allow_partial: bool = False,
) -> ExitDecision:
    """CI rejimi uchun chiqish kodi.

    * ``2`` — birorta vosita ishlamadi, yoki tekshiruv qisman va
      ``--allow-partial`` berilmagan. Xavfsizlik tekshiruvi "xato bo‘lsa
      to‘xtatish" qoidasiga bo‘ysunadi: masalan, Checkov yiqilsa, faqat u
      topadigan xatolar konveyerdan jimgina o‘tib ketmasligi kerak.
    * ``1`` — chegaradan oshgan topilma bor (``--fail-on``).
    * ``0`` — chegaradan oshmadi.
    """
    partial = status == "partial"
    if status == "failed":
        return ExitDecision(2, "Tekshiruv bajarilmadi: birorta vosita ishlamadi", partial, allow_partial)
    if partial and not allow_partial:
        return ExitDecision(
            2,
            f"Tekshiruv qisman: {', '.join(failed_tools)} ishlamadi (istisno uchun --allow-partial)",
            partial,
            allow_partial,
        )
    if gate is not None and gate.failed:
        return ExitDecision(1, "Chegaradan oshgan topilmalar bor", partial, allow_partial)
    if partial:
        return ExitDecision(
            0, f"Qisman natija qabul qilindi (--allow-partial): {', '.join(failed_tools)} ishlamadi", partial, allow_partial
        )
    return ExitDecision(0, "Chegaradan oshmadi" if gate is not None else "Tekshiruv tugadi", partial, allow_partial)

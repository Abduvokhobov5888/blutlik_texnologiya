"""Vositalararo konsensus va Jaccard koeffitsienti (asosiy ilmiy g‘oya).

Obraz tekshiruvida Trivy va Grype topilmalari normallashtirilgan CVE kaliti
bo‘yicha, IaC tekshiruvida esa Checkov, KICS va Trivy topilmalari xato
toifasi bo‘yicha guruhlanadi. Kamida ikki vosita topgan guruh
"Tasdiqlangan", bittasi topgani "Tekshirish talab etiladi" deb belgilanadi.

Hisob-kitob ``stats3.py`` (obrazlar) va ``analyze.py`` (IaC) bilan bir xil.
"""

from __future__ import annotations

import itertools
from collections.abc import Iterable, Mapping, Sequence
from dataclasses import dataclass, field
from enum import StrEnum

from bulutskan.core.categories import GroundTruth, TfBlock, categorize
from bulutskan.core.models import Finding, FindingKind, FindingStatus, Severity, Tool
from bulutskan.core.normalize import match_path


_TOOL_ORDER = {tool: i for i, tool in enumerate(Tool)}


def tool_order(tools: Iterable[Tool]) -> list[Tool]:
    """Vositalarni e’lon qilingan tartibda saralaydi: checkov, kics, trivy, grype."""
    return sorted(set(tools), key=_TOOL_ORDER.__getitem__)


class ConsensusLabel(StrEnum):
    """Konsensus belgisi."""

    CONFIRMED = "confirmed"  # Tasdiqlangan
    NEEDS_REVIEW = "needs_review"  # Tekshirish talab etiladi


@dataclass
class ConsensusGroup:
    """Bir xil zaiflik yoki xato toifasiga tegishli topilmalar guruhi."""

    key: str
    kind: FindingKind
    title: str
    members: list[Finding] = field(default_factory=list)
    category: str | None = None
    description: str | None = None
    uncategorized: bool = False

    @property
    def tools(self) -> tuple[Tool, ...]:
        """Guruhdagi vositalar (tartiblangan)."""
        return tuple(tool_order(m.tool for m in self.members))

    @property
    def tool_count(self) -> int:
        """Nechta vosita topgan."""
        return len(self.tools)

    @property
    def label(self) -> ConsensusLabel:
        """Kamida ikki vosita topgan bo‘lsa — tasdiqlangan."""
        return ConsensusLabel.CONFIRMED if self.tool_count >= 2 else ConsensusLabel.NEEDS_REVIEW

    @property
    def severity(self) -> Severity:
        """Guruh darajasi: a’zolarning ma’lum bo‘lgan eng yuqori darajasi."""
        return max((m.severity for m in self.members), key=lambda s: s.rank, default=Severity.UNKNOWN)

    def severity_by_tool(self) -> dict[Tool, Severity]:
        """Har bir vosita bergan eng yuqori daraja."""
        out: dict[Tool, Severity] = {}
        for m in self.members:
            cur = out.get(m.tool)
            if cur is None or m.severity.rank > cur.rank:
                out[m.tool] = m.severity
        return out

    @property
    def cpe_suspect(self) -> bool:
        """Grype bu guruhni faqat CPE yoki binar fayl orqali topgan.

        ``stats3.py``: Grype yozuvlarining barchasi CPE asosida bo‘lsa.
        """
        grype = [m for m in self.members if m.tool is Tool.GRYPE]
        return bool(grype) and all(m.cpe_based for m in grype)

    @property
    def fix_available(self) -> bool:
        """Kamida bitta vosita tuzatilgan versiyani ko‘rsatgan."""
        return any(m.status is FindingStatus.FIX_AVAILABLE for m in self.members)

    @property
    def fixed_versions(self) -> list[str]:
        """Barcha a’zolardagi tuzatilgan versiyalar (takrorlarsiz)."""
        seen: list[str] = []
        for m in self.members:
            if m.fixed_version and m.fixed_version not in seen:
                seen.append(m.fixed_version)
        return seen

    @property
    def known_exploited(self) -> bool:
        """CISA KEV ro‘yxatida bor."""
        return any(m.known_exploited for m in self.members)

    @property
    def targets(self) -> list[str]:
        """Paketlar yoki fayllar (takrorlarsiz)."""
        seen: list[str] = []
        for m in self.members:
            if m.target not in seen:
                seen.append(m.target)
        return seen


@dataclass
class ConsensusResult:
    """Bitta tekshiruvning konsensus natijasi."""

    groups: list[ConsensusGroup]
    #: Vosita → solishtirishda qatnashgan kalitlar to‘plami.
    key_sets: dict[Tool, set[str]]
    #: Juftlik nomi ("trivy|grype") yoki "all" → Jaccard.
    jaccard: dict[str, float]
    #: Obraz uchun: CVE bo‘lmagan va faqat CPE asosidagi kalitlarsiz Jaccard.
    jaccard_core: float | None = None

    def count(self, label: ConsensusLabel) -> int:
        """Berilgan belgili guruhlar soni."""
        return sum(1 for g in self.groups if g.label is label)

    @property
    def cpe_suspect_count(self) -> int:
        """CPE asosidagi guruhlar soni."""
        return sum(1 for g in self.groups if g.cpe_suspect)


def jaccard(a: set[str], b: set[str], empty: float) -> float:
    """Jaccard koeffitsienti; ikkala to‘plam bo‘sh bo‘lsa ``empty`` qaytadi."""
    union = a | b
    return len(a & b) / len(union) if union else empty


def pair_name(a: Tool, b: Tool) -> str:
    """Juftlik kaliti, masalan ``trivy|grype``."""
    return f"{a.value}|{b.value}"


# ------------------------------------------------------------------ obrazlar


def image_consensus(reports: Mapping[Tool, Sequence[Finding]]) -> ConsensusResult:
    """Trivy va Grype zaifliklari bo‘yicha konsensus.

    ``reports`` faqat ishlagan vositalarni o‘z ichiga oladi. Ikkala to‘plam
    bo‘sh bo‘lsa Jaccard 1,0 (``stats3.py`` bilan bir xil).
    """
    groups: dict[str, ConsensusGroup] = {}
    key_sets: dict[Tool, set[str]] = {tool: set() for tool in reports}
    for tool, findings in reports.items():
        for f in findings:
            key = f.vuln_key
            key_sets[tool].add(key)
            group = groups.get(key)
            if group is None:
                group = groups[key] = ConsensusGroup(
                    key=key, kind=FindingKind.VULNERABILITY, title=f.title or key
                )
            elif not group.title or group.title == key:
                group.title = f.title or group.title
            group.members.append(f)

    pairs: dict[str, float] = {}
    for a, b in itertools.combinations(tool_order(key_sets), 2):
        pairs[pair_name(a, b)] = jaccard(key_sets[a], key_sets[b], empty=1.0)

    core: float | None = None
    if Tool.TRIVY in key_sets and Tool.GRYPE in key_sets:
        trivy_core = {k for k in key_sets[Tool.TRIVY] if k.startswith("CVE-")}
        grype_core = {
            k for k in key_sets[Tool.GRYPE] if not groups[k].cpe_suspect
        }
        core = jaccard(trivy_core, grype_core, empty=1.0)
    ordered = sorted(groups.values(), key=lambda g: (-g.severity.rank, -g.tool_count, g.key))
    return ConsensusResult(groups=ordered, key_sets=key_sets, jaccard=pairs, jaccard_core=core)


# ----------------------------------------------------------------------- IaC


def iac_consensus(
    reports: Mapping[Tool, Sequence[Finding]],
    gt: GroundTruth,
    block_maps: Mapping[str, Mapping[int, TfBlock | None]] | None = None,
) -> ConsensusResult:
    """Checkov, KICS va Trivy config topilmalari bo‘yicha konsensus.

    Toifaga tushgan topilmalar ``fayl + toifa`` kaliti bo‘yicha guruhlanadi
    va Jaccard faqat shu kalitlar bo‘yicha hisoblanadi (``analyze.py`` kabi;
    ikkala to‘plam bo‘sh bo‘lsa 0). Toifalanmagan topilma o‘z qoidasi
    bo‘yicha alohida guruhda qoladi. Har bir topilmaning ``category``
    maydoniga birinchi mos toifa yoziladi.
    """
    index = gt.by_id()
    groups: dict[str, ConsensusGroup] = {}
    key_sets: dict[Tool, set[str]] = {tool: set() for tool in reports}
    for tool, findings in reports.items():
        for f in findings:
            path = match_path(f.target)
            cats = categorize(f, gt, block_maps)
            f.category = cats[0] if cats else None
            if not cats:
                key = f"{tool.value}::{f.rule_id}::{path}::{f.resource or ''}"
                group = groups.get(key)
                if group is None:
                    group = groups[key] = ConsensusGroup(
                        key=key,
                        kind=FindingKind.MISCONFIGURATION,
                        title=f.title or f.rule_id,
                        uncategorized=True,
                    )
                group.members.append(f)
                continue
            for cat in cats:
                key = f"{path}::{cat}"
                key_sets[tool].add(key)
                group = groups.get(key)
                if group is None:
                    rule = index[cat]
                    group = groups[key] = ConsensusGroup(
                        key=key,
                        kind=FindingKind.MISCONFIGURATION,
                        title=rule.category,
                        category=cat,
                        description=rule.description,
                    )
                group.members.append(f)

    tools = tool_order(key_sets)
    pairs: dict[str, float] = {}
    for a, b in itertools.combinations(tools, 2):
        pairs[pair_name(a, b)] = jaccard(key_sets[a], key_sets[b], empty=0.0)
    if len(tools) > 2:
        union = set().union(*key_sets.values())
        inter = set.intersection(*key_sets.values())
        pairs["all"] = len(inter) / len(union) if union else 0.0
    ordered = sorted(
        groups.values(),
        key=lambda g: (g.uncategorized, -g.tool_count, -g.severity.rank, g.key),
    )
    return ConsensusResult(groups=ordered, key_sets=key_sets, jaccard=pairs)

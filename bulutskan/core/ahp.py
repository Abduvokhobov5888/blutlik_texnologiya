"""AHP (Analytic Hierarchy Process) asosida vosita tanlash moduli.

Dissertatsiyaning II bobidagi model: yettita mezon (K1..K7), xos vektor
usulida olingan vaznlar va har bir vosita uchun 1–5 shkaladagi ballar.

Vositaning umumiy bali::

    S_j = sum_i w_i * a_ij

Ssenariyda har bir vazn ko‘paytiruvchiga ko‘paytiriladi va yig‘indisi
1 ga keltiriladi::

    w'_i = w_i * m_i / sum_k (w_k * m_k)

Aniq vaznlar va ballar ``resources/`` dagi JSON fayllardan o‘qiladi;
bu modul faqat hisoblash mantiqini saqlaydi.
"""

from __future__ import annotations

import math
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field

#: Ballar teng deb hisoblanadigan farq (suzuvchi nuqta xatosi uchun).
_TIE_TOLERANCE = 1e-9


@dataclass(frozen=True)
class Criterion:
    """AHP mezoni."""

    code: str
    name_uz: str
    name_en: str


CRITERIA: tuple[Criterion, ...] = (
    Criterion("K1", "Funksional qamrov", "Functional coverage"),
    Criterion("K2", "Aniqlash sifati", "Detection quality"),
    Criterion("K3", "CI/CD integratsiyasi", "CI/CD integration"),
    Criterion("K4", "Moslashuvchanlik va me’yoriy xaritalash", "Flexibility and compliance mapping"),
    Criterion("K5", "Iqtisodiy samaradorlik", "Cost efficiency"),
    Criterion("K6", "Ta’minot zanjiri xavfsizligi", "Supply chain security"),
    Criterion("K7", "Normativ muvofiqlik va ma’lumotlar mahalliyligi", "Regulatory compliance and data residency"),
)

CRITERION_CODES: tuple[str, ...] = tuple(c.code for c in CRITERIA)


@dataclass(frozen=True)
class Scenario:
    """Tayyor ssenariy: mezon kodi → vazn ko‘paytiruvchisi."""

    key: str
    name_uz: str
    name_en: str
    multipliers: Mapping[str, float] = field(default_factory=dict)

    def multiplier_vector(self) -> tuple[float, ...]:
        """K1..K7 tartibidagi ko‘paytiruvchilar (berilmagani 1)."""
        unknown = set(self.multipliers) - set(CRITERION_CODES)
        if unknown:
            raise ValueError(f"Noma’lum mezon kodlari: {sorted(unknown)}")
        return tuple(float(self.multipliers.get(code, 1.0)) for code in CRITERION_CODES)


SCENARIOS: dict[str, Scenario] = {
    s.key: s
    for s in (
        Scenario("bazaviy", "Bazaviy", "Baseline"),
        Scenario("davlat", "Davlat tashkiloti", "Government organisation", {"K6": 2.0, "K7": 2.0}),
        Scenario(
            "korporativ",
            "Yirik korporativ",
            "Large enterprise",
            {"K1": 2.0, "K2": 1.5, "K5": 0.3},
        ),
        Scenario("kichik", "Kichik tashkilot", "Small organisation", {"K5": 3.0}),
    )
}


@dataclass(frozen=True)
class RankedTool:
    """Reytingdagi bitta qator."""

    position: int
    tool: str
    score: float


@dataclass(frozen=True)
class AhpModel:
    """AHP modeli: bazaviy vaznlar va vositalar ballari."""

    weights: tuple[float, ...]
    scores: Mapping[str, tuple[float, ...]]

    def __post_init__(self) -> None:
        _check_vector(self.weights, "vaznlar")
        if not self.scores:
            raise ValueError("Ballar jadvali bo‘sh")
        for tool, row in self.scores.items():
            _check_vector(row, f"{tool} ballari")

    @classmethod
    def from_mapping(
        cls,
        weights: Sequence[float],
        scores: Mapping[str, Sequence[float]],
    ) -> AhpModel:
        """Ro‘yxat va lug‘atlardan model yaratadi."""
        return cls(
            weights=tuple(float(w) for w in weights),
            scores={tool: tuple(float(x) for x in row) for tool, row in scores.items()},
        )

    @property
    def tools(self) -> tuple[str, ...]:
        """Vositalar nomlari (kiritilgan tartibda)."""
        return tuple(self.scores)

    def weights_for(self, scenario: Scenario | str) -> tuple[float, ...]:
        """Ssenariy uchun normallashtirilgan vaznlar."""
        if isinstance(scenario, str):
            try:
                scenario = SCENARIOS[scenario]
            except KeyError as exc:
                raise ValueError(f"Noma’lum ssenariy: {scenario}") from exc
        return apply_multipliers(self.weights, scenario.multiplier_vector())

    def rank(self, weights: Sequence[float] | None = None) -> list[RankedTool]:
        """Vositalarni umumiy ball bo‘yicha kamayish tartibida saralaydi.

        Ballari teng vositalar bir xil o‘rinni oladi (masalan, 6, 6, 8).
        ``weights`` berilmasa, bazaviy vaznlar ishlatiladi.
        """
        w = tuple(self.weights if weights is None else weights)
        _check_vector(w, "vaznlar")
        scored = sorted(
            ((tool, total_score(w, row)) for tool, row in self.scores.items()),
            key=lambda item: (-item[1], item[0]),
        )
        ranked: list[RankedTool] = []
        for index, (tool, value) in enumerate(scored):
            if ranked and math.isclose(value, ranked[-1].score, abs_tol=_TIE_TOLERANCE):
                position = ranked[-1].position
            else:
                position = index + 1
            ranked.append(RankedTool(position=position, tool=tool, score=value))
        return ranked


def normalize_weights(weights: Sequence[float]) -> tuple[float, ...]:
    """Vaznlarni yig‘indisi 1 bo‘ladigan qilib normallashtiradi."""
    _check_vector(weights, "vaznlar")
    total = math.fsum(weights)
    if total <= 0:
        raise ValueError("Vaznlar yig‘indisi musbat bo‘lishi kerak")
    return tuple(w / total for w in weights)


def apply_multipliers(weights: Sequence[float], multipliers: Sequence[float]) -> tuple[float, ...]:
    """Vaznlarni ko‘paytiruvchilarga ko‘paytirib, qayta normallashtiradi."""
    _check_vector(weights, "vaznlar")
    _check_vector(multipliers, "ko‘paytiruvchilar")
    return normalize_weights([w * m for w, m in zip(weights, multipliers, strict=True)])


def total_score(weights: Sequence[float], scores: Sequence[float]) -> float:
    """Vositaning umumiy bali: vaznlangan yig‘indi."""
    return math.fsum(w * a for w, a in zip(weights, scores, strict=True))


def _check_vector(values: Sequence[float], label: str) -> None:
    """Vektor uzunligi 7 va qiymatlari manfiy bo‘lmagan chekli son ekanini tekshiradi."""
    if len(values) != len(CRITERIA):
        raise ValueError(f"{label}: {len(CRITERIA)} ta qiymat kutilgan, {len(values)} ta berildi")
    for value in values:
        if not math.isfinite(value) or value < 0:
            raise ValueError(f"{label}: noto‘g‘ri qiymat {value!r}")

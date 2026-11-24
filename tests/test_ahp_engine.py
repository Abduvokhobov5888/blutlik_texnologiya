"""AHP hisoblash yadrosi: normallashtirish, ssenariylar va reyting.

Bu yerda hisoblash qoidalari tekshiriladi. Dissertatsiyadagi 3.9-jadval
bilan solishtirish aniq vaznlar (ahp.json) qo‘shilgach alohida testda
bajariladi.
"""

import math

import pytest

from bulutskan.core.ahp import (
    CRITERION_CODES,
    SCENARIOS,
    AhpModel,
    apply_multipliers,
    normalize_weights,
    total_score,
)

# Qoidalarni tekshirish uchun ixtiyoriy kirish vektori.
WEIGHTS = (0.2, 0.3, 0.05, 0.05, 0.1, 0.15, 0.15)


def test_normalize_weights_sums_to_one() -> None:
    result = normalize_weights([2, 2, 1, 0, 0, 0, 5])
    assert math.isclose(sum(result), 1.0)
    assert result[0] == pytest.approx(0.2)


@pytest.mark.parametrize("key", sorted(SCENARIOS))
def test_every_scenario_yields_normalized_weights(key: str) -> None:
    model = AhpModel.from_mapping(WEIGHTS, {"A": [1] * 7})
    assert math.isclose(sum(model.weights_for(key)), 1.0)


def test_scenario_multipliers_change_ratios_as_specified() -> None:
    model = AhpModel.from_mapping(WEIGHTS, {"A": [1] * 7})
    w = model.weights_for("davlat")
    k = {code: i for i, code in enumerate(CRITERION_CODES)}
    # K6 va K7 ikki baravar, qolganlari o‘zgarmagan: nisbat 2 marta oshadi.
    assert w[k["K6"]] / w[k["K1"]] == pytest.approx(2 * WEIGHTS[k["K6"]] / WEIGHTS[k["K1"]])
    w = model.weights_for("korporativ")
    assert w[k["K5"]] / w[k["K3"]] == pytest.approx(0.3 * WEIGHTS[k["K5"]] / WEIGHTS[k["K3"]])
    assert w[k["K2"]] / w[k["K3"]] == pytest.approx(1.5 * WEIGHTS[k["K2"]] / WEIGHTS[k["K3"]])


def test_baseline_scenario_keeps_normalized_weights_unchanged() -> None:
    model = AhpModel.from_mapping(WEIGHTS, {"A": [1] * 7})
    assert model.weights_for("bazaviy") == pytest.approx(WEIGHTS)


def test_total_score_is_weighted_sum() -> None:
    assert total_score(WEIGHTS, [5] * 7) == pytest.approx(5.0)
    assert total_score(WEIGHTS, [1, 0, 0, 0, 0, 0, 0]) == pytest.approx(0.2)


def test_rank_sorts_descending_and_shares_position_on_tie() -> None:
    model = AhpModel.from_mapping(
        WEIGHTS,
        {"A": [1] * 7, "B": [3] * 7, "C": [2] * 7, "D": [2] * 7},
    )
    ranked = model.rank()
    assert [r.tool for r in ranked] == ["B", "C", "D", "A"]
    assert [r.position for r in ranked] == [1, 2, 2, 4]


def test_custom_weights_override_baseline() -> None:
    model = AhpModel.from_mapping(WEIGHTS, {"A": [5, 1, 1, 1, 1, 1, 1], "B": [1, 5, 1, 1, 1, 1, 1]})
    only_k1 = apply_multipliers(WEIGHTS, [1, 0, 0, 0, 0, 0, 0])
    assert model.rank(only_k1)[0].tool == "A"


@pytest.mark.parametrize(
    "weights",
    [
        [0.5] * 6,  # uzunlik noto‘g‘ri
        [0.1, 0.1, 0.1, 0.1, 0.1, 0.1, -0.1],  # manfiy
        [0.1, 0.1, 0.1, 0.1, 0.1, 0.1, float("nan")],
    ],
)
def test_invalid_weights_are_rejected(weights: list[float]) -> None:
    with pytest.raises(ValueError):
        normalize_weights(weights)


def test_all_zero_weights_are_rejected() -> None:
    with pytest.raises(ValueError):
        normalize_weights([0] * 7)


def test_unknown_scenario_is_rejected() -> None:
    model = AhpModel.from_mapping(WEIGHTS, {"A": [1] * 7})
    with pytest.raises(ValueError):
        model.weights_for("mavjud-emas")

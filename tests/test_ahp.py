"""AHP: dissertatsiyaning II bobidagi aniq qiymatlar (3.9-jadval)."""

import json
import math

import pytest

from bulutskan.core.ahp import (
    DEFAULT_AHP_FILE,
    DEFAULT_SCORES_FILE,
    load_dissertation_model,
    principal_eigenvector,
    sensitivity,
)

# 3.9-jadval (3 xonagacha).
TABLE_3_9 = {
    "Checkov": 3.874,
    "Trivy": 3.817,
    "Grype": 3.704,
    "Prowler": 3.529,
    "KICS": 3.483,
    "Wiz": 3.148,
    "Cortex Cloud": 3.148,
    "MS Defender for Cloud": 3.057,
}


@pytest.fixture(scope="module")
def model():
    return load_dissertation_model()


def test_exact_weights_sum_to_one(model) -> None:
    assert math.isclose(sum(model.weights), 1.0, abs_tol=1e-12)


def test_scores_match_table_3_9(model) -> None:
    ranked = model.rank()
    got = {r.tool: round(r.score, 3) for r in ranked}
    assert got == TABLE_3_9
    assert [r.tool for r in ranked][:5] == ["Checkov", "Trivy", "Grype", "Prowler", "KICS"]


def test_ties_share_position(model) -> None:
    positions = {r.tool: r.position for r in model.rank()}
    assert positions["Wiz"] == positions["Cortex Cloud"] == 6
    assert positions["MS Defender for Cloud"] == 8


def test_scores_match_ahp_upd_new(model) -> None:
    new = json.loads(DEFAULT_SCORES_FILE.read_text(encoding="utf-8"))["new"]
    for r in model.rank():
        assert r.score == pytest.approx(new[r.tool], abs=1e-12)


def test_eigenvector_reproduces_weights_and_consistency(model) -> None:
    data = json.loads(DEFAULT_AHP_FILE.read_text(encoding="utf-8"))
    lam, w = principal_eigenvector(model.matrix)
    assert w == pytest.approx(data["w"], abs=1e-12)
    assert lam == pytest.approx(data["lam"], abs=1e-9)
    c = model.consistency()
    assert c is not None
    assert c.ci == pytest.approx(data["CI"], abs=1e-9)
    assert c.cr == pytest.approx(data["CR"], abs=1e-9)
    assert c.acceptable


def test_sensitivity_matches_dissertation(model) -> None:
    upd = json.loads(DEFAULT_SCORES_FILE.read_text(encoding="utf-8"))
    rows = sensitivity(model, factors=(0.5, 1.5))
    assert [[r.criterion, r.factor, r.leader] for r in rows] == upd["lead"]
    assert sum(r.same_top3 for r in rows) == upd["same3"]
    assert [r.tool for r in model.rank()] == upd["base"]


@pytest.mark.parametrize("scenario", ["bazaviy", "davlat", "korporativ", "kichik"])
def test_scenarios_produce_full_ranking(model, scenario: str) -> None:
    w = model.weights_for(scenario)
    assert math.isclose(sum(w), 1.0)
    assert len(model.rank(w)) == 8


def test_government_scenario_raises_supply_chain_weight(model) -> None:
    base = model.weights
    gov = model.weights_for("davlat")
    assert gov[5] > base[5] and gov[6] > base[6]  # K6, K7
    assert gov[1] < base[1]

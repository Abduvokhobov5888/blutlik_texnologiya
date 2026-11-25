"""--fail-on qarori va --unknown-severity siyosati."""

import pytest

from bulutskan.core.consensus import ConsensusLabel, image_consensus
from bulutskan.core.gate import (
    UnknownSeverityPolicy,
    ci_severity,
    evaluate_gate,
    parse_fail_on,
    severity_label,
)
from bulutskan.core.models import Finding, FindingKind, FindingStatus, Severity, Tool
from bulutskan.reporting.json_export import build_export
from tests.helpers import iac_outcome, image_outcome

P = UnknownSeverityPolicy


def _checkov_only_outcome():
    return iac_outcome(only=(Tool.CHECKOV,))


def test_checkov_only_categories_match_experiment(summary: dict) -> None:
    """III bob ma’lumotlari: Checkov topgan, lekin KICS topmagan xatolar — 4 ta
    (``iac_overlap`` dagi ``only_a``). Ulardan uchtasini Trivy topgan; uchala
    vosita orasida Checkov yolg‘iz o‘zi topgani — bitta, TF-20.
    """
    by_tool = {n: set(v["detected_ids"]) for n, v in summary["iac_summary"].items()}
    checkov, kics, trivy = by_tool["Checkov"], by_tool["KICS"], by_tool["Trivy (config)"]
    assert sorted(checkov - kics) == ["DF-04", "TF-03", "TF-04", "TF-20"]
    assert summary["iac_overlap"]["Checkov vs KICS"]["only_a"] == 4
    assert sorted(checkov - kics - trivy) == ["TF-20"]

    consensus = iac_outcome().consensus
    assert consensus is not None
    alone = [
        g for g in consensus.groups
        if not g.uncategorized and "/insecure/" in g.key and g.tools == (Tool.CHECKOV,)
    ]
    assert [g.category for g in alone] == ["TF-20"]
    # Bunday guruhning darajasi noma’lum: siyosatsiz u konveyerni hech qachon to‘xtatmasdi.
    assert alone[0].severity is Severity.UNKNOWN
    assert alone[0].label is ConsensusLabel.NEEDS_REVIEW
    uncategorized_checkov = [g for g in consensus.groups if g.uncategorized and g.tools == (Tool.CHECKOV,)]
    assert uncategorized_checkov and all(g.severity is Severity.UNKNOWN for g in uncategorized_checkov)


def test_checkov_only_group_fails_pipeline_with_default_policy() -> None:
    consensus = iac_outcome().consensus
    assert consensus is not None
    tf20 = next(g for g in consensus.groups if g.key == "terraform/insecure/main.tf::TF-20")
    assert tf20 not in evaluate_gate(consensus, Severity.MEDIUM, unknown_policy=P.IGNORE).counted
    assert tf20 in evaluate_gate(consensus, Severity.MEDIUM).counted


@pytest.mark.parametrize(
    ("fail_on", "policy", "failed"),
    [
        ("medium", P.IGNORE, False),
        ("low", P.IGNORE, False),
        ("medium", P.MEDIUM, True),
        ("high", P.MEDIUM, False),
        ("high", P.HIGH, True),
        ("critical", P.HIGH, False),
        ("low", P.LOW, True),
        ("medium", P.LOW, False),
    ],
)
def test_unknown_policy_decides_checkov_only_findings(fail_on: str, policy: UnknownSeverityPolicy, failed: bool) -> None:
    outcome = _checkov_only_outcome()
    assert outcome.consensus is not None
    assert {g.severity for g in outcome.consensus.groups} == {Severity.UNKNOWN}
    decision = evaluate_gate(outcome.consensus, parse_fail_on(fail_on), unknown_policy=policy)
    assert decision.failed is failed
    assert decision.exit_code == (1 if failed else 0)
    assert decision.unknown_counted == len(decision.counted)


def test_default_policy_is_medium() -> None:
    outcome = _checkov_only_outcome()
    assert outcome.consensus is not None
    assert evaluate_gate(outcome.consensus, Severity.MEDIUM).failed
    assert evaluate_gate(outcome.consensus, Severity.MEDIUM).policy is P.MEDIUM


def test_known_severity_from_other_tools_wins() -> None:
    """Checkov va KICS topgan guruh KICS darajasini oladi, siyosat unga ta’sir qilmaydi."""
    outcome = iac_outcome()
    assert outcome.consensus is not None
    group = next(g for g in outcome.consensus.groups if g.key == "terraform/insecure/main.tf::TF-09")
    assert group.severity is Severity.CRITICAL
    decision = evaluate_gate(outcome.consensus, Severity.CRITICAL, unknown_policy=P.IGNORE)
    assert decision.failed and group in decision.counted


def test_ci_severity_and_labels() -> None:
    assert ci_severity(Severity.UNKNOWN, P.IGNORE) is None
    assert ci_severity(Severity.UNKNOWN, P.MEDIUM) is Severity.MEDIUM
    assert ci_severity(Severity.HIGH, P.IGNORE) is Severity.HIGH
    assert severity_label(Severity.UNKNOWN, P.MEDIUM) == "noma’lum (CI uchun medium deb olindi)"
    assert severity_label(Severity.UNKNOWN, P.HIGH) == "noma’lum (CI uchun high deb olindi)"
    assert severity_label(Severity.UNKNOWN, P.IGNORE) == "noma’lum (CI uchun hisobga olinmadi)"
    assert severity_label(Severity.UNKNOWN, P.MEDIUM, "en") == "unknown (treated as medium for CI)"
    assert severity_label(Severity.HIGH, P.MEDIUM) == "HIGH"


def test_export_keeps_unknown_and_explains_ci_value() -> None:
    outcome = iac_outcome()
    data = build_export(outcome, P.MEDIUM)
    checkov = [f for f in data["findings"] if f["tool"] == "checkov"]
    assert checkov and all(f["severity"] == "UNKNOWN" for f in checkov)
    assert all(f["severity_ci"] == "MEDIUM" for f in checkov)
    assert all(f["severity_label"] == "noma’lum (CI uchun medium deb olindi)" for f in checkov)
    assert data["unknown_severity_policy"] == "medium"


def test_parse_fail_on() -> None:
    assert parse_fail_on("HIGH") is Severity.HIGH
    with pytest.raises(ValueError):
        parse_fail_on("unknown")


def test_no_threshold_never_fails() -> None:
    outcome = image_outcome("nginx:1.21")
    assert outcome.consensus is not None
    assert not evaluate_gate(outcome.consensus, None).failed


@pytest.mark.parametrize(
    ("image", "fail_on", "fixable", "failed"),
    [
        ("nginx:1.21", "critical", False, True),
        ("nginx:1.21", "critical", True, True),
        ("alpine:3.18", "critical", False, False),
        ("alpine:3.18", "high", False, True),
        # stats3: debian:12-slim da tuzatiladigan zaiflik yo‘q (t_fix = g_fix = 0).
        ("debian:12-slim", "low", False, True),
        ("debian:12-slim", "low", True, False),
    ],
)
def test_image_gate_on_real_reports(image: str, fail_on: str, fixable: bool, failed: bool) -> None:
    outcome = image_outcome(image)
    assert outcome.consensus is not None
    assert evaluate_gate(outcome.consensus, parse_fail_on(fail_on), fixable_only=fixable).failed is failed


def test_fixable_only_is_ignored_for_iac_with_note() -> None:
    outcome = iac_outcome()
    assert outcome.consensus is not None
    decision = evaluate_gate(outcome.consensus, Severity.HIGH, fixable_only=True)
    assert decision.failed and decision.notes


def test_cve_found_by_both_counts_once() -> None:
    def f(tool: Tool) -> Finding:
        return Finding(tool=tool, kind=FindingKind.VULNERABILITY, target="openssl", rule_id="CVE-2024-1",
                       cve="CVE-2024-1", severity=Severity.HIGH, status=FindingStatus.FIX_AVAILABLE)

    consensus = image_consensus({Tool.TRIVY: [f(Tool.TRIVY)], Tool.GRYPE: [f(Tool.GRYPE)]})
    assert len(evaluate_gate(consensus, Severity.HIGH).counted) == 1


def test_decide_exit_rules() -> None:
    from bulutskan.core.gate import GateDecision, decide_exit

    failing = GateDecision(failed=True, threshold=Severity.HIGH, policy=P.MEDIUM, fixable_only=False)
    passing = GateDecision(failed=False, threshold=Severity.HIGH, policy=P.MEDIUM, fixable_only=False)
    assert decide_exit("done", [], None).code == 0
    assert decide_exit("done", [], passing).code == 0
    assert decide_exit("done", [], failing).code == 1
    assert decide_exit("failed", ["trivy", "grype"], None).code == 2
    assert decide_exit("partial", ["checkov"], passing).code == 2
    assert decide_exit("partial", ["checkov"], failing).code == 2
    assert decide_exit("partial", ["checkov"], passing, allow_partial=True).code == 0
    assert decide_exit("partial", ["checkov"], failing, allow_partial=True).code == 1
    assert "checkov" in decide_exit("partial", ["checkov"], None).reason

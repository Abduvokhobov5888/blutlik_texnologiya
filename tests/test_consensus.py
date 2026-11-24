"""Konsensus va Jaccard: stats3.py (obrazlar) va analyze.py (IaC) natijalari bilan solishtirish."""

import itertools

import pytest

from bulutskan.core.categories import DEFAULT_IAC_ROOT, GroundTruth, build_block_maps, load_sources
from bulutskan.core.consensus import (
    ConsensusLabel,
    iac_consensus,
    image_consensus,
    jaccard,
)
from bulutskan.core.dedup import dedup_findings
from bulutskan.core.models import Finding, FindingKind, FindingStatus, Severity, Tool
from tests.conftest import IMAGES, ch3_row, grype_report, iac_reports, trivy_report


def _image_result(image: str):
    return image_consensus(
        {
            Tool.TRIVY: dedup_findings(trivy_report(image).findings),
            Tool.GRYPE: dedup_findings(grype_report(image).findings),
        }
    )


def _tool_max(group, tool: Tool) -> Severity:
    return max((m.severity for m in group.members if m.tool is tool), key=lambda s: s.rank)


@pytest.mark.parametrize("image", IMAGES)
def test_image_consensus_matches_stats3(image: str) -> None:
    res = _image_result(image)
    row = ch3_row(image)
    t, g = res.key_sets[Tool.TRIVY], res.key_sets[Tool.GRYPE]
    groups = {x.key: x for x in res.groups}

    assert len(t) == row["t_n"]
    assert len(g) == row["g_n"]
    assert len(t & g) == row["common"]
    assert len(t - g) == row["only_t"]
    assert len(g - t) == row["only_g"]
    assert res.jaccard["trivy|grype"] == pytest.approx(row["j"], abs=1e-12)
    assert res.jaccard_core == pytest.approx(row["j_core"], abs=1e-12)
    assert sum(1 for k in g if groups[k].cpe_suspect) == row["g_cpe"]

    def fixable(keys: set[str], tool: Tool) -> int:
        return sum(
            1
            for k in keys
            if any(m.status is FindingStatus.FIX_AVAILABLE for m in groups[k].members if m.tool is tool)
        )

    assert fixable(t, Tool.TRIVY) == row["t_fix"]
    assert fixable(g, Tool.GRYPE) == row["g_fix"]
    for tool, keys, prefix in ((Tool.TRIVY, t, "t"), (Tool.GRYPE, g, "g")):
        assert sum(1 for k in keys if _tool_max(groups[k], tool) is Severity.CRITICAL) == row[f"{prefix}_crit"]
        assert sum(1 for k in keys if _tool_max(groups[k], tool) is Severity.HIGH) == row[f"{prefix}_high"]

    # Ikkala vosita topgani — tasdiqlangan, qolgani — tekshirish talab etiladi.
    assert res.count(ConsensusLabel.CONFIRMED) == row["common"]
    assert res.count(ConsensusLabel.NEEDS_REVIEW) == row["only_t"] + row["only_g"]


def test_overall_image_jaccard_matches_stats3(ch3: dict) -> None:
    pairs_t: set[tuple[str, str]] = set()
    pairs_g: set[tuple[str, str]] = set()
    for image in IMAGES:
        res = _image_result(image)
        pairs_t |= {(image, k) for k in res.key_sets[Tool.TRIVY]}
        pairs_g |= {(image, k) for k in res.key_sets[Tool.GRYPE]}
    overall = ch3["overall"]
    assert len(pairs_t) == overall["t"]
    assert len(pairs_g) == overall["g"]
    assert len(pairs_t & pairs_g) == overall["common"]
    assert len(pairs_t & pairs_g) / len(pairs_t | pairs_g) == pytest.approx(overall["j"], abs=1e-12)


def test_dedup_does_not_change_cve_sets() -> None:
    image = "nginx:1.21"
    raw = image_consensus({Tool.GRYPE: grype_report(image).findings})
    deduped = image_consensus({Tool.GRYPE: dedup_findings(grype_report(image).findings)})
    assert raw.key_sets == deduped.key_sets
    assert len(dedup_findings(grype_report(image).findings)) <= len(grype_report(image).findings)


def test_cpe_only_grype_finding_needs_review_and_is_flagged() -> None:
    res = _image_result("alpine:3.18")
    # stats3: Trivy 0 ta, Grype 6 ta CVE, hammasi CPE asosida.
    assert res.count(ConsensusLabel.CONFIRMED) == 0
    assert all(g.label is ConsensusLabel.NEEDS_REVIEW and g.cpe_suspect for g in res.groups)


def test_cpe_flag_requires_all_grype_records_cpe() -> None:
    def f(cpe: bool, pkg: str) -> Finding:
        return Finding(
            tool=Tool.GRYPE,
            kind=FindingKind.VULNERABILITY,
            target=pkg,
            rule_id="CVE-2024-0001",
            cve="CVE-2024-0001",
            cpe_based=cpe,
        )

    mixed = image_consensus({Tool.GRYPE: [f(True, "a"), f(False, "b")]})
    assert not mixed.groups[0].cpe_suspect
    only_cpe = image_consensus({Tool.GRYPE: [f(True, "a"), f(True, "b")]})
    assert only_cpe.groups[0].cpe_suspect


def test_jaccard_empty_conventions() -> None:
    assert jaccard(set(), set(), empty=1.0) == 1.0
    assert jaccard(set(), set(), empty=0.0) == 0.0
    assert jaccard({"a", "b"}, {"b", "c"}, empty=0.0) == pytest.approx(1 / 3)


def test_single_tool_image_scan_has_no_pairs() -> None:
    res = image_consensus({Tool.TRIVY: trivy_report("debian:12-slim").findings})
    assert res.jaccard == {}
    assert res.jaccard_core is None
    assert res.count(ConsensusLabel.CONFIRMED) == 0


# ----------------------------------------------------------------------- IaC

_IAC_TOOLS = {"Checkov": Tool.CHECKOV, "KICS": Tool.KICS, "Trivy (config)": Tool.TRIVY}


def _iac_result():
    reports = iac_reports()
    gt = GroundTruth.load()
    targets = sorted({f.target for r in reports.values() for f in r.findings})
    block_maps = build_block_maps(load_sources(DEFAULT_IAC_ROOT, targets))
    findings = {_IAC_TOOLS[name]: [f.model_copy() for f in r.findings] for name, r in reports.items()}
    return iac_consensus(findings, gt, block_maps)


def test_iac_jaccard_on_insecure_files_matches_analyze(summary: dict) -> None:
    res = _iac_result()
    insecure = {
        tool: {k for k in keys if "/insecure/" in k} for tool, keys in res.key_sets.items()
    }
    names = {v: k for k, v in _IAC_TOOLS.items()}
    for a, b in itertools.combinations([Tool.CHECKOV, Tool.KICS, Tool.TRIVY], 2):
        expected = summary["iac_overlap"][f"{names[a]} vs {names[b]}"]
        assert len(insecure[a] & insecure[b]) == expected["both"]
        assert jaccard(insecure[a], insecure[b], empty=0.0) == pytest.approx(expected["jaccard"])
    detected = [set(summary["iac_summary"][n]["detected_ids"]) for n in _IAC_TOOLS]
    expected_all = len(set.intersection(*detected)) / len(set.union(*detected))
    union = set().union(*insecure.values())
    assert len(set.intersection(*insecure.values())) / len(union) == pytest.approx(expected_all)


def test_iac_groups_are_labelled() -> None:
    res = _iac_result()
    categorized = [g for g in res.groups if not g.uncategorized]
    assert categorized, "toifalangan guruhlar bo‘lishi kerak"
    for g in categorized:
        expected = ConsensusLabel.CONFIRMED if g.tool_count >= 2 else ConsensusLabel.NEEDS_REVIEW
        assert g.label is expected
        assert g.category and g.title
    for g in res.groups:
        if g.uncategorized:
            assert g.tool_count == 1 and g.label is ConsensusLabel.NEEDS_REVIEW
    assert {"checkov|kics", "checkov|trivy", "kics|trivy", "all"} <= set(res.jaccard)


def test_iac_group_severity_ignores_unknown_checkov() -> None:
    """Checkov darajasiz; guruh KICS/Trivy bergan ma’lum darajani oladi."""
    res = _iac_result()
    group = next(
        g for g in res.groups if g.key == "terraform/insecure/main.tf::TF-09"
    )
    assert Tool.CHECKOV in group.tools and group.tool_count >= 2
    assert group.severity is not Severity.UNKNOWN
    assert group.severity_by_tool()[Tool.CHECKOV] is Severity.UNKNOWN

"""IaC toifalash: ground_truth.csv va analyze.py natijalari."""

import pytest

from bulutskan.core.categories import (
    DEFAULT_IAC_ROOT,
    GroundTruth,
    build_block_maps,
    categorize,
    evaluate_ground_truth,
    file_family,
    load_sources,
    tf_block_map,
)
from bulutskan.core.models import Finding, FindingKind, FindingStatus, Tool
from tests.conftest import iac_reports


@pytest.fixture(scope="module")
def gt() -> GroundTruth:
    return GroundTruth.load()


def test_ground_truth_has_40_rules(gt: GroundTruth) -> None:
    ids = [r.id for r in gt.rules]
    assert len(ids) == 40
    assert sum(i.startswith("TF-") for i in ids) == 20
    assert sum(i.startswith("K8S-") for i in ids) == 13
    assert sum(i.startswith("DF-") for i in ids) == 7


def test_resource_types_are_derived_from_tokens(gt: GroundTruth) -> None:
    rules = gt.by_id()
    assert rules["TF-02"].resource_type == "aws_s3_bucket"
    assert rules["TF-10"].resource_type == "aws_db_instance"
    assert rules["TF-13"].resource_type == "aws_ebs_volume"
    assert rules["TF-19"].resource_type == "aws_cloudtrail"
    assert rules["TF-01"].resource_type is None  # provider bloki, tokensiz
    assert rules["K8S-01"].resource_type is None


def test_evaluation_matches_analyze(gt: GroundTruth, summary: dict) -> None:
    ev = evaluate_ground_truth({k: v.findings for k, v in iac_reports().items()}, gt)
    for name, expected in summary["iac_summary"].items():
        got = ev.tools[name]
        assert got.tp == expected["tp"], name
        assert got.fp == expected["fp"], name
        assert got.gt == expected["gt"]
        assert list(got.detected_ids) == expected["detected_ids"], name
        assert list(got.fp_ids) == expected["fp_ids"], name
        assert got.groups == expected["groups"], name
        assert got.recall == pytest.approx(expected["recall"])
        assert got.precision == pytest.approx(expected["precision"])
        assert got.f1 == pytest.approx(expected["f1"])
        assert got.findings_total == expected["findings_total"]
        assert got.findings_insecure == expected["findings_insecure"]
        assert got.findings_secure == expected["findings_secure"]
        assert got.findings_unmatched_insecure == expected["findings_unmatched_insecure"]
    for pair, expected in summary["iac_overlap"].items():
        pair_got = ev.overlap[pair]
        assert (pair_got["both"], pair_got["only_a"], pair_got["only_b"]) == (
            expected["both"],
            expected["only_a"],
            expected["only_b"],
        )
        assert pair_got["jaccard"] == pytest.approx(expected["jaccard"])
    assert list(ev.missed_by_all) == summary["missed_by_all"]


def test_generic_categorize_equals_ground_truth_on_insecure_files(
    gt: GroundTruth, summary: dict
) -> None:
    """GT tokenlarisiz (resurs turi bo‘yicha) toifalash ham III bob natijasini beradi."""
    reports = iac_reports()
    targets = sorted({f.target for r in reports.values() for f in r.findings})
    block_maps = build_block_maps(load_sources(DEFAULT_IAC_ROOT, targets))
    for name, report in reports.items():
        found: set[str] = set()
        for f in report.findings:
            if "/insecure/" in f.target:
                found.update(categorize(f, gt, block_maps))
        assert sorted(found) == summary["iac_summary"][name]["detected_ids"], name


def _tf_finding(title: str, line: int | None, resource: str | None = None) -> Finding:
    return Finding(
        tool=Tool.KICS,
        kind=FindingKind.MISCONFIGURATION,
        target="infra/main.tf",
        resource=resource,
        rule_id="x",
        title=title,
        status=FindingStatus.FAILED,
        line_start=line,
    )


def test_resource_type_disambiguates_encryption(gt: GroundTruth) -> None:
    source = (
        'resource "aws_db_instance" "prod" {\n'
        "  storage_encrypted = false\n"
        "}\n"
        'resource "aws_ebs_volume" "data" {\n'
        "  encrypted = false\n"
        "}\n"
    )
    maps = build_block_maps({"infra/main.tf": source})
    assert categorize(_tf_finding("Storage not encrypted", 2), gt, maps) == ["TF-10"]
    assert categorize(_tf_finding("Volume not encrypted", 5), gt, maps) == ["TF-13"]
    # Qator xaritasi bo‘lmasa, resurs manzilidan tur olinadi.
    assert categorize(_tf_finding("not encrypted", None, "aws_db_instance[prod]"), gt, {}) == ["TF-10"]
    # Turi noma’lum bo‘lsa, resursga bog‘liq toifa berilmaydi.
    assert categorize(_tf_finding("not encrypted", None), gt, {}) == []


def test_exclude_regex_is_applied(gt: GroundTruth) -> None:
    f = Finding(
        tool=Tool.TRIVY,
        kind=FindingKind.MISCONFIGURATION,
        target="k8s/app.yaml",
        rule_id="KSV-0001",
        title="Can elevate its own privileges (privilege escalation)",
        status=FindingStatus.FAILED,
    )
    cats = categorize(f, gt)
    assert "K8S-02" in cats
    assert "K8S-01" not in cats  # K8S-01 istisnosi: "escalation"


def test_tf_block_map_follows_analyze() -> None:
    src = '# izoh\nprovider "aws" {\n  region = "x"\n}\nresource "aws_s3_bucket" "b" {\n  ingress {\n  }\n}\n'
    m = tf_block_map(src)
    assert m[1] is None
    assert m[3] is not None and m[3].label == "aws"
    assert m[7] is not None and m[7].label == "b" and m[7].type == "aws_s3_bucket"


@pytest.mark.parametrize(
    ("path", "family"),
    [
        ("infra/main.tf", "terraform"),
        ("x.tf.json", "terraform"),
        ("k8s/deploy.yaml", "kubernetes"),
        ("k8s/deploy.yml", "kubernetes"),
        ("docker/Dockerfile", "dockerfile"),
        ("api.Dockerfile", "dockerfile"),
        ("Dockerfile.prod", "dockerfile"),
        ("README.md", None),
    ],
)
def test_file_family(path: str, family: str | None) -> None:
    assert file_family(path) == family


def test_load_sources_stays_inside_root() -> None:
    sources = load_sources(DEFAULT_IAC_ROOT, ["terraform/insecure/main.tf", "../../pyproject.toml"])
    assert list(sources) == ["terraform/insecure/main.tf"]

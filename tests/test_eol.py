"""Eskirgan bazaviy obrazni aniqlash."""

import pytest

from bulutskan.core.eol import (
    EOL_WARNING_UZ,
    detect_eol,
    load_eol_list,
    split_image_ref,
    version_matches,
)
from tests.conftest import IMAGES, ch3_row, grype_report, trivy_report

# stats3.py dagi B guruhi — eskirgan obrazlar; nginx:1.21 va juice-shop
# Debian 11 asosida (Trivy EOSL = true).
EXPECTED_EOL = {
    "alpine:3.18",
    "alpine:3.20",
    "debian:11-slim",
    "ubuntu:20.04",
    "centos:7",
    "python:3.9-slim",
    "node:16-alpine",
    "nginx:1.21",
    "bkimminich/juice-shop:v15.0.0",
}


@pytest.mark.parametrize("image", IMAGES)
def test_eol_detection_on_real_reports(image: str) -> None:
    result = detect_eol(image, trivy_report(image), grype_report(image))
    assert result.is_eol is (image in EXPECTED_EOL)


def test_group_b_is_always_eol() -> None:
    group_b = [i for i in IMAGES if ch3_row(i)["group"] == "B"]
    assert len(group_b) == 7
    assert set(group_b) <= EXPECTED_EOL


def test_python39_is_found_without_trivy_eosl() -> None:
    """python:3.9-slim Debian 13 asosida: Trivy EOSL bermaydi, lekin runtime eskirgan."""
    image = "python:3.9-slim"
    result = detect_eol(image, trivy_report(image), grype_report(image))
    sources = {r.source for r in result.reasons}
    assert "trivy-eosl" not in sources
    assert {"image-ref", "grype-binary"} <= sources
    assert [e.id for e in result.entries] == ["python-3.9"]


def test_reports_alone_are_enough_for_node16() -> None:
    result = detect_eol(None, trivy_report("node:16-alpine"), grype_report("node:16-alpine"))
    assert {e.id for e in result.entries} == {"alpine-3.18", "node-16"}


def test_image_name_alone() -> None:
    assert detect_eol("node:16", None, None).is_eol
    assert detect_eol("registry.local:5000/team/python:3.9.18-slim", None, None).is_eol
    assert not detect_eol("python:3.12-slim", None, None).is_eol
    assert not detect_eol("node:160", None, None).is_eol
    assert not detect_eol("nginx:latest", None, None).is_eol


def test_internal_list_covers_requirement() -> None:
    ids = {e.id for e in load_eol_list()}
    assert ids == {
        "centos-7",
        "ubuntu-20.04",
        "debian-11",
        "alpine-3.18",
        "alpine-3.20",
        "node-16",
        "python-3.9",
    }


@pytest.mark.parametrize(
    ("version", "prefix", "ok"),
    [
        ("11", "11", True),
        ("11.11", "11", True),
        ("110", "11", False),
        ("3.18.12", "3.18", True),
        ("3.180", "3.18", False),
        ("7.9.2009", "7", True),
        ("20.04", "20.04", True),
        ("v16.20.2", "16", True),
    ],
)
def test_version_matches(version: str, prefix: str, ok: bool) -> None:
    assert version_matches(version, prefix) is ok


def test_split_image_ref() -> None:
    assert split_image_ref("bkimminich/juice-shop:v15.0.0") == ("juice-shop", "v15.0.0")
    assert split_image_ref("localhost:5000/node") == ("node", None)
    assert split_image_ref("python@sha256:" + "a" * 64) == ("python", None)


def test_warning_text_is_exact() -> None:
    assert EOL_WARNING_UZ == (
        "Bazaviy obrazning qo‘llab-quvvatlash muddati tugagan. "
        "Skanerlar natijalari to‘liq emas, obrazni almashtiring."
    )

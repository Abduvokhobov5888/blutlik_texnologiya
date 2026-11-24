"""Umumiy fixture’lar: dissertatsiya eksperimentining real hisobotlari.

Hisobotlar ``demo/sinov/natijalar`` katalogida (Sinov papkasidan nusxa).
``tahlil/ch3.json`` va ``tahlil/summary.json`` — dissertatsiya skriptlari
(``stats3.py``, ``analyze.py``) hisoblagan kutilgan natijalar.
"""

from __future__ import annotations

import json
from functools import cache
from pathlib import Path
from typing import Any

import pytest

from bulutskan.core.models import ToolReport
from bulutskan.parsers import (
    load_json,
    parse_checkov,
    parse_grype,
    parse_kics,
    parse_trivy_config,
    parse_trivy_image,
)

ROOT = Path(__file__).resolve().parent.parent
SINOV = ROOT / "demo" / "sinov"
NATIJALAR = SINOV / "natijalar"
IMAGES_DIR = NATIJALAR / "images"
IAC_RUN = NATIJALAR / "iac" / "run1"
TAHLIL = NATIJALAR / "tahlil"

#: Eksperimentdagi 15 ta obraz (stats3.py dagi GROUPS tartibida).
IMAGES: tuple[str, ...] = tuple(
    r["image"] for r in json.loads((TAHLIL / "ch3.json").read_text(encoding="utf-8"))["images"]
)

#: Konteyner ichida IaC fayllar ulangan katalog (run_tests.ps1: -v iac:/iac:ro).
IAC_MOUNT = "iac"


def file_stem(image: str) -> str:
    """``bkimminich/juice-shop:v15.0.0`` → ``bkimminich_juice-shop_v15.0.0``."""
    return image.replace("/", "_").replace(":", "_")


@cache
def trivy_report(image: str) -> ToolReport:
    return parse_trivy_image(load_json(IMAGES_DIR / f"trivy_{file_stem(image)}_run1.json"))


@cache
def grype_report(image: str) -> ToolReport:
    return parse_grype(load_json(IMAGES_DIR / f"grype_{file_stem(image)}_run1.json"))


@cache
def iac_reports() -> dict[str, ToolReport]:
    """analyze.py dagi nomlar bilan: Checkov, KICS, Trivy (config)."""
    return {
        "Checkov": parse_checkov(load_json(IAC_RUN / "checkov" / "results_json.json"), mount=IAC_MOUNT),
        "KICS": parse_kics(load_json(IAC_RUN / "kics" / "results.json"), mount=IAC_MOUNT),
        "Trivy (config)": parse_trivy_config(load_json(IAC_RUN / "trivy_config.json"), mount=IAC_MOUNT),
    }


@cache
def _ch3() -> dict[str, Any]:
    return json.loads((TAHLIL / "ch3.json").read_text(encoding="utf-8"))


@cache
def _summary() -> dict[str, Any]:
    return json.loads((TAHLIL / "summary.json").read_text(encoding="utf-8"))


@pytest.fixture(scope="session")
def ch3() -> dict[str, Any]:
    """stats3.py natijalari."""
    return _ch3()


@pytest.fixture(scope="session")
def summary() -> dict[str, Any]:
    """analyze.py natijalari."""
    return _summary()


def ch3_row(image: str) -> dict[str, Any]:
    return next(r for r in _ch3()["images"] if r["image"] == image)


def summary_row(image: str) -> dict[str, Any]:
    return next(r for r in _summary()["images"] if r["image"] == image)

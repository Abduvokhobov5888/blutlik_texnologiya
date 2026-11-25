"""DOCX va JSON hisobotlar: tarkib, raqamlash, CLI --docx/--save."""

from __future__ import annotations

import io
import json
import re
from pathlib import Path

import pytest
from docx import Document
from sqlalchemy import select
from typer.testing import CliRunner

from bulutskan import cli
from bulutskan.core.categories import DEFAULT_IAC_ROOT
from bulutskan.core.models import Tool
from bulutskan.scanner.docker import DockerClient
from bulutskan.services.demo import import_demo
from bulutskan.services.history import docx_for, docx_from_outcome, record_outcome
from bulutskan.storage.db import Database
from bulutskan.storage.tables import Scan
from tests.fakes import FakeDocker
from tests.helpers import iac_outcome, image_outcome

runner = CliRunner()


def _text(data: bytes) -> tuple[list[str], str]:
    """Sarlavhalar va butun matn (jadvallar bilan)."""
    doc = Document(io.BytesIO(data))
    headings = [p.text for p in doc.paragraphs if p.style is not None and p.style.name.startswith("Heading")]
    parts = [p.text for p in doc.paragraphs]
    for table in doc.tables:
        for row in table.rows:
            parts.append(" | ".join(c.text for c in row.cells))
    return headings, "\n".join(parts)


def _numbers(headings: list[str]) -> list[int]:
    return [int(m.group(1)) for h in headings if (m := re.match(r"(\d+)\. ", h))]


def test_docx_image_report(db: Database) -> None:
    uid = record_outcome(db, image_outcome("nginx:1.21"))
    headings, text = _text(docx_for(db, uid))
    assert _numbers(headings) == list(range(1, len(_numbers(headings)) + 1))  # bo‘shliqsiz raqamlash
    assert any("Eskirgan bazaviy obraz" in h for h in headings)
    assert "qo‘llab-quvvatlash muddati tugagan" in text
    assert "nginx:1.21" in text and "Ma’lumotlar O‘zbekiston hududidan chiqmaydi." in text
    assert "Barcha vositalar muvaffaqiyatli ishladi." in text
    assert not any("Ground truth" in h for h in headings)


def test_docx_iac_report_has_ground_truth(db: Database) -> None:
    uid = record_outcome(db, iac_outcome())
    headings, text = _text(docx_for(db, uid))
    assert any("Ground truth" in h for h in headings)
    assert "36/40" in text and "34/40" in text and "32/40" in text
    assert "DF-03" in text and "K8S-09" in text  # hech bir vosita topmagan


def test_docx_for_every_demo_scan(db: Database) -> None:
    assert import_demo(db) == 16
    with db.session() as s:
        uids = list(s.scalars(select(Scan.uid)))
    for uid in uids:
        data = docx_for(db, uid)
        assert data[:2] == b"PK" and len(data) > 10_000
    with pytest.raises(KeyError):
        docx_for(db, "yoq")


def test_docx_without_history_leaves_no_trace(settings) -> None:
    data = docx_from_outcome(image_outcome("redis:6.2"))
    _, text = _text(data)
    assert "redis:6.2" in text
    assert not settings.db_path.exists()


# ------------------------------------------------------------- CLI


@pytest.fixture
def fake(settings, monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    f = FakeDocker(settings)
    f.install_tools()
    f.install_databases()
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "make_client", lambda s: DockerClient(f))
    return f


def test_cli_docx_without_save(fake: FakeDocker, tmp_path: Path) -> None:
    out = tmp_path / "hisobot" / "iac.docx"
    res = runner.invoke(cli.app, ["scan", "--iac", str(DEFAULT_IAC_ROOT), "--docx", str(out)])
    assert res.exit_code == 0, res.output
    assert f"DOCX: {out}" in res.output and "Tarixga yozildi" not in res.output
    _, text = _text(out.read_bytes())
    assert "36/40" in text
    assert not fake.settings.db_path.exists()


def test_cli_save_and_docx(fake: FakeDocker, tmp_path: Path) -> None:
    out = tmp_path / "nginx.docx"
    js = tmp_path / "nginx.json"
    res = runner.invoke(cli.app, ["scan", "--image", "nginx:1.21", "--save", "--docx", str(out), "--json", str(js),
                                  "--fail-on", "critical"])
    assert res.exit_code == 1, res.output
    uid = re.search(r"Tarixga yozildi: (\w+)", res.output).group(1)  # type: ignore[union-attr]
    db = Database(fake.settings.db_path)
    try:
        with db.session() as s:
            scan = s.scalar(select(Scan).where(Scan.uid == uid))
            assert scan is not None and scan.source == "cli" and scan.target == "nginx:1.21"
            assert scan.eol["is_eol"] is True
    finally:
        db.dispose()
    _, text = _text(out.read_bytes())
    assert "qo‘llab-quvvatlash muddati tugagan" in text
    data = json.loads(js.read_text(encoding="utf-8"))
    assert data["exit"]["code"] == 1 and data["scan"]["target"] == "nginx:1.21"


def test_cli_docx_partial_iac_scan(fake: FakeDocker, tmp_path: Path) -> None:
    fake.fail[Tool.TRIVY] = (2, "o‘chirilgan")
    out = tmp_path / "qisman_iac.docx"
    res = runner.invoke(cli.app, ["scan", "--iac", str(DEFAULT_IAC_ROOT), "--docx", str(out), "--allow-partial"])
    assert res.exit_code == 0, res.output
    headings, text = _text(out.read_bytes())
    assert "Tekshiruv qisman: trivy" in text and "Natija to‘liq emas" in text
    assert _numbers(headings) == list(range(1, len(_numbers(headings)) + 1))


def test_cli_docx_for_partial_scan(fake: FakeDocker, tmp_path: Path) -> None:
    fake.fail[Tool.GRYPE] = (137, "")
    out = tmp_path / "qisman.docx"
    res = runner.invoke(cli.app, ["scan", "--image", "nginx:1.21", "--docx", str(out)])
    assert res.exit_code == 2
    _, text = _text(out.read_bytes())  # qisman bo‘lsa ham hisobot yoziladi
    assert "Tekshiruv qisman: grype" in text and "Xotira yetmadi" in text

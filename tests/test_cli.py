"""CLI: chiqish kodlari 0/1/2 va --unknown-severity."""

import json
from pathlib import Path

import pytest
from typer.testing import CliRunner

from bulutskan import cli
from bulutskan.core.categories import DEFAULT_IAC_ROOT
from bulutskan.core.models import Tool
from bulutskan.scanner.docker import DockerClient
from tests.fakes import FakeDocker

runner = CliRunner()
IAC = str(DEFAULT_IAC_ROOT)


@pytest.fixture
def fake(settings, monkeypatch: pytest.MonkeyPatch) -> FakeDocker:
    f = FakeDocker(settings)
    f.install_tools()
    f.install_databases()
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    monkeypatch.setattr(cli, "make_client", lambda s: DockerClient(f))
    return f


def _run(*args: str):
    return runner.invoke(cli.app, list(args))


def test_iac_fail_on_high_exits_1(fake: FakeDocker) -> None:
    res = _run("scan", "--iac", IAC, "--fail-on", "high")
    assert res.exit_code == 1, res.output
    assert "Tasdiqlangan" in res.output
    assert "KONVEYER TO‘XTATILADI" in res.output


def test_iac_without_threshold_exits_0(fake: FakeDocker) -> None:
    res = _run("scan", "--iac", IAC)
    assert res.exit_code == 0, res.output
    assert "Ground truth" in res.output and "36/40" in res.output


def test_image_fail_on_critical_fixable_only(fake: FakeDocker) -> None:
    res = _run("scan", "--image", "nginx:1.21", "--fail-on", "critical", "--fixable-only")
    assert res.exit_code == 1, res.output
    assert "Bazaviy obrazning qo‘llab-quvvatlash muddati tugagan" in res.output


def test_image_below_threshold_exits_0(fake: FakeDocker) -> None:
    fake.image_fixture = "alpine:3.18"
    res = _run("scan", "--image", "alpine:3.18", "--fail-on", "critical")
    assert res.exit_code == 0, res.output


@pytest.mark.parametrize(
    ("extra", "code"),
    [
        (["--fail-on", "medium"], 1),  # sukut: medium
        (["--fail-on", "medium", "--unknown-severity", "ignore"], 0),
        (["--fail-on", "high"], 0),
        (["--fail-on", "high", "--unknown-severity", "high"], 1),
        (["--fail-on", "low", "--unknown-severity", "low"], 1),
    ],
)
def test_unknown_severity_option(fake: FakeDocker, extra: list[str], code: int) -> None:
    """Faqat Checkov ishlagan holat: barcha topilmalar darajasi noma’lum.

    Bu qisman tekshiruv, shuning uchun natija ``--allow-partial`` bilan qabul qilinadi.
    """
    fake.fail[Tool.KICS] = (2, "o‘chirilgan")
    fake.fail[Tool.TRIVY] = (2, "o‘chirilgan")
    res = _run("scan", "--iac", IAC, "--allow-partial", *extra)
    assert res.exit_code == code, res.output


def test_unknown_severity_is_labelled_in_output_and_json(fake: FakeDocker, tmp_path: Path) -> None:
    out = tmp_path / "natija.json"
    res = _run("scan", "--iac", IAC, "--fail-on", "high", "--json", str(out))
    assert "noma’lum (CI uchun medium deb olindi)" in res.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["gate"]["unknown_severity"] == "medium"
    labels = {f["severity_label"] for f in data["findings"] if f["tool"] == "checkov"}
    assert labels == {"noma’lum (CI uchun medium deb olindi)"}
    assert {f["severity"] for f in data["findings"] if f["tool"] == "checkov"} == {"UNKNOWN"}


def test_invalid_unknown_severity_value(fake: FakeDocker) -> None:
    res = _run("scan", "--iac", IAC, "--unknown-severity", "critical")
    assert res.exit_code == 2


def test_bad_image_name_exits_2(fake: FakeDocker) -> None:
    res = _run("scan", "--image", "nginx;whoami")
    assert res.exit_code == 2
    assert fake.runs() == []


def test_integrity_mismatch_exits_2(fake: FakeDocker) -> None:
    kics = fake.registry.images[Tool.KICS]
    del fake.images[kics.digest_ref]
    fake.images[kics.tag_ref] = {"Id": "sha256:" + "9" * 64, "RepoDigests": []}
    res = _run("scan", "--iac", IAC, "--fail-on", "high")
    assert res.exit_code == 2
    assert "bloklandi" in res.output
    assert fake.runs() == []


def test_requires_exactly_one_target(fake: FakeDocker) -> None:
    assert _run("scan").exit_code == 2
    assert _run("scan", "--iac", IAC, "--image", "nginx:1.21").exit_code == 2


def test_tools_verify(fake: FakeDocker) -> None:
    assert _run("tools", "verify").exit_code == 0
    fake.settings.tool_lock_file.unlink()
    res = _run("tools", "verify")
    assert res.exit_code == 2 and "lock-checkov" in res.output


def test_tools_lock_checkov(fake: FakeDocker) -> None:
    fake.settings.tool_lock_file.unlink()
    res = _run("tools", "lock-checkov")
    assert res.exit_code == 0, res.output
    assert _run("tools", "verify").exit_code == 0


def test_db_update_and_status(fake: FakeDocker) -> None:
    fake.proxy = "http://10.20.30.40:3128"
    res = _run("db-update")
    assert res.exit_code == 0, res.output
    assert "10.20.30.40" not in res.output
    assert "Proksi: aniqlandi" in res.output
    status = _run("db-status")
    assert status.exit_code == 0 and "Trivy asosiy bazasi" in status.output


def test_version() -> None:
    res = runner.invoke(cli.app, ["--version"])
    assert res.exit_code == 0 and "BulutSkan" in res.output


def test_partial_iac_scan_is_clearly_marked(fake: FakeDocker, tmp_path: Path) -> None:
    """Checkov ishlamasa, "hech kim topmagan" ro‘yxati to‘liq emas deb belgilanadi."""
    fake.fail[Tool.CHECKOV] = (2, "ProxySchemeUnknown: Proxy URL had no scheme")
    out = tmp_path / "qisman.json"
    res = _run("scan", "--iac", IAC, "--json", str(out))
    assert "DIQQAT: tekshiruv qisman" in res.output
    assert "III bob bilan solishtirib bo‘lmaydi" in res.output
    assert "Ishlagan vositalar (KICS, Trivy (config)) orasida hech biri topmagan" in res.output
    assert "sxemasiz" in res.output  # tushunarli xato izohi
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["ground_truth"]["complete"] is False
    assert data["ground_truth"]["tools_failed"] == ["checkov"]
    assert res.exit_code == 2


def test_full_iac_scan_is_complete(fake: FakeDocker, tmp_path: Path) -> None:
    out = tmp_path / "toliq.json"
    res = _run("scan", "--iac", IAC, "--json", str(out))
    assert "DIQQAT" not in res.output
    assert "Hech bir vosita topmagan: DF-03, K8S-09" in res.output
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["ground_truth"]["complete"] is True


@pytest.mark.parametrize(
    ("extra", "code"),
    [
        ([], 2),  # qisman → 2 (sukut)
        (["--fail-on", "critical"], 2),  # chegara oshgan bo‘lsa ham avval qisman ekani
        (["--allow-partial"], 0),
        (["--allow-partial", "--fail-on", "high"], 1),  # KICS va Trivy HIGH topgan
    ],
)
def test_partial_scan_exit_codes(fake: FakeDocker, extra: list[str], code: int) -> None:
    fake.fail[Tool.CHECKOV] = (2, "ProxySchemeUnknown: Proxy URL had no scheme")
    res = _run("scan", "--iac", IAC, *extra)
    assert res.exit_code == code, res.output
    assert "Ishlamagan vositalar:" in res.output
    assert "checkov — Sxemasiz proksi o‘zgaruvchisi [proxy_scheme, chiqish kodi 2]" in res.output
    assert f"Chiqish kodi {code}:" in res.output


def test_partial_scan_reasons_in_json(fake: FakeDocker, tmp_path: Path) -> None:
    fake.fail[Tool.GRYPE] = (137, "")
    out = tmp_path / "obraz.json"
    res = _run("scan", "--image", "nginx:1.21", "--fail-on", "critical", "--json", str(out))
    assert res.exit_code == 2
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["scan"]["status"] == "partial"
    assert data["failures"] == [
        {
            "tool": "grype",
            "reason_code": "out_of_memory",
            "reason_title": "Xotira yetmadi",
            "returncode": 137,
            "error": data["failures"][0]["error"],
            "duration_s": data["failures"][0]["duration_s"],
        }
    ]
    assert "BULUTSKAN_CONTAINER_MEMORY" in data["failures"][0]["error"]
    assert data["exit"] == {
        "code": 2,
        "reason": "Tekshiruv qisman: grype ishlamadi (istisno uchun --allow-partial)",
        "partial": True,
        "allow_partial": False,
    }
    grype = next(t for t in data["tools"] if t["tool"] == "grype")
    assert grype["ok"] is False and grype["reason_code"] == "out_of_memory"


def test_missing_database_reason(fake: FakeDocker) -> None:
    for p in (fake.settings.grype_cache / "6").iterdir():
        p.unlink()
    res = _run("scan", "--image", "nginx:1.21", "--allow-partial")
    assert res.exit_code == 0
    assert "grype — Zaifliklar bazasi yo‘q [missing_db]" in res.output
    assert "Qisman natija qabul qilindi" in res.output


def test_complete_scan_has_no_failures_in_json(fake: FakeDocker, tmp_path: Path) -> None:
    out = tmp_path / "toliq.json"
    res = _run("scan", "--image", "nginx:1.21", "--json", str(out))
    assert res.exit_code == 0
    data = json.loads(out.read_text(encoding="utf-8"))
    assert data["failures"] == [] and data["exit"]["code"] == 0 and data["exit"]["partial"] is False

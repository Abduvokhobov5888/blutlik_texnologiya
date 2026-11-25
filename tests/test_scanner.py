"""Tekshiruv quvuri soxta docker bilan: buyruqlar xavfsiz, natijalar real ma’lumotga mos."""

from pathlib import Path

import pytest

from bulutskan.core.categories import DEFAULT_IAC_ROOT
from bulutskan.core.models import Tool
from bulutskan.scanner.docker import DockerClient
from bulutskan.scanner.image import ImagePrepareError
from bulutskan.scanner.tools import IntegrityError
from bulutskan.security.validators import InvalidImageReference
from bulutskan.services.pipeline import Scanner, ScanStatus
from tests.conftest import ch3_row
from tests.fakes import CHECKOV_ID, FakeDocker, make_docker_archive


def _pairs(cmd: list[str]) -> set[tuple[str, str]]:
    return set(zip(cmd, cmd[1:], strict=False))


def _mounts(cmd: list[str]) -> list[str]:
    return [cmd[i + 1] for i, c in enumerate(cmd) if c == "--mount"]


@pytest.fixture
def fake(settings) -> FakeDocker:
    f = FakeDocker(settings)
    f.install_tools()
    f.install_databases()
    return f


def _scanner(fake: FakeDocker) -> Scanner:
    return Scanner(fake.settings, DockerClient(fake))


def _assert_isolated(cmd: list[str]) -> None:
    pairs = _pairs(cmd)
    assert ("--network", "none") in pairs
    assert ("--pull", "never") in pairs
    assert ("--cap-drop", "ALL") in pairs
    assert ("--security-opt", "no-new-privileges") in pairs
    assert "--read-only" in cmd and "--rm" in cmd
    envs = [cmd[i + 1].split("=", 1)[0] for i, c in enumerate(cmd) if c == "--env"]
    assert not {e.lower() for e in envs} & {"http_proxy", "https_proxy", "no_proxy"}
    assert any(t.startswith("aquasec/") or t.startswith("anchore/") or t.startswith("checkmarx/") or t == CHECKOV_ID
               for t in cmd)
    # Teg bilan chaqirilmaydi: faqat digest yoki obraz ID.
    assert not any(t in {"aquasec/trivy:0.76.1", "anchore/grype:v0.121.0", "checkmarx/kics:v2.2.0",
                         "diss-checkov:3.3.26"} for t in cmd)


def test_iac_scan_reproduces_experiment(fake: FakeDocker, summary: dict) -> None:
    outcome = _scanner(fake).scan_iac_directory(DEFAULT_IAC_ROOT)
    assert outcome.status == ScanStatus.DONE
    assert [r.tool for r in outcome.tool_runs] == [Tool.CHECKOV, Tool.KICS, Tool.TRIVY]
    assert len(outcome.files) == 6
    ev = outcome.gt_evaluation
    assert ev is not None
    for name, expected in summary["iac_summary"].items():
        assert ev.tools[name].tp == expected["tp"]
        assert list(ev.tools[name].detected_ids) == expected["detected_ids"]

    runs = fake.runs()
    assert len(runs) == 3
    for cmd in runs:
        _assert_isolated(cmd)
        mounts = _mounts(cmd)
        scan_mount = next(m for m in mounts if "target=/scan" in m)
        assert scan_mount.endswith(",readonly")
        for m in mounts:
            if not m.endswith(",readonly"):
                assert "target=/out" in m  # yagona yozish katalogi
    kics = fake.run_for(Tool.KICS)[0]
    assert kics[-8:] == ["scan", "-p", "/scan", "-o", "/out", "--report-formats", "json", "--no-progress"]

    # Vaqtinchalik katalog o‘chirilgan, xom hisobotlar saqlangan.
    assert list(fake.settings.workdir.iterdir()) == []
    saved = fake.settings.reports_dir / outcome.uid
    assert sorted(p.name for p in saved.iterdir()) == ["checkov.json", "kics.json", "trivy_config.json"]


def test_iac_scan_sees_only_whitelisted_files(fake: FakeDocker, tmp_path: Path) -> None:
    src = tmp_path / "proj"
    src.mkdir()
    (src / "main.tf").write_text('resource "aws_s3_bucket" "b" {}\n')
    (src / ".env").write_text("SECRET=1\n")
    outcome = _scanner(fake).scan_iac_directory(src)
    assert outcome.files == ["main.tf"]
    assert ".env" in outcome.skipped_files


def test_image_scan_pull_save_offline(fake: FakeDocker) -> None:
    outcome = _scanner(fake).scan_image("nginx:1.21")
    assert outcome.status == ScanStatus.DONE
    cmds = [c[1] for c in fake.calls]
    assert cmds.index("pull") < cmds.index("save") < cmds.index("run")
    row = ch3_row("nginx:1.21")
    assert outcome.consensus is not None
    assert outcome.consensus.jaccard["trivy|grype"] == pytest.approx(row["j"])
    assert outcome.eol is not None and outcome.eol.is_eol

    trivy = fake.run_for(Tool.TRIVY)[0]
    grype = fake.run_for(Tool.GRYPE)[0]
    for cmd in (trivy, grype):
        _assert_isolated(cmd)
        assert any("target=/input/image.tar,readonly" in m for m in _mounts(cmd))
    assert any(m.endswith("target=/tmp/trivy/db,readonly") for m in _mounts(trivy))
    assert any(m.endswith("target=/cache,readonly") for m in _mounts(grype))
    assert {"--skip-db-update", "--skip-java-db-update", "--offline-scan"} <= set(trivy)
    envs = {grype[i + 1] for i, c in enumerate(grype) if c == "--env"}
    assert {"GRYPE_DB_AUTO_UPDATE=false", "GRYPE_CHECK_FOR_APP_UPDATE=false", "TMPDIR=/scratch"} <= envs
    assert grype[-3:] == ["docker-archive:/input/image.tar", "-o", "json"]
    assert list(fake.settings.workdir.iterdir()) == []


def test_readonly_db_falls_back_to_copy(fake: FakeDocker) -> None:
    fake.readonly_fail = {Tool.TRIVY, Tool.GRYPE}
    outcome = _scanner(fake).scan_image("alpine:3.20")
    assert outcome.status == ScanStatus.DONE
    assert len(fake.run_for(Tool.TRIVY)) == 2 and len(fake.run_for(Tool.GRYPE)) == 2
    assert all(r.notes for r in outcome.tool_runs)
    retry = fake.run_for(Tool.TRIVY)[1]
    assert ("--network", "none") in _pairs(retry)


def test_copy_mode_from_settings(fake: FakeDocker) -> None:
    fake.settings.trivy_db_mode = "copy"
    _scanner(fake).scan_image("alpine:3.20")
    trivy = fake.run_for(Tool.TRIVY)
    assert len(trivy) == 1 and "/cache" in trivy[0]


def test_one_tool_failing_gives_partial_result(fake: FakeDocker) -> None:
    fake.fail[Tool.KICS] = (2, "kics xatosi")
    outcome = _scanner(fake).scan_iac_directory(DEFAULT_IAC_ROOT)
    assert outcome.status == ScanStatus.PARTIAL
    failed = next(r for r in outcome.tool_runs if r.tool is Tool.KICS)
    assert not failed.ok and failed.error and "kics xatosi" in failed.error
    assert outcome.consensus is not None and "checkov|trivy" in outcome.consensus.jaccard


def test_out_of_memory_is_explained(fake: FakeDocker) -> None:
    fake.fail[Tool.GRYPE] = (137, "")
    outcome = _scanner(fake).scan_image("alpine:3.20")
    run = next(r for r in outcome.tool_runs if r.tool is Tool.GRYPE)
    assert run.error is not None and "BULUTSKAN_CONTAINER_MEMORY" in run.error


def test_integrity_problem_blocks_before_any_container(fake: FakeDocker) -> None:
    trivy = fake.registry.images[Tool.TRIVY]
    del fake.images[trivy.digest_ref]
    fake.images[trivy.tag_ref] = {"Id": "sha256:" + "f" * 64, "RepoDigests": []}
    with pytest.raises(IntegrityError):
        _scanner(fake).scan_image("nginx:1.21")
    with pytest.raises(IntegrityError):
        _scanner(fake).scan_iac_directory(DEFAULT_IAC_ROOT)
    assert fake.runs() == [] and not any(c[1] == "pull" for c in fake.calls)


def test_invalid_image_name_is_rejected_before_docker(fake: FakeDocker) -> None:
    with pytest.raises(InvalidImageReference):
        _scanner(fake).scan_image("nginx:1.21; rm -rf /")
    assert fake.calls == []


def test_pull_failure(fake: FakeDocker) -> None:
    fake.pull_fail = True
    with pytest.raises(ImagePrepareError):
        _scanner(fake).scan_image("nginx:1.21")
    assert fake.runs() == []
    assert list(fake.settings.workdir.iterdir()) == []


def test_missing_database_is_reported(settings) -> None:
    fake = FakeDocker(settings)
    fake.install_tools()
    outcome = Scanner(settings, DockerClient(fake)).scan_image("alpine:3.20")
    assert outcome.status == ScanStatus.FAILED
    assert all("db-update" in (r.error or "") for r in outcome.tool_runs)


def test_existing_tar_is_mounted_without_pull(fake: FakeDocker, tmp_path: Path) -> None:
    tar = tmp_path / "Sinov tar" / "nginx_1.21.tar"
    tar.parent.mkdir()
    make_docker_archive(tar)
    outcome = _scanner(fake).scan_image_tar(tar, image_name="nginx:1.21")
    assert outcome.status == ScanStatus.DONE
    assert not any(c[1] in {"pull", "save"} for c in fake.calls)
    trivy = fake.run_for(Tool.TRIVY)[0]
    assert f"type=bind,source={tar},target=/input/image.tar,readonly" in _mounts(trivy)
    assert outcome.eol is not None and outcome.eol.is_eol


def test_fake_checkov_rejects_empty_proxy_like_real_checkov(fake: FakeDocker) -> None:
    """Soxta Checkov ham haqiqiysi kabi bo‘sh https_proxy da yiqiladi: regressiya qopqoni."""
    from bulutskan.scanner.docker import DockerClient as Client

    argv = ["docker", "run", "--env", "https_proxy=", CHECKOV_ID, "-d", "/scan"]
    res = fake.run(argv, timeout=5)
    assert res.returncode == 2 and b"ProxySchemeUnknown" in res.stderr
    assert isinstance(Client(fake), Client)


def test_checkov_runs_in_iac_scan_and_finds_tf20(fake: FakeDocker) -> None:
    """Windows’dagi xato: Checkov ishlamasa TF-20 "hech kim topmagan" ro‘yxatiga tushib qolardi."""
    outcome = _scanner(fake).scan_iac_directory(DEFAULT_IAC_ROOT)
    checkov = next(r for r in outcome.tool_runs if r.tool is Tool.CHECKOV)
    assert checkov.ok, checkov.error
    assert outcome.gt_evaluation is not None
    assert "TF-20" in outcome.gt_evaluation.tools["Checkov"].detected_ids
    assert list(outcome.gt_evaluation.missed_by_all) == ["DF-03", "K8S-09"]

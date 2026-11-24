"""Vositalar reestri, digest tekshiruvi va Checkov qulfi."""

import json

import pytest

from bulutskan.config import RESOURCES
from bulutskan.core.models import Tool
from bulutskan.scanner.docker import DockerClient
from bulutskan.scanner.tools import (
    IntegrityError,
    IntegrityStatus,
    LockError,
    load_tool_digests,
    lock_checkov,
    locked_checkov_id,
    verify_tools,
)
from tests.fakes import CHECKOV_ID, FakeDocker


def test_tool_digests_file_from_experiment() -> None:
    reg = load_tool_digests(RESOURCES / "tool_digests.txt")
    assert reg.images[Tool.TRIVY].digest_ref == (
        "aquasec/trivy@sha256:790fd66d1697395d8693d1acaa1ea702406a20f109b6fc7bac8db623eca6c06c"
    )
    assert reg.images[Tool.GRYPE].tag_ref == "anchore/grype:v0.121.0"
    assert reg.images[Tool.KICS].version == "v2.2.0"
    assert reg.checkov_version == "3.3.26"
    assert reg.checkov_tag == "diss-checkov:3.3.26"


def test_tool_digests_rejects_garbage(tmp_path) -> None:
    p = tmp_path / "d.txt"
    p.write_text("aquasec/trivy:latest -> aquasec/trivy:latest\n")
    with pytest.raises(ValueError):
        load_tool_digests(p)


def _verify(fake: FakeDocker):
    return verify_tools(DockerClient(fake), fake.registry, fake.settings.tool_lock_file)


def test_all_tools_ok(settings) -> None:
    fake = FakeDocker(settings)
    fake.install_tools()
    report = _verify(fake)
    assert report.ok
    assert [c.tool for c in report.checks] == [Tool.CHECKOV, Tool.KICS, Tool.TRIVY, Tool.GRYPE]
    assert report.run_ref(Tool.TRIVY).startswith("aquasec/trivy@sha256:")
    assert report.run_ref(Tool.CHECKOV) == CHECKOV_ID


def test_tag_pointing_to_other_image_is_mismatch(settings) -> None:
    fake = FakeDocker(settings)
    fake.install_tools()
    trivy = fake.registry.images[Tool.TRIVY]
    del fake.images[trivy.digest_ref]
    fake.images[trivy.tag_ref] = {"Id": "sha256:" + "e" * 64, "RepoDigests": ["aquasec/trivy@sha256:" + "e" * 64]}
    report = _verify(fake)
    assert not report.ok and report.has_mismatch
    check = next(c for c in report.checks if c.tool is Tool.TRIVY)
    assert check.status is IntegrityStatus.MISMATCH
    with pytest.raises(IntegrityError):
        report.run_ref(Tool.TRIVY)


def test_missing_image(settings) -> None:
    fake = FakeDocker(settings)
    fake.install_tools()
    kics = fake.registry.images[Tool.KICS]
    del fake.images[kics.digest_ref]
    del fake.images[kics.tag_ref]
    report = _verify(fake)
    assert next(c for c in report.checks if c.tool is Tool.KICS).status is IntegrityStatus.MISSING
    assert not report.ok and not report.has_mismatch


def test_checkov_not_locked_blocks(settings) -> None:
    fake = FakeDocker(settings)
    fake.install_tools()
    settings.tool_lock_file.unlink()
    report = _verify(fake)
    assert next(c for c in report.checks if c.tool is Tool.CHECKOV).status is IntegrityStatus.NOT_LOCKED
    assert not report.ok


def test_rebuilt_checkov_is_mismatch(settings) -> None:
    fake = FakeDocker(settings)
    fake.install_tools()
    del fake.images[CHECKOV_ID]
    fake.images["diss-checkov:3.3.26"] = {"Id": "sha256:" + "d" * 64}
    report = _verify(fake)
    assert next(c for c in report.checks if c.tool is Tool.CHECKOV).status is IntegrityStatus.MISMATCH


def test_docker_unavailable(settings) -> None:
    fake = FakeDocker(settings, available=False)
    report = _verify(fake)
    assert not report.docker_available and not report.ok
    assert {c.status for c in report.checks} == {IntegrityStatus.DOCKER_UNAVAILABLE}


def test_lock_checkov_records_id_after_version_check(settings) -> None:
    fake = FakeDocker(settings)
    fake.images["diss-checkov:3.3.26"] = {"Id": CHECKOV_ID}
    image_id = lock_checkov(DockerClient(fake), fake.registry, settings.tool_lock_file)
    assert image_id == CHECKOV_ID
    assert locked_checkov_id(settings.tool_lock_file) == CHECKOV_ID
    data = json.loads(settings.tool_lock_file.read_text())
    assert data["checkov"]["version"] == "3.3.26"
    run = fake.runs()[-1]
    assert ("--network", "none") in set(zip(run, run[1:], strict=False))


def test_lock_checkov_fails_without_image(settings) -> None:
    fake = FakeDocker(settings)
    with pytest.raises(LockError):
        lock_checkov(DockerClient(fake), fake.registry, settings.tool_lock_file)

"""Bazalarni yangilash: proksi faqat shu bosqichda, sanalar saqlanadi."""

import json
import shutil

import pytest

from bulutskan.core.models import Tool
from bulutskan.scanner.dbupdate import (
    database_status,
    detect_proxy,
    mask_proxy,
    normalize_proxy,
    parse_grype_status_text,
    read_trivy_metadata,
    update_databases,
)
from bulutskan.scanner.docker import DockerClient
from bulutskan.scanner.tools import verify_tools
from tests.conftest import NATIJALAR
from tests.fakes import FakeDocker


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("", None),
        ("<no value>", None),
        ("http.docker.internal:3128", "http://http.docker.internal:3128"),
        ("http://127.0.0.1:3128", "http://host.docker.internal:3128"),
        ("http://localhost:8080/", "http://host.docker.internal:8080/"),
        ("https://proxy.example.uz:443", "https://proxy.example.uz:443"),
        ("http://localhostx:1", "http://localhostx:1"),
    ],
)
def test_normalize_proxy(raw: str, expected: str | None) -> None:
    assert normalize_proxy(raw) == expected


def test_mask_never_reveals_address() -> None:
    assert mask_proxy("http://user:parol@10.1.2.3:3128") == "aniqlandi"
    assert mask_proxy(None) == "yo‘q"


def test_detect_proxy_falls_back_to_http(settings) -> None:
    fake = FakeDocker(settings, proxy="")
    assert detect_proxy(DockerClient(fake)) is None
    fake.proxy = "proxy.local:3128"
    assert detect_proxy(DockerClient(fake)) == "http://proxy.local:3128"


def test_update_uses_network_and_proxy_only_here(settings) -> None:
    fake = FakeDocker(settings, proxy="http://127.0.0.1:3128")
    fake.install_tools()
    client = DockerClient(fake)
    integrity = verify_tools(client, fake.registry, settings.tool_lock_file)
    results = update_databases(client, integrity, settings)
    assert [r.name for r in results] == ["trivy", "trivy-java", "grype"]
    assert all(r.ok for r in results)

    downloads = [c for c in fake.runs() if "--download-db-only" in c or "--download-java-db-only" in c or c[-2:] == ["db", "update"]]
    assert len(downloads) == 3
    for cmd in downloads:
        pairs = set(zip(cmd, cmd[1:], strict=False))
        assert ("--network", "bridge") in pairs
        assert ("--env", "HTTPS_PROXY=http://host.docker.internal:3128") in pairs
        assert ("--cap-drop", "ALL") in pairs and "--read-only" in cmd
    status_run = [c for c in fake.runs() if c[-2:] == ["db", "status"]][0]
    assert ("--network", "none") in set(zip(status_run, status_run[1:], strict=False))

    state = json.loads(settings.db_state_file.read_text(encoding="utf-8"))
    assert "127.0.0.1" not in settings.db_state_file.read_text(encoding="utf-8")
    assert state["trivy"]["metadata"]["UpdatedAt"] == "2026-11-24T07:08:30Z"
    assert state["grype"]["metadata"]["built"] == "2026-11-24T06:22:05Z"
    assert state["grype"]["last_attempt"]["proxy"] == "aniqlandi"

    status = database_status(settings)
    assert all(v["present"] for v in status.values())
    assert status["trivy"]["updated_at"]


def test_failed_update_hides_proxy_in_error(settings) -> None:
    fake = FakeDocker(settings, proxy="http://user:parol@10.0.0.9:3128")
    fake.install_tools()
    fake.fail[Tool.GRYPE] = (1, "dial tcp via http://user:parol@10.0.0.9:3128: refused")
    client = DockerClient(fake)
    integrity = verify_tools(client, fake.registry, settings.tool_lock_file)
    results = update_databases(client, integrity, settings, which=("grype",))
    assert not results[0].ok
    assert results[0].error is not None and "parol" not in results[0].error
    assert "parol" not in settings.db_state_file.read_text(encoding="utf-8")


def test_unknown_database_name(settings) -> None:
    fake = FakeDocker(settings)
    fake.install_tools()
    client = DockerClient(fake)
    with pytest.raises(ValueError):
        update_databases(client, verify_tools(client, fake.registry, settings.tool_lock_file), settings, which=("x",))


def test_experiment_metadata_files_are_readable(tmp_path) -> None:
    db = tmp_path / "db"
    db.mkdir()
    shutil.copyfile(NATIJALAR / "trivy_db_metadata.json", db / "metadata.json")
    meta = read_trivy_metadata(db)
    assert meta is not None and meta["UpdatedAt"].startswith("2026-11-24T07:08:30")
    status = parse_grype_status_text((NATIJALAR / "grype_db_status.txt").read_text(encoding="utf-8-sig"))
    assert status["schema"] == "v6.1.10"
    assert status["built"] == "2026-11-24T06:22:05Z"
    assert "checksum" not in status["from"]

"""Bazalarni yangilash: proksi faqat shu bosqichda, sanalar saqlanadi."""

import json
import shutil
from pathlib import Path

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


def _grype_v6_db(cache: Path, built: object = "2026-11-24 06:22:05+00:00", with_import: bool = True) -> Path:
    """Grype v6 bazasining metama’lumot qismi (grype v0.121.0 models.go dagi DBMetadata jadvali)."""
    import sqlite3
    from contextlib import closing

    d = cache / "6"
    d.mkdir(parents=True)
    db = d / "vulnerability.db"
    with closing(sqlite3.connect(db)) as con:
        con.execute(
            "CREATE TABLE db_metadata (build_timestamp datetime NOT NULL, model integer NOT NULL, "
            "revision integer NOT NULL, addition integer NOT NULL)"
        )
        con.execute("CREATE TABLE vulnerability_handles (id integer PRIMARY KEY, name text)")
        con.execute("INSERT INTO db_metadata VALUES (?, 6, 1, 10)", (built,))
        con.commit()
    if with_import:
        (d / "import.json").write_text(
            json.dumps(
                {
                    "digest": "xxh64:0123456789abcdef",
                    "source": "https://grype.anchore.io/databases/v6/vulnerability-db_v6.1.10_"
                    "2026-11-24T00:20:31Z_1795501325.tar.zst?checksum=sha256%3Afdf0",
                    "client_version": "6.1.10",
                }
            ),
            encoding="utf-8",
        )
    return db


def test_grype_metadata_is_read_from_copied_database(settings) -> None:
    """Sinov\\cache\\grype dan nusxalangan baza: sana grype db status bilan bir xil chiqadi."""
    from bulutskan.scanner.dbupdate import read_grype_metadata

    _grype_v6_db(settings.grype_cache)
    meta = read_grype_metadata(settings.grype_cache)
    expected = parse_grype_status_text((NATIJALAR / "grype_db_status.txt").read_text(encoding="utf-8-sig"))
    assert meta is not None
    assert meta["built"] == expected["built"] == "2026-11-24T06:22:05Z"
    assert meta["schema"] == expected["schema"] == "v6.1.10"
    assert meta["path"] == "6/vulnerability.db"
    assert meta["from"].endswith(".tar.zst") and "checksum" not in meta["from"]

    status = database_status(settings)
    assert status["grype"]["present"] is True
    assert status["grype"]["metadata"]["built"] == "2026-11-24T06:22:05Z"


@pytest.mark.parametrize(
    ("raw", "expected"),
    [
        ("2026-11-24 06:22:05+00:00", "2026-11-24T06:22:05Z"),
        ("2026-11-24 06:22:05.123456789+00:00", "2026-11-24T06:22:05Z"),
        ("2026-11-24T11:22:05+05:00", "2026-11-24T06:22:05Z"),
        ("2026-11-24T06:22:05Z", "2026-11-24T06:22:05Z"),
        ("2026-11-24 06:22:05", "2026-11-24T06:22:05Z"),
        (1795501325, "2026-11-24T06:22:05Z"),
    ],
)
def test_grype_build_timestamp_formats(settings, raw: object, expected: str) -> None:
    from bulutskan.scanner.dbupdate import read_grype_metadata

    _grype_v6_db(settings.grype_cache, built=raw, with_import=False)
    meta = read_grype_metadata(settings.grype_cache)
    assert meta is not None and meta["built"] == expected


def test_grype_metadata_handles_missing_or_broken_db(settings) -> None:
    from bulutskan.scanner.dbupdate import read_grype_metadata

    assert read_grype_metadata(settings.grype_cache) is None
    d = settings.grype_cache / "6"
    d.mkdir(parents=True)
    (d / "vulnerability.db").write_bytes(b"bu sqlite emas" * 50)
    assert read_grype_metadata(settings.grype_cache) is None


def test_grype_metadata_read_does_not_modify_or_lock_db(settings) -> None:
    from bulutskan.scanner.dbupdate import read_grype_metadata

    db = _grype_v6_db(settings.grype_cache)
    before = db.read_bytes()
    assert read_grype_metadata(settings.grype_cache) is not None
    assert db.read_bytes() == before
    assert sorted(p.name for p in db.parent.iterdir()) == ["import.json", "vulnerability.db"]
    db.unlink()  # Windows qoidasi: fayl yopilgan bo‘lishi kerak

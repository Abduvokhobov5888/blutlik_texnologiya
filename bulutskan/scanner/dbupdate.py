"""Zaifliklar bazalarini yangilash: Trivy, Trivy Java va Grype.

Internet faqat shu bosqichda kerak. Proksi manzili ``docker info``
orqali aniqlanadi (``run_tests.ps1`` dagi kabi): avval ``HTTPSProxy``, bo‘lmasa
``HTTPProxy``. ``127.0.0.1`` yoki ``localhost`` konteyner ichidan
``host.docker.internal`` ga almashtiriladi. Manzil faqat xotirada saqlanadi,
jurnal va fayllarga yozilmaydi.
"""

from __future__ import annotations

import json
import re
import sqlite3
from contextlib import closing
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from bulutskan.config import Settings
from bulutskan.core.models import Tool
from bulutskan.scanner.docker import ContainerSpec, DockerClient, Mount
from bulutskan.scanner.tools import IntegrityReport
from bulutskan.security.workspace import new_uid

DB_NAMES: tuple[str, ...] = ("trivy", "trivy-java", "grype")
DB_LABELS = {"trivy": "Trivy asosiy bazasi", "trivy-java": "Trivy Java bazasi", "grype": "Grype bazasi"}

_LOCAL = re.compile(r"//(127\.0\.0\.1|localhost)(?=[:/]|$)")


def normalize_proxy(value: str) -> str | None:
    """Proksi manzilini konteyner uchun tayyorlaydi."""
    v = (value or "").strip()
    if not v or v == "<no value>":
        return None
    if not re.match(r"^https?://", v):
        v = "http://" + v
    return _LOCAL.sub("//host.docker.internal", v)


def detect_proxy(client: DockerClient) -> str | None:
    """Docker Desktop’da sozlangan proksi (bo‘lmasa ``None``)."""
    for template in ("{{.HTTPSProxy}}", "{{.HTTPProxy}}"):
        proxy = normalize_proxy(client.info_field(template))
        if proxy:
            return proxy
    return None


def mask_proxy(proxy: str | None) -> str:
    """Jurnal uchun: manzil o‘rniga faqat borligi."""
    return "aniqlandi" if proxy else "yo‘q"


def proxy_env(proxy: str | None) -> dict[str, str]:
    """Baza yuklovchi konteyner uchun proksi o‘zgaruvchilari."""
    if not proxy:
        return {}
    return {
        "HTTP_PROXY": proxy,
        "HTTPS_PROXY": proxy,
        "http_proxy": proxy,
        "https_proxy": proxy,
        "NO_PROXY": "localhost,127.0.0.1",
        "no_proxy": "localhost,127.0.0.1",
    }


def _scrub(text: str, proxy: str | None) -> str:
    """Xato matnidan proksi manzilini olib tashlaydi."""
    out = text
    if proxy:
        out = out.replace(proxy, "<proksi>")
    return out[-2000:]


@dataclass
class DbUpdateResult:
    """Bitta bazani yangilash natijasi."""

    name: str
    ok: bool
    started_at: str
    finished_at: str
    duration_s: float
    error: str | None = None
    metadata: dict[str, Any] | None = None


def _now() -> str:
    return datetime.now(UTC).isoformat(timespec="seconds")


def _spec(settings: Settings, name: str, image: str, args: tuple[str, ...], cache: Path, env: dict[str, str], network: str) -> ContainerSpec:
    return ContainerSpec(
        image=image,
        args=args,
        name=f"bulutskan-db-{name}-{new_uid()[:12]}",
        mounts=(Mount(cache, "/cache", read_only=False),),
        env=env,
        network=network,
        cpus=settings.container_cpus,
        memory=settings.container_memory,
        pids=settings.container_pids,
        tmpfs_size=settings.container_tmpfs,
    )


def update_databases(
    client: DockerClient,
    integrity: IntegrityReport,
    settings: Settings,
    which: tuple[str, ...] = DB_NAMES,
) -> list[DbUpdateResult]:
    """Tanlangan bazalarni yuklab oladi va holatini ``holat.json`` ga yozadi."""
    unknown = set(which) - set(DB_NAMES)
    if unknown:
        raise ValueError(f"Noma’lum baza: {sorted(unknown)}")
    proxy = detect_proxy(client)
    env = proxy_env(proxy)
    settings.trivy_cache.mkdir(parents=True, exist_ok=True)
    settings.grype_cache.mkdir(parents=True, exist_ok=True)
    results: list[DbUpdateResult] = []
    jobs: list[tuple[str, ContainerSpec]] = []
    if "trivy" in which:
        jobs.append(("trivy", _spec(settings, "trivy", integrity.run_ref(Tool.TRIVY),
                                    ("image", "--cache-dir", "/cache", "--download-db-only"),
                                    settings.trivy_cache, env, "bridge")))
    if "trivy-java" in which:
        jobs.append(("trivy-java", _spec(settings, "trivyjava", integrity.run_ref(Tool.TRIVY),
                                         ("image", "--cache-dir", "/cache", "--download-java-db-only"),
                                         settings.trivy_cache, env, "bridge")))
    if "grype" in which:
        jobs.append(("grype", _spec(settings, "grype", integrity.run_ref(Tool.GRYPE), ("db", "update"),
                                    settings.grype_cache, {**env, "GRYPE_DB_CACHE_DIR": "/cache",
                                                           "GRYPE_CHECK_FOR_APP_UPDATE": "false"}, "bridge")))
    for name, spec in jobs:
        started = _now()
        res = client.run_container(spec, timeout=settings.db_update_timeout_s)
        ok = res.returncode == 0 and not res.timed_out
        error = None
        if not ok:
            error = "Vaqt tugadi" if res.timed_out else _scrub(res.stderr_text.strip(), proxy) or f"Chiqish kodi {res.returncode}"
        metadata = None
        if ok and name == "grype":
            metadata = read_grype_metadata(settings.grype_cache) or grype_status(client, integrity, settings)
        elif ok:
            metadata = read_trivy_metadata(settings.trivy_cache / ("db" if name == "trivy" else "java-db"))
        results.append(DbUpdateResult(name, ok, started, _now(), res.duration_s, error, metadata))
    _record(settings.db_state_file, results, proxy_used=proxy is not None)
    return results


def read_trivy_metadata(db_dir: Path) -> dict[str, Any] | None:
    """Trivy ``metadata.json`` (Version, UpdatedAt, NextUpdate, DownloadedAt)."""
    path = db_dir / "metadata.json"
    if not path.is_file():
        return None
    try:
        data = json.loads(path.read_text(encoding="utf-8-sig"))
    except (OSError, json.JSONDecodeError):
        return None
    if not isinstance(data, dict):
        return None
    return {k: data.get(k) for k in ("Version", "UpdatedAt", "NextUpdate", "DownloadedAt")}


_STATUS_LINE = re.compile(r"^(?P<key>Path|Schema|Built|From|Status):\s+(?P<value>.+)$")


def parse_grype_status_text(text: str) -> dict[str, Any]:
    """``grype db status`` matnli chiqishini o‘qiydi (``grype_db_status.txt`` formati)."""
    out: dict[str, Any] = {}
    for line in text.splitlines():
        m = _STATUS_LINE.match(line.strip().lstrip("﻿"))
        if m:
            key = m.group("key").lower()
            value = m.group("value").strip()
            if key == "from":
                value = value.split("?", 1)[0]  # checksum so‘rov qismisiz
            out[key] = value
    return out


_GRYPE_METADATA_COLUMNS = ("build_timestamp", "model", "revision", "addition")
_FRACTION = re.compile(r"(\.\d{6})\d+")


def _iso_utc(value: Any) -> str | None:
    """Vaqt qiymatini ``2026-11-24T06:22:05Z`` ko‘rinishiga keltiradi."""
    if value is None:
        return None
    try:
        if isinstance(value, (int, float)):
            dt = datetime.fromtimestamp(float(value), tz=UTC)
        else:
            text = str(value).strip().replace(" ", "T", 1)
            if text.endswith("Z"):
                text = text[:-1] + "+00:00"
            text = _FRACTION.sub(r"\1", text)  # nanosekundlar → mikrosekundlar
            dt = datetime.fromisoformat(text)
            if dt.tzinfo is None:
                dt = dt.replace(tzinfo=UTC)
    except (ValueError, OverflowError, OSError):
        return None
    return dt.astimezone(UTC).strftime("%Y-%m-%dT%H:%M:%SZ")


def _quote_identifier(name: str) -> str:
    return '"' + name.replace('"', '""') + '"'


def _sqlite_db_metadata(db_path: Path) -> dict[str, Any] | None:
    """Grype v6 bazasining ``db_metadata`` jadvali (yig‘ilgan vaqt va sxema).

    Baza faqat o‘qish rejimida (``mode=ro``, ``immutable=1``) ochiladi:
    hech narsa yozilmaydi, yon fayllar (journal/WAL) yaratilmaydi va ulanish
    darhol yopiladi (Windows: fayl band bo‘lib qolmaydi).
    """
    uri = db_path.resolve().as_uri() + "?mode=ro&immutable=1"
    try:
        with closing(sqlite3.connect(uri, uri=True, timeout=1)) as con:
            tables = [r[0] for r in con.execute("SELECT name FROM sqlite_master WHERE type = 'table'")]
            for table in tables:
                cols = {r[1] for r in con.execute(f"PRAGMA table_info({_quote_identifier(table)})")}
                if set(_GRYPE_METADATA_COLUMNS) <= cols:
                    row = con.execute(
                        f"SELECT {', '.join(_GRYPE_METADATA_COLUMNS)} FROM {_quote_identifier(table)} LIMIT 1"
                    ).fetchone()
                    if row is None:
                        return None
                    built, model, revision, addition = row
                    return {"built": _iso_utc(built), "schema": f"v{model}.{revision}.{addition}"}
    except sqlite3.Error:
        return None
    return None


def read_grype_metadata(cache_dir: Path) -> dict[str, Any] | None:
    """Grype bazasi holatini fayllardan o‘qiydi (Docker kerak emas).

    ``grype db status`` ko‘rsatadigan ``Built`` va ``Schema`` qiymatlari
    ``{cache}/6/vulnerability.db`` ichidagi ``db_metadata`` jadvalidan
    olinadi (grype v0.121.0: ``grype/db/v6/models.go``, ``DBMetadata``).
    ``import.json`` dan esa bazaning manbasi va digesti olinadi. Baza boshqa
    joydan (masalan, ``Sinov\\cache\\grype``) nusxalangan bo‘lsa ham ishlaydi.
    """
    for db_path in sorted(Path(cache_dir).glob("*/vulnerability.db"), reverse=True):
        meta = _sqlite_db_metadata(db_path)
        if meta is None:
            continue
        meta["path"] = f"{db_path.parent.name}/{db_path.name}"
        import_file = db_path.parent / "import.json"
        if import_file.is_file():
            try:
                info = json.loads(import_file.read_text(encoding="utf-8-sig"))
            except (OSError, json.JSONDecodeError):
                info = {}
            if isinstance(info, dict):
                if info.get("source"):
                    meta["from"] = str(info["source"]).split("?", 1)[0]
                if info.get("digest"):
                    meta["digest"] = str(info["digest"])
        return meta
    return None


def grype_status(client: DockerClient, integrity: IntegrityReport, settings: Settings) -> dict[str, Any] | None:
    """Grype bazasi holati (tarmoqsiz konteynerda)."""
    spec = ContainerSpec(
        image=integrity.run_ref(Tool.GRYPE),
        args=("db", "status"),
        name=f"bulutskan-db-grypestatus-{new_uid()[:12]}",
        mounts=(Mount(settings.grype_cache, "/cache", read_only=True),),
        env={"GRYPE_DB_CACHE_DIR": "/cache", "GRYPE_CHECK_FOR_APP_UPDATE": "false"},
        cpus=settings.container_cpus,
        memory=settings.container_memory,
        pids=settings.container_pids,
        tmpfs_size=settings.container_tmpfs,
    )
    res = client.run_container(spec, timeout=120)
    if res.returncode != 0:
        return None
    return parse_grype_status_text(res.stdout_text) or None


def _record(state_file: Path, results: list[DbUpdateResult], proxy_used: bool) -> None:
    state = load_db_state(state_file)
    for r in results:
        entry = state.get(r.name, {}) if isinstance(state.get(r.name), dict) else {}
        entry["last_attempt"] = {
            "ok": r.ok,
            "started_at": r.started_at,
            "finished_at": r.finished_at,
            "duration_s": round(r.duration_s, 2),
            "error": r.error,
            "proxy": "aniqlandi" if proxy_used else "yo‘q",
        }
        if r.ok:
            entry["updated_at"] = r.finished_at
            entry["metadata"] = r.metadata
        state[r.name] = entry
    state_file.parent.mkdir(parents=True, exist_ok=True)
    state_file.write_text(json.dumps(state, ensure_ascii=False, indent=2), encoding="utf-8")


def load_db_state(state_file: Path) -> dict[str, Any]:
    """``holat.json`` (yo‘q bo‘lsa bo‘sh)."""
    if not state_file.is_file():
        return {}
    try:
        data = json.loads(state_file.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def database_status(settings: Settings) -> dict[str, dict[str, Any]]:
    """Interfeys va CLI uchun: har bir bazaning mavjudligi va sanalari."""
    state = load_db_state(settings.db_state_file)
    trivy_db = settings.trivy_cache / "db"
    java_db = settings.trivy_cache / "java-db"
    out: dict[str, dict[str, Any]] = {}
    for name, present, meta in (
        ("trivy", (trivy_db / "trivy.db").is_file(), read_trivy_metadata(trivy_db)),
        ("trivy-java", (java_db / "trivy-java.db").is_file(), read_trivy_metadata(java_db)),
        ("grype", any(settings.grype_cache.glob("*/vulnerability.db")), read_grype_metadata(settings.grype_cache)),
    ):
        entry = state.get(name, {}) if isinstance(state.get(name), dict) else {}
        out[name] = {
            "label": DB_LABELS[name],
            "present": present,
            "updated_at": entry.get("updated_at"),
            "metadata": meta if meta is not None else entry.get("metadata"),
            "last_attempt": entry.get("last_attempt"),
        }
    return out

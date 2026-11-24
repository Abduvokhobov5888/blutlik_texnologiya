"""Konteyner obrazi tekshiruvi: pull → save → internetsiz Trivy va Grype.

Foydalanuvchi obrazi hech qachon ishga tushirilmaydi: u faqat yuklab
olinadi va ``docker save`` bilan ``.tar`` ga saqlanadi. Skanerlar shu
arxivni tarmoqsiz konteynerda o‘qiydi. Zaifliklar bazalari faqat o‘qish
uchun ulanadi; vosita buni qabul qilmasa, baza tekshiruv katalogiga
nusxalanib, bir marta qayta uriniladi.
"""

from __future__ import annotations

import shutil
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bulutskan.config import Settings
from bulutskan.core.models import Tool
from bulutskan.parsers import parse_grype, parse_trivy_image
from bulutskan.scanner.docker import ContainerSpec, DockerClient, Mount
from bulutskan.scanner.runs import ToolRun, explain_failure, finish_run, looks_like_readonly_error
from bulutskan.scanner.tools import IntegrityReport
from bulutskan.security.upload_guard import validate_image_tar
from bulutskan.security.validators import ImageReference
from bulutskan.security.workspace import Workspace

IMAGE_TARGET = "/input/image.tar"
IMAGE_TOOLS: tuple[Tool, ...] = (Tool.TRIVY, Tool.GRYPE)


class ImagePrepareError(RuntimeError):
    """Obrazni yuklab olish yoki saqlab bo‘lmadi."""


@dataclass
class ImageInput:
    """Skanerlarga beriladigan obraz arxivi."""

    tar_path: Path
    archive_type: str  # docker-archive yoki oci-archive
    reference: str | None = None
    image_id: str | None = None
    repo_digests: list[str] = field(default_factory=list)

    def to_dict(self) -> dict[str, Any]:
        return {
            "reference": self.reference,
            "archive_type": self.archive_type,
            "image_id": self.image_id,
            "repo_digests": list(self.repo_digests),
            "tar_name": self.tar_path.name,
        }


def pull_and_save(client: DockerClient, settings: Settings, ws: Workspace, ref: ImageReference) -> ImageInput:
    """Obrazni yuklab oladi va ``ws.input/image.tar`` ga saqlaydi."""
    res = client.pull(ref.raw, timeout=settings.pull_timeout_s)
    if res.returncode != 0 or res.timed_out:
        raise ImagePrepareError(f"Obrazni yuklab bo‘lmadi ({ref.raw}): {explain_failure(res)}")
    info = client.image_inspect(ref.raw) or {}
    tar_path = ws.input / "image.tar"
    res = client.save(ref.raw, tar_path, timeout=settings.pull_timeout_s)
    if res.returncode != 0 or res.timed_out or not tar_path.is_file():
        raise ImagePrepareError(f"docker save bajarilmadi: {explain_failure(res)}")
    archive_type = validate_image_tar(tar_path, settings.max_image_tar_bytes)
    digests = info.get("RepoDigests")
    return ImageInput(
        tar_path=tar_path,
        archive_type=archive_type,
        reference=ref.raw,
        image_id=str(info.get("Id")) if info.get("Id") else None,
        repo_digests=[str(d) for d in digests] if isinstance(digests, list) else [],
    )


def existing_tar(path: Path, settings: Settings) -> ImageInput:
    """Foydalanuvchi bergan ``.tar`` faylni tekshiradi (nusxalanmaydi)."""
    p = Path(path).resolve()
    return ImageInput(tar_path=p, archive_type=validate_image_tar(p, settings.max_image_tar_bytes))


def _spec(settings: Settings, ws: Workspace, tool: Tool, image: str, args: tuple[str, ...],
          mounts: tuple[Mount, ...], env: dict[str, str], suffix: str = "") -> ContainerSpec:
    return ContainerSpec(
        image=image,
        args=args,
        name=f"bulutskan-{ws.uid[:16]}-{tool.value}{suffix}",
        mounts=mounts,
        env=env,
        cpus=settings.container_cpus,
        memory=settings.container_memory,
        pids=settings.container_pids,
        tmpfs_size=settings.container_tmpfs,
    )


def trivy_args(cache_dir: str) -> tuple[str, ...]:
    """Eksperimentdagi Trivy argumentlari (``run_tests.ps1``)."""
    return (
        "image", "--cache-dir", cache_dir, "--skip-db-update", "--skip-java-db-update", "--offline-scan",
        "--scanners", "vuln", "--format", "json", "--input", IMAGE_TARGET,
    )


def _trivy_db_mounts_readonly(settings: Settings) -> tuple[Mount, ...]:
    mounts = [Mount(settings.trivy_cache / "db", "/tmp/trivy/db", read_only=True)]
    java = settings.trivy_cache / "java-db"
    if java.is_dir():
        mounts.append(Mount(java, "/tmp/trivy/java-db", read_only=True))
    return tuple(mounts)


def _copy_trivy_db(settings: Settings, ws: Workspace) -> Path:
    target = ws.scratch / "trivy-cache"
    for name in ("db", "java-db"):
        src = settings.trivy_cache / name
        if src.is_dir():
            shutil.copytree(src, target / name, dirs_exist_ok=True)
    target.mkdir(parents=True, exist_ok=True)
    return target


def run_trivy(client: DockerClient, integrity: IntegrityReport, settings: Settings, ws: Workspace,
              image: ImageInput, report_dir: Path) -> ToolRun:
    """Trivy: baza faqat o‘qish uchun; kerak bo‘lsa nusxa bilan qayta urinish."""
    ref = integrity.run_ref(Tool.TRIVY)
    tar = Mount(image.tar_path, IMAGE_TARGET, read_only=True)
    raw = report_dir / "trivy.json"
    if not (settings.trivy_cache / "db" / "trivy.db").is_file():
        return ToolRun(Tool.TRIVY, ref, False, None, None, 0.0,
                       "Trivy bazasi yo‘q: avval `bulutskan db-update` ni bajaring", raw)
    notes: list[str] = []
    if settings.trivy_db_mode == "readonly":
        res = client.run_container(
            _spec(settings, ws, Tool.TRIVY, ref, trivy_args("/tmp/trivy"), (tar, *_trivy_db_mounts_readonly(settings)), {}),
            settings.scan_timeout_s, stdout_path=raw,
        )
        if not looks_like_readonly_error(res):
            run = finish_run(Tool.TRIVY, ref, res, raw, parse_trivy_image)
            run.notes = notes
            return run
        notes.append("Trivy bazani faqat o‘qish rejimida ocha olmadi: nusxa bilan qayta urinildi")
    copy = _copy_trivy_db(settings, ws)
    res = client.run_container(
        _spec(settings, ws, Tool.TRIVY, ref, trivy_args("/cache"), (tar, Mount(copy, "/cache", read_only=False)), {}, "-copy"),
        settings.scan_timeout_s, stdout_path=raw,
    )
    run = finish_run(Tool.TRIVY, ref, res, raw, parse_trivy_image)
    run.notes = notes + ["Trivy bazasining nusxasi ishlatildi"]
    return run


def run_grype(client: DockerClient, integrity: IntegrityReport, settings: Settings, ws: Workspace,
              image: ImageInput, report_dir: Path) -> ToolRun:
    """Grype: baza faqat o‘qish uchun, vaqtinchalik fayllar ``scratch`` da."""
    ref = integrity.run_ref(Tool.GRYPE)
    raw = report_dir / "grype.json"
    if not any(settings.grype_cache.glob("*/vulnerability.db")):
        return ToolRun(Tool.GRYPE, ref, False, None, None, 0.0,
                       "Grype bazasi yo‘q: avval `bulutskan db-update` ni bajaring", raw)
    scratch = ws.scratch / "grype"
    scratch.mkdir(parents=True, exist_ok=True)
    env = {
        "GRYPE_DB_CACHE_DIR": "/cache",
        "GRYPE_DB_AUTO_UPDATE": "false",
        "GRYPE_CHECK_FOR_APP_UPDATE": "false",
        "GRYPE_DB_VALIDATE_AGE": "true" if settings.grype_validate_age else "false",
        "TMPDIR": "/scratch",
    }
    args = (f"{image.archive_type}:{IMAGE_TARGET}", "-o", "json")
    base = (Mount(image.tar_path, IMAGE_TARGET, read_only=True), Mount(scratch, "/scratch", read_only=False))
    res = client.run_container(
        _spec(settings, ws, Tool.GRYPE, ref, args, (*base, Mount(settings.grype_cache, "/cache", read_only=True)), env),
        settings.scan_timeout_s, stdout_path=raw,
    )
    if not looks_like_readonly_error(res):
        return finish_run(Tool.GRYPE, ref, res, raw, parse_grype)
    copy = ws.scratch / "grype-cache"
    shutil.copytree(settings.grype_cache, copy, dirs_exist_ok=True)
    res = client.run_container(
        _spec(settings, ws, Tool.GRYPE, ref, args, (*base, Mount(copy, "/cache", read_only=False)), env, "-copy"),
        settings.scan_timeout_s, stdout_path=raw,
    )
    run = finish_run(Tool.GRYPE, ref, res, raw, parse_grype)
    run.notes = ["Grype bazani faqat o‘qish rejimida ocha olmadi: nusxa ishlatildi"]
    return run


def run_image_tools(client: DockerClient, integrity: IntegrityReport, settings: Settings, ws: Workspace,
                    image: ImageInput, report_dir: Path) -> list[ToolRun]:
    """Obraz arxivini Trivy va Grype bilan ketma-ket tekshiradi."""
    report_dir.mkdir(parents=True, exist_ok=True)
    return [
        run_trivy(client, integrity, settings, ws, image, report_dir),
        run_grype(client, integrity, settings, ws, image, report_dir),
    ]

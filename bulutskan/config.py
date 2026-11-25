"""Platforma sozlamalari.

Qiymatlar ``.env`` faylidan yoki ``BULUTSKAN_`` prefiksli muhit
o‘zgaruvchilaridan o‘qiladi (namuna: ``.env.example``). Proksi manzili bu
yerda saqlanmaydi: u faqat bazalarni yangilash paytida ``docker info``
orqali o‘qiladi.
"""

from __future__ import annotations

import hashlib
import os
import shutil
import sys
from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = Path(__file__).resolve().parent
RESOURCES = PACKAGE_ROOT / "resources"

#: PyInstaller bilan yig‘ilgan dasturmi (Windows o‘rnatuvchisi).
FROZEN = bool(getattr(sys, "frozen", False))


def bundle_root() -> Path:
    """Dastur bilan birga keladigan fayllar ildizi (PyInstaller’da ``_MEIPASS``)."""
    if FROZEN:
        return Path(getattr(sys, "_MEIPASS", Path(sys.executable).parent))
    return PROJECT_ROOT


def demo_root() -> Path:
    """Namoyish ma’lumotlari: III bob eksperimentining real hisobotlari."""
    return bundle_root() / "demo" / "sinov"


def default_data_dir() -> Path:
    """Ish ma’lumotlari katalogi.

    O‘rnatilgan dasturda: ``%LOCALAPPDATA%\\BulutSkan\\data`` (dastur papkasi
    yangilanganda ma’lumotlar yo‘qolmaydi); manba koddan ishlaganda: ``./data``.
    """
    if FROZEN:
        base = os.environ.get("LOCALAPPDATA") or str(Path.home() / "AppData" / "Local")
        return Path(base) / "BulutSkan" / "data"
    return Path("./data")


#: Docker Desktop’ning standart o‘rnatish yo‘li (PATH da bo‘lmasa).
WINDOWS_DOCKER = Path(os.environ.get("ProgramFiles", r"C:\Program Files")) / "Docker" / "Docker" / "resources" / "bin" / "docker.exe"


def default_docker_bin() -> str:
    """``docker`` buyrug‘i: PATH dan, Windows’da topilmasa Docker Desktop papkasidan.

    Ish stolidagi belgidan ishga tushirilganda PATH Docker Desktop o‘rnatilgandan
    oldingi holatda qolgan bo‘lishi mumkin (kompyuter qayta yuklanmagan).
    """
    if shutil.which("docker") is None and sys.platform == "win32" and WINDOWS_DOCKER.is_file():
        return str(WINDOWS_DOCKER)
    return "docker"


def env_files() -> tuple[str, ...]:
    """Sozlamalar fayllari: joriy katalogdagi ``.env``; o‘rnatilgan dasturda
    ``%LOCALAPPDATA%\\BulutSkan\\bulutskan.env`` ham."""
    if FROZEN:
        return (".env", str(default_data_dir().parent / "bulutskan.env"))
    return (".env",)


_MB = 1024 * 1024


class Settings(BaseSettings):
    """BulutSkan sozlamalari."""

    model_config = SettingsConfigDict(
        env_prefix="BULUTSKAN_",
        env_file=env_files(),
        env_file_encoding="utf-8",
        extra="ignore",
    )

    #: Ish rejimi: ``local`` (Windows, bitta foydalanuvchi) yoki ``server`` (VPS, HTTPS).
    mode: str = "local"
    secret_key: SecretStr | None = None
    #: Server rejimi: tashqi manzil (``https://...``).
    public_url: str | None = None
    #: Birinchi administrator (faqat serverdagi ``.env`` da).
    admin_username: str | None = None
    admin_password: SecretStr | None = None
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    lang: str = "uz"
    data_dir: Path = Field(default_factory=default_data_dir)

    # Fayl yuklash limitlari
    max_upload_mb: int = Field(default=20, ge=1)
    max_unzipped_mb: int = Field(default=100, ge=1)
    max_zip_entries: int = Field(default=1000, ge=1)
    max_file_mb: int = Field(default=10, ge=1)
    max_image_tar_mb: int = Field(default=4096, ge=1)

    # Skaner konteynerlari limitlari
    container_cpus: str = "2"
    container_memory: str = "2g"
    container_pids: int = Field(default=512, ge=16)
    container_tmpfs: str = "512m"
    scan_timeout_s: int = Field(default=900, ge=10)
    pull_timeout_s: int = Field(default=1800, ge=10)
    db_update_timeout_s: int = Field(default=1800, ge=10)

    docker_bin: str = Field(default_factory=default_docker_bin)
    #: Grype bazasi eskirganini tekshirsinmi (sukut: ha). Eksperimentni eski
    #: baza bilan qayta takrorlash uchun ``false`` qilish mumkin.
    grype_validate_age: bool = True
    #: Trivy bazasini ulash usuli: ``readonly`` (sukut) yoki ``copy``.
    trivy_db_mode: str = "readonly"

    # Navbat, kvota, saqlash muddati
    worker_slots: int | None = Field(default=None, ge=1, le=8)
    queue_max: int = Field(default=20, ge=1)
    queue_per_user: int = Field(default=2, ge=1)
    scan_min_interval_s: int = Field(default=30, ge=0)
    quota_analyst: int = Field(default=20, ge=0)
    quota_guest: int = Field(default=3, ge=0)
    report_retention_days: int | None = Field(default=None, ge=0)
    audit_retention_days: int = Field(default=365, ge=1)
    login_attempts: int = Field(default=5, ge=1)
    login_window_min: int = Field(default=15, ge=1)
    rate_limit_per_min: int = Field(default=120, ge=1)
    session_hours: int = Field(default=8, ge=1)
    session_idle_min: int = Field(default=30, ge=1)
    #: Server rejimida ruxsat etilgan registrlar (SSRF himoyasi).
    allowed_registries: list[str] = Field(
        default_factory=lambda: ["docker.io", "ghcr.io", "quay.io", "mcr.microsoft.com", "public.ecr.aws",
                                 "registry.gitlab.com"]
    )
    #: Lokal rejim: ishga tushganda brauzerni ochish.
    open_browser: bool = True

    @field_validator("mode")
    @classmethod
    def _mode(cls, v: str) -> str:
        if v not in {"local", "server"}:
            raise ValueError("mode: local yoki server")
        return v

    @field_validator("lang")
    @classmethod
    def _lang(cls, v: str) -> str:
        if v not in {"uz", "en"}:
            raise ValueError("lang: uz yoki en")
        return v

    @field_validator("trivy_db_mode")
    @classmethod
    def _db_mode(cls, v: str) -> str:
        if v not in {"readonly", "copy"}:
            raise ValueError("trivy_db_mode: readonly yoki copy")
        return v

    # ------------------------------------------------------------- rejim

    @property
    def is_server(self) -> bool:
        return self.mode == "server"

    @property
    def effective_worker_slots(self) -> int:
        """Bir vaqtdagi tekshiruvlar: lokalda 1, serverda 2 (sozlanadi)."""
        return self.worker_slots or (2 if self.is_server else 1)

    @property
    def effective_retention_days(self) -> int:
        """Hisobotlar saqlanish muddati: serverda 30 kun, lokalda cheklanmagan (0)."""
        if self.report_retention_days is not None:
            return self.report_retention_days
        return 30 if self.is_server else 0

    # ------------------------------------------------------------- yo‘llar

    @property
    def db_path(self) -> Path:
        """SQLite bazasi: tarix, navbat, audit."""
        return self.data_path / "bulutskan.db"

    @property
    def data_path(self) -> Path:
        """Ma’lumotlar katalogining mutlaq yo‘li."""
        p = self.data_dir
        return (p if p.is_absolute() else Path.cwd() / p).resolve()

    @property
    def instance_id(self) -> str:
        """Ma’lumotlar katalogi identifikatori (bitta nusxa tekshiruvi uchun)."""
        return hashlib.sha256(str(self.data_path).encode("utf-8")).hexdigest()[:16]

    @property
    def instance_file(self) -> Path:
        """Ishlab turgan lokal nusxa porti."""
        return self.data_path / "instance.json"

    @property
    def workdir(self) -> Path:
        """Tekshiruvlar uchun vaqtinchalik kataloglar ildizi."""
        return self.data_path / "workdir"

    @property
    def db_dir(self) -> Path:
        """Zaifliklar bazalari ildizi."""
        return self.data_path / "db"

    @property
    def trivy_cache(self) -> Path:
        """Trivy keshi: ``db/`` va ``java-db/`` shu yerda."""
        return self.db_dir / "trivy"

    @property
    def grype_cache(self) -> Path:
        """Grype bazasi katalogi."""
        return self.db_dir / "grype"

    @property
    def reports_dir(self) -> Path:
        """Xom hisobotlar va DOCX fayllar."""
        return self.data_path / "hisobotlar"

    @property
    def tool_lock_file(self) -> Path:
        """Mahalliy yig‘ilgan Checkov obrazining qulflangan ID si."""
        return self.data_path / "tool_lock.json"

    @property
    def db_state_file(self) -> Path:
        """Bazalarni yangilash tarixi."""
        return self.db_dir / "holat.json"

    @property
    def tool_digests_file(self) -> Path:
        """Vositalar digestlari ro‘yxati."""
        return RESOURCES / "tool_digests.txt"

    # ------------------------------------------------------------- limitlar

    @property
    def max_upload_bytes(self) -> int:
        return self.max_upload_mb * _MB

    @property
    def max_unzipped_bytes(self) -> int:
        return self.max_unzipped_mb * _MB

    @property
    def max_file_bytes(self) -> int:
        return self.max_file_mb * _MB

    @property
    def max_image_tar_bytes(self) -> int:
        return self.max_image_tar_mb * _MB


@lru_cache(maxsize=1)
def get_settings() -> Settings:
    """Jarayon uchun yagona sozlamalar nusxasi."""
    return Settings()

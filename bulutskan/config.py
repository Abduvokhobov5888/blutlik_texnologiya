"""Platforma sozlamalari.

Qiymatlar ``.env`` faylidan yoki ``BULUTSKAN_`` prefiksli muhit
o‘zgaruvchilaridan o‘qiladi (namuna: ``.env.example``). Proksi manzili bu
yerda saqlanmaydi: u faqat bazalarni yangilash paytida ``docker info``
orqali o‘qiladi.
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

from pydantic import Field, SecretStr, field_validator
from pydantic_settings import BaseSettings, SettingsConfigDict

PROJECT_ROOT = Path(__file__).resolve().parent.parent
PACKAGE_ROOT = Path(__file__).resolve().parent
RESOURCES = PACKAGE_ROOT / "resources"

_MB = 1024 * 1024


class Settings(BaseSettings):
    """BulutSkan sozlamalari."""

    model_config = SettingsConfigDict(
        env_prefix="BULUTSKAN_",
        env_file=".env",
        env_file_encoding="utf-8",
        extra="ignore",
    )

    secret_key: SecretStr | None = None
    host: str = "127.0.0.1"
    port: int = Field(default=8000, ge=1, le=65535)
    lang: str = "uz"
    data_dir: Path = Path("./data")

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

    docker_bin: str = "docker"
    #: Grype bazasi eskirganini tekshirsinmi (sukut: ha). Eksperimentni eski
    #: baza bilan qayta takrorlash uchun ``false`` qilish mumkin.
    grype_validate_age: bool = True
    #: Trivy bazasini ulash usuli: ``readonly`` (sukut) yoki ``copy``.
    trivy_db_mode: str = "readonly"

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

    # ------------------------------------------------------------- yo‘llar

    @property
    def data_path(self) -> Path:
        """Ma’lumotlar katalogining mutlaq yo‘li."""
        p = self.data_dir
        return (p if p.is_absolute() else Path.cwd() / p).resolve()

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

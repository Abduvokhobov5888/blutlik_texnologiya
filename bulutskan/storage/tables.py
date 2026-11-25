"""ORM jadvallari (``docs/arxitektura.md``, 10-bo‘lim)."""

from __future__ import annotations

from datetime import datetime
from typing import Any

from sqlalchemy import JSON, Boolean, Column, DateTime, Float, ForeignKey, Index, Integer, String, Table, Text
from sqlalchemy.orm import DeclarativeBase, Mapped, mapped_column, relationship

from bulutskan.storage.db import utcnow


class Base(DeclarativeBase):
    """Barcha jadvallar asosi."""


ROLE_ADMIN = "admin"
ROLE_ANALYST = "analyst"
ROLE_GUEST = "guest"
ROLES: tuple[str, ...] = (ROLE_ADMIN, ROLE_ANALYST, ROLE_GUEST)


class User(Base):
    __tablename__ = "users"

    id: Mapped[int] = mapped_column(primary_key=True)
    username: Mapped[str] = mapped_column(String(64), unique=True, index=True)
    password_hash: Mapped[str] = mapped_column(String(128))
    role: Mapped[str] = mapped_column(String(16), default=ROLE_ANALYST)
    is_active: Mapped[bool] = mapped_column(Boolean, default=True)
    #: Oshirilsa, foydalanuvchining barcha eski sessiyalari bekor bo‘ladi.
    session_epoch: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    last_login_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)


class Scan(Base):
    """Tekshiruv; navbat ham shu jadvalning o‘zi (``status``)."""

    __tablename__ = "scans"

    id: Mapped[int] = mapped_column(primary_key=True)
    uid: Mapped[str] = mapped_column(String(32), unique=True, index=True)
    kind: Mapped[str] = mapped_column(String(8))  # iac | image
    target: Mapped[str] = mapped_column(String(512))
    source: Mapped[str] = mapped_column(String(8), default="web")  # web | cli | demo
    status: Mapped[str] = mapped_column(String(16), default="queued", index=True)
    user_id: Mapped[int | None] = mapped_column(ForeignKey("users.id"), nullable=True, index=True)
    is_demo: Mapped[bool] = mapped_column(Boolean, default=False, index=True)
    request: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    worker_id: Mapped[str | None] = mapped_column(String(64), nullable=True)
    attempts: Mapped[int] = mapped_column(Integer, default=0)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    heartbeat_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    purged_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    # Natija xulosasi (tafsilotlar o‘chirilganda ham qoladi)
    summary: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    jaccard: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    jaccard_core: Mapped[float | None] = mapped_column(Float, nullable=True)
    consensus: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    eol: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    ground_truth: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    image: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    integrity: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    failures: Mapped[list[Any]] = mapped_column(JSON, default=list)
    files: Mapped[list[Any]] = mapped_column(JSON, default=list)
    skipped_files: Mapped[list[Any]] = mapped_column(JSON, default=list)

    user: Mapped[User | None] = relationship()
    tool_runs: Mapped[list[ToolRunRow]] = relationship(back_populates="scan", cascade="all, delete-orphan")


class ToolRunRow(Base):
    __tablename__ = "tool_runs"

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    tool: Mapped[str] = mapped_column(String(16))
    tool_version: Mapped[str | None] = mapped_column(String(32), nullable=True)
    image_ref: Mapped[str] = mapped_column(String(160), default="")
    ok: Mapped[bool] = mapped_column(Boolean, default=False)
    returncode: Mapped[int | None] = mapped_column(Integer, nullable=True)
    reason_code: Mapped[str | None] = mapped_column(String(32), nullable=True)
    duration_s: Mapped[float] = mapped_column(Float, default=0.0)
    error: Mapped[str | None] = mapped_column(Text, nullable=True)
    notes: Mapped[list[Any]] = mapped_column(JSON, default=list)
    raw_report_path: Mapped[str | None] = mapped_column(String(512), nullable=True)
    finding_count: Mapped[int] = mapped_column(Integer, default=0)
    raw_count: Mapped[int] = mapped_column(Integer, default=0)
    passed_count: Mapped[int | None] = mapped_column(Integer, nullable=True)
    metadata_json: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    scan: Mapped[Scan] = relationship(back_populates="tool_runs")


group_members = Table(
    "group_members",
    Base.metadata,
    Column("group_id", ForeignKey("finding_groups.id", ondelete="CASCADE"), primary_key=True),
    Column("finding_id", ForeignKey("findings.id", ondelete="CASCADE"), primary_key=True),
)


class FindingRow(Base):
    __tablename__ = "findings"
    __table_args__ = (Index("ix_findings_scan_tool", "scan_id", "tool"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    tool_run_id: Mapped[int] = mapped_column(ForeignKey("tool_runs.id", ondelete="CASCADE"))
    tool: Mapped[str] = mapped_column(String(16))
    kind: Mapped[str] = mapped_column(String(20))
    target: Mapped[str] = mapped_column(String(512))
    resource: Mapped[str | None] = mapped_column(String(512), nullable=True)
    rule_id: Mapped[str] = mapped_column(String(128))
    title: Mapped[str] = mapped_column(Text, default="")
    severity: Mapped[str] = mapped_column(String(10), index=True)
    cve: Mapped[str | None] = mapped_column(String(64), nullable=True)
    fixed_version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    installed_version: Mapped[str | None] = mapped_column(String(256), nullable=True)
    status: Mapped[str] = mapped_column(String(16))
    package_type: Mapped[str | None] = mapped_column(String(32), nullable=True)
    category: Mapped[str | None] = mapped_column(String(16), nullable=True)
    cpe_based: Mapped[bool] = mapped_column(Boolean, default=False)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    line_start: Mapped[int | None] = mapped_column(Integer, nullable=True)
    line_end: Mapped[int | None] = mapped_column(Integer, nullable=True)
    primary_url: Mapped[str | None] = mapped_column(String(512), nullable=True)
    fingerprint: Mapped[str] = mapped_column(String(32))


class FindingGroupRow(Base):
    __tablename__ = "finding_groups"
    __table_args__ = (Index("ix_groups_scan_severity", "scan_id", "severity_rank"),)

    id: Mapped[int] = mapped_column(primary_key=True)
    scan_id: Mapped[int] = mapped_column(ForeignKey("scans.id", ondelete="CASCADE"), index=True)
    key: Mapped[str] = mapped_column(String(600))
    kind: Mapped[str] = mapped_column(String(20))
    title: Mapped[str] = mapped_column(Text, default="")
    category: Mapped[str | None] = mapped_column(String(16), nullable=True)
    description: Mapped[str | None] = mapped_column(Text, nullable=True)
    severity: Mapped[str] = mapped_column(String(10))
    severity_rank: Mapped[int] = mapped_column(Integer, default=0)
    tools: Mapped[str] = mapped_column(String(64))
    tool_count: Mapped[int] = mapped_column(Integer)
    consensus: Mapped[str] = mapped_column(String(16), index=True)
    cpe_suspect: Mapped[bool] = mapped_column(Boolean, default=False)
    uncategorized: Mapped[bool] = mapped_column(Boolean, default=False)
    fix_available: Mapped[bool] = mapped_column(Boolean, default=False)
    known_exploited: Mapped[bool] = mapped_column(Boolean, default=False)
    fixed_versions: Mapped[list[Any]] = mapped_column(JSON, default=list)
    targets: Mapped[list[Any]] = mapped_column(JSON, default=list)
    severity_by_tool: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)

    members: Mapped[list[FindingRow]] = relationship(secondary=group_members)


class AuditLog(Base):
    __tablename__ = "audit_log"

    id: Mapped[int] = mapped_column(primary_key=True)
    ts: Mapped[datetime] = mapped_column(DateTime, default=utcnow, index=True)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    username: Mapped[str | None] = mapped_column(String(64), nullable=True)
    role: Mapped[str | None] = mapped_column(String(16), nullable=True)
    ip: Mapped[str | None] = mapped_column(String(64), nullable=True)
    action: Mapped[str] = mapped_column(String(32), index=True)
    target: Mapped[str | None] = mapped_column(String(512), nullable=True)
    result: Mapped[str] = mapped_column(String(8), default="ok")
    detail: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)


class Setting(Base):
    __tablename__ = "settings"

    key: Mapped[str] = mapped_column(String(64), primary_key=True)
    value: Mapped[Any] = mapped_column(JSON)


class SetupTask(Base):
    """Birinchi sozlash ustasining vazifasi (worker bajaradi)."""

    __tablename__ = "setup_tasks"

    id: Mapped[int] = mapped_column(primary_key=True)
    action: Mapped[str] = mapped_column(String(24))  # check, pull, lock_checkov, build_checkov, db_update
    status: Mapped[str] = mapped_column(String(12), default="queued", index=True)
    progress: Mapped[int] = mapped_column(Integer, default=0)  # 0-100, aniq foiz yo‘q bo‘lsa -1
    message: Mapped[str] = mapped_column(Text, default="")
    result: Mapped[dict[str, Any]] = mapped_column(JSON, default=dict)
    user_id: Mapped[int | None] = mapped_column(Integer, nullable=True)
    created_at: Mapped[datetime] = mapped_column(DateTime, default=utcnow)
    started_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)
    finished_at: Mapped[datetime | None] = mapped_column(DateTime, nullable=True)

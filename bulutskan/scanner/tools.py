"""Vositalar reestri va digest yaxlitligi.

Trivy, Grype va KICS registrdan olinadi va faqat ``repo@sha256:...``
orqali chaqiriladi; digestlar ``resources/tool_digests.txt`` da.

Checkov registrda yo‘q: u ``checkov.Dockerfile`` dan mahalliy yig‘iladi.
Mahalliy yig‘ish takrorlanuvchan emas, shuning uchun birinchi ishonch
tamoyili (trust on first use) qo‘llanadi: ``bulutskan tools lock-checkov``
obraz ``Id`` sini ``data/tool_lock.json`` ga yozadi, keyin Checkov faqat shu
``sha256:{Id}`` orqali chaqiriladi.
"""

from __future__ import annotations

import json
import re
from dataclasses import dataclass, field
from datetime import UTC, datetime
from enum import StrEnum
from pathlib import Path
from typing import Any

from bulutskan.core.models import Tool
from bulutskan.scanner.docker import ContainerSpec, DockerClient, DockerUnavailable

CHECKOV_VERSION = "3.3.26"
CHECKOV_LOCAL_TAG = f"diss-checkov:{CHECKOV_VERSION}"

_DIGEST_LINE = re.compile(r"^(?P<tag>\S+)\s+->\s+(?P<ref>(?P<repo>[^@\s]+)@(?P<digest>sha256:[a-f0-9]{64}))\s*$")
_PIP_LINE = re.compile(r"^checkov\s+\(pip\)\s+==\s+(?P<version>\S+)\s*$")
_IMAGE_ID = re.compile(r"^sha256:[a-f0-9]{64}$")

_REPO_TOOL = {"aquasec/trivy": Tool.TRIVY, "anchore/grype": Tool.GRYPE, "checkmarx/kics": Tool.KICS}


@dataclass(frozen=True)
class ToolImage:
    """Registrdagi vosita obrazi."""

    tool: Tool
    tag_ref: str  # aquasec/trivy:0.76.1
    digest_ref: str  # aquasec/trivy@sha256:...
    repo: str
    digest: str

    @property
    def version(self) -> str:
        return self.tag_ref.rsplit(":", 1)[-1]


@dataclass(frozen=True)
class ToolRegistry:
    """Platforma ishlatadigan vositalar."""

    images: dict[Tool, ToolImage]
    checkov_version: str = CHECKOV_VERSION
    checkov_tag: str = CHECKOV_LOCAL_TAG


def load_tool_digests(path: Path) -> ToolRegistry:
    """``tool_digests.txt`` faylini o‘qiydi (``run_tests.ps1`` formati, BOM bilan)."""
    images: dict[Tool, ToolImage] = {}
    checkov_version = CHECKOV_VERSION
    for raw in Path(path).read_text(encoding="utf-8-sig").splitlines():
        line = raw.strip()
        if not line:
            continue
        m = _DIGEST_LINE.match(line)
        if m:
            tool = _REPO_TOOL.get(m.group("repo"))
            if tool is None:
                raise ValueError(f"Noma’lum vosita: {m.group('repo')}")
            images[tool] = ToolImage(
                tool=tool,
                tag_ref=m.group("tag"),
                digest_ref=m.group("ref"),
                repo=m.group("repo"),
                digest=m.group("digest"),
            )
            continue
        p = _PIP_LINE.match(line)
        if p:
            checkov_version = p.group("version")
            continue
        raise ValueError(f"tool_digests.txt: tushunarsiz qator: {line}")
    missing = {Tool.TRIVY, Tool.GRYPE, Tool.KICS} - set(images)
    if missing:
        raise ValueError(f"tool_digests.txt da digest yo‘q: {sorted(m.value for m in missing)}")
    return ToolRegistry(images=images, checkov_version=checkov_version, checkov_tag=f"diss-checkov:{checkov_version}")


# ----------------------------------------------------------- Checkov qulfi


def read_lock(path: Path) -> dict[str, Any]:
    """Qulf faylini o‘qiydi (yo‘q bo‘lsa bo‘sh lug‘at)."""
    if not path.is_file():
        return {}
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return {}
    return data if isinstance(data, dict) else {}


def locked_checkov_id(path: Path) -> str | None:
    """Qulflangan Checkov obrazi ID si."""
    entry = read_lock(path).get("checkov")
    if isinstance(entry, dict) and isinstance(entry.get("image_id"), str) and _IMAGE_ID.match(entry["image_id"]):
        return str(entry["image_id"])
    return None


class LockError(RuntimeError):
    """Checkov obrazini qulflab bo‘lmadi."""


def lock_checkov(client: DockerClient, registry: ToolRegistry, lock_path: Path, tag: str | None = None) -> str:
    """Mahalliy Checkov obrazini tekshiradi va uning ID sini qulflaydi.

    Obraz ichidagi ``checkov --version`` kutilgan versiyaga teng bo‘lishi
    kerak. Tekshiruv tarmoqsiz konteynerda bajariladi.
    """
    ref = tag or registry.checkov_tag
    info = client.image_inspect(ref)
    if info is None:
        raise LockError(f"Obraz topilmadi: {ref}")
    image_id = str(info.get("Id", ""))
    if not _IMAGE_ID.match(image_id):
        raise LockError(f"Obraz ID si noto‘g‘ri: {image_id!r}")
    spec = ContainerSpec(image=image_id, args=("--version",), name=f"bulutskan-lock-checkov-{image_id[7:19]}")
    res = client.run_container(spec, timeout=120)
    version = res.stdout_text.strip().splitlines()[-1].strip() if res.stdout_text.strip() else ""
    if res.returncode != 0 or version != registry.checkov_version:
        raise LockError(
            f"Checkov versiyasi mos emas: kutilgan {registry.checkov_version}, obrazda {version or 'aniqlanmadi'}"
        )
    data = read_lock(lock_path)
    data["checkov"] = {
        "tag": ref,
        "image_id": image_id,
        "version": version,
        "locked_at": datetime.now(UTC).isoformat(timespec="seconds"),
    }
    lock_path.parent.mkdir(parents=True, exist_ok=True)
    lock_path.write_text(json.dumps(data, ensure_ascii=False, indent=2), encoding="utf-8")
    return image_id


# ------------------------------------------------------------ yaxlitlik


class IntegrityStatus(StrEnum):
    """Vosita obrazining holati."""

    OK = "ok"
    MISMATCH = "mismatch"
    MISSING = "missing"
    NOT_LOCKED = "not_locked"
    DOCKER_UNAVAILABLE = "docker_unavailable"


@dataclass(frozen=True)
class ToolCheck:
    """Bitta vosita tekshiruvi."""

    tool: Tool
    status: IntegrityStatus
    expected: str | None
    actual: str | None
    message: str
    #: Skanerni chaqirish uchun havola (faqat OK holatida).
    run_ref: str | None = None


@dataclass
class IntegrityReport:
    """Barcha vositalar holati."""

    checks: list[ToolCheck] = field(default_factory=list)
    docker_version: str | None = None
    checked_at: str = field(default_factory=lambda: datetime.now(UTC).isoformat(timespec="seconds"))

    @property
    def docker_available(self) -> bool:
        return self.docker_version is not None

    @property
    def ok(self) -> bool:
        """Barcha vositalar mos: tekshiruvlarga ruxsat."""
        return self.docker_available and bool(self.checks) and all(c.status is IntegrityStatus.OK for c in self.checks)

    @property
    def has_mismatch(self) -> bool:
        """Kamida bitta digest mos kelmadi (qizil ogohlantirish)."""
        return any(c.status is IntegrityStatus.MISMATCH for c in self.checks)

    def run_ref(self, tool: Tool) -> str:
        """Vositani chaqirish uchun digest havolasi."""
        for c in self.checks:
            if c.tool is tool and c.status is IntegrityStatus.OK and c.run_ref:
                return c.run_ref
        raise IntegrityError(f"{tool.value}: vosita yaxlitligi tasdiqlanmagan")

    def to_dict(self) -> dict[str, Any]:
        return {
            "ok": self.ok,
            "docker_version": self.docker_version,
            "checked_at": self.checked_at,
            "checks": [
                {
                    "tool": c.tool.value,
                    "status": c.status.value,
                    "expected": c.expected,
                    "actual": c.actual,
                    "message": c.message,
                }
                for c in self.checks
            ],
        }


class IntegrityError(RuntimeError):
    """Vosita yaxlitligi tasdiqlanmagan: tekshiruv bloklanadi."""


def _repo_digests(info: dict[str, Any]) -> list[str]:
    value = info.get("RepoDigests")
    return [str(x) for x in value] if isinstance(value, list) else []


def verify_tools(client: DockerClient, registry: ToolRegistry, lock_path: Path) -> IntegrityReport:
    """Barcha vositalar obrazlarini digest bo‘yicha tekshiradi."""
    report = IntegrityReport()
    try:
        report.docker_version = client.server_version()
    except DockerUnavailable as exc:
        for tool in (Tool.CHECKOV, Tool.KICS, Tool.TRIVY, Tool.GRYPE):
            report.checks.append(
                ToolCheck(tool, IntegrityStatus.DOCKER_UNAVAILABLE, None, None, f"Docker ishlamayapti: {exc}")
            )
        return report

    for tool in (Tool.KICS, Tool.TRIVY, Tool.GRYPE):
        img = registry.images[tool]
        info = client.image_inspect(img.digest_ref)
        if info is not None and img.digest_ref in _repo_digests(info):
            report.checks.append(
                ToolCheck(tool, IntegrityStatus.OK, img.digest, img.digest, "Digest mos", run_ref=img.digest_ref)
            )
            continue
        tagged = client.image_inspect(img.tag_ref)
        if tagged is not None:
            actual = ", ".join(d.split("@", 1)[-1] for d in _repo_digests(tagged)) or str(tagged.get("Id", ""))
            report.checks.append(
                ToolCheck(
                    tool,
                    IntegrityStatus.MISMATCH,
                    img.digest,
                    actual,
                    f"{img.tag_ref} tegi boshqa obrazga ko‘rsatmoqda: digest mos kelmadi",
                )
            )
        else:
            report.checks.append(
                ToolCheck(
                    tool,
                    IntegrityStatus.MISSING,
                    img.digest,
                    None,
                    f"Obraz yo‘q. Yuklab olish: bulutskan tools pull ({img.digest_ref})",
                )
            )

    locked = locked_checkov_id(lock_path)
    if locked is None:
        report.checks.append(
            ToolCheck(
                Tool.CHECKOV,
                IntegrityStatus.NOT_LOCKED,
                None,
                None,
                f"Checkov obrazi qulflanmagan. Bajaring: bulutskan tools lock-checkov ({registry.checkov_tag})",
            )
        )
    else:
        info = client.image_inspect(locked)
        if info is not None and str(info.get("Id")) == locked:
            report.checks.append(ToolCheck(Tool.CHECKOV, IntegrityStatus.OK, locked, locked, "ID mos", run_ref=locked))
        else:
            tagged = client.image_inspect(registry.checkov_tag)
            if tagged is not None:
                report.checks.append(
                    ToolCheck(
                        Tool.CHECKOV,
                        IntegrityStatus.MISMATCH,
                        locked,
                        str(tagged.get("Id")),
                        f"{registry.checkov_tag} obrazi qulflangan ID dan farq qiladi",
                    )
                )
            else:
                report.checks.append(
                    ToolCheck(Tool.CHECKOV, IntegrityStatus.MISSING, locked, None, "Qulflangan Checkov obrazi topilmadi")
                )
    order = {Tool.CHECKOV: 0, Tool.KICS: 1, Tool.TRIVY: 2, Tool.GRYPE: 3}
    report.checks.sort(key=lambda c: order[c.tool])
    return report


def pull_tools(client: DockerClient, registry: ToolRegistry, timeout: float) -> dict[Tool, str]:
    """Registr vositalarini faqat digest bo‘yicha yuklab oladi."""
    results: dict[Tool, str] = {}
    for tool, img in registry.images.items():
        res = client.pull(img.digest_ref, timeout=timeout)
        results[tool] = "ok" if res.returncode == 0 else (res.stderr_text.strip() or "xato")
    return results

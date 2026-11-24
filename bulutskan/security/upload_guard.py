"""Yuklangan fayllarni xavfsiz qabul qilish.

Himoya choralari:

* hajm limiti — oqim bo‘yicha sanaladi, ``Content-Length`` ga ishonilmaydi;
* ZIP ichidagi yo‘llar tekshiriladi (zip-slip): absolyut yo‘l, ``..``, disk
  harfi, simvolik havola, shifrlangan yozuv, ichma-ich arxiv rad etiladi;
* zip-bomba: yozuvlar soni, ochilgan umumiy hajm, bitta fayl hajmi va siqish
  nisbati cheklanadi, ochish paytida haqiqiy baytlar ham sanaladi;
* fayl turlari oq ro‘yxat bo‘yicha qabul qilinadi, faqat matnli fayllar;
* Windows’da to‘qnashadigan nomlar (katta-kichik harf farqi) rad etiladi.

Obraz ``.tar`` arxivi xostda ochilmaydi: faqat tuzilmasi ko‘riladi.
"""

from __future__ import annotations

import stat
import tarfile
import zipfile
from collections.abc import Iterable
from dataclasses import dataclass, field
from pathlib import Path, PurePosixPath
from typing import BinaryIO

_CHUNK = 64 * 1024

#: Ruxsat etilgan kengaytmalar (kichik harflarda).
ALLOWED_SUFFIXES: tuple[str, ...] = (".tf", ".tfvars", ".hcl", ".yaml", ".yml", ".json")
#: Kengaytmasiz ruxsat etilgan nomlar.
ALLOWED_NAMES: frozenset[str] = frozenset({"dockerfile", "containerfile"})
#: Ichma-ich arxivlar: ular ochilmaydi, butun yuklama rad etiladi.
ARCHIVE_SUFFIXES: tuple[str, ...] = (".zip", ".tar", ".gz", ".tgz", ".bz2", ".xz", ".7z", ".rar", ".jar")
#: Katalog bo‘yicha tekshirishda o‘tkazib yuboriladigan kataloglar.
SKIPPED_DIRS: frozenset[str] = frozenset({".git", ".terraform", ".svn", ".hg", "node_modules", "__pycache__"})

_WINDOWS_RESERVED = frozenset(
    {"con", "prn", "aux", "nul"} | {f"com{i}" for i in range(1, 10)} | {f"lpt{i}" for i in range(1, 10)}
)


class UploadRejected(ValueError):
    """Yuklama xavfsizlik talablariga mos emas."""

    def __init__(self, code: str, message: str) -> None:
        super().__init__(message)
        self.code = code
        self.message = message


@dataclass(frozen=True)
class UploadLimits:
    """Yuklama limitlari (baytlarda)."""

    max_upload_bytes: int = 20 * 1024 * 1024
    max_unzipped_bytes: int = 100 * 1024 * 1024
    max_entries: int = 1000
    max_file_bytes: int = 10 * 1024 * 1024
    max_ratio: float = 100.0
    #: Siqish nisbati shu hajmdan katta fayllar uchun tekshiriladi (kichik
    #: matnlar tabiiy ravishda yaxshi siqiladi).
    ratio_min_bytes: int = 1024 * 1024
    max_path_length: int = 240
    max_depth: int = 20


@dataclass
class AcceptedFiles:
    """Qabul qilingan va o‘tkazib yuborilgan fayllar."""

    files: list[str] = field(default_factory=list)
    skipped: list[str] = field(default_factory=list)
    total_bytes: int = 0


def is_allowed_name(name: str) -> bool:
    """Fayl nomi oq ro‘yxatga kiradimi (``Dockerfile``, ``*.Dockerfile``, ``Dockerfile.*`` ham)."""
    base = PurePosixPath(name.replace("\\", "/")).name.lower()
    if base in ALLOWED_NAMES or base.endswith(".dockerfile") or base.startswith("dockerfile."):
        return True
    return base.endswith(ALLOWED_SUFFIXES)


def _is_archive(name: str) -> bool:
    return PurePosixPath(name.replace("\\", "/")).name.lower().endswith(ARCHIVE_SUFFIXES)


def safe_relative_path(name: str, limits: UploadLimits = UploadLimits()) -> PurePosixPath:
    """Arxiv yozuvi nomini xavfsiz nisbiy yo‘lga aylantiradi.

    Raises:
        UploadRejected: yo‘l katalogdan tashqariga chiqishi mumkin bo‘lsa.
    """
    if not name or "\x00" in name or any(ord(c) < 32 for c in name):
        raise UploadRejected("bad_name", "Fayl nomida ruxsat etilmagan belgilar bor")
    if len(name) > limits.max_path_length:
        raise UploadRejected("long_name", "Fayl yo‘li juda uzun")
    unified = name.replace("\\", "/")
    if unified.startswith("/") or (len(unified) > 1 and unified[1] == ":"):
        raise UploadRejected("absolute_path", f"Absolyut yo‘l rad etildi: {name}")
    parts = [p for p in unified.split("/") if p not in ("", ".")]
    if not parts:
        raise UploadRejected("bad_name", "Bo‘sh fayl nomi")
    for part in parts:
        if part == "..":
            raise UploadRejected("path_traversal", f"Katalogdan chiqishga urinish (zip-slip): {name}")
        if ":" in part:
            raise UploadRejected("bad_name", f"Fayl nomida ':' belgisi bor: {name}")
        stem = part.split(".", 1)[0].lower()
        if stem in _WINDOWS_RESERVED or part.endswith((" ", ".")):
            raise UploadRejected("bad_name", f"Windows’da ruxsat etilmagan nom: {name}")
    if len(parts) > limits.max_depth:
        raise UploadRejected("too_deep", "Kataloglar chuqurligi juda katta")
    return PurePosixPath(*parts)


def _inside(base: Path, candidate: Path) -> bool:
    base = base.resolve()
    candidate = candidate.resolve()
    return candidate == base or base in candidate.parents


def _looks_binary(head: bytes) -> bool:
    return b"\x00" in head


def save_stream(src: BinaryIO, dest: Path, max_bytes: int) -> int:
    """Oqimni faylga yozadi va hajmni o‘zi sanaydi.

    Limitdan oshsa, qisman yozilgan fayl o‘chiriladi.
    """
    written = 0
    try:
        with dest.open("xb") as out:
            while True:
                chunk = src.read(_CHUNK)
                if not chunk:
                    break
                written += len(chunk)
                if written > max_bytes:
                    raise UploadRejected("too_large", f"Fayl hajmi {max_bytes // (1024 * 1024)} MB dan oshdi")
                out.write(chunk)
    except BaseException:
        dest.unlink(missing_ok=True)
        raise
    return written


def extract_zip(zip_path: Path, dest_dir: Path, limits: UploadLimits = UploadLimits()) -> AcceptedFiles:
    """ZIP arxivni tekshiradi va ruxsat etilgan fayllarni ``dest_dir`` ga ochadi.

    Avval barcha yozuvlar tekshiriladi; birorta xavfli yozuv bo‘lsa, hech
    narsa ochilmaydi.
    """
    try:
        archive = zipfile.ZipFile(zip_path)
    except (zipfile.BadZipFile, OSError) as exc:
        raise UploadRejected("bad_zip", "ZIP arxiv buzilgan yoki ZIP emas") from exc
    result = AcceptedFiles()
    with archive:
        infos = archive.infolist()
        if len(infos) > limits.max_entries:
            raise UploadRejected("too_many_entries", f"Arxivda {limits.max_entries} tadan ko‘p yozuv bor")
        plan: list[tuple[zipfile.ZipInfo, PurePosixPath]] = []
        seen: set[str] = set()
        declared_total = 0
        for info in infos:
            rel = safe_relative_path(info.filename, limits)
            mode = info.external_attr >> 16
            if stat.S_ISLNK(mode):
                raise UploadRejected("symlink", f"Simvolik havola rad etildi: {info.filename}")
            if info.flag_bits & 0x1:
                raise UploadRejected("encrypted", f"Shifrlangan yozuv rad etildi: {info.filename}")
            if info.is_dir():
                continue
            if _is_archive(info.filename):
                raise UploadRejected("nested_archive", f"Ichma-ich arxiv rad etildi: {info.filename}")
            key = str(rel).lower()
            if key in seen:
                raise UploadRejected("duplicate", f"Takroriy (yoki faqat harf kattaligi bilan farq qiluvchi) nom: {rel}")
            seen.add(key)
            if not is_allowed_name(str(rel)):
                result.skipped.append(str(rel))
                continue
            if info.file_size > limits.max_file_bytes:
                raise UploadRejected("file_too_large", f"Fayl juda katta: {rel}")
            if (
                info.file_size >= limits.ratio_min_bytes
                and info.compress_size > 0
                and info.file_size / info.compress_size > limits.max_ratio
            ):
                raise UploadRejected("zip_bomb", f"Siqish nisbati shubhali (zip-bomba): {rel}")
            declared_total += info.file_size
            if declared_total > limits.max_unzipped_bytes:
                raise UploadRejected("unzipped_too_large", "Arxiv ochilgandagi hajm limitdan oshdi")
            plan.append((info, rel))

        dest_root = dest_dir.resolve()
        actual_total = 0
        for info, rel in plan:
            target = dest_root.joinpath(*rel.parts)
            if not _inside(dest_root, target):
                raise UploadRejected("path_traversal", f"Katalogdan chiqishga urinish: {rel}")
            target.parent.mkdir(parents=True, exist_ok=True)
            written = 0
            with archive.open(info) as src, target.open("xb") as out:
                head = b""
                while True:
                    chunk = src.read(_CHUNK)
                    if not chunk:
                        break
                    if not head:
                        head = chunk[:8192]
                        if _looks_binary(head):
                            break
                    written += len(chunk)
                    actual_total += len(chunk)
                    if written > limits.max_file_bytes or actual_total > limits.max_unzipped_bytes:
                        raise UploadRejected("unzipped_too_large", "Arxiv ochilgandagi hajm limitdan oshdi")
                    out.write(chunk)
            if head and _looks_binary(head):
                target.unlink()
                result.skipped.append(str(rel))
                continue
            result.files.append(str(rel))
        result.total_bytes = actual_total
    return result


def accept_plain_file(src: BinaryIO, filename: str, dest_dir: Path, limits: UploadLimits = UploadLimits()) -> str:
    """Alohida yuklangan bitta IaC faylni qabul qiladi (faqat fayl nomi saqlanadi)."""
    base = PurePosixPath(filename.replace("\\", "/")).name
    rel = safe_relative_path(base, limits)
    if not is_allowed_name(str(rel)):
        raise UploadRejected("not_allowed", f"Fayl turi ruxsat etilmagan: {base}")
    target = dest_dir.resolve() / rel.name
    if target.exists():
        raise UploadRejected("duplicate", f"Bir xil nomli fayl ikki marta yuklandi: {base}")
    save_stream(src, target, min(limits.max_file_bytes, limits.max_upload_bytes))
    with target.open("rb") as fh:
        if _looks_binary(fh.read(8192)):
            target.unlink()
            raise UploadRejected("binary", f"Fayl matnli emas: {base}")
    return rel.name


def stage_directory(src_dir: Path, dest_dir: Path, limits: UploadLimits = UploadLimits()) -> AcceptedFiles:
    """CLI uchun: mahalliy katalogdan faqat ruxsat etilgan fayllarni nusxalaydi.

    Simvolik havolalar va ``.git``, ``.terraform`` kabi kataloglar
    o‘tkazib yuboriladi. Shunday qilib skaner konteyneriga loyihadagi
    boshqa fayllar (``.env``, kalitlar) ko‘rinmaydi.
    """
    src_root = Path(src_dir).resolve()
    if not src_root.is_dir():
        raise UploadRejected("not_a_directory", f"Katalog topilmadi: {src_dir}")
    result = AcceptedFiles()
    total = 0
    for path in sorted(_walk(src_root)):
        rel_posix = path.relative_to(src_root).as_posix()
        if path.is_symlink():
            result.skipped.append(rel_posix)
            continue
        if not is_allowed_name(rel_posix):
            result.skipped.append(rel_posix)
            continue
        rel = safe_relative_path(rel_posix, limits)
        size = path.stat().st_size
        if size > limits.max_file_bytes:
            raise UploadRejected("file_too_large", f"Fayl juda katta: {rel_posix}")
        total += size
        if total > limits.max_unzipped_bytes:
            raise UploadRejected("too_large", "Katalogdagi fayllar umumiy hajmi limitdan oshdi")
        if len(result.files) >= limits.max_entries:
            raise UploadRejected("too_many_entries", f"{limits.max_entries} tadan ko‘p fayl")
        with path.open("rb") as fh:
            if _looks_binary(fh.read(8192)):
                result.skipped.append(rel_posix)
                continue
        target = dest_dir.resolve().joinpath(*rel.parts)
        target.parent.mkdir(parents=True, exist_ok=True)
        with path.open("rb") as fh:
            save_stream(fh, target, limits.max_file_bytes)
        result.files.append(str(rel))
    result.total_bytes = total
    return result


def _walk(root: Path) -> Iterable[Path]:
    for entry in root.iterdir():
        if entry.is_symlink():
            yield entry
        elif entry.is_dir():
            if entry.name in SKIPPED_DIRS:
                continue
            yield from _walk(entry)
        elif entry.is_file():
            yield entry


def validate_image_tar(path: Path, max_bytes: int, max_members: int = 200_000) -> str:
    """Obraz arxivi tuzilmasini tekshiradi va uning turini qaytaradi.

    Returns:
        ``docker-archive`` (``docker save`` natijasi, ``manifest.json`` bor)
        yoki ``oci-archive`` (``index.json`` va ``oci-layout`` bor).
    """
    p = Path(path)
    if not p.is_file():
        raise UploadRejected("not_found", f"Fayl topilmadi: {p.name}")
    if p.stat().st_size > max_bytes:
        raise UploadRejected("too_large", "Obraz arxivi hajmi limitdan oshdi")
    names: set[str] = set()
    try:
        with tarfile.open(p, mode="r:") as tar:
            for count, member in enumerate(tar, 1):
                if count > max_members:
                    raise UploadRejected("too_many_entries", "Arxivda juda ko‘p yozuv bor")
                name = member.name
                unified = name.replace("\\", "/")
                if unified.startswith("/") or ".." in unified.split("/"):
                    raise UploadRejected("path_traversal", f"Arxivda xavfli yo‘l: {name}")
                if member.islnk() or member.issym():
                    link = member.linkname.replace("\\", "/")
                    if link.startswith("/") or ".." in link.split("/"):
                        raise UploadRejected("path_traversal", f"Arxivda xavfli havola: {name}")
                names.add(unified.lstrip("./"))
    except tarfile.TarError as exc:
        raise UploadRejected("bad_tar", "Fayl tar arxiv emas yoki buzilgan") from exc
    if "manifest.json" in names:
        return "docker-archive"
    if "index.json" in names and "oci-layout" in names:
        return "oci-archive"
    raise UploadRejected("not_image", "Arxivda manifest.json yoki index.json topilmadi: bu konteyner obrazi emas")

"""Skaner ishga tushirish natijasi va umumiy yordamchilar."""

from __future__ import annotations

import re
from collections.abc import Callable
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from bulutskan.core.models import Tool, ToolReport
from bulutskan.parsers import ParseError, load_json
from bulutskan.scanner.docker import RunResult

#: Vositalar muvaffaqiyatli tugaganda qaytaradigan kodlar. Checkov xato
#: topsa 1, KICS esa eng yuqori daraja bo‘yicha 20..60 qaytaradi
#: (eksperimentdagi ``timings.csv`` da ham shunday).
ACCEPTED_EXIT_CODES: dict[Tool, frozenset[int]] = {
    Tool.CHECKOV: frozenset({0, 1}),
    Tool.KICS: frozenset({0, 20, 30, 40, 50, 60}),
    Tool.TRIVY: frozenset({0}),
    Tool.GRYPE: frozenset({0}),
}


@dataclass
class ToolRun:
    """Bitta vositaning bitta ishga tushirilishi."""

    tool: Tool
    image_ref: str
    ok: bool
    report: ToolReport | None
    returncode: int | None
    duration_s: float
    error: str | None = None
    raw_path: Path | None = None
    notes: list[str] = field(default_factory=list)
    #: Ishlamaganlik sababi kodi (:data:`FAILURE_CODES`), muvaffaqiyatda ``None``.
    reason_code: str | None = None

    def to_dict(self) -> dict[str, Any]:
        return {
            "tool": self.tool.value,
            "image_ref": self.image_ref,
            "ok": self.ok,
            "returncode": self.returncode,
            "duration_s": round(self.duration_s, 2),
            "error": self.error,
            "reason_code": self.reason_code,
            "version": self.report.tool_version if self.report else None,
            "findings": len(self.report.findings) if self.report else 0,
            "notes": list(self.notes),
        }


#: Vosita ishlamaganligi sabablari (hisobot va JSON uchun).
FAILURE_CODES: dict[str, str] = {
    "timeout": "Vaqt tugadi",
    "out_of_memory": "Xotira yetmadi",
    "docker_error": "Docker konteynerni ishga tushira olmadi",
    "proxy_scheme": "Sxemasiz proksi o‘zgaruvchisi",
    "missing_db": "Zaifliklar bazasi yo‘q",
    "bad_report": "Hisobotni o‘qib bo‘lmadi",
    "exit_code": "Vosita xato kodi bilan tugadi",
}


def failure_code(res: RunResult) -> str:
    """Xato turini qisqa kod bilan belgilaydi."""
    if res.timed_out:
        return "timeout"
    if res.returncode == 137:
        return "out_of_memory"
    if res.returncode == 125:
        return "docker_error"
    if "ProxySchemeUnknown" in res.stderr_text or "Proxy URL had no scheme" in res.stderr_text:
        return "proxy_scheme"
    return "exit_code"


def explain_failure(res: RunResult) -> str:
    """Foydalanuvchi uchun tushunarli xato matni."""
    if res.timed_out:
        return "Vaqt tugadi: konteyner to‘xtatildi (BULUTSKAN_SCAN_TIMEOUT_S ni oshiring)"
    if res.returncode == 137:
        return "Xotira yetmadi (chiqish kodi 137): BULUTSKAN_CONTAINER_MEMORY ni oshiring"
    if res.returncode == 125:
        return "Docker konteynerni ishga tushira olmadi: " + _tail(res.stderr_text)
    if "ProxySchemeUnknown" in res.stderr_text or "Proxy URL had no scheme" in res.stderr_text:
        return (
            "Konteynerga sxemasiz (http:// siz) proksi o‘zgaruvchisi o‘tgan, Checkov uni o‘qiy olmadi. "
            "BulutSkan tarmoqsiz konteynerlarga proksi bermaydi: o‘zgaruvchini Docker o‘zi qo‘shgan. "
            "Docker Desktop → Settings → Resources → Proxies (yoki ~/.docker/config.json dagi \"proxies\") "
            "manzilini http:// bilan yozing. Chiqish kodi "
            f"{res.returncode}: " + _tail(res.stderr_text, 400)
        )
    return f"Chiqish kodi {res.returncode}: " + _tail(res.stderr_text)


def _tail(text: str, limit: int = 1200) -> str:
    text = text.strip()
    return text[-limit:] if text else "(stderr bo‘sh)"


_READONLY_HINT = re.compile(r"read-only|readonly|permission denied", re.I)


def looks_like_readonly_error(res: RunResult) -> bool:
    """Xato baza faqat o‘qish uchun ulangani sababli chiqqanmi."""
    return not res.timed_out and res.returncode != 0 and bool(_READONLY_HINT.search(res.stderr_text))


def finish_run(
    tool: Tool,
    image_ref: str,
    res: RunResult,
    raw_path: Path,
    parse: Callable[[Any], ToolReport],
) -> ToolRun:
    """Natija faylini o‘qiydi va parser orqali :class:`ToolRun` ga aylantiradi."""
    if res.timed_out or res.returncode not in ACCEPTED_EXIT_CODES[tool]:
        return ToolRun(tool, image_ref, False, None, res.returncode, res.duration_s, explain_failure(res), raw_path,
                       reason_code=failure_code(res))
    try:
        report = parse(load_json(raw_path))
    except ParseError as exc:
        return ToolRun(
            tool, image_ref, False, None, res.returncode, res.duration_s,
            f"Hisobotni o‘qib bo‘lmadi: {exc}. stderr: {_tail(res.stderr_text, 400)}", raw_path,
            reason_code="bad_report",
        )
    return ToolRun(tool, image_ref, True, report, res.returncode, res.duration_s, None, raw_path)

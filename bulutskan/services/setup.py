"""Birinchi sozlash ustasi: Docker → vositalar → Checkov → bazalar.

Har bir amal ``SetupTask`` sifatida navbatga qo‘yiladi va worker bajaradi
(server rejimida veb Docker’ga kira olmaydi). Holatlar: ``green``, ``yellow``,
``red``. Jarayon ko‘rsatkichi faqat haqiqiy qadamlar bo‘yicha hisoblanadi:
vosita aniq foiz bermasa, foiz to‘qib chiqarilmaydi.
"""

from __future__ import annotations

from collections.abc import Callable
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select, update

from bulutskan.config import RESOURCES, Settings
from bulutskan.core.models import Tool
from bulutskan.scanner.dbupdate import DB_LABELS, DbUpdateResult, database_status, detect_proxy, mask_proxy, proxy_env, update_databases
from bulutskan.scanner.docker import DockerClient, DockerUnavailable
from bulutskan.scanner.tools import IntegrityStatus, LockError, load_tool_digests, lock_checkov, verify_tools
from bulutskan.storage.db import Database, utcnow
from bulutskan.storage.tables import Setting, SetupTask

ACTIONS = ("check", "pull", "lock_checkov", "build_checkov", "db_update")
GRYPE_MAX_AGE_DAYS = 5  # Grype 120 soatdan eski bazani qabul qilmaydi
STALE_WARN_DAYS = 4

Progress = Callable[[int, str], None]


def _age_days(stamp: str | None) -> float | None:
    if not stamp:
        return None
    try:
        dt = datetime.fromisoformat(str(stamp).replace("Z", "+00:00")[:25])
    except ValueError:
        try:
            dt = datetime.fromisoformat(str(stamp)[:19]).replace(tzinfo=UTC)
        except ValueError:
            return None
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return (datetime.now(UTC) - dt).total_seconds() / 86400


def check_state(settings: Settings, client: DockerClient) -> dict[str, Any]:
    """To‘rt qadamning holati (yashil, sariq, qizil) va o‘zbekcha xabarlar."""
    state: dict[str, Any] = {"checked_at": utcnow().isoformat(timespec="seconds")}
    # 1. Docker
    try:
        version = client.server_version()
        ostype = client.info_field("{{.OSType}}")
        mem = client.info_field("{{.MemTotal}}")
        mem_gb = round(int(mem) / 1024**3, 1) if mem.isdigit() else None
        docker: dict[str, Any] = {"status": "green", "version": version, "ostype": ostype, "mem_gb": mem_gb,
                                  "message": f"Docker ishlayapti ({version}, {ostype or '?'} konteynerlari"
                                             + (f", {str(mem_gb).replace('.', ',')} GB xotira)" if mem_gb else ")")}
        if ostype and ostype != "linux":
            docker.update(status="red", message="Docker Windows konteynerlari rejimida. Docker Desktop’da "
                                                 "“Switch to Linux containers” ni tanlang.")
        elif mem_gb is not None and mem_gb < 4:
            docker.update(status="yellow", message=docker["message"] + ". Docker’ga 4 GB dan kam xotira ajratilgan")
    except DockerUnavailable as exc:
        text = str(exc)
        not_installed = "topilmadi" in text or "not found" in text.lower()
        docker = {"status": "red", "kind": "not_installed" if not_installed else "not_running",
                  "message": ("Docker Desktop topilmadi. Skanerlar Docker konteynerlarida ishlaydi, shuning uchun uni "
                              "o‘rnatish kerak." if not_installed else
                              "Docker Desktop o‘rnatilgan, lekin ishga tushirilmagan. Uni Boshlash menyusidan oching "
                              "va bir daqiqadan keyin “Qayta tekshirish” ni bosing.")}
    state["docker"] = docker
    if docker["status"] == "red":
        state.update(tools={"status": "red", "message": "Avval Docker kerak", "items": []},
                     checkov={"status": "red", "message": "Avval Docker kerak"},
                     databases=_db_state(settings))
        return state
    # 2-3. Vositalar va Checkov
    registry = load_tool_digests(settings.tool_digests_file)
    report = verify_tools(client, registry, settings.tool_lock_file)
    items = [{"tool": c.tool.value, "status": c.status.value, "message": c.message, "expected": c.expected}
             for c in report.checks]
    reg_checks = [c for c in report.checks if c.tool is not Tool.CHECKOV]
    if all(c.status is IntegrityStatus.OK for c in reg_checks):
        tools = {"status": "green", "message": "Uchala vosita digest bo‘yicha mos", "items": items}
    elif any(c.status is IntegrityStatus.MISMATCH for c in reg_checks):
        tools = {"status": "red", "message": "Teg boshqa obrazga ko‘rsatmoqda: bu ta’minot zanjiri hujumi belgisi "
                 "bo‘lishi mumkin. Platforma faqat dissertatsiyada tekshirilgan digest bo‘yicha yuklaydi.",
                 "items": items, "action": "pull"}
    else:
        tools = {"status": "red", "message": "Vosita obrazlari yo‘q: ularni digest bo‘yicha yuklab oling",
                 "items": items, "action": "pull"}
    state["tools"] = tools
    ck = next(c for c in report.checks if c.tool is Tool.CHECKOV)
    if ck.status is IntegrityStatus.OK:
        checkov = {"status": "green", "message": f"Checkov qulflangan: {ck.expected}"}
    elif ck.status is IntegrityStatus.NOT_LOCKED and client.image_inspect(registry.checkov_tag) is not None:
        checkov = {"status": "red", "message": f"{registry.checkov_tag} bor, lekin qulflanmagan", "action": "lock_checkov"}
    elif ck.status is IntegrityStatus.MISMATCH:
        checkov = {"status": "red", "message": ck.message, "action": "lock_checkov"}
    else:
        checkov = {"status": "red", "message": f"{registry.checkov_tag} obrazi yo‘q: uni yig‘ish kerak "
                   "(internet va proksi kerak, bir necha daqiqa)", "action": "build_checkov"}
    state["checkov"] = checkov
    state["databases"] = _db_state(settings)
    return state


def _db_state(settings: Settings) -> dict[str, Any]:
    status = database_status(settings)
    items = []
    worst = "green"
    order = {"green": 0, "yellow": 1, "red": 2}
    for name, info in status.items():
        meta = info.get("metadata") or {}
        stamp = meta.get("UpdatedAt") or meta.get("built")
        age = _age_days(stamp)
        if not info["present"]:
            st, msg = "red", f"{DB_LABELS[name]} yo‘q"
        elif name == "grype" and age is not None and age > GRYPE_MAX_AGE_DAYS:
            st, msg = "red", f"Grype bazasi {int(age)} kun oldin yig‘ilgan va tekshiruvda ishlamaydi. Yangilang"
        elif age is not None and age > STALE_WARN_DAYS:
            st, msg = "yellow", f"{DB_LABELS[name]} {int(age)} kun eski"
        else:
            st, msg = "green", f"{DB_LABELS[name]}: {stamp or 'sana noma’lum'}"
        items.append({"name": name, "status": st, "message": msg, "stamp": stamp,
                      "age_days": round(age, 1) if age is not None else None})
        if order[st] > order[worst]:
            worst = st
    msg = {"green": "Bazalar tayyor", "yellow": "Bazalar eskirmoqda: yangilash tavsiya etiladi",
           "red": "Bazalarni yuklab olish yoki yangilash kerak"}[worst]
    return {"status": worst, "message": msg, "items": items, **({"action": "db_update"} if worst != "green" else {})}


def run_action(action: str, settings: Settings, client: DockerClient, progress: Progress) -> dict[str, Any]:
    """Ustaning bitta amalini bajaradi; natija (va yangi holat) qaytariladi."""
    if action == "check":
        progress(50, "Tekshirilmoqda…")
        return check_state(settings, client)
    registry = load_tool_digests(settings.tool_digests_file)
    if action == "pull":
        items = list(registry.images.items())
        pulled: dict[str, str] = {}
        for i, (tool, img) in enumerate(items):
            progress(int(i * 100 / len(items)), f"{tool.value}: yuklab olinmoqda ({i + 1}/{len(items)})")
            res = client.pull(img.digest_ref, timeout=settings.pull_timeout_s)
            pulled[tool.value] = "ok" if res.returncode == 0 else (res.stderr_text.strip()[-300:] or "xato")
        progress(100, "Yuklab olindi")
        return {"pull": pulled, "state": check_state(settings, client)}
    if action == "lock_checkov":
        progress(50, "Checkov versiyasi tekshirilmoqda…")
        try:
            image_id = lock_checkov(client, registry, settings.tool_lock_file)
        except LockError as exc:
            raise RuntimeError(str(exc)) from exc
        return {"image_id": image_id, "state": check_state(settings, client)}
    if action == "build_checkov":
        progress(-1, "Checkov yig‘ilmoqda (pip orqali yuklab olinadi, bir necha daqiqa)…")
        proxy = detect_proxy(client)
        args = {"CHECKOV_VERSION": registry.checkov_version,
                **{k: v for k, v in proxy_env(proxy).items() if k.lower() != "no_proxy"}}
        res = client.build(RESOURCES / "checkov.Dockerfile", RESOURCES, registry.checkov_tag, args,
                           settings.pull_timeout_s)
        if res.returncode != 0:
            raise RuntimeError("Yig‘ish bajarilmadi: " + res.stderr_text.strip()[-500:])
        progress(80, "Checkov qulflanmoqda…")
        image_id = lock_checkov(client, registry, settings.tool_lock_file)
        return {"image_id": image_id, "proxy": mask_proxy(proxy), "state": check_state(settings, client)}
    if action == "db_update":
        report = verify_tools(client, registry, settings.tool_lock_file)
        results: list[DbUpdateResult] = []
        for i, name in enumerate(("trivy", "trivy-java", "grype")):
            progress(int(i * 100 / 3), f"{DB_LABELS[name]} yuklab olinmoqda ({i + 1}/3)…")
            results.extend(update_databases(client, report, settings, (name,)))
        failed = [r for r in results if not r.ok]
        if failed:
            raise RuntimeError("; ".join(f"{r.name}: {r.error}" for r in failed))
        return {"updated": [r.name for r in results], "state": check_state(settings, client)}
    raise ValueError(f"Noma’lum amal: {action}")


# ---------------------------------------------------------------- vazifalar


def enqueue_task(db: Database, action: str, user_id: int | None) -> int:
    if action not in ACTIONS:
        raise ValueError(f"Noma’lum amal: {action}")
    with db.session() as s:
        busy = s.scalar(select(SetupTask.id).where(SetupTask.status.in_(("queued", "running"))).limit(1))
        if busy is not None:
            return int(busy)
        task = SetupTask(action=action, user_id=user_id)
        s.add(task)
        s.flush()
        return task.id


def claim_task(db: Database) -> int | None:
    oldest = select(SetupTask.id).where(SetupTask.status == "queued").order_by(SetupTask.id).limit(1).scalar_subquery()
    stmt = (update(SetupTask).where(SetupTask.id == oldest, SetupTask.status == "queued")
            .values(status="running", started_at=utcnow()).returning(SetupTask.id)
            .execution_options(synchronize_session=False))
    with db.engine.begin() as conn:
        row = conn.execute(stmt).fetchone()
    return int(row[0]) if row else None


def execute_task(db: Database, task_id: int, settings: Settings, client: DockerClient) -> None:
    with db.session() as s:
        task = s.get(SetupTask, task_id)
        assert task is not None
        action = task.action

    def progress(pct: int, message: str) -> None:
        with db.engine.begin() as conn:
            conn.execute(update(SetupTask).where(SetupTask.id == task_id).values(progress=pct, message=message))

    try:
        result = run_action(action, settings, client, progress)
        status, message, pct = "done", "Bajarildi", 100
    except Exception as exc:  # noqa: BLE001 - foydalanuvchiga xabar qaytadi
        result, status, message, pct = {}, "failed", str(exc)[:2000], 100
    with db.session() as s:
        task = s.get(SetupTask, task_id)
        assert task is not None
        task.status, task.message, task.progress, task.result, task.finished_at = status, message, pct, result, utcnow()
        new_state = result.get("state") if action != "check" else result
        if isinstance(new_state, dict) and new_state:
            save_setting(s, "setup_state", new_state)


def save_setting(session: Any, key: str, value: Any) -> None:
    row = session.get(Setting, key)
    if row is None:
        session.add(Setting(key=key, value=value))
    else:
        row.value = value


def get_setting(db: Database, key: str, default: Any = None) -> Any:
    with db.session() as s:
        row = s.get(Setting, key)
        return row.value if row is not None else default


def latest_task(db: Database) -> SetupTask | None:
    with db.session() as s:
        return s.scalar(select(SetupTask).order_by(SetupTask.id.desc()).limit(1))


def all_green(state: dict[str, Any] | None) -> bool:
    if not state:
        return False
    return all((state.get(k) or {}).get("status") == "green" for k in ("docker", "tools", "checkov", "databases"))

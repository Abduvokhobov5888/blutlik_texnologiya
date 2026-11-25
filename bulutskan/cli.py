"""BulutSkan buyruq qatori (Typer).

Misollar::

    bulutskan scan --iac ./infra --fail-on high
    bulutskan scan --image nginx:1.21 --fail-on critical --fixable-only
    bulutskan db-update
    bulutskan tools verify

Chiqish kodlari: 0 — chegaradan oshmadi; 1 — chegaradan oshdi;
2 — foydalanish xatosi, vosita yaxlitligi buzilgan yoki tekshiruv bajarilmadi.
"""

from __future__ import annotations

import os
import sys
from collections.abc import Iterable
from enum import StrEnum
from pathlib import Path
from typing import TextIO

import typer

from bulutskan import __version__
from bulutskan.config import RESOURCES, Settings, get_settings
from bulutskan.core.consensus import ConsensusLabel
from bulutskan.core.eol import EOL_WARNING_UZ
from bulutskan.core.gate import (
    GateDecision,
    UnknownSeverityPolicy,
    decide_exit,
    evaluate_gate,
    parse_fail_on,
    severity_label,
)
from bulutskan.core.models import SEVERITY_ORDER, ScanKind, Tool
from bulutskan.reporting.json_export import build_export, write_export
from bulutskan.scanner.dbupdate import DB_NAMES, database_status, detect_proxy, mask_proxy, proxy_env, update_databases
from bulutskan.scanner.docker import DockerClient, DockerUnavailable
from bulutskan.scanner.image import ImagePrepareError
from bulutskan.scanner.runs import FAILURE_CODES
from bulutskan.scanner.tools import (
    IntegrityError,
    IntegrityStatus,
    LockError,
    load_tool_digests,
    lock_checkov,
    pull_tools,
    verify_tools,
)
from bulutskan.security.upload_guard import UploadRejected
from bulutskan.security.validators import InvalidImageReference
from bulutskan.security.passwords import WeakPassword
from bulutskan.services import audit
from bulutskan.services.demo import demo_available, import_demo
from bulutskan.services.pipeline import Scanner, ScanOutcome, ScanStatus
from bulutskan.services.users import UserError, add_user, disable_user, enable_user, get_user, set_password
from bulutskan.storage.db import Database
from bulutskan.storage.tables import User
from bulutskan.worker import Worker
from sqlalchemy import select

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_ERROR = 2


def configure_utf8_output(streams: Iterable[TextIO] | None = None) -> None:
    """Chiqishni UTF-8 ga o‘tkazadi.

    Windows PowerShell 5.1 da chiqish quvur orqali o‘tsa (masalan,
    ``| Tee-Object``), Python ANSI kodlashida (cp1251) yozadi, PowerShell esa
    uni OEM kodlashi (cp866) deb o‘qiydi: ``bo‘yicha`` → ``boСyicha``,
    ``—`` → ``Ч``. Shuning uchun CLI har doim UTF-8 da yozadi; PowerShell
    tomonida ``[Console]::OutputEncoding = [Text.Encoding]::UTF8`` kerak
    (``docs/windows_sinov.md``). Kodlashda yo‘q belgi xato bermaydi, ``?``
    bilan almashtiriladi.
    """
    for stream in streams if streams is not None else (sys.stdout, sys.stderr):
        encoding = (getattr(stream, "encoding", None) or "").lower().replace("-", "").replace("_", "")
        if encoding == "utf8":
            continue
        reconfigure = getattr(stream, "reconfigure", None)
        if callable(reconfigure):
            try:
                reconfigure(encoding="utf-8", errors="replace")
            except (ValueError, OSError):
                pass


# ``bulutskan`` buyrug‘i ``bulutskan.cli:app`` ga ishora qiladi, shuning uchun
# sozlash modul yuklanganda, Typer biror narsa chiqarishidan oldin bajariladi.
configure_utf8_output()

app = typer.Typer(
    name="bulutskan",
    help="BulutSkan: IaC fayllari va konteyner obrazlarini ochiq kodli skanerlar bilan tekshirish.",
    no_args_is_help=True,
    add_completion=False,
)
tools_app = typer.Typer(help="Vositalar: digest tekshiruvi, yuklab olish, Checkov qulfi.", no_args_is_help=True)
app.add_typer(tools_app, name="tools")
user_app = typer.Typer(help="Akkauntlar: faqat administrator CLI orqali yaratadi.", no_args_is_help=True)
app.add_typer(user_app, name="user")


class FailOn(StrEnum):
    critical = "critical"
    high = "high"
    medium = "medium"
    low = "low"


class UnknownSeverity(StrEnum):
    ignore = "ignore"
    low = "low"
    medium = "medium"
    high = "high"


def make_client(settings: Settings) -> DockerClient:
    """Docker mijozi (testlarda soxtasi bilan almashtiriladi)."""
    return DockerClient(docker_bin=settings.docker_bin)


def _err(message: str) -> None:
    typer.secho(message, fg=typer.colors.RED, err=True)


def _ok(message: str) -> None:
    typer.secho(message, fg=typer.colors.GREEN)


def _num(value: float, digits: int = 3) -> str:
    """O‘zbekcha o‘nlik kasr: 0,729."""
    return f"{value:.{digits}f}".replace(".", ",")


@app.callback(invoke_without_command=True)
def _main(
    version: bool = typer.Option(False, "--version", help="Versiyani ko‘rsatish."),
) -> None:
    if version:
        typer.echo(f"BulutSkan {__version__}")
        raise typer.Exit(EXIT_OK)


# ------------------------------------------------------------------- scan


def _print_outcome(outcome: ScanOutcome, policy: UnknownSeverityPolicy) -> None:
    kind = "IaC" if outcome.kind is ScanKind.IAC else "Obraz"
    typer.secho(f"\n{kind} tekshiruvi: {outcome.target}", bold=True)
    typer.echo(f"Holat: {outcome.status}   ID: {outcome.uid}")
    if outcome.skipped_files:
        typer.echo(f"O‘tkazib yuborilgan fayllar ({len(outcome.skipped_files)}): " + ", ".join(outcome.skipped_files[:10]))
    if outcome.eol is not None and outcome.eol.is_eol:
        typer.secho("\n" + "!" * 72, fg=typer.colors.RED, bold=True)
        typer.secho(EOL_WARNING_UZ, fg=typer.colors.RED, bold=True)
        for reason in outcome.eol.reasons:
            typer.secho(f"  - {reason.detail}", fg=typer.colors.RED)
        typer.secho("!" * 72, fg=typer.colors.RED, bold=True)

    typer.echo("\nVositalar:")
    for run in outcome.tool_runs:
        if run.ok and run.report is not None:
            version = run.report.tool_version or "?"
            count = len(run.report.findings)
            raw = run.report.metadata.get("raw_count", count)
            extra = f", xom yozuvlar: {raw}" if raw != count else ""
            typer.echo(f"  {run.tool.value:8} {version:10} {count:5} ta topilma{extra}  ({_num(run.duration_s, 1)} s)")
        else:
            typer.secho(f"  {run.tool.value:8} XATO: {run.error}", fg=typer.colors.RED)
        for note in run.notes:
            typer.echo(f"           ({note})")

    table = outcome.severity_table()
    if table:
        header = "  " + "vosita".ljust(9) + "".join(s.value[:8].rjust(10) for s in SEVERITY_ORDER)
        typer.echo("\nJiddiylik bo‘yicha (takrorlar birlashtirilgan):")
        typer.echo(header)
        for tool, counts in table.items():
            typer.echo("  " + tool.ljust(9) + "".join(str(counts[s.value]).rjust(10) for s in SEVERITY_ORDER))
        if any(counts["UNKNOWN"] for counts in table.values()):
            typer.echo(f"  UNKNOWN = {severity_label(SEVERITY_ORDER[-1], policy)}")

    c = outcome.consensus
    if c is not None:
        typer.echo("\nKonsensus:")
        typer.echo(f"  Tasdiqlangan: {c.count(ConsensusLabel.CONFIRMED)}")
        typer.echo(f"  Tekshirish talab etiladi: {c.count(ConsensusLabel.NEEDS_REVIEW)}")
        if outcome.kind is ScanKind.IMAGE:
            typer.echo(f"  CPE asosida, soxta bo‘lishi mumkin: {c.cpe_suspect_count}")
            sets = c.key_sets
            if Tool.TRIVY in sets and Tool.GRYPE in sets:
                common = len(sets[Tool.TRIVY] & sets[Tool.GRYPE])
                typer.echo(
                    f"  Noyob CVE: Trivy {len(sets[Tool.TRIVY])}, Grype {len(sets[Tool.GRYPE])}, umumiy {common}"
                )
        for pair, value in c.jaccard.items():
            label = "uchala vosita" if pair == "all" else pair.replace("|", " – ")
            typer.echo(f"  Jaccard {label}: {_num(value)}")
        if c.jaccard_core is not None:
            typer.echo(f"  Asosiy Jaccard (CVE, CPE’siz): {_num(c.jaccard_core)}")
    failed = [t.value for t in outcome.failed_tools]
    if failed and outcome.status != "failed":
        typer.secho(
            f"\nDIQQAT: tekshiruv qisman — ishlamagan vosita: {', '.join(failed)}. "
            "Konsensus va Jaccard faqat ishlagan vositalar bo‘yicha hisoblandi.",
            fg=typer.colors.YELLOW,
            bold=True,
        )
    if outcome.gt_evaluation is not None:
        typer.echo("\nGround truth bo‘yicha (namoyish fayllari, III bob usuli):")
        if failed:
            typer.secho(
                f"  Natija to‘liq emas: {', '.join(failed)} ishlamadi, shuning uchun uni III bob bilan solishtirib bo‘lmaydi.",
                fg=typer.colors.YELLOW,
            )
        for name, ev in outcome.gt_evaluation.tools.items():
            typer.echo(f"  {name:15} {ev.tp}/{ev.gt}  recall={_num(ev.recall)}  precision={_num(ev.precision)}  FP={ev.fp}")
        for pair, info in outcome.gt_evaluation.overlap.items():
            typer.echo(f"  Jaccard {pair}: {_num(info['jaccard'])}")
        if outcome.gt_evaluation.missed_by_all:
            ran = ", ".join(outcome.gt_evaluation.tools)
            label = f"Ishlagan vositalar ({ran}) orasida hech biri topmagan" if failed else "Hech bir vosita topmagan"
            typer.echo(f"  {label}: " + ", ".join(outcome.gt_evaluation.missed_by_all))


def _print_gate(gate: GateDecision) -> None:
    if gate.threshold is None:
        return
    for note in gate.notes:
        typer.echo(f"Eslatma: {note}")
    extra = f", shundan noma’lum darajali: {gate.unknown_counted}" if gate.unknown_counted else ""
    msg = (
        f"\n--fail-on {gate.threshold.value.lower()}: chegaradan oshgan guruhlar — {len(gate.counted)}{extra}"
        f" (--unknown-severity {gate.policy.value})"
    )
    if gate.failed:
        typer.secho(msg + " → KONVEYER TO‘XTATILADI", fg=typer.colors.RED, bold=True)
    else:
        _ok(msg + " → o‘tdi")


@app.command()
def scan(
    iac: Path | None = typer.Option(None, "--iac", help="IaC fayllari katalogi (Terraform, Kubernetes, Dockerfile).",
                                    exists=True, file_okay=False, dir_okay=True, resolve_path=True),
    image: str | None = typer.Option(None, "--image", help="Obraz nomi, masalan nginx:1.21."),
    image_tar: Path | None = typer.Option(None, "--image-tar", help="docker save bilan olingan .tar fayl.",
                                          exists=True, file_okay=True, dir_okay=False, resolve_path=True),
    image_name: str | None = typer.Option(None, "--image-name", help="--image-tar uchun obraz nomi (EOL tekshiruvi uchun)."),
    fail_on: FailOn | None = typer.Option(None, "--fail-on", help="Shu darajadan past bo‘lmagan topilma bo‘lsa, 1 kodi bilan chiqish."),
    fixable_only: bool = typer.Option(False, "--fixable-only", help="Faqat tuzatilgan versiyasi bor zaifliklarni sanash."),
    unknown_severity: UnknownSeverity = typer.Option(
        UnknownSeverity.medium, "--unknown-severity",
        help="Darajasi noma’lum topilmalar (masalan, faqat Checkov topgani) --fail-on qarorida qaysi daraja deb olinadi.",
    ),
    json_out: Path | None = typer.Option(None, "--json", help="Natijani JSON faylga yozish."),
    allow_partial: bool = typer.Option(
        False, "--allow-partial",
        help="Biror vosita ishlamasa ham natijani qabul qilish. Sukut bo‘yicha qisman tekshiruv 2 kodi bilan tugaydi.",
    ),
) -> None:
    """IaC katalogi yoki konteyner obrazini tekshirish."""
    chosen = [x for x in (iac, image, image_tar) if x is not None]
    if len(chosen) != 1:
        _err("Bittasini ko‘rsating: --iac, --image yoki --image-tar")
        raise typer.Exit(EXIT_ERROR)
    policy = UnknownSeverityPolicy(unknown_severity.value)
    settings = get_settings()
    scanner = Scanner(settings, make_client(settings))
    try:
        if iac is not None:
            outcome = scanner.scan_iac_directory(iac)
        elif image is not None:
            outcome = scanner.scan_image(image)
        else:
            assert image_tar is not None
            outcome = scanner.scan_image_tar(image_tar, image_name=image_name)
    except IntegrityError as exc:
        _err(str(exc))
        raise typer.Exit(EXIT_ERROR) from exc
    except (InvalidImageReference, UploadRejected, ImagePrepareError, DockerUnavailable) as exc:
        _err(f"Xato: {exc}")
        raise typer.Exit(EXIT_ERROR) from exc

    _print_outcome(outcome, policy)
    gate = evaluate_gate(outcome.consensus, parse_fail_on(fail_on.value), fixable_only, policy) \
        if (fail_on is not None and outcome.consensus is not None) else None
    failed_tools = [t.value for t in outcome.failed_tools]
    decision = decide_exit(outcome.status, failed_tools, gate, allow_partial)
    if json_out is not None:
        write_export(json_out, build_export(outcome, policy, gate, exit_decision=decision))
        typer.echo(f"\nJSON: {json_out}")
    if outcome.status == ScanStatus.FAILED and outcome.error:
        _err(outcome.error)
    _print_failures(outcome)
    if gate is not None:
        _print_gate(gate)
    color = typer.colors.RED if decision.code else typer.colors.GREEN
    typer.secho(f"\nChiqish kodi {decision.code}: {decision.reason}", fg=color, bold=True, err=decision.code == EXIT_ERROR)
    raise typer.Exit(decision.code)


def _print_failures(outcome: ScanOutcome) -> None:
    """Qaysi vosita nima sababdan ishlamaganini aniq ko‘rsatadi."""
    failed = [r for r in outcome.tool_runs if not r.ok]
    if not failed:
        return
    typer.secho("\nIshlamagan vositalar:", fg=typer.colors.RED, bold=True)
    for run in failed:
        code = run.reason_code or "exit_code"
        title = FAILURE_CODES.get(code, code)
        rc = f", chiqish kodi {run.returncode}" if run.returncode is not None else ""
        typer.secho(f"  {run.tool.value} — {title} [{code}{rc}]", fg=typer.colors.RED)
        if run.error:
            typer.echo(f"    {run.error}")


# ------------------------------------------------------------- bazalar


@app.command("db-update")
def db_update(
    only: list[str] = typer.Option([], "--only", help="Faqat shu bazalar: trivy, trivy-java, grype."),
) -> None:
    """Zaifliklar bazalarini yangilash (internet faqat shu yerda ishlatiladi)."""
    which = tuple(only) or DB_NAMES
    if set(which) - set(DB_NAMES):
        _err(f"--only qiymatlari: {', '.join(DB_NAMES)}")
        raise typer.Exit(EXIT_ERROR)
    settings = get_settings()
    client = make_client(settings)
    registry = load_tool_digests(settings.tool_digests_file)
    integrity = verify_tools(client, registry, settings.tool_lock_file)
    try:
        for name in which:
            integrity.run_ref(Tool.GRYPE if name == "grype" else Tool.TRIVY)
    except IntegrityError as exc:
        _err(f"Bazalarni yangilash bloklandi: {exc}")
        raise typer.Exit(EXIT_ERROR) from exc
    typer.echo(f"Proksi: {mask_proxy(detect_proxy(client))}")
    results = update_databases(client, integrity, settings, which)
    failed = False
    for r in results:
        if r.ok:
            meta = r.metadata or {}
            stamp = meta.get("UpdatedAt") or meta.get("built") or ""
            _ok(f"  {r.name:11} yangilandi ({r.duration_s:.0f} s) {stamp}")
        else:
            failed = True
            _err(f"  {r.name:11} XATO: {r.error}")
    raise typer.Exit(EXIT_ERROR if failed else EXIT_OK)


@app.command("db-status")
def db_status() -> None:
    """Zaifliklar bazalarining yangilanish sanalari."""
    settings = get_settings()
    for name, info in database_status(settings).items():
        meta = info.get("metadata") or {}
        built = meta.get("UpdatedAt") or meta.get("built") or "—"
        present = "bor" if info["present"] else "YO‘Q"
        schema = f"  sxema: {meta['schema']}" if meta.get("schema") else ""
        typer.echo(
            f"{info['label']:22} {present:4}  baza sanasi: {built}{schema}  yangilangan: {info.get('updated_at') or '—'}"
        )


# --------------------------------------------------------------- tools


@tools_app.command("verify")
def tools_verify() -> None:
    """Vositalar obrazlarini sha256 digest bo‘yicha tekshirish."""
    settings = get_settings()
    report = verify_tools(make_client(settings), load_tool_digests(settings.tool_digests_file), settings.tool_lock_file)
    if report.docker_version:
        typer.echo(f"Docker: {report.docker_version}")
    for c in report.checks:
        line = f"  {c.tool.value:8} {c.status.value:18} {c.message}"
        if c.status is IntegrityStatus.OK:
            _ok(line)
        else:
            _err(line)
    if report.has_mismatch:
        _err("DIQQAT: vosita digesti mos kelmadi. Barcha tekshiruvlar bloklanadi.")
    raise typer.Exit(EXIT_OK if report.ok else EXIT_ERROR)


@tools_app.command("pull")
def tools_pull() -> None:
    """Trivy, Grype va KICS obrazlarini faqat digest bo‘yicha yuklab olish."""
    settings = get_settings()
    results = pull_tools(make_client(settings), load_tool_digests(settings.tool_digests_file), settings.pull_timeout_s)
    for tool, status in results.items():
        (_ok if status == "ok" else _err)(f"  {tool.value:8} {status}")
    raise typer.Exit(EXIT_OK if all(s == "ok" for s in results.values()) else EXIT_ERROR)


@tools_app.command("lock-checkov")
def tools_lock_checkov(
    tag: str | None = typer.Option(None, "--tag", help="Mahalliy Checkov obrazi (sukut: diss-checkov:3.3.26)."),
) -> None:
    """Mahalliy Checkov obrazi ID sini qulflash (birinchi ishonch tamoyili)."""
    settings = get_settings()
    registry = load_tool_digests(settings.tool_digests_file)
    try:
        image_id = lock_checkov(make_client(settings), registry, settings.tool_lock_file, tag)
    except LockError as exc:
        _err(str(exc))
        raise typer.Exit(EXIT_ERROR) from exc
    _ok(f"Checkov qulflandi: {image_id}")
    typer.echo(f"Qulf fayli: {settings.tool_lock_file}")


@tools_app.command("build-checkov")
def tools_build_checkov() -> None:
    """Checkov obrazini checkov.Dockerfile dan yig‘ish (internet va proksi kerak)."""
    settings = get_settings()
    client = make_client(settings)
    registry = load_tool_digests(settings.tool_digests_file)
    proxy = detect_proxy(client)
    args = {"CHECKOV_VERSION": registry.checkov_version, **proxy_env(proxy)}
    args.pop("NO_PROXY", None)
    args.pop("no_proxy", None)
    res = client.build(RESOURCES / "checkov.Dockerfile", RESOURCES, registry.checkov_tag, args, settings.pull_timeout_s)
    if res.returncode != 0:
        _err(f"Yig‘ish bajarilmadi: {res.stderr_text.strip()[-800:]}")
        raise typer.Exit(EXIT_ERROR)
    _ok(f"Yig‘ildi: {registry.checkov_tag}. Endi bajaring: bulutskan tools lock-checkov")


# ------------------------------------------------------------- baza


def open_db(settings: Settings) -> Database:
    """SQLite bazasini ochadi va jadvallarni yaratadi."""
    db = Database(settings.db_path)
    db.init_schema()
    return db


# ------------------------------------------------------------- user


class Role(StrEnum):
    admin = "admin"
    analyst = "analyst"
    guest = "guest"


def _read_password(password_stdin: bool) -> str:
    if password_stdin:
        return sys.stdin.readline().rstrip("\r\n")
    return str(typer.prompt("Parol", hide_input=True, confirmation_prompt="Parolni takrorlang"))


@user_app.command("add")
def user_add(
    username: str = typer.Argument(..., help="Login (kichik lotin harflari)."),
    role: Role = typer.Option(Role.analyst, "--role", help="admin, analyst yoki guest."),
    password_stdin: bool = typer.Option(False, "--password-stdin", help="Parolni standart kirishdan o‘qish (avtomatlashtirish uchun)."),
) -> None:
    """Akkaunt yaratish. Parol ekranga chiqmaydi va bcrypt bilan xeshlanadi."""
    settings = get_settings()
    db = open_db(settings)
    try:
        with db.session() as s:
            user = add_user(s, username, _read_password(password_stdin), role.value)
            audit.record(s, "user_added", username="cli", target=user.username, detail={"role": user.role})
    except (UserError, WeakPassword) as exc:
        _err(str(exc))
        raise typer.Exit(EXIT_ERROR) from exc
    finally:
        db.dispose()
    _ok(f"Akkaunt yaratildi: {username.strip().lower()} ({role.value})")


@user_app.command("list")
def user_list() -> None:
    """Akkauntlar ro‘yxati."""
    settings = get_settings()
    db = open_db(settings)
    try:
        with db.session() as s:
            for u in s.scalars(select(User).order_by(User.username)):
                state = "faol" if u.is_active else "o‘chirilgan"
                last = u.last_login_at.strftime("%Y-%m-%d %H:%M") if u.last_login_at else "—"
                typer.echo(f"{u.username:24} {u.role:8} {state:12} oxirgi kirish: {last}")
    finally:
        db.dispose()


def _change_user(username: str, action: str) -> None:
    settings = get_settings()
    db = open_db(settings)
    try:
        with db.session() as s:
            user = get_user(s, username)
            if user is None:
                _err(f"Foydalanuvchi topilmadi: {username}")
                raise typer.Exit(EXIT_ERROR)
            if action == "disable":
                disable_user(s, user)
                audit.record(s, "user_disabled", username="cli", target=user.username)
            elif action == "enable":
                enable_user(s, user)
                audit.record(s, "user_enabled", username="cli", target=user.username)
            else:
                try:
                    set_password(s, user, _read_password(action == "passwd-stdin"))
                except WeakPassword as exc:
                    _err(str(exc))
                    raise typer.Exit(EXIT_ERROR) from exc
                audit.record(s, "password_changed", username="cli", target=user.username)
    finally:
        db.dispose()
    _ok("Bajarildi")


@user_app.command("disable")
def user_disable(username: str = typer.Argument(...)) -> None:
    """Akkauntni o‘chirish (barcha sessiyalari darhol bekor bo‘ladi)."""
    _change_user(username, "disable")


@user_app.command("enable")
def user_enable(username: str = typer.Argument(...)) -> None:
    """O‘chirilgan akkauntni qayta yoqish."""
    _change_user(username, "enable")


@user_app.command("passwd")
def user_passwd(
    username: str = typer.Argument(...),
    password_stdin: bool = typer.Option(False, "--password-stdin"),
) -> None:
    """Parolni almashtirish (eski sessiyalar bekor bo‘ladi)."""
    _change_user(username, "passwd-stdin" if password_stdin else "passwd")


# ------------------------------------------------------------- demo, worker


@app.command("demo-import")
def demo_import(force: bool = typer.Option(False, "--force", help="Mavjud namoyish ma’lumotlarini almashtirish.")) -> None:
    """III bob natijalarini (15 obraz va IaC) Docker va internetsiz bazaga yozish."""
    settings = get_settings()
    db = open_db(settings)
    try:
        if not demo_available():
            _err("Namoyish ma’lumotlari topilmadi (demo/sinov/natijalar)")
            raise typer.Exit(EXIT_ERROR)
        n = import_demo(db, force=force)
    finally:
        db.dispose()
    _ok(f"Import qilindi: {n} ta tekshiruv" if n else "Namoyish ma’lumotlari allaqachon bor (--force bilan almashtirish mumkin)")


@app.command("worker")
def worker_cmd() -> None:
    """Navbatdan tekshiruvlarni olib bajaruvchi jarayon (server rejimi)."""
    import signal
    import threading

    settings = get_settings()
    db = open_db(settings)
    stop = threading.Event()
    signal.signal(signal.SIGINT, lambda *_: stop.set())
    signal.signal(signal.SIGTERM, lambda *_: stop.set())
    typer.echo(f"Worker ishga tushdi: {settings.effective_worker_slots} slot")
    Worker(settings, db, client_factory=lambda: make_client(settings)).run_forever(stop)
    db.dispose()


def _free_port(host: str, start: int, tries: int = 10) -> int:
    """Lokal rejim: band bo‘lmagan birinchi port (8000, 8001, …)."""
    import socket

    for port in range(start, start + tries):
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as sock:
            try:
                sock.bind((host, port))
            except OSError:
                continue
            return port
    return start


def _open_browser_when_ready(url: str) -> None:
    import threading
    import time
    import urllib.request
    import webbrowser

    def wait() -> None:
        for _ in range(120):
            try:
                with urllib.request.urlopen(url + "health", timeout=2) as resp:  # noqa: S310 - faqat 127.0.0.1
                    if resp.status == 200:
                        webbrowser.open(url)
                        return
            except OSError:
                time.sleep(0.5)

    threading.Thread(target=wait, daemon=True).start()


@app.command("serve")
def serve(
    host: str | None = typer.Option(None, "--host", help="Tinglash manzili (sukut: 127.0.0.1)."),
    port: int | None = typer.Option(None, "--port", help="Port (sukut: 8000)."),
    no_browser: bool = typer.Option(False, "--no-browser", help="Brauzerni avtomatik ochmaslik."),
) -> None:
    """Veb-interfeysni ishga tushirish. Lokal rejimda worker ham shu jarayonda ishlaydi."""
    import uvicorn

    from bulutskan.web.app import create_app

    settings = get_settings()
    host = host or settings.host
    port = port or settings.port
    if not settings.is_server and host not in ("127.0.0.1", "localhost", "::1"):
        typer.secho(f"Ogohlantirish: lokal rejimda {host} manzili tashqi tarmoqqa ochiq bo‘lishi mumkin", fg="yellow")
    if not settings.is_server:
        port = _free_port(host, port)
    url = f"http://{'127.0.0.1' if host in ('0.0.0.0', '::') else host}:{port}/"
    web_app = create_app(settings)
    typer.secho(f"BulutSkan {__version__} ishlayapti: {url}", fg=typer.colors.GREEN, bold=True)
    typer.echo(f"Ma’lumotlar katalogi: {settings.data_path}")
    if not settings.is_server:
        typer.echo("Dasturni to‘xtatish uchun shu oynani yoping (yoki Ctrl+C).")
        if settings.open_browser and not no_browser:
            _open_browser_when_ready(url)
    uvicorn.run(
        web_app,
        host=host,
        port=port,
        log_level="info",
        proxy_headers=settings.is_server,
        forwarded_allow_ips=os.environ.get("BULUTSKAN_TRUSTED_PROXY", "127.0.0.1"),
        server_header=False,
    )


def main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":  # pragma: no cover
    main()

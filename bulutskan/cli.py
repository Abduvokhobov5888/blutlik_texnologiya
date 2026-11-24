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

from enum import StrEnum
from pathlib import Path

import typer

from bulutskan import __version__
from bulutskan.config import RESOURCES, Settings, get_settings
from bulutskan.core.consensus import ConsensusLabel
from bulutskan.core.eol import EOL_WARNING_UZ
from bulutskan.core.gate import GateDecision, UnknownSeverityPolicy, evaluate_gate, parse_fail_on, severity_label
from bulutskan.core.models import SEVERITY_ORDER, ScanKind, Tool
from bulutskan.reporting.json_export import build_export, write_export
from bulutskan.scanner.dbupdate import DB_NAMES, database_status, detect_proxy, mask_proxy, proxy_env, update_databases
from bulutskan.scanner.docker import DockerClient, DockerUnavailable
from bulutskan.scanner.image import ImagePrepareError
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
from bulutskan.services.pipeline import Scanner, ScanOutcome, ScanStatus

EXIT_OK = 0
EXIT_THRESHOLD = 1
EXIT_ERROR = 2

app = typer.Typer(
    name="bulutskan",
    help="BulutSkan: IaC fayllari va konteyner obrazlarini ochiq kodli skanerlar bilan tekshirish.",
    no_args_is_help=True,
    add_completion=False,
)
tools_app = typer.Typer(help="Vositalar: digest tekshiruvi, yuklab olish, Checkov qulfi.", no_args_is_help=True)
app.add_typer(tools_app, name="tools")


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
    if outcome.gt_evaluation is not None:
        typer.echo("\nGround truth bo‘yicha (namoyish fayllari, III bob usuli):")
        for name, ev in outcome.gt_evaluation.tools.items():
            typer.echo(f"  {name:15} {ev.tp}/{ev.gt}  recall={_num(ev.recall)}  precision={_num(ev.precision)}  FP={ev.fp}")
        for pair, info in outcome.gt_evaluation.overlap.items():
            typer.echo(f"  Jaccard {pair}: {_num(info['jaccard'])}")
        if outcome.gt_evaluation.missed_by_all:
            typer.echo("  Hech bir vosita topmagan: " + ", ".join(outcome.gt_evaluation.missed_by_all))


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
        typer.secho(msg + " → KONVEYER TO‘XTATILADI (chiqish kodi 1)", fg=typer.colors.RED, bold=True)
    else:
        _ok(msg + " → o‘tdi (chiqish kodi 0)")


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
    if json_out is not None:
        write_export(json_out, build_export(outcome, policy, gate))
        typer.echo(f"\nJSON: {json_out}")
    if outcome.status == ScanStatus.FAILED:
        _err(outcome.error or "Tekshiruv bajarilmadi: birorta vosita ishlamadi")
        raise typer.Exit(EXIT_ERROR)
    if gate is not None:
        _print_gate(gate)
        raise typer.Exit(gate.exit_code)
    raise typer.Exit(EXIT_OK)


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
        typer.echo(f"{info['label']:22} {present:4}  baza sanasi: {built}  yangilangan: {info.get('updated_at') or '—'}")


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


def main() -> None:  # pragma: no cover
    app()


if __name__ == "__main__":  # pragma: no cover
    main()

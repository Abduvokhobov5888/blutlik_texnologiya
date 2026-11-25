"""Veb-interfeys marshrutlari."""

from __future__ import annotations

import csv
import io
import json
import math
import time
from collections import Counter, defaultdict
from datetime import timedelta
from typing import Any

from fastapi import APIRouter, Depends, File, Form, HTTPException, Request, UploadFile
from fastapi.responses import HTMLResponse, JSONResponse, RedirectResponse, Response
from sqlalchemy import Select, func, or_, select

from bulutskan import __version__
from bulutskan.core.ahp import CRITERIA, CRITERION_CODES, SCENARIOS, apply_multipliers, sensitivity
from bulutskan.core.models import SEVERITY_ORDER, Severity
from bulutskan.reporting.docx_report import build_docx
from bulutskan.reporting.scan_view import CONSENSUS_UZ, STATUS_UZ, export_dict, load_view
from bulutskan.scanner.dbupdate import database_status
from bulutskan.security.upload_guard import (
    UploadLimits,
    UploadRejected,
    accept_plain_file,
    extract_zip,
    save_stream,
    validate_image_tar,
)
from bulutskan.security.passwords import WeakPassword
from bulutskan.security.validators import InvalidImageReference, parse_image_reference
from bulutskan.security.workspace import Workspace
from bulutskan.services import audit, jobs, quota, setup
from bulutskan.services.demo import import_demo
from bulutskan.services.users import UserError, add_user, authenticate, count_users
from bulutskan.storage.repo import scan_by_uid
from bulutskan.storage.tables import ROLE_ADMIN, AuditLog, FindingGroupRow, Scan, User
from bulutskan.web.deps import (
    FirstRunRequired,
    admin_required,
    csrf_protect,
    current_user,
    is_guest,
    is_loopback,
    login_required,
    state,
)
from bulutskan.web.i18n import LANGS, translate
from bulutskan.web.security import client_ip, csrf_token

router = APIRouter()

PAGE_SIZE = 50
SEV_CLASS = {s.value: s.value.lower() for s in SEVERITY_ORDER}


# ----------------------------------------------------------------- yordamchi


def lang_of(request: Request) -> str:
    lang = request.cookies.get("lang") or state(request).settings.lang
    return lang if lang in LANGS else "uz"


def fmt_dt(dt: Any) -> str:
    return (dt + timedelta(hours=5)).strftime("%Y-%m-%d %H:%M") if dt else "—"


def fmt_num(value: Any, digits: int = 3) -> str:
    if value is None or (isinstance(value, float) and math.isnan(value)):
        return "—"
    return f"{float(value):.{digits}f}".replace(".", ",")


def render(request: Request, name: str, ctx: dict[str, Any] | None = None, status: int = 200) -> HTMLResponse:
    st = state(request)
    lang = lang_of(request)
    user = current_user(request)
    base = {
        "request": request,
        "t": lambda text: translate(text, lang),
        "lang": lang,
        "user": user,
        "csrf": csrf_token(request),
        "settings": st.settings,
        "version": __version__,
        "nav": request.url.path,
        "fmt_dt": fmt_dt,
        "fmt_num": fmt_num,
        "short_ref": short_ref,
        "sev_class": SEV_CLASS,
        "status_uz": STATUS_UZ,
        "consensus_uz": CONSENSUS_UZ,
        "severities": [s.value for s in SEVERITY_ORDER],
        "demo_importing": st.extra.get("demo_importing", False),
        "setup_banner": setup_banner(
            setup.get_setting(st.db, "setup_state"), bool(setup.get_setting(st.db, "demo_mode", False))
        ),
    }
    base.update(ctx or {})
    return st.templates.TemplateResponse(request, name, base, status_code=status)


def short_ref(ref: str | None) -> str:
    """Obraz havolasini qisqartiradi: ``aquasec/trivy@sha256:790fd66d1697…``."""
    if not ref:
        return "—"
    name, sep, digest = ref.partition("@")
    if sep and digest.startswith("sha256:") and len(digest) > 19:
        return f"{name}@{digest[:19]}…"
    if ref.startswith("sha256:") and len(ref) > 19:
        return ref[:19] + "…"
    return ref


def setup_banner(setup_state: Any, demo_mode: bool) -> str | None:
    """Sahifa tepasidagi ogohlantirish: ``mismatch``, ``demo`` yoki ``None``.

    Mantiq shablonda emas, shu yerda: Jinja’da ``state.tools.items`` lug‘at
    kaliti emas, ``dict.items`` metodini qaytaradi.
    """
    state_ = setup_state if isinstance(setup_state, dict) else {}
    tools = state_.get("tools") or {}
    items = tools.get("items") or []
    if tools.get("status") == "red" and any(i.get("status") == "mismatch" for i in items if isinstance(i, dict)):
        return "mismatch"
    if demo_mode or (state_.get("docker") or {}).get("status") == "red":
        return "demo"
    return None


def page_user(request: Request) -> User:
    """Sahifa uchun: lokal rejimda administrator hali yo‘q bo‘lsa — birinchi sozlash."""
    st = state(request)
    if not st.settings.is_server:
        with st.db.session() as s:
            if count_users(s) == 0:
                raise FirstRunRequired()
    return login_required(request)


def page_admin(request: Request) -> User:
    """Administrator sahifasi (lokal rejimda avval birinchi sozlash)."""
    page_user(request)
    return admin_required(request)


def visible_scans(user: User) -> Select[Any]:
    q = select(Scan)
    if user.role != ROLE_ADMIN:
        q = q.where(or_(Scan.is_demo.is_(True), Scan.user_id == user.id))
    return q


def get_visible_scan(request: Request, user: User, uid: str) -> Scan:
    st = state(request)
    with st.db.session() as s:
        scan = scan_by_uid(s, uid)
        if scan is None or (user.role != ROLE_ADMIN and not scan.is_demo and scan.user_id != user.id):
            raise HTTPException(status_code=404, detail="Tekshiruv topilmadi")
        return scan


# ------------------------------------------------------------------- tizim


@router.get("/health")
def health(request: Request) -> JSONResponse:
    st = state(request)
    with st.db.session() as s:
        demo = int(s.scalar(select(func.count()).select_from(Scan).where(Scan.is_demo.is_(True))) or 0)
    return JSONResponse({"status": "ok", "version": __version__, "mode": st.settings.mode, "demo_scans": demo,
                         "demo_importing": bool(st.extra.get("demo_importing"))})


@router.post("/lang", dependencies=[Depends(csrf_protect)])
async def set_lang(request: Request, lang: str = Form("uz"), next: str = Form("/")) -> Response:
    target = next if next.startswith("/") and not next.startswith("//") else "/"
    response = RedirectResponse(target, status_code=303)
    if lang in LANGS:
        response.set_cookie("lang", lang, max_age=365 * 86400, samesite="strict", httponly=True,
                            secure=state(request).settings.is_server)
    return response


# ------------------------------------------------------------------- kirish


@router.get("/setup/admin", response_class=HTMLResponse)
def first_admin_form(request: Request) -> Response:
    st = state(request)
    with st.db.session() as s:
        if st.settings.is_server or count_users(s) > 0 or not is_loopback(request):
            raise HTTPException(status_code=404)
    return render(request, "setup_admin.html", {"error": None})


@router.post("/setup/admin", dependencies=[Depends(csrf_protect)])
async def first_admin_create(request: Request, username: str = Form(...), password: str = Form(...),
                             password2: str = Form(...)) -> Response:
    st = state(request)
    if st.settings.is_server or not is_loopback(request):
        raise HTTPException(status_code=404)
    error = None
    if password != password2:
        error = "Parollar mos kelmadi"
    else:
        try:
            with st.db.session() as s:
                if count_users(s) > 0:
                    raise HTTPException(status_code=404)
                user = add_user(s, username, password, ROLE_ADMIN)
                audit.record(s, "user_added", user=user, ip=client_ip(request), target=user.username,
                             detail={"role": ROLE_ADMIN, "first_run": True})
        except (UserError, WeakPassword) as exc:
            error = str(exc)
    if error:
        return render(request, "setup_admin.html", {"error": error}, status=400)
    return RedirectResponse("/login?first=1", status_code=303)


@router.get("/login", response_class=HTMLResponse)
def login_form(request: Request, first: int = 0) -> Response:
    st = state(request)
    if not st.settings.is_server:
        with st.db.session() as s:
            if count_users(s) == 0:
                return RedirectResponse("/setup/admin", status_code=303)
    return render(request, "login.html", {"error": None, "first": bool(first)})


@router.post("/login", dependencies=[Depends(csrf_protect)])
async def login(request: Request, username: str = Form(...), password: str = Form(...)) -> Response:
    st = state(request)
    ip = client_ip(request)
    name = username.strip().lower()[:64]
    if st.login_limiter.blocked(ip, name):
        with st.db.session() as s:
            audit.record(s, "login_locked", username=name, ip=ip, result="denied")
        return render(request, "login.html", {"error": "Urinishlar juda ko‘p. 15 daqiqadan keyin qayta urinib ko‘ring.",
                                              "first": False}, status=429)
    with st.db.session() as s:
        user = authenticate(s, name, password)
        if user is None:
            st.login_limiter.failure(ip, name)
            audit.record(s, "login_failed", username=name, ip=ip, result="denied")
            return render(request, "login.html", {"error": "Login yoki parol noto‘g‘ri", "first": False},
                          status=401)
        st.login_limiter.success(ip, name)
        audit.record(s, "login_ok", user=user, ip=ip)
        request.session.clear()
        request.session.update({"u": user.id, "e": user.session_epoch, "iat": time.time(), "seen": time.time()})
        csrf_token(request)
    return RedirectResponse("/", status_code=303)


@router.post("/logout", dependencies=[Depends(csrf_protect)])
async def logout(request: Request) -> Response:
    user = current_user(request)
    st = state(request)
    if user is not None:
        with st.db.session() as s:
            audit.record(s, "logout", user=user, ip=client_ip(request))
    request.session.clear()
    return RedirectResponse("/login", status_code=303)


# ------------------------------------------------------------------- panel


@router.get("/", response_class=HTMLResponse)
def dashboard(request: Request) -> Response:
    user = page_user(request)
    st = state(request)
    with st.db.session() as s:
        scans: list[Scan] = list(s.scalars(visible_scans(user).order_by(Scan.created_at.desc())))
    done = [sc for sc in scans if sc.status in ("done", "partial")]
    groups_sev: Counter[str] = Counter()
    tools_sev: dict[str, Counter[str]] = defaultdict(Counter)
    confirmed = total_groups = 0
    for sc in done:
        summ = sc.summary or {}
        groups_sev.update(summ.get("groups_by_severity", {}))
        for tool, counts in summ.get("severity_table", {}).items():
            tools_sev[tool].update(counts)
        confirmed += int(summ.get("confirmed", 0))
        total_groups += int(summ.get("groups_total", 0))
    images = sorted((sc for sc in done if sc.kind == "image" and "trivy|grype" in (sc.jaccard or {})),
                    key=lambda sc: sc.target)
    seen: set[str] = set()
    latest_images = []
    for sc in sorted(images, key=lambda sc: sc.created_at, reverse=True):
        if sc.target not in seen:
            seen.add(sc.target)
            latest_images.append(sc)
    latest_images.sort(key=lambda sc: sc.target)
    per_day: Counter[str] = Counter(fmt_dt(sc.created_at)[:10] for sc in scans)
    sev_list = [s.value for s in SEVERITY_ORDER]
    charts = {
        "tools": {"labels": sorted(tools_sev), "severities": sev_list,
                  "data": {sev: [tools_sev[t].get(sev, 0) for t in sorted(tools_sev)] for sev in sev_list}},
        "severity": {"labels": sev_list, "data": [groups_sev.get(sev, 0) for sev in sev_list]},
        "jaccard": {"labels": [sc.target for sc in latest_images],
                    "j": [round(sc.jaccard.get("trivy|grype", 0), 3) for sc in latest_images],
                    "j_core": [round(sc.jaccard_core or 0, 3) for sc in latest_images]},
        "timeline": {"labels": sorted(per_day), "data": [per_day[d] for d in sorted(per_day)]},
    }
    cards = {
        "total": len(scans),
        "demo": sum(1 for sc in scans if sc.is_demo),
        "critical": groups_sev.get("CRITICAL", 0),
        "high": groups_sev.get("HIGH", 0),
        "confirmed_share": (confirmed / total_groups) if total_groups else None,
        "eol": sum(1 for sc in done if (sc.eol or {}).get("is_eol")),
        "active": sum(1 for sc in scans if sc.status in jobs.ACTIVE),
    }
    return render(request, "dashboard.html", {
        "cards": cards, "charts_json": json.dumps(charts, ensure_ascii=False), "recent": scans[:10],
        "dbs": database_status(st.settings),
    })


# ---------------------------------------------------------------- tarix


@router.get("/scans", response_class=HTMLResponse)
def scans_list(request: Request, kind: str = "", source: str = "") -> Response:
    user = page_user(request)
    st = state(request)
    q = visible_scans(user)
    if kind in ("iac", "image"):
        q = q.where(Scan.kind == kind)
    if source == "demo":
        q = q.where(Scan.is_demo.is_(True))
    elif source == "mine":
        q = q.where(Scan.user_id == user.id)
    with st.db.session() as s:
        rows = list(s.scalars(q.order_by(Scan.created_at.desc()).limit(500)))
        owners = {u.id: u.username for u in s.scalars(select(User))}
    return render(request, "scans.html", {"scans": rows, "kind": kind, "source": source, "owners": owners})


@router.get("/scans/{uid}", response_class=HTMLResponse)
def scan_detail(request: Request, uid: str) -> Response:
    user = page_user(request)
    st = state(request)
    get_visible_scan(request, user, uid)
    with st.db.session() as s:
        scan = scan_by_uid(s, uid)
        assert scan is not None
        view = load_view(s, scan, max_groups=1)
        position = jobs.queue_position(s, scan)
    return render(request, "scan_detail.html", {"scan": scan, "view": view, "position": position})


@router.get("/scans/{uid}/status", response_class=HTMLResponse)
def scan_status(request: Request, uid: str) -> Response:
    user = page_user(request)
    scan = get_visible_scan(request, user, uid)
    with state(request).db.session() as s:
        position = jobs.queue_position(s, scan)
    response = render(request, "partials/scan_status.html", {"scan": scan, "position": position})
    if scan.status not in jobs.ACTIVE:
        response.headers["HX-Refresh"] = "true"
    return response


@router.get("/scans/{uid}/groups", response_class=HTMLResponse)
def scan_groups(request: Request, uid: str, consensus: str = "", severity: str = "", cpe: str = "", q: str = "",
                page: int = 1) -> Response:
    user = page_user(request)
    scan = get_visible_scan(request, user, uid)
    stmt = select(FindingGroupRow).where(FindingGroupRow.scan_id == scan.id)
    if consensus in ("confirmed", "needs_review"):
        stmt = stmt.where(FindingGroupRow.consensus == consensus)
    if severity in SEV_CLASS:
        stmt = stmt.where(FindingGroupRow.severity_rank >= Severity(severity).rank)
    if cpe == "1":
        stmt = stmt.where(FindingGroupRow.cpe_suspect.is_(True))
    if q.strip():
        like = f"%{q.strip()[:100]}%"
        stmt = stmt.where(or_(FindingGroupRow.key.ilike(like), FindingGroupRow.title.ilike(like)))
    page = max(1, page)
    with state(request).db.session() as s:
        total = int(s.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
        rows = list(s.scalars(stmt.order_by(FindingGroupRow.severity_rank.desc(), FindingGroupRow.tool_count.desc(),
                                            FindingGroupRow.key).offset((page - 1) * PAGE_SIZE).limit(PAGE_SIZE)))
    pages = max(1, math.ceil(total / PAGE_SIZE))
    return render(request, "partials/groups.html", {
        "scan": scan, "groups": rows, "total": total, "page": page, "pages": pages,
        "filters": {"consensus": consensus, "severity": severity, "cpe": cpe, "q": q},
    })


@router.get("/scans/{uid}/export.json")
def scan_export(request: Request, uid: str) -> Response:
    user = page_user(request)
    st = state(request)
    get_visible_scan(request, user, uid)
    with st.db.session() as s:
        scan = scan_by_uid(s, uid)
        assert scan is not None
        data = export_dict(s, scan, lang=lang_of(request))
        audit.record(s, "export_downloaded", user=user, ip=client_ip(request), target=scan.target,
                     detail={"uid": uid, "format": "json"})
    body = json.dumps(data, ensure_ascii=False, indent=2)
    return Response(body, media_type="application/json; charset=utf-8",
                    headers={"Content-Disposition": f'attachment; filename="bulutskan_{uid[:8]}.json"'})


@router.get("/scans/{uid}/report.docx")
def scan_report(request: Request, uid: str) -> Response:
    user = page_user(request)
    st = state(request)
    get_visible_scan(request, user, uid)
    with st.db.session() as s:
        scan = scan_by_uid(s, uid)
        assert scan is not None
        data = build_docx(load_view(s, scan))
        audit.record(s, "export_downloaded", user=user, ip=client_ip(request), target=scan.target,
                     detail={"uid": uid, "format": "docx"})
    return Response(data, media_type="application/vnd.openxmlformats-officedocument.wordprocessingml.document",
                    headers={"Content-Disposition": f'attachment; filename="bulutskan_{uid[:8]}.docx"'})


# ----------------------------------------------------------- yangi tekshiruv


def _limits(request: Request) -> UploadLimits:
    s = state(request).settings
    return UploadLimits(max_upload_bytes=s.max_upload_bytes, max_unzipped_bytes=s.max_unzipped_bytes,
                        max_entries=s.max_zip_entries, max_file_bytes=s.max_file_bytes)


def _quota_ctx(request: Request, user: User) -> dict[str, Any]:
    st = state(request)
    with st.db.session() as s:
        return {"remaining": quota.remaining_today(s, user, st.settings), "guest": is_guest(user),
                "demo_images": st.demo_images}


@router.get("/scan/iac", response_class=HTMLResponse)
def iac_form(request: Request) -> Response:
    user = page_user(request)
    return render(request, "scan_iac.html", {"error": None, **_quota_ctx(request, user)})


@router.post("/scan/iac", dependencies=[Depends(csrf_protect)])
async def iac_submit(request: Request, files: list[UploadFile] = File(default=[]), demo: str = Form("")) -> Response:
    user = page_user(request)
    st = state(request)
    use_demo = demo == "1" or is_guest(user)
    uploads = [f for f in files if f.filename]
    if not use_demo and not uploads:
        return render(request, "scan_iac.html", {"error": "Fayl tanlang yoki namoyish fayllarini belgilang",
                                                 **_quota_ctx(request, user)}, status=400)
    try:
        with st.db.session() as s:
            quota.check_can_submit(s, user, st.settings)
    except quota.QuotaExceeded as exc:
        with st.db.session() as s:
            audit.record(s, "quota_exceeded", user=user, ip=client_ip(request), result="denied", detail={"msg": str(exc)})
        return render(request, "scan_iac.html", {"error": str(exc), **_quota_ctx(request, user)}, status=429)
    ws = Workspace(st.settings.workdir).create()
    request_data: dict[str, Any]
    try:
        if use_demo:
            request_data, target = {"demo": True}, "Namoyish IaC fayllari"
        else:
            limits = _limits(request)
            accepted: list[str] = []
            skipped: list[str] = []
            for up in uploads:
                name = up.filename or ""
                if name.lower().endswith(".zip"):
                    tmp = ws.path / "upload.zip"
                    save_stream(up.file, tmp, limits.max_upload_bytes)
                    res = extract_zip(tmp, ws.input, limits)
                    tmp.unlink()
                    accepted += res.files
                    skipped += res.skipped
                else:
                    accepted.append(accept_plain_file(up.file, name, ws.input, limits))
            if not accepted:
                raise UploadRejected("empty", "Ruxsat etilgan IaC fayli topilmadi (Terraform, Kubernetes YAML, Dockerfile)")
            request_data = {"files": accepted, "skipped": skipped}
            target = ", ".join(accepted[:3]) + (f" (+{len(accepted) - 3})" if len(accepted) > 3 else "")
    except UploadRejected as exc:
        ws.cleanup()
        return render(request, "scan_iac.html", {"error": exc.message, **_quota_ctx(request, user)}, status=400)
    with st.db.session() as s:
        db_user = s.get(User, user.id)
        jobs.enqueue(s, uid=ws.uid, kind="iac", target=target, request=request_data, user=db_user)
        audit.record(s, "scan_submitted", user=user, ip=client_ip(request), target=target,
                     detail={"uid": ws.uid, "kind": "iac"})
    return RedirectResponse(f"/scans/{ws.uid}", status_code=303)


@router.get("/scan/image", response_class=HTMLResponse)
def image_form(request: Request) -> Response:
    user = page_user(request)
    return render(request, "scan_image.html", {"error": None, **_quota_ctx(request, user)})


@router.post("/scan/image", dependencies=[Depends(csrf_protect)])
async def image_submit(request: Request, image: str = Form(""), tar: UploadFile | None = File(default=None),
                       image_name: str = Form("")) -> Response:
    user = page_user(request)
    st = state(request)
    ctx = _quota_ctx(request, user)
    has_tar = tar is not None and bool(tar.filename)
    image = image.strip()
    try:
        if is_guest(user):
            if has_tar or image not in st.demo_images:
                raise UploadRejected("guest", "Mehmon faqat eksperimentdagi obrazlardan birini tanlay oladi")
        if not has_tar:
            ref = parse_image_reference(image)
            if not quota.registry_allowed(ref, st.settings):
                raise UploadRejected("registry", "Bu registr ruxsat etilmagan (faqat ochiq registrlar)")
        name = parse_image_reference(image_name.strip()).raw if image_name.strip() else None
    except (InvalidImageReference, UploadRejected) as exc:
        msg = exc.message if isinstance(exc, UploadRejected) else str(exc)
        return render(request, "scan_image.html", {"error": msg, **ctx}, status=400)
    try:
        with st.db.session() as s:
            quota.check_can_submit(s, user, st.settings)
    except quota.QuotaExceeded as exc:
        return render(request, "scan_image.html", {"error": str(exc), **ctx}, status=429)
    ws = Workspace(st.settings.workdir).create()
    if has_tar:
        assert tar is not None
        try:
            save_stream(tar.file, ws.input / "image.tar", st.settings.max_image_tar_bytes)
            validate_image_tar(ws.input / "image.tar", st.settings.max_image_tar_bytes)
        except UploadRejected as exc:
            ws.cleanup()
            return render(request, "scan_image.html", {"error": exc.message, **ctx}, status=400)
        request_data: dict[str, Any] = {"tar": "image.tar", "image_name": name}
        target = name or (tar.filename or "image.tar")
    else:
        request_data, target = {"image": image}, image
    with st.db.session() as s:
        db_user = s.get(User, user.id)
        jobs.enqueue(s, uid=ws.uid, kind="image", target=target, request=request_data, user=db_user)
        audit.record(s, "scan_submitted", user=user, ip=client_ip(request), target=target,
                     detail={"uid": ws.uid, "kind": "image"})
    return RedirectResponse(f"/scans/{ws.uid}", status_code=303)


# ---------------------------------------------------------------- solishtirish


@router.get("/compare", response_class=HTMLResponse)
def compare(request: Request, a: str = "", b: str = "") -> Response:
    user = page_user(request)
    st = state(request)
    with st.db.session() as s:
        options = list(s.scalars(visible_scans(user).where(Scan.status.in_(("done", "partial")))
                                 .order_by(Scan.created_at.desc()).limit(300)))
    result = None
    if a and b:
        sa, sb = get_visible_scan(request, user, a), get_visible_scan(request, user, b)
        with st.db.session() as s:
            ga = {g.key: g for g in s.scalars(select(FindingGroupRow).where(FindingGroupRow.scan_id == sa.id))}
            gb = {g.key: g for g in s.scalars(select(FindingGroupRow).where(FindingGroupRow.scan_id == sb.id))}
        ka, kb = set(ga), set(gb)
        union = ka | kb

        def top(keys: set[str], src: dict[str, FindingGroupRow]) -> list[FindingGroupRow]:
            return sorted((src[k] for k in keys), key=lambda g: (-g.severity_rank, g.key))[:200]

        result = {
            "a": sa, "b": sb, "same_kind": sa.kind == sb.kind,
            "new": top(kb - ka, gb), "fixed": top(ka - kb, ga), "common": len(ka & kb),
            "jaccard": (len(ka & kb) / len(union)) if union else None,
            "count_a": len(ka), "count_b": len(kb),
        }
    return render(request, "compare.html", {"options": options, "a": a, "b": b, "result": result})


# ------------------------------------------------------------------- AHP


def _ahp_result(request: Request, weights: list[float]) -> dict[str, Any]:
    model = state(request).ahp
    norm = apply_multipliers(weights, [1.0] * len(CRITERIA))
    ranked = model.rank(norm)
    return {
        "weights": norm,
        "ranked": ranked,
        "chart_json": json.dumps({"labels": [r.tool for r in ranked], "data": [round(r.score, 3) for r in ranked]},
                                 ensure_ascii=False),
    }


@router.get("/ahp", response_class=HTMLResponse)
def ahp_page(request: Request, scenario: str = "bazaviy") -> Response:
    page_user(request)
    model = state(request).ahp
    key = scenario if scenario in SCENARIOS else "bazaviy"
    weights = list(model.weights_for(key))
    consistency = model.consistency()
    return render(request, "ahp.html", {
        "criteria": CRITERIA, "codes": CRITERION_CODES, "scenarios": SCENARIOS, "scenario": key,
        "scores": model.scores, "consistency": consistency, "sens": sensitivity(model),
        **_ahp_result(request, weights),
    })


@router.post("/ahp/calc", response_class=HTMLResponse, dependencies=[Depends(csrf_protect)])
async def ahp_calc(request: Request) -> Response:
    page_user(request)
    form = await request.form()
    weights = []
    for code in CRITERION_CODES:
        try:
            value = float(str(form.get(f"w_{code}", "0")).replace(",", "."))
        except ValueError:
            value = 0.0
        weights.append(min(max(value, 0.0), 1.0))
    if sum(weights) <= 0:
        weights = [1.0] * len(CRITERIA)
    return render(request, "partials/ahp_result.html", _ahp_result(request, weights))


# ----------------------------------------------------- vositalar va sozlash


def _setup_ctx(st: Any) -> dict[str, Any]:
    """Sozlash ustasi shablonlari uchun: oxirgi holat va oxirgi vazifa."""
    return {"setup_state": setup.get_setting(st.db, "setup_state"), "task": setup.latest_task(st.db)}


@router.get("/tools", response_class=HTMLResponse)
def tools_page(request: Request) -> Response:
    page_admin(request)
    st = state(request)
    return render(request, "tools.html", {**_setup_ctx(st), "dbs": database_status(st.settings)})


@router.get("/tools/status", response_class=HTMLResponse)
def tools_status(request: Request) -> Response:
    admin_required(request)
    st = state(request)
    return render(request, "partials/setup_steps.html", _setup_ctx(st))


@router.post("/tools/run", response_class=HTMLResponse, dependencies=[Depends(csrf_protect)])
async def tools_run(request: Request, action: str = Form(...)) -> Response:
    user = admin_required(request)
    st = state(request)
    if action not in setup.ACTIONS:
        raise HTTPException(status_code=400, detail="Noma’lum amal")
    setup.enqueue_task(st.db, action, user.id)
    with st.db.session() as s:
        audit.record(s, f"setup_{action}", user=user, ip=client_ip(request))
    return render(request, "partials/setup_steps.html", _setup_ctx(st))


@router.post("/tools/demo-mode", dependencies=[Depends(csrf_protect)])
async def tools_demo_mode(request: Request) -> Response:
    user = admin_required(request)
    st = state(request)
    import_demo(st.db)
    with st.db.session() as s:
        setup.save_setting(s, "demo_mode", True)
        audit.record(s, "demo_mode_enabled", user=user, ip=client_ip(request))
    return RedirectResponse("/", status_code=303)


@router.get("/help/docker", response_class=HTMLResponse)
def help_docker(request: Request) -> Response:
    page_user(request)
    return render(request, "help_docker.html")


# ----------------------------------------------------------- administrator


@router.get("/admin/audit", response_class=HTMLResponse)
def admin_audit(request: Request, action: str = "", username: str = "", page: int = 1) -> Response:
    page_admin(request)
    st = state(request)
    stmt = select(AuditLog)
    if action:
        stmt = stmt.where(AuditLog.action == action[:32])
    if username:
        stmt = stmt.where(AuditLog.username == username[:64])
    page = max(1, page)
    with st.db.session() as s:
        total = int(s.scalar(select(func.count()).select_from(stmt.subquery())) or 0)
        rows = list(s.scalars(stmt.order_by(AuditLog.id.desc()).offset((page - 1) * 100).limit(100)))
        actions = sorted(set(s.scalars(select(AuditLog.action).distinct())))
    return render(request, "admin_audit.html", {"rows": rows, "total": total, "page": page,
                                                "pages": max(1, math.ceil(total / 100)), "actions": actions,
                                                "f_action": action, "f_user": username})


_CSV_FORMULA = ("=", "+", "-", "@", "\t", "\r")


def csv_cell(value: Any) -> str:
    """Excel formula in’ektsiyasidan himoya: ``=``, ``+``, ``-``, ``@`` bilan boshlansa ``'`` qo‘shiladi."""
    text = "" if value is None else str(value)
    return "'" + text if text.startswith(_CSV_FORMULA) else text


@router.get("/admin/audit.csv")
def admin_audit_csv(request: Request) -> Response:
    admin_required(request)
    st = state(request)
    buf = io.StringIO()
    writer = csv.writer(buf, delimiter=";")
    writer.writerow(["vaqt_utc", "foydalanuvchi", "rol", "ip", "amal", "obyekt", "natija", "tafsilot"])
    with st.db.session() as s:
        for r in s.scalars(select(AuditLog).order_by(AuditLog.id)):
            writer.writerow([csv_cell(v) for v in (r.ts.isoformat(timespec="seconds"), r.username, r.role, r.ip,
                                                    r.action, r.target, r.result,
                                                    json.dumps(r.detail, ensure_ascii=False))])
    return Response("﻿" + buf.getvalue(), media_type="text/csv; charset=utf-8",
                    headers={"Content-Disposition": 'attachment; filename="bulutskan_audit.csv"'})


@router.get("/admin/users", response_class=HTMLResponse)
def admin_users(request: Request) -> Response:
    page_admin(request)
    with state(request).db.session() as s:
        users = list(s.scalars(select(User).order_by(User.username)))
    return render(request, "admin_users.html", {"users": users})

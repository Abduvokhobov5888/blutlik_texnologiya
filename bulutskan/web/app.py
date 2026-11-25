"""FastAPI ilovasi fabrikasi."""

from __future__ import annotations

import logging
import os
import secrets
import threading
from collections.abc import AsyncIterator
from contextlib import asynccontextmanager
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.responses import HTMLResponse, RedirectResponse, Response
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.exceptions import HTTPException as StarletteHTTPException
from starlette.middleware.sessions import SessionMiddleware

from bulutskan import __version__
from bulutskan.config import Settings, demo_root, get_settings
from bulutskan.core.ahp import load_dissertation_model
from bulutskan.services.demo import demo_available, demo_images, demo_scan_count, import_demo
from bulutskan.services.users import bootstrap_admin
from bulutskan.storage.db import Database
from bulutskan.web.deps import AppState, FirstRunRequired, LoginRequired
from bulutskan.web.i18n import LANGS, translate
from bulutskan.web.security import LoginLimiter, RateLimitMiddleware, SecurityHeadersMiddleware

log = logging.getLogger(__name__)

WEB_DIR = Path(__file__).resolve().parent
EXAMPLE_SECRET = "almashtiring-bu-faqat-namuna"
#: Server rejimida web konteynerida ko‘rinmasligi kerak bo‘lgan soketlar.
DOCKER_SOCKETS: tuple[str, ...] = ("/var/run/docker.sock", "/run/docker.sock")


def resolve_secret(settings: Settings) -> str:
    """Sessiya kaliti.

    Server rejimida faqat ``.env`` dan (kamida 32 bayt, namuna emas), aks holda
    ilova ishga tushmaydi. Lokal rejimda berilmagan bo‘lsa, ``data/secret_key``
    ga tasodifiy kalit yaratiladi (repozitoriyga tushmaydi).
    """
    value = settings.secret_key.get_secret_value() if settings.secret_key else ""
    if settings.is_server:
        if len(value.encode()) < 32 or value == EXAMPLE_SECRET:
            raise RuntimeError("Server rejimi: BULUTSKAN_SECRET_KEY kamida 32 bayt bo‘lishi va namunaga teng bo‘lmasligi kerak")
        return value
    if value and value != EXAMPLE_SECRET:
        return value
    path = settings.data_path / "secret_key"
    if path.is_file():
        stored = path.read_text(encoding="utf-8").strip()
        if len(stored) >= 32:
            return stored
    path.parent.mkdir(parents=True, exist_ok=True)
    key = secrets.token_urlsafe(48)
    path.write_text(key, encoding="utf-8")
    try:
        os.chmod(path, 0o600)
    except OSError:
        pass
    return key


def check_server_mode(settings: Settings) -> None:
    """Server rejimi xavfli sozlama bilan ishga tushmasin."""
    if not settings.is_server:
        return
    if not (settings.public_url or "").startswith("https://"):
        raise RuntimeError("Server rejimi: BULUTSKAN_PUBLIC_URL https:// bilan boshlanishi kerak")
    for sock in DOCKER_SOCKETS:
        if Path(sock).exists():
            raise RuntimeError("Server rejimi: web konteynerida docker.sock ko‘rinmasligi kerak")


def create_app(
    settings: Settings | None = None,
    *,
    start_worker: bool | None = None,
    auto_demo: bool = True,
) -> FastAPI:
    """Ilova. Lokal rejimda ichki worker oqimi ishga tushadi (``start_worker``)."""
    settings = settings or get_settings()
    check_server_mode(settings)
    db = Database(settings.db_path)
    db.init_schema()
    templates = Jinja2Templates(directory=str(WEB_DIR / "templates"))
    run_worker = (not settings.is_server) if start_worker is None else start_worker
    try:
        images = demo_images(demo_root()) if demo_available() else []
    except (OSError, ValueError):
        images = []
    app_state = AppState(
        settings=settings,
        db=db,
        templates=templates,
        login_limiter=LoginLimiter(settings.login_attempts, settings.login_window_min),
        ahp=load_dissertation_model(),
        demo_images=images,
    )

    @asynccontextmanager
    async def lifespan(app: FastAPI) -> AsyncIterator[None]:
        stop = threading.Event()
        if settings.is_server:
            admin_pw = settings.admin_password.get_secret_value() if settings.admin_password else None
            with db.session() as s:
                bootstrap_admin(s, settings.admin_username, admin_pw)
        app_state.extra["demo_importing"] = False
        if auto_demo and demo_available() and demo_scan_count(db) == 0:
            def _import() -> None:
                app_state.extra["demo_importing"] = True
                try:
                    import_demo(db)
                except Exception:  # noqa: BLE001
                    log.exception("Namoyish ma’lumotlarini import qilib bo‘lmadi")
                finally:
                    app_state.extra["demo_importing"] = False

            threading.Thread(target=_import, name="bulutskan-demo-import", daemon=True).start()
        worker_thread = None
        if run_worker:
            from bulutskan.scanner.docker import DockerClient
            from bulutskan.worker import Worker

            worker = Worker(settings, db, client_factory=lambda: DockerClient(docker_bin=settings.docker_bin))
            worker_thread = threading.Thread(target=worker.run_forever, args=(stop,), name="bulutskan-worker",
                                             daemon=True)
            worker_thread.start()
        yield
        stop.set()
        if worker_thread is not None:
            worker_thread.join(timeout=10)
        db.dispose()

    app = FastAPI(title="BulutSkan", version=__version__, lifespan=lifespan, docs_url=None, redoc_url=None,
                  openapi_url=None)
    app.state.bulutskan = app_state

    app.add_middleware(
        SessionMiddleware,
        secret_key=resolve_secret(settings),
        session_cookie="bulutskan_session",
        max_age=settings.session_hours * 3600,
        same_site="strict",
        https_only=settings.is_server,
    )
    app.add_middleware(RateLimitMiddleware, limit_per_min=settings.rate_limit_per_min)
    app.add_middleware(SecurityHeadersMiddleware, hsts=settings.is_server)
    app.mount("/static", StaticFiles(directory=str(WEB_DIR / "static")), name="static")

    from bulutskan.web.routes import router

    app.include_router(router)

    @app.exception_handler(LoginRequired)
    async def _login(request: Request, _exc: LoginRequired) -> Response:
        target = "/login"
        if request.headers.get("HX-Request"):
            return Response(status_code=204, headers={"HX-Redirect": target})
        return RedirectResponse(target, status_code=303)

    @app.exception_handler(FirstRunRequired)
    async def _first(request: Request, _exc: FirstRunRequired) -> Response:
        return RedirectResponse("/setup/admin", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def _http(request: Request, exc: StarletteHTTPException) -> Response:
        lang = request.cookies.get("lang", settings.lang)
        lang = lang if lang in LANGS else "uz"
        detail = exc.detail if isinstance(exc.detail, str) else ""
        if exc.status_code == 404 and not detail:
            detail = "Sahifa topilmadi"
        html = templates.get_template("error.html").render(
            request=request, t=lambda x: translate(x, lang), lang=lang, code=exc.status_code, detail=detail,
            user=None, version=__version__, settings=settings, csrf="", nav="",
        )
        return HTMLResponse(html, status_code=exc.status_code)

    return app

"""HTTP xavfsizligi: sarlavhalar, tezlik cheklovi, kirish urinishlari, CSRF."""

from __future__ import annotations

import hmac
import secrets
import threading
import time
from collections import deque
from collections.abc import Awaitable, Callable

from starlette.middleware.base import BaseHTTPMiddleware
from starlette.requests import Request
from starlette.responses import PlainTextResponse, Response

CSP = (
    "default-src 'self'; script-src 'self'; style-src 'self'; img-src 'self' data:; font-src 'self'; "
    "connect-src 'self'; object-src 'none'; base-uri 'self'; form-action 'self'; frame-ancestors 'none'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    """CSP, HSTS (server rejimida), X-Frame-Options va boshqa sarlavhalar."""

    def __init__(self, app: object, hsts: bool) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.hsts = hsts

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        response = await call_next(request)
        h = response.headers
        h["Content-Security-Policy"] = CSP
        h["X-Frame-Options"] = "DENY"
        h["X-Content-Type-Options"] = "nosniff"
        h["Referrer-Policy"] = "no-referrer"
        h["Permissions-Policy"] = "camera=(), microphone=(), geolocation=()"
        h["Cross-Origin-Opener-Policy"] = "same-origin"
        if self.hsts:
            h["Strict-Transport-Security"] = "max-age=31536000; includeSubDomains"
        if not request.url.path.startswith("/static/"):
            h["Cache-Control"] = "no-store"
        if "server" in h:
            del h["server"]
        return response


class SlidingWindow:
    """Oddiy sirpanuvchi oyna: kalit bo‘yicha ``limit`` ta hodisa ``window`` soniyada."""

    def __init__(self, limit: int, window_s: float) -> None:
        self.limit, self.window = limit, window_s
        self._events: dict[str, deque[float]] = {}
        self._lock = threading.Lock()

    def _trim(self, key: str, now: float) -> deque[float]:
        q = self._events.setdefault(key, deque())
        while q and now - q[0] > self.window:
            q.popleft()
        return q

    def hit(self, key: str) -> bool:
        """Hodisani qayd etadi; limit oshgan bo‘lsa ``False``."""
        now = time.monotonic()
        with self._lock:
            q = self._trim(key, now)
            if len(q) >= self.limit:
                return False
            q.append(now)
            return True

    def count(self, key: str) -> int:
        with self._lock:
            return len(self._trim(key, time.monotonic()))

    def reset(self, key: str) -> None:
        with self._lock:
            self._events.pop(key, None)


class RateLimitMiddleware(BaseHTTPMiddleware):
    """IP bo‘yicha daqiqasiga ``limit`` ta so‘rov (statik fayllar va /health bundan mustasno)."""

    def __init__(self, app: object, limit_per_min: int) -> None:
        super().__init__(app)  # type: ignore[arg-type]
        self.window = SlidingWindow(limit_per_min, 60)

    async def dispatch(self, request: Request, call_next: Callable[[Request], Awaitable[Response]]) -> Response:
        path = request.url.path
        if path.startswith("/static/") or path == "/health":
            return await call_next(request)
        ip = client_ip(request)
        if not self.window.hit(ip):
            return PlainTextResponse("So‘rovlar juda ko‘p. Bir daqiqadan keyin qayta urinib ko‘ring.", status_code=429,
                                     headers={"Retry-After": "60"})
        return await call_next(request)


class LoginLimiter:
    """Login va IP bo‘yicha muvaffaqiyatsiz urinishlar; limit oshsa vaqtincha blok."""

    def __init__(self, attempts: int, window_min: int) -> None:
        self.by_user = SlidingWindow(attempts, window_min * 60)
        self.by_ip = SlidingWindow(attempts * 4, window_min * 60)

    def blocked(self, ip: str, username: str) -> bool:
        key = f"{ip}|{username.lower()}"
        return self.by_user.count(key) >= self.by_user.limit or self.by_ip.count(ip) >= self.by_ip.limit

    def failure(self, ip: str, username: str) -> None:
        self.by_user.hit(f"{ip}|{username.lower()}")
        self.by_ip.hit(ip)

    def success(self, ip: str, username: str) -> None:
        self.by_user.reset(f"{ip}|{username.lower()}")


def client_ip(request: Request) -> str:
    """Mijoz IP si (server rejimida uvicorn ``--proxy-headers`` faqat Caddy’ga ishonadi)."""
    return request.client.host if request.client else "?"


def csrf_token(request: Request) -> str:
    """Sessiyaga bog‘langan CSRF token (bo‘lmasa yaratiladi)."""
    token = request.session.get("csrf")
    if not isinstance(token, str) or len(token) < 32:
        token = secrets.token_urlsafe(32)
        request.session["csrf"] = token
    return token


def csrf_valid(request: Request, submitted: str | None) -> bool:
    expected = request.session.get("csrf")
    if not isinstance(expected, str) or not submitted:
        return False
    return hmac.compare_digest(expected, submitted)

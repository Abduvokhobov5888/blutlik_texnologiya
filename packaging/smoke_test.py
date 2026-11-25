"""O‘rnatilgan BulutSkan’ni HTTP orqali tekshirish (Docker talab qilinmaydi).

Faqat standart kutubxona: o‘rnatilgan dastur Python’ga bog‘liq emas, bu skript
esa tekshiruvchi kompyuterdagi Python bilan ishlaydi.

    python packaging/smoke_test.py --url http://127.0.0.1:8765/ --user smoke --password-env SMOKE_PASSWORD

Tekshiriladi: /health; III bob namoyish ma’lumotlari (16 ta tekshiruv);
kirish va CSRF; boshqaruv paneli; nginx:1.21 sahifasi (EOL, Jaccard 0,729);
IaC ground truth (36/40, 34/40, 32/40); AHP (Checkov, Trivy, Grype; CR 0,0053);
JSON va DOCX eksport; xavfsizlik sarlavhalari; sozlash ustasi sahifasi.
"""

from __future__ import annotations

import argparse
import html
import http.cookiejar
import json
import os
import re
import sys
import time
import urllib.error
import urllib.parse
import urllib.request
import zipfile
from io import BytesIO
from typing import Any


class Client:
    def __init__(self, base: str) -> None:
        self.base = base.rstrip("/") + "/"
        self.jar = http.cookiejar.CookieJar()
        self.opener = urllib.request.build_opener(urllib.request.HTTPCookieProcessor(self.jar), _NoRedirect())

    def request(self, path: str, data: dict[str, str] | None = None) -> tuple[int, dict[str, str], bytes]:
        body = urllib.parse.urlencode(data).encode() if data is not None else None
        req = urllib.request.Request(urllib.parse.urljoin(self.base, path.lstrip("/")), data=body)
        try:
            with self.opener.open(req, timeout=60) as resp:
                return resp.status, dict(resp.headers.items()), resp.read()
        except urllib.error.HTTPError as exc:
            return exc.code, dict(exc.headers.items()), exc.read()

    def get(self, path: str) -> tuple[int, dict[str, str], str]:
        code, headers, body = self.request(path)
        return code, headers, body.decode("utf-8", "replace")

    def csrf(self, path: str) -> str:
        _, _, text = self.get(path)
        m = re.search(r'name="csrf_token" value="([^"]+)"', text)
        if not m:
            raise AssertionError(f"{path}: CSRF token topilmadi")
        return m.group(1)


class _NoRedirect(urllib.request.HTTPRedirectHandler):
    def redirect_request(self, *args: Any, **kwargs: Any) -> None:
        return None


def check(cond: bool, message: str) -> None:
    if not cond:
        raise AssertionError(message)
    print(f"  ok  {message}")


def wait_health(c: Client, timeout_s: float) -> dict[str, Any]:
    deadline = time.monotonic() + timeout_s
    last: Any = None
    while time.monotonic() < deadline:
        try:
            code, _, text = c.get("/health")
            if code == 200:
                data = json.loads(text)
                last = data
                if data.get("demo_scans", 0) >= 16 and not data.get("demo_importing"):
                    return dict(data)
        except OSError as exc:
            last = exc
        time.sleep(1)
    raise AssertionError(f"/health {timeout_s:.0f} soniyada tayyor bo‘lmadi: {last}")


def main() -> int:
    ap = argparse.ArgumentParser()
    ap.add_argument("--url", default="http://127.0.0.1:8765/")
    ap.add_argument("--user", default="smoke")
    ap.add_argument("--password-env", default="SMOKE_PASSWORD")
    ap.add_argument("--timeout", type=float, default=180)
    args = ap.parse_args()
    password = os.environ[args.password_env]
    c = Client(args.url)

    print("1. /health va namoyish ma’lumotlari")
    health = wait_health(c, args.timeout)
    check(health["status"] == "ok" and health["mode"] == "local", f"/health 200: {health}")
    check(health["demo_scans"] == 16, "III bob: 16 ta namoyish tekshiruvi (15 obraz + IaC)")

    print("2. Kirish va xavfsizlik")
    code, headers, _ = c.get("/")
    check(code == 303 and headers.get("location") == "/login", "kirmagan foydalanuvchi /login ga yo‘naltiriladi")
    code, _, _ = c.request("/login", {"username": args.user, "password": password})
    check(code == 403, "CSRF tokensiz POST rad etiladi (403)")
    code, headers, _ = c.request("/login", {"username": args.user, "password": password,
                                            "csrf_token": c.csrf("/login")})
    check(code == 303, f"kirish muvaffaqiyatli ({headers.get('location')})")
    cookie = headers.get("set-cookie", "").lower()
    check("httponly" in cookie and "samesite=strict" in cookie, "sessiya cookie: HttpOnly, SameSite=Strict")
    code, headers, text = c.get("/")
    check(code == 200 and "Boshqaruv paneli" in text, "boshqaruv paneli ochildi")
    csp = headers.get("content-security-policy", "")
    check("default-src 'self'" in csp and "unsafe-inline" not in csp, "CSP: default-src 'self', inline yo‘q")
    check(headers.get("x-frame-options") == "DENY", "X-Frame-Options: DENY")
    check('id="dashboard-data"' in text, "diagrammalar ma’lumoti sahifada")

    print("3. Namoyish natijalari (III bob)")
    code, _, text = c.get("/scans?source=demo")
    uids = dict((html.unescape(t), u) for u, t in re.findall(r'href="/scans/([0-9a-f]{32})">([^<]+)</a>', text))
    check(len(uids) == 16, f"tarixda 16 ta namoyish tekshiruvi ({len(uids)})")
    code, _, text = c.get(f"/scans/{uids['nginx:1.21']}")
    check(code == 200 and "qo‘llab-quvvatlash muddati tugagan" in text, "nginx:1.21: EOL ogohlantirishi")
    check("0,729" in text, "nginx:1.21: Jaccard 0,729")
    iac_uid = next(u for t, u in uids.items() if "IaC" in t)
    code, _, text = c.get(f"/scans/{iac_uid}")
    check(all(x in text for x in ("36/40", "34/40", "32/40")), "IaC ground truth: Checkov 36, KICS 34, Trivy 32")

    print("4. AHP")
    code, _, text = c.get("/ahp")
    check(code == 200 and "CR = 0,0053" in text, "AHP: CR = 0,0053")
    order = re.findall(r"<td>\d+</td><td>([^<]+)</td>", text)
    check(order[:3] == ["Checkov", "Trivy", "Grype"], f"AHP reytingi: {order[:3]}")
    weights = {"w_K1": "1", "w_K2": "0", "w_K3": "0", "w_K4": "0", "w_K5": "0", "w_K6": "0", "w_K7": "0"}
    code, _, body = c.request("/ahp/calc", {**weights, "csrf_token": c.csrf("/ahp")})
    order = re.findall(r"<td>\d+</td><td>([^<]+)</td>", body.decode("utf-8"))
    check(code == 200 and order[0] in ("Wiz", "Cortex Cloud"), f"vaznlar o‘zgarsa reyting qayta hisoblanadi: {order[0]}")

    print("5. Hisobotlar")
    code, headers, body = c.request(f"/scans/{uids['nginx:1.21']}/export.json")
    data = json.loads(body.decode("utf-8"))
    check(code == 200 and data["scan"]["target"] == "nginx:1.21" and data["eol"]["is_eol"], "JSON eksport")
    code, headers, body = c.request(f"/scans/{iac_uid}/report.docx")
    with zipfile.ZipFile(BytesIO(body)) as zf:
        document = zf.read("word/document.xml").decode("utf-8")
    check(code == 200 and "Ground truth" in document and "36/40" in document, f"DOCX hisobot ({len(body)} bayt)")

    print("6. Sozlash ustasi")
    code, _, text = c.get("/tools")
    check(code == 200 and "Docker" in text, "vositalar va bazalar sahifasi ochildi")
    code, _, text = c.get("/help/docker")
    check(code == 200, "Docker o‘rnatish ko‘rsatmasi")

    print("Hammasi joyida.")
    return 0


if __name__ == "__main__":
    sys.exit(main())

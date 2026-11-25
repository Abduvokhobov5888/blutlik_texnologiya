"""Veb-interfeys: kirish, CSRF, rollar, sarlavhalar, kvota, namoyish, i18n, sozlash ustasi."""

from __future__ import annotations

import io
import json
import re
import zipfile
from collections.abc import Iterator
from pathlib import Path
from typing import Any

import pytest
from fastapi.testclient import TestClient
from sqlalchemy import select

from bulutskan.config import Settings
from bulutskan.scanner.docker import DockerClient
from bulutskan.services import setup
from bulutskan.services.demo import import_demo
from bulutskan.services.users import add_user, get_user, set_password
from bulutskan.storage.db import Database
from bulutskan.storage.tables import AuditLog, Scan
from bulutskan.web import app as web_app
from bulutskan.web.app import create_app, resolve_secret
from bulutskan.web.routes import csv_cell, setup_banner, short_ref
from tests.fakes import FakeDocker

PASSWORD = "Juda-Kuchli-Parol-2026"
WEB = Path(__file__).resolve().parent.parent / "bulutskan" / "web"
CSRF_RE = re.compile(r'name="csrf_token" value="([^"]+)"')


def make_settings(tmp_path: Path, **kw: Any) -> Settings:
    return Settings(_env_file=None, data_dir=tmp_path / "data", **kw)  # type: ignore[call-arg]


def csrf(client: TestClient, path: str = "/login") -> str:
    match = CSRF_RE.search(client.get(path).text)
    assert match, f"{path} sahifasida CSRF token yo‘q"
    return match.group(1)


def db_of(client: TestClient) -> Database:
    db: Database = client.app.state.bulutskan.db  # type: ignore[attr-defined]
    return db


def login(client: TestClient, username: str, password: str = PASSWORD) -> Any:
    return client.post("/login", data={"username": username, "password": password, "csrf_token": csrf(client)},
                       follow_redirects=False)


def add(client: TestClient, username: str, role: str) -> None:
    with db_of(client).session() as s:
        add_user(s, username, PASSWORD, role)


@pytest.fixture
def client(tmp_path: Path) -> Iterator[TestClient]:
    """Lokal rejim, worker’siz, avtomatik namoyish importisiz."""
    app = create_app(make_settings(tmp_path), start_worker=False, auto_demo=False)
    with TestClient(app) as c:
        yield c


@pytest.fixture
def admin(client: TestClient) -> TestClient:
    add(client, "admin", "admin")
    assert login(client, "admin").status_code == 303
    return client


@pytest.fixture
def demo(admin: TestClient) -> TestClient:
    import_demo(db_of(admin))
    return admin


def demo_uid(client: TestClient, target: str) -> str:
    with db_of(client).session() as s:
        scan = s.scalar(select(Scan).where(Scan.target == target, Scan.is_demo.is_(True)))
        assert scan is not None
        return scan.uid


# ------------------------------------------------------------- tizim va kirish


def test_health(client: TestClient) -> None:
    r = client.get("/health")
    assert r.status_code == 200
    body = r.json()
    assert body["status"] == "ok" and body["mode"] == "local" and body["demo_scans"] == 0


def test_first_run_creates_admin_once(client: TestClient) -> None:
    r = client.get("/", follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/setup/admin"
    assert client.get("/login", follow_redirects=False).headers["location"] == "/setup/admin"
    token = csrf(client, "/setup/admin")
    form = {"username": "admin", "password": PASSWORD, "password2": PASSWORD}
    assert client.post("/setup/admin", data=form, follow_redirects=False).status_code == 403  # CSRF’siz
    bad = client.post("/setup/admin", data={**form, "password2": "boshqa-parol-1234", "csrf_token": token})
    assert bad.status_code == 400 and "Parollar mos kelmadi" in bad.text
    weak = client.post("/setup/admin", data={**form, "password": "qisqa", "password2": "qisqa", "csrf_token": token})
    assert weak.status_code == 400
    ok = client.post("/setup/admin", data={**form, "csrf_token": token}, follow_redirects=False)
    assert ok.status_code == 303 and ok.headers["location"] == "/login?first=1"
    assert client.get("/setup/admin").status_code == 404
    assert client.post("/setup/admin", data={**form, "csrf_token": token}).status_code == 404
    assert login(client, "admin").status_code == 303
    assert "Boshqaruv paneli" in client.get("/").text


def test_login_logout_and_audit(client: TestClient) -> None:
    add(client, "admin", "admin")
    r = login(client, "admin", "noto‘g‘ri-parol-123")
    assert r.status_code == 401 and "Login yoki parol noto‘g‘ri" in r.text
    assert login(client, "ADMIN").status_code == 303  # login kichik harfga keltiriladi
    assert client.get("/").status_code == 200
    token = csrf(client, "/")
    assert client.post("/logout", follow_redirects=False).status_code == 403
    r = client.post("/logout", headers={"X-CSRF-Token": token}, follow_redirects=False)
    assert r.status_code == 303 and r.headers["location"] == "/login"
    assert client.get("/", follow_redirects=False).headers["location"] == "/login"
    with db_of(client).session() as s:
        actions = [a.action for a in s.scalars(select(AuditLog).order_by(AuditLog.id))]
    assert actions[:3] == ["login_failed", "login_ok", "logout"]


def test_htmx_request_without_session_gets_hx_redirect(client: TestClient) -> None:
    add(client, "admin", "admin")
    r = client.get("/scans", headers={"HX-Request": "true"}, follow_redirects=False)
    assert r.status_code == 204 and r.headers["HX-Redirect"] == "/login"


def test_login_attempts_are_limited(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path, login_attempts=2), start_worker=False, auto_demo=False)
    with TestClient(app) as c:
        add(c, "admin", "admin")
        assert login(c, "admin", "xato-parol-12345").status_code == 401
        assert login(c, "admin", "xato-parol-12345").status_code == 401
        blocked = login(c, "admin")  # to‘g‘ri parol ham bloklanadi
        assert blocked.status_code == 429 and "Urinishlar juda ko‘p" in blocked.text
        with db_of(c).session() as s:
            assert s.scalar(select(AuditLog).where(AuditLog.action == "login_locked")) is not None


def test_password_change_invalidates_sessions(admin: TestClient) -> None:
    assert admin.get("/").status_code == 200
    with db_of(admin).session() as s:
        user = get_user(s, "admin")
        assert user is not None
        set_password(s, user, "Yangi-Kuchli-Parol-2027")
    assert admin.get("/", follow_redirects=False).headers["location"] == "/login"


def test_rate_limit_spares_health(tmp_path: Path) -> None:
    app = create_app(make_settings(tmp_path, rate_limit_per_min=5), start_worker=False, auto_demo=False)
    with TestClient(app) as c:
        codes = [c.get("/login", follow_redirects=False).status_code for _ in range(6)]
        assert codes[-1] == 429 and 429 not in codes[:5]
        assert c.get("/health").status_code == 200
        assert c.get("/static/css/app.css").status_code == 200


# ------------------------------------------------------------- xavfsizlik sarlavhalari


def test_security_headers_and_cookie_flags(client: TestClient) -> None:
    add(client, "admin", "admin")
    r = login(client, "admin")
    h = r.headers
    assert "default-src 'self'" in h["content-security-policy"]
    assert "script-src 'self';" in h["content-security-policy"] and "unsafe-inline" not in h["content-security-policy"]
    assert "frame-ancestors 'none'" in h["content-security-policy"]
    assert h["x-frame-options"] == "DENY" and h["x-content-type-options"] == "nosniff"
    assert h["referrer-policy"] == "no-referrer" and h["cache-control"] == "no-store"
    assert "server" not in h and "strict-transport-security" not in h  # lokal rejim: HTTP
    cookie = h["set-cookie"].lower()
    assert "bulutskan_session=" in cookie and "httponly" in cookie and "samesite=strict" in cookie
    assert "secure" not in cookie
    assert client.get("/docs").status_code == 404 and client.get("/openapi.json").status_code == 404


def test_server_mode(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(web_app, "DOCKER_SOCKETS", ())
    key = "k" * 48
    with pytest.raises(RuntimeError, match="https://"):
        create_app(make_settings(tmp_path, mode="server", secret_key=key), start_worker=False, auto_demo=False)
    with pytest.raises(RuntimeError, match="SECRET_KEY"):
        create_app(make_settings(tmp_path, mode="server", public_url="https://bulutskan.uz", secret_key="qisqa"),
                   start_worker=False, auto_demo=False)
    sock = tmp_path / "docker.sock"
    sock.write_text("")
    monkeypatch.setattr(web_app, "DOCKER_SOCKETS", (str(sock),))
    with pytest.raises(RuntimeError, match="docker.sock"):
        create_app(make_settings(tmp_path, mode="server", public_url="https://bulutskan.uz", secret_key=key),
                   start_worker=False, auto_demo=False)
    monkeypatch.setattr(web_app, "DOCKER_SOCKETS", ())
    settings = make_settings(tmp_path, mode="server", public_url="https://bulutskan.uz", secret_key=key,
                             admin_username="admin", admin_password=PASSWORD)
    with TestClient(create_app(settings, start_worker=False, auto_demo=False), base_url="https://testserver") as c:
        assert c.get("/setup/admin").status_code == 404  # serverda faqat .env dagi administrator
        r = login(c, "admin")
        assert r.status_code == 303
        assert "max-age=31536000" in r.headers["strict-transport-security"]
        assert "secure" in r.headers["set-cookie"].lower()
        assert c.get("/").status_code == 200
    assert not (settings.data_path / "secret_key").exists()


def test_local_secret_is_generated_once(tmp_path: Path) -> None:
    settings = make_settings(tmp_path)
    first = resolve_secret(settings)
    assert len(first) >= 32 and resolve_secret(settings) == first
    assert resolve_secret(make_settings(tmp_path, secret_key="almashtiring-bu-faqat-namuna")) == first


def test_lang_redirect_is_local_only(admin: TestClient) -> None:
    token = csrf(admin, "/")
    r = admin.post("/lang", data={"lang": "en", "next": "//evil.example", "csrf_token": token}, follow_redirects=False)
    assert r.headers["location"] == "/"
    assert "Dashboard" in admin.get("/").text
    r = admin.post("/lang", data={"lang": "uz", "next": "/ahp", "csrf_token": token}, follow_redirects=False)
    assert r.headers["location"] == "/ahp"


# ------------------------------------------------------------- rollar


def test_roles_and_scan_visibility(demo: TestClient) -> None:
    add(demo, "tahlilchi", "analyst")
    add(demo, "boshqa", "analyst")
    add(demo, "mehmon", "guest")
    nginx = demo_uid(demo, "nginx:1.21")
    # boshqa tahlilchining tekshiruvi
    login(demo, "boshqa")
    token = csrf(demo, "/scan/image")
    r = demo.post("/scan/image", data={"image": "busybox:1.36", "csrf_token": token}, follow_redirects=False)
    assert r.status_code == 303
    private_uid = r.headers["location"].rsplit("/", 1)[1]
    login(demo, "tahlilchi")
    assert demo.get(f"/scans/{nginx}").status_code == 200  # namoyish hammaga ochiq
    assert demo.get(f"/scans/{private_uid}").status_code == 404  # boshqaning tekshiruvi ko‘rinmaydi
    assert demo.get(f"/scans/{private_uid}/export.json").status_code == 404
    assert "busybox:1.36" not in demo.get("/scans").text
    for path in ("/tools", "/admin/audit", "/admin/users", "/admin/audit.csv"):
        assert demo.get(path).status_code == 403, path
    token = csrf(demo, "/")
    assert demo.post("/tools/run", data={"action": "check", "csrf_token": token}).status_code == 403
    login(demo, "admin")
    assert demo.get(f"/scans/{private_uid}").status_code == 200  # administrator hammasini ko‘radi


def test_guest_can_only_use_demo_inputs(demo: TestClient) -> None:
    add(demo, "mehmon", "guest")
    login(demo, "mehmon")
    token = csrf(demo, "/scan/image")
    r = demo.post("/scan/image", data={"image": "alpine:latest", "csrf_token": token})
    assert r.status_code == 400 and "Mehmon faqat eksperimentdagi obrazlardan" in r.text
    tar = {"tar": ("image.tar", io.BytesIO(b"x" * 1024), "application/x-tar")}
    r = demo.post("/scan/image", data={"image": "", "csrf_token": token}, files=tar)
    assert r.status_code == 400
    r = demo.post("/scan/image", data={"image": "redis:6.2", "csrf_token": token}, follow_redirects=False)
    assert r.status_code == 303, re.findall(r'alert[^>]*>([^<]+)', r.text)
    # IaC: mehmon yuborgan fayl e’tiborga olinmaydi, namoyish fayllari tekshiriladi
    assert demo.post("/scan/iac", data={"csrf_token": token}).status_code == 429  # 30 soniya o‘tmadi
    demo.app.state.bulutskan.settings.scan_min_interval_s = 0  # type: ignore[attr-defined]
    token = csrf(demo, "/scan/iac")
    files = {"files": ("main.tf", io.BytesIO(b'resource "aws_s3_bucket" "b" {}\n'), "text/plain")}
    r = demo.post("/scan/iac", data={"csrf_token": token}, files=files, follow_redirects=False)
    assert r.status_code == 303
    uid = r.headers["location"].rsplit("/", 1)[1]
    with db_of(demo).session() as s:
        scan = s.scalar(select(Scan).where(Scan.uid == uid))
        assert scan is not None and scan.request == {"demo": True} and scan.status == "queued"


def test_quota_and_queue_limits(tmp_path: Path) -> None:
    settings = make_settings(tmp_path, quota_analyst=2, scan_min_interval_s=0, queue_per_user=5)
    with TestClient(create_app(settings, start_worker=False, auto_demo=False)) as c:
        add(c, "admin", "admin")
        add(c, "tahlilchi", "analyst")
        login(c, "tahlilchi")
        token = csrf(c, "/scan/image")
        codes = [c.post("/scan/image", data={"image": "alpine:3.20", "csrf_token": token},
                        follow_redirects=False).status_code for _ in range(3)]
        assert codes == [303, 303, 429]
        assert "Kunlik kvota tugadi (2 ta)" in c.post("/scan/image", data={"image": "alpine:3.20",
                                                                           "csrf_token": token}).text
        login(c, "admin")  # administratorda kvota yo‘q
        token = csrf(c, "/scan/image")
        assert c.post("/scan/image", data={"image": "alpine:3.20", "csrf_token": token},
                      follow_redirects=False).status_code == 303


def test_min_interval_between_scans(tmp_path: Path) -> None:
    with TestClient(create_app(make_settings(tmp_path), start_worker=False, auto_demo=False)) as c:
        add(c, "admin", "admin")
        add(c, "tahlilchi", "analyst")
        login(c, "tahlilchi")
        token = csrf(c, "/scan/image")
        assert c.post("/scan/image", data={"image": "alpine:3.20", "csrf_token": token},
                      follow_redirects=False).status_code == 303
        r = c.post("/scan/image", data={"image": "alpine:3.18", "csrf_token": token})
        assert r.status_code == 429 and "30 soniya" in r.text


def test_image_reference_validation(admin: TestClient) -> None:
    token = csrf(admin, "/scan/image")
    for bad in ("nginx;rm -rf /", "--privileged", "NGINX:1", "a" * 300, ""):
        r = admin.post("/scan/image", data={"image": bad, "csrf_token": token})
        assert r.status_code == 400, bad
    with db_of(admin).session() as s:
        assert s.scalar(select(Scan)) is None


def test_server_registry_allowlist(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Server rejimi (SSRF): IP, ichki nomlar va ro‘yxatda yo‘q registrlar rad etiladi."""
    monkeypatch.setattr(web_app, "DOCKER_SOCKETS", ())
    settings = make_settings(tmp_path, mode="server", public_url="https://bulutskan.uz", secret_key="k" * 48,
                             admin_username="admin", admin_password=PASSWORD)
    with TestClient(create_app(settings, start_worker=False, auto_demo=False), base_url="https://testserver") as c:
        login(c, "admin")
        token = csrf(c, "/scan/image")
        for bad in ("10.0.0.5:5000/ichki:1", "localhost:5000/x:1", "registry.corp.internal/x:1", "evil.example/x:1"):
            r = c.post("/scan/image", data={"image": bad, "csrf_token": token})
            assert r.status_code == 400 and "registr ruxsat etilmagan" in r.text, bad
        r = c.post("/scan/image", data={"image": "ghcr.io/org/app:1.0", "csrf_token": token}, follow_redirects=False)
        assert r.status_code == 303


def test_iac_upload_validation(admin: TestClient) -> None:
    token = csrf(admin, "/scan/iac")
    assert admin.post("/scan/iac", data={"csrf_token": token}).status_code == 400  # fayl yo‘q
    exe = {"files": ("virus.exe", io.BytesIO(b"MZ\x90\x00"), "application/octet-stream")}
    assert admin.post("/scan/iac", data={"csrf_token": token}, files=exe).status_code == 400
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w") as zf:
        zf.writestr("../../yomon.tf", "x")
    zip_files = {"files": ("iac.zip", io.BytesIO(buf.getvalue()), "application/zip")}
    assert admin.post("/scan/iac", data={"csrf_token": token}, files=zip_files).status_code == 400
    ok = {"files": ("main.tf", io.BytesIO(b'resource "aws_s3_bucket" "b" {}\n'), "text/plain")}
    r = admin.post("/scan/iac", data={"csrf_token": token}, files=ok, follow_redirects=False)
    assert r.status_code == 303
    uid = r.headers["location"].rsplit("/", 1)[1]
    assert "Navbatda" in admin.get(f"/scans/{uid}").text
    status = admin.get(f"/scans/{uid}/status")
    assert status.status_code == 200 and "HX-Refresh" not in status.headers


# ------------------------------------------------------------- namoyish sahifalari


def test_demo_pages_render(demo: TestClient) -> None:
    nginx = demo_uid(demo, "nginx:1.21")
    iac = demo_uid(demo, "Namoyish IaC fayllari (III bob)")
    dash = demo.get("/")
    assert dash.status_code == 200 and 'id="dashboard-data"' in dash.text
    charts = json.loads(re.search(r'id="dashboard-data" data-json="([^"]*)"', dash.text).group(1)  # type: ignore[union-attr]
                        .replace("&#34;", '"').replace("&quot;", '"').replace("&amp;", "&").replace("&#39;", "'"))
    assert len(charts["jaccard"]["labels"]) == 15 and set(charts["tools"]["labels"]) == {"checkov", "grype", "kics",
                                                                                          "trivy"}
    for path in ("/scans", "/scans?kind=iac", "/scans?source=demo", f"/scans/{nginx}", f"/scans/{iac}", "/compare",
                 f"/compare?a={nginx}&b={demo_uid(demo, 'redis:6.2')}", "/scan/iac", "/scan/image", "/ahp",
                 "/ahp?scenario=gov", "/tools", "/help/docker", "/admin/audit", "/admin/users"):
        r = demo.get(path)
        assert r.status_code == 200, path
        assert "Traceback" not in r.text
    detail = demo.get(f"/scans/{nginx}").text
    assert "qo‘llab-quvvatlash muddati tugagan" in detail  # EOL ogohlantirishi
    assert "0,729" in detail  # Jaccard (ch3.json)
    gt = demo.get(f"/scans/{iac}").text
    assert "36/40" in gt and "34/40" in gt and "32/40" in gt


def test_groups_filters(demo: TestClient) -> None:
    nginx = demo_uid(demo, "nginx:1.21")
    all_groups = demo.get(f"/scans/{nginx}/groups")
    assert all_groups.status_code == 200 and "Jami: 689" in all_groups.text
    crit = demo.get(f"/scans/{nginx}/groups?severity=CRITICAL")
    assert "Jami: 38" in crit.text
    confirmed = demo.get(f"/scans/{nginx}/groups?consensus=confirmed")
    assert "Jami: 502" in confirmed.text
    found = demo.get(f"/scans/{nginx}/groups?q=CVE-2021-44228&page=999")
    assert found.status_code == 200


def test_exports(demo: TestClient) -> None:
    nginx = demo_uid(demo, "nginx:1.21")
    r = demo.get(f"/scans/{nginx}/export.json")
    assert r.status_code == 200 and "attachment" in r.headers["content-disposition"]
    data = r.json()
    assert data["scan"]["target"] == "nginx:1.21" and data["failures"] == []
    assert len(data["consensus"]["groups"]) == 689 and data["eol"]["is_eol"] is True
    assert "exit" not in data  # CI qarori faqat CLI’da
    docx = demo.get(f"/scans/{nginx}/report.docx")
    assert docx.status_code == 200 and docx.content[:2] == b"PK" and len(docx.content) > 20_000
    csv_resp = demo.get("/admin/audit.csv")
    assert csv_resp.status_code == 200 and csv_resp.text.startswith("﻿vaqt_utc;")
    assert "export_downloaded" in csv_resp.text


def test_ahp_page_and_recalculation(demo: TestClient) -> None:
    page = demo.get("/ahp").text
    assert "CR = 0,0053" in page
    token = csrf(demo, "/ahp")
    base = {"w_K1": "0.167", "w_K2": "0.293", "w_K3": "0.056", "w_K4": "0.056", "w_K5": "0.096", "w_K6": "0.167",
            "w_K7": "0.167"}
    r = demo.post("/ahp/calc", data={**base, "csrf_token": token})
    assert r.status_code == 200
    order = re.findall(r"<td>\d+</td><td>([^<]+)</td>", r.text)
    assert order[:3] == ["Checkov", "Trivy", "Grype"]  # 3.9-jadval
    only_k1 = {k: "0" for k in base} | {"w_K1": "1"}
    order = re.findall(r"<td>\d+</td><td>([^<]+)</td>", demo.post("/ahp/calc", data={**only_k1,
                                                                                     "csrf_token": token}).text)
    assert order[0] in ("Wiz", "Cortex Cloud")
    zero = demo.post("/ahp/calc", data={k: "0" for k in base} | {"csrf_token": token})
    assert zero.status_code == 200  # nol vaznlar teng vaznlarga aylanadi
    assert demo.post("/ahp/calc", data=base).status_code == 403


# ------------------------------------------------------------- sozlash ustasi


def test_setup_wizard_with_fake_docker(admin: TestClient) -> None:
    db = db_of(admin)
    settings: Settings = admin.app.state.bulutskan.settings  # type: ignore[attr-defined]
    page = admin.get("/tools").text
    assert 'hx-trigger="load"' in page  # holat hali yo‘q: sahifa ochilganda tekshiradi
    token = csrf(admin, "/tools")
    r = admin.post("/tools/run", data={"action": "check", "csrf_token": token})
    assert r.status_code == 200
    assert admin.post("/tools/run", data={"action": "rm -rf", "csrf_token": token}).status_code == 400
    fake = FakeDocker(settings)
    fake.install_tools()
    fake.install_databases()
    task_id = setup.claim_task(db)
    assert task_id is not None
    setup.execute_task(db, task_id, settings, DockerClient(fake))
    state = setup.get_setting(db, "setup_state")
    assert state["docker"]["status"] == "green" and state["tools"]["status"] == "green"
    assert state["checkov"]["status"] == "green"
    status = admin.get("/tools/status")
    assert status.status_code == 200 and "Uchala vosita digest bo‘yicha mos" in status.text
    assert setup_banner(state, False) is None


def test_setup_wizard_without_docker_offers_demo(admin: TestClient) -> None:
    db = db_of(admin)
    settings: Settings = admin.app.state.bulutskan.settings  # type: ignore[attr-defined]
    setup.enqueue_task(db, "check", None)
    task_id = setup.claim_task(db)
    assert task_id is not None
    setup.execute_task(db, task_id, settings, DockerClient(FakeDocker(settings, available=False)))
    page = admin.get("/tools").text
    assert "Namoyish rejimida davom etish" in page and "O‘rnatish ko‘rsatmasi" in page
    assert "Namoyish rejimi: Docker topilmagani uchun" in admin.get("/").text
    token = csrf(admin, "/tools")
    r = admin.post("/tools/demo-mode", data={"csrf_token": token}, follow_redirects=False)
    assert r.status_code == 303
    assert setup.get_setting(db, "demo_mode") is True
    assert admin.get("/health").json()["demo_scans"] == 16


def test_digest_mismatch_banner_regression(admin: TestClient) -> None:
    """``state.tools.items`` Jinja’da ``dict.items`` bo‘lib qolgan va har sahifa 500 qaytargan."""
    state = {"docker": {"status": "green"},
             "tools": {"status": "red", "items": [{"tool": "trivy", "status": "mismatch", "message": "x"}]}}
    with db_of(admin).session() as s:
        setup.save_setting(s, "setup_state", state)
    page = admin.get("/ahp")
    assert page.status_code == 200 and "vosita digesti mos kelmadi" in page.text
    assert setup_banner(state, False) == "mismatch"
    assert setup_banner({"tools": {"status": "red", "items": []}}, True) == "demo"
    assert setup_banner(None, False) is None and setup_banner("buzilgan", False) is None


# ------------------------------------------------------------- yordamchilar va resurslar


def test_short_ref_and_csv_cell() -> None:
    ref = "aquasec/trivy@sha256:" + "7" * 64
    assert short_ref(ref) == "aquasec/trivy@sha256:777777777777…"
    assert short_ref(None) == "—" and short_ref("nginx:1.21") == "nginx:1.21"
    assert csv_cell("=HYPERLINK(1)") == "'=HYPERLINK(1)" and csv_cell("-1") == "'-1" and csv_cell(None) == ""
    assert csv_cell("nginx:1.21") == "nginx:1.21"


def _template_keys() -> set[str]:
    keys: set[str] = set()
    pattern = re.compile(r"""\bt\(\s*(["'])(.+?)\1\s*\)""")
    for path in (WEB / "templates").rglob("*.html"):
        keys.update(m.group(2) for m in pattern.finditer(path.read_text(encoding="utf-8")))
    return keys


def test_every_template_string_is_translated() -> None:
    en = json.loads((WEB / "i18n" / "en.json").read_text(encoding="utf-8"))
    keys = _template_keys()
    assert len(keys) > 100
    missing = sorted(k for k in keys if k not in en)
    assert not missing, f"en.json da yo‘q: {missing}"
    assert all(isinstance(v, str) and v.strip() for v in en.values())


def test_no_external_resources_or_inline_code() -> None:
    """CSP va "tashqi CDN yo‘q" talabi: shablonlarda tashqi manzil va inline skript/stil yo‘q."""
    for path in (WEB / "templates").rglob("*.html"):
        text = path.read_text(encoding="utf-8")
        assert not re.search(r"""(src|href)=["']https?://""", text), path
        assert not re.search(r"<script(?![^>]*\bsrc=)", text), path  # faqat tashqi fayldan
        assert "style=" not in text and "<style" not in text, path
        assert not re.search(r"\son[a-z]+=", text), path  # onclick va h.k.
    vendor = {p.name for p in (WEB / "static" / "vendor").iterdir()}
    assert {"htmx-2.0.4.min.js", "chart-4.4.7.umd.min.js", "LICENSES.txt"} <= vendor


# ------------------------------------------------------------- Windows dasturi


def test_first_admin_login_opens_setup_wizard(client: TestClient) -> None:
    add(client, "admin", "admin")
    add(client, "tahlilchi", "analyst")
    assert login(client, "admin").headers["location"] == "/tools"  # vositalar hali tekshirilmagan
    assert login(client, "tahlilchi").headers["location"] == "/"
    with db_of(client).session() as s:
        setup.save_setting(s, "setup_state", {"docker": {"status": "red"}})
    assert login(client, "admin").headers["location"] == "/"


def test_health_reports_instance_id(client: TestClient) -> None:
    settings: Settings = client.app.state.bulutskan.settings  # type: ignore[attr-defined]
    assert client.get("/health").json()["instance"] == settings.instance_id


class _Resp(io.BytesIO):
    def __enter__(self) -> _Resp:
        return self

    def __exit__(self, *_: object) -> None:
        self.close()


def test_second_launch_reuses_running_instance(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Ish stolidagi belgi ikkinchi marta bosilsa, yangi server va worker ochilmaydi."""
    import urllib.request

    from typer.testing import CliRunner

    from bulutskan import cli

    settings = make_settings(tmp_path)
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    assert cli._running_instance(settings) is None  # fayl yo‘q
    cli._write_instance(settings, 8123)
    seen: list[str] = []

    def fake_urlopen(url: str, timeout: float = 0) -> _Resp:
        seen.append(url)
        return _Resp(json.dumps({"status": "ok", "instance": settings.instance_id}).encode())

    monkeypatch.setattr(urllib.request, "urlopen", fake_urlopen)
    assert cli._running_instance(settings) == "http://127.0.0.1:8123/"
    res = CliRunner().invoke(cli.app, ["serve", "--no-browser"])
    assert res.exit_code == 0 and "allaqachon ishlayapti: http://127.0.0.1:8123/" in res.output
    assert seen[-1] == "http://127.0.0.1:8123/health"
    # boshqa ma’lumotlar katalogidagi nusxa hisobga olinmaydi
    monkeypatch.setattr(urllib.request, "urlopen", lambda url, timeout=0: _Resp(b'{"instance": "boshqa"}'))
    assert cli._running_instance(settings) is None

    def refused(url: str, timeout: float = 0) -> _Resp:
        raise ConnectionRefusedError(url)

    monkeypatch.setattr(urllib.request, "urlopen", refused)
    assert cli._running_instance(settings) is None  # eski fayl qolgan, server yopilgan


def test_docker_desktop_path_fallback(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    import shutil
    import sys

    from bulutskan import config

    exe = tmp_path / "docker.exe"
    exe.write_bytes(b"")
    monkeypatch.setattr(config, "WINDOWS_DOCKER", exe)
    monkeypatch.setattr(shutil, "which", lambda name: None)
    monkeypatch.setattr(sys, "platform", "win32")
    assert config.default_docker_bin() == str(exe)
    monkeypatch.setattr(shutil, "which", lambda name: "C:/docker/docker.exe")
    assert config.default_docker_bin() == "docker"
    monkeypatch.setattr(sys, "platform", "linux")
    monkeypatch.setattr(shutil, "which", lambda name: None)
    assert config.default_docker_bin() == "docker"


def test_footer_text(admin: TestClient) -> None:
    from bulutskan import __version__

    page = admin.get("/").text
    expected = f"Ma’lumotlar O‘zbekiston hududidan chiqmaydi · BulutSkan {__version__} · Andijon davlat universiteti</footer>"
    assert expected in page
    token = csrf(admin, "/")
    admin.post("/lang", data={"lang": "en", "next": "/", "csrf_token": token})
    assert f"BulutSkan {__version__} · Andijan State University</footer>" in admin.get("/").text

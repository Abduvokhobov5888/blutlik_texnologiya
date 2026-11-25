"""Namoyish importi va foydalanuvchilar."""

import pytest
from sqlalchemy import select
from typer.testing import CliRunner

from bulutskan import cli
from bulutskan.security.passwords import WeakPassword, check_policy, hash_password, verify_password
from bulutskan.services.demo import demo_scan_count, import_demo
from bulutskan.services.users import (
    UserError,
    add_user,
    authenticate,
    bootstrap_admin,
    disable_user,
    get_user,
    set_password,
)
from bulutskan.storage.tables import AuditLog, Scan
from tests.conftest import IMAGES, ch3_row

PASSWORD = "Juda-Kuchli-Parol-2026"


def test_demo_import_matches_dissertation(db, summary) -> None:
    assert import_demo(db) == 16
    assert import_demo(db) == 0  # takrorlanmaydi
    with db.session() as s:
        scans = list(s.scalars(select(Scan).where(Scan.is_demo.is_(True)).order_by(Scan.id)))
        assert len(scans) == 16
        iac = scans[0]
        assert iac.kind == "iac" and iac.ground_truth["tools"]["Checkov"]["tp"] == 36
        assert iac.ground_truth["missed_by_all"] == summary["missed_by_all"]
        by_target = {sc.target: sc for sc in scans[1:]}
        assert set(by_target) == set(IMAGES)
        for image in IMAGES:
            assert abs(by_target[image].jaccard["trivy|grype"] - ch3_row(image)["j"]) < 1e-12
        nginx = by_target["nginx:1.21"]
        runs = {r.tool: r for r in nginx.tool_runs}
        assert runs["trivy"].duration_s > 0 and runs["grype"].duration_s > 0  # timings.csv dan
        assert nginx.image["repo_digests"][0].startswith("nginx@sha256:")
        assert nginx.created_at.year == 2026
    assert import_demo(db, force=True) == 16
    assert demo_scan_count(db) == 16


def test_password_policy_and_hashing() -> None:
    with pytest.raises(WeakPassword):
        check_policy("qisqa")
    with pytest.raises(WeakPassword):
        check_policy("x" * 73)
    with pytest.raises(WeakPassword):
        check_policy(" bo‘shliq-bilan-boshlanadi")
    h = hash_password(PASSWORD)
    assert h.startswith("$2b$12$") and PASSWORD not in h
    assert verify_password(PASSWORD, h) and not verify_password("noto‘g‘ri-parol-123", h)
    assert not verify_password(PASSWORD, None)


def test_user_lifecycle(db) -> None:
    with db.session() as s:
        user = add_user(s, "Robiyaxon", PASSWORD, "analyst")
        assert user.username == "robiyaxon"
        with pytest.raises(UserError):
            add_user(s, "robiyaxon", PASSWORD, "analyst")
        with pytest.raises(UserError):
            add_user(s, "x", PASSWORD, "analyst")
        with pytest.raises(UserError):
            add_user(s, "boshqa", PASSWORD, "root")
    with db.session() as s:
        assert authenticate(s, "robiyaxon", PASSWORD) is not None
        assert authenticate(s, "robiyaxon", "noto‘g‘ri-parol-123") is None
        assert authenticate(s, "yoq", PASSWORD) is None
        found = get_user(s, "robiyaxon")
        assert found is not None
        epoch = found.session_epoch
        set_password(s, found, "Yangi-Kuchli-Parol-2027")
        assert found.session_epoch == epoch + 1
        disable_user(s, found)
    with db.session() as s:
        assert authenticate(s, "robiyaxon", "Yangi-Kuchli-Parol-2027") is None  # o‘chirilgan


def test_bootstrap_admin_once(db) -> None:
    with db.session() as s:
        assert bootstrap_admin(s, "admin", PASSWORD) is not None
        assert bootstrap_admin(s, "admin2", PASSWORD) is None
        assert bootstrap_admin(s, None, None) is None


runner = CliRunner()


def test_cli_user_and_demo(settings, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(cli, "get_settings", lambda: settings)
    res = runner.invoke(cli.app, ["user", "add", "mehmon", "--role", "guest", "--password-stdin"], input=PASSWORD + "\n")
    assert res.exit_code == 0, res.output
    res = runner.invoke(cli.app, ["user", "add", "zaif", "--password-stdin"], input="123\n")
    assert res.exit_code == 2 and "kamida 12" in res.output
    res = runner.invoke(cli.app, ["user", "list"])
    assert "mehmon" in res.output and "guest" in res.output
    assert runner.invoke(cli.app, ["user", "disable", "mehmon"]).exit_code == 0
    assert "o‘chirilgan" in runner.invoke(cli.app, ["user", "list"]).output
    assert runner.invoke(cli.app, ["user", "enable", "mehmon"]).exit_code == 0
    res = runner.invoke(cli.app, ["user", "passwd", "mehmon", "--password-stdin"], input="Boshqa-Kuchli-Parol-1\n")
    assert res.exit_code == 0
    assert runner.invoke(cli.app, ["user", "disable", "yoq"]).exit_code == 2
    res = runner.invoke(cli.app, ["demo-import"])
    assert res.exit_code == 0 and "16" in res.output
    db = cli.open_db(settings)
    with db.session() as s:
        actions = {a.action for a in s.scalars(select(AuditLog))}
        assert {"user_added", "user_disabled", "user_enabled", "password_changed"} <= actions
        rows = list(s.scalars(select(AuditLog)))
        assert all("parol" not in str(r.detail).lower() for r in rows)
    db.dispose()

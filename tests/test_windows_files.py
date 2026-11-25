"""Windows fayl qoidasi bo‘yicha regressiya testlari (WinError 32).

Windows ochiq faylni o‘chirishga va nomini o‘zgartirishga ruxsat bermaydi.
``conftest.windows_file_semantics`` bu qoidani barcha testlarda Linux’da ham
yoqadi; bu yerda esa xato bir marta chiqqan joylar (``accept_plain_file``)
va unga o‘xshash barcha yo‘llar alohida tekshiriladi.
"""

import io
import zipfile
from pathlib import Path

import pytest

from bulutskan.security import workspace as workspace_module
from bulutskan.security.upload_guard import (
    UploadLimits,
    UploadRejected,
    accept_plain_file,
    extract_zip,
    save_stream,
    stage_directory,
)
from bulutskan.security.workspace import Workspace, purge_stale, remove_tree


def test_fixture_behaves_like_windows(tmp_path: Path) -> None:
    """Fixture faol: ochiq faylni o‘chirish va ko‘chirish rad etiladi."""
    f = tmp_path / "band.tf"
    f.write_text("x")
    with f.open("rb"):
        with pytest.raises(PermissionError, match="WinError 32"):
            f.unlink()
        with pytest.raises(PermissionError, match="WinError 32"):
            f.rename(tmp_path / "boshqa.tf")
    f.unlink()
    assert not f.exists()


def test_binary_plain_upload_is_removed_after_close(tmp_path: Path) -> None:
    """Windows’da yiqilgan holat: matnli bo‘lmagan fayl yopilgandan keyin o‘chiriladi."""
    dest = tmp_path / "input"
    dest.mkdir()
    with pytest.raises(UploadRejected) as exc:
        accept_plain_file(io.BytesIO(b"a\x00b"), "binary.tf", dest)
    assert exc.value.code == "binary"
    assert list(dest.iterdir()) == []


def test_save_stream_limit_removes_partial_file(tmp_path: Path) -> None:
    target = tmp_path / "katta.tf"
    with pytest.raises(UploadRejected):
        save_stream(io.BytesIO(b"x" * 200_000), target, max_bytes=100_000)
    assert not target.exists()


def test_save_stream_never_deletes_existing_file(tmp_path: Path) -> None:
    target = tmp_path / "mavjud.tf"
    target.write_text("asl mazmun")
    with pytest.raises(FileExistsError):
        save_stream(io.BytesIO(b"yangi"), target, max_bytes=100)
    assert target.read_text() == "asl mazmun"


def _corrupt_second_entry_zip(path: Path) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_STORED) as zf:
        zf.writestr("infra/a.tf", b"a" * 100)
        zf.writestr("infra/b.tf", b"y" * 100)
    data = bytearray(path.read_bytes())
    pos = data.find(b"y" * 100)
    data[pos] = ord("z")  # CRC endi mos kelmaydi
    path.write_bytes(bytes(data))
    return path


def test_corrupted_zip_is_rolled_back(tmp_path: Path) -> None:
    """Ikkinchi yozuv buzilgan: birinchisi ham o‘chiriladi, kataloglar qolmaydi."""
    dest = tmp_path / "input"
    dest.mkdir()
    z = _corrupt_second_entry_zip(tmp_path / "buzuq.zip")
    with pytest.raises(UploadRejected) as exc:
        extract_zip(z, dest)
    assert exc.value.code == "bad_zip"
    assert list(dest.rglob("*")) == []


def test_binary_entry_in_zip_is_removed_after_close(tmp_path: Path) -> None:
    dest = tmp_path / "input"
    dest.mkdir()
    z = tmp_path / "bin.zip"
    with zipfile.ZipFile(z, "w") as zf:
        zf.writestr("k8s/evil.yaml", b"\x7fELF\x00\x00")
        zf.writestr("k8s/ok.yaml", b"a: 1\n")
    res = extract_zip(z, dest)
    assert res.files == ["k8s/ok.yaml"] and res.skipped == ["k8s/evil.yaml"]
    assert sorted(p.name for p in (dest / "k8s").iterdir()) == ["ok.yaml"]


def test_stage_directory_rolls_back_on_limit(tmp_path: Path) -> None:
    src = tmp_path / "proj"
    (src / "a").mkdir(parents=True)
    (src / "a" / "kichik.tf").write_text("x\n")
    (src / "b.tf").write_text("y" * 5000)
    dest = tmp_path / "input"
    dest.mkdir()
    with pytest.raises(UploadRejected) as exc:
        stage_directory(src, dest, UploadLimits(max_file_bytes=1000))
    assert exc.value.code == "file_too_large"
    assert list(dest.rglob("*")) == []


def test_remove_tree_waits_for_busy_file(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fayl bir lahza band bo‘lsa (antivirus, Docker Desktop), qayta urinib o‘chiriladi."""
    d = tmp_path / "ish"
    d.mkdir()
    handle = (d / "hisobot.json").open("w")
    sleeps: list[float] = []

    def fake_sleep(seconds: float) -> None:
        sleeps.append(seconds)
        handle.close()  # "boshqa jarayon" faylni qo‘yib yubordi

    monkeypatch.setattr(workspace_module.time, "sleep", fake_sleep)
    assert remove_tree(d) is True
    assert sleeps and not d.exists()


def test_remove_tree_gives_up_without_raising(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    monkeypatch.setattr(workspace_module.time, "sleep", lambda s: None)
    d = tmp_path / "ish"
    d.mkdir()
    with (d / "band.tf").open("w"):
        assert remove_tree(d, attempts=3) is False
        assert d.exists()
    assert remove_tree(d) is True


def test_workspace_cleanup_does_not_crash_scan(tmp_path: Path, monkeypatch: pytest.MonkeyPatch) -> None:
    """Fayl band bo‘lsa ham tekshiruv natijasi yo‘qolmaydi; katalogni keyin purge_stale tozalaydi."""
    monkeypatch.setattr(workspace_module.time, "sleep", lambda s: None)
    root = tmp_path / "workdir"
    with Workspace(root) as ws:
        handle = (ws.input / "main.tf").open("w")
    assert ws.cleaned is False and ws.path.exists()
    handle.close()
    assert purge_stale(root, max_age_s=-1) == [ws.uid]
    assert not ws.path.exists()


def test_readonly_file_is_removed(tmp_path: Path) -> None:
    """Windows: faqat o‘qish uchun belgilangan fayl (WinError 5) ham o‘chiriladi."""
    d = tmp_path / "ish"
    d.mkdir()
    f = d / "ro.tf"
    f.write_text("x")
    f.chmod(0o444)
    assert remove_tree(d) is True

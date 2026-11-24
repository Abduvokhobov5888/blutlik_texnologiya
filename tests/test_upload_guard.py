"""Fayl yuklash himoyasi: zip-slip, zip-bomba, oq ro‘yxat, hajm, tar tekshiruvi."""

import io
import os
import stat
import tarfile
import zipfile
from pathlib import Path

import pytest

from bulutskan.security.upload_guard import (
    UploadLimits,
    UploadRejected,
    accept_plain_file,
    extract_zip,
    is_allowed_name,
    safe_relative_path,
    save_stream,
    stage_directory,
    validate_image_tar,
)
from bulutskan.security.workspace import Workspace, purge_stale


def _zip(path: Path, entries: dict[str, bytes], symlink: str | None = None) -> Path:
    with zipfile.ZipFile(path, "w", zipfile.ZIP_DEFLATED) as zf:
        for name, data in entries.items():
            info = zipfile.ZipInfo(name)
            info.compress_type = zipfile.ZIP_DEFLATED
            if name == symlink:
                info.external_attr = (stat.S_IFLNK | 0o777) << 16
            zf.writestr(info, data)
    return path


@pytest.fixture
def dest(tmp_path: Path) -> Path:
    d = tmp_path / "input"
    d.mkdir()
    return d


def test_valid_zip_is_extracted_and_others_skipped(tmp_path: Path, dest: Path) -> None:
    z = _zip(
        tmp_path / "ok.zip",
        {
            "infra/main.tf": b'resource "aws_s3_bucket" "b" {}\n',
            "k8s/deploy.yaml": b"kind: Deployment\n",
            "Dockerfile": b"FROM alpine:3.20\n",
            "api.Dockerfile": b"FROM alpine:3.20\n",
            "README.md": b"# izoh\n",
            "script.sh": b"echo\n",
        },
    )
    res = extract_zip(z, dest)
    assert sorted(res.files) == ["Dockerfile", "api.Dockerfile", "infra/main.tf", "k8s/deploy.yaml"]
    assert sorted(res.skipped) == ["README.md", "script.sh"]
    assert (dest / "infra" / "main.tf").read_text() == 'resource "aws_s3_bucket" "b" {}\n'
    assert not (dest / "README.md").exists()


@pytest.mark.parametrize(
    "name",
    [
        "../evil.tf",
        "infra/../../evil.tf",
        "/etc/evil.tf",
        "\\windows\\evil.tf",
        "C:\\evil.tf",
        "C:/evil.tf",
        "..\\..\\evil.tf",
        "infra/file:stream.tf",
        "con.tf",
        "infra/nul.yaml",
    ],
)
def test_zip_slip_names_are_rejected(tmp_path: Path, dest: Path, name: str) -> None:
    z = _zip(tmp_path / "slip.zip", {"ok.tf": b"x\n", name: b"pwned\n"})
    with pytest.raises(UploadRejected):
        extract_zip(z, dest)
    # Birorta fayl ham ochilmagan bo‘lishi kerak.
    assert list(dest.iterdir()) == []
    assert not (tmp_path / "evil.tf").exists()


def test_symlink_entry_is_rejected(tmp_path: Path, dest: Path) -> None:
    z = _zip(tmp_path / "link.zip", {"link.tf": b"/etc/passwd"}, symlink="link.tf")
    with pytest.raises(UploadRejected) as exc:
        extract_zip(z, dest)
    assert exc.value.code == "symlink"


def _set_encrypted_flag(path: Path) -> None:
    # zipfile.writestr flag_bits ni o‘zi qayta yozadi, shuning uchun bitni baytlarda o‘rnatamiz.
    data = bytearray(path.read_bytes())
    for sig, offset in ((b"PK\x03\x04", 6), (b"PK\x01\x02", 8)):
        pos = data.find(sig)
        data[pos + offset] |= 0x01
    path.write_bytes(bytes(data))


def test_encrypted_entry_is_rejected(tmp_path: Path, dest: Path) -> None:
    z = _zip(tmp_path / "enc.zip", {"a.tf": b"x"})
    _set_encrypted_flag(z)
    with pytest.raises(UploadRejected) as exc:
        extract_zip(z, dest)
    assert exc.value.code == "encrypted"


def test_nested_archive_is_rejected(tmp_path: Path, dest: Path) -> None:
    z = _zip(tmp_path / "nested.zip", {"inner.zip": b"PK\x03\x04"})
    with pytest.raises(UploadRejected) as exc:
        extract_zip(z, dest)
    assert exc.value.code == "nested_archive"


def test_case_insensitive_duplicates_are_rejected(tmp_path: Path, dest: Path) -> None:
    z = _zip(tmp_path / "dup.zip", {"Main.tf": b"a", "main.tf": b"b"})
    with pytest.raises(UploadRejected) as exc:
        extract_zip(z, dest)
    assert exc.value.code == "duplicate"


def test_too_many_entries(tmp_path: Path, dest: Path) -> None:
    z = _zip(tmp_path / "many.zip", {f"f{i}.tf": b"x" for i in range(11)})
    with pytest.raises(UploadRejected) as exc:
        extract_zip(z, dest, UploadLimits(max_entries=10))
    assert exc.value.code == "too_many_entries"


def test_zip_bomb_ratio_is_rejected(tmp_path: Path, dest: Path) -> None:
    z = _zip(tmp_path / "bomb.zip", {"bomb.tf": b"0" * (5 * 1024 * 1024)})
    with pytest.raises(UploadRejected) as exc:
        extract_zip(z, dest)
    assert exc.value.code == "zip_bomb"


def test_unzipped_total_limit(tmp_path: Path, dest: Path) -> None:
    z = _zip(tmp_path / "big.zip", {"a.tf": os.urandom(600).hex().encode(), "b.tf": os.urandom(600).hex().encode()})
    with pytest.raises(UploadRejected) as exc:
        extract_zip(z, dest, UploadLimits(max_unzipped_bytes=2000))
    assert exc.value.code == "unzipped_too_large"


def test_binary_content_with_allowed_extension_is_skipped(tmp_path: Path, dest: Path) -> None:
    z = _zip(tmp_path / "bin.zip", {"evil.yaml": b"\x7fELF\x00\x00\x00", "ok.yaml": b"a: 1\n"})
    res = extract_zip(z, dest)
    assert res.files == ["ok.yaml"]
    assert res.skipped == ["evil.yaml"]
    assert not (dest / "evil.yaml").exists()


def test_not_a_zip(tmp_path: Path, dest: Path) -> None:
    p = tmp_path / "x.zip"
    p.write_bytes(b"bu zip emas")
    with pytest.raises(UploadRejected) as exc:
        extract_zip(p, dest)
    assert exc.value.code == "bad_zip"


def test_save_stream_enforces_limit_and_removes_partial(tmp_path: Path) -> None:
    target = tmp_path / "upload.bin"
    with pytest.raises(UploadRejected):
        save_stream(io.BytesIO(b"x" * 1000), target, max_bytes=999)
    assert not target.exists()
    assert save_stream(io.BytesIO(b"x" * 999), target, max_bytes=999) == 999


def test_accept_plain_file(tmp_path: Path, dest: Path) -> None:
    assert accept_plain_file(io.BytesIO(b"FROM alpine\n"), "C:\\Users\\x\\Dockerfile", dest) == "Dockerfile"
    with pytest.raises(UploadRejected):
        accept_plain_file(io.BytesIO(b"x"), "evil.exe", dest)
    with pytest.raises(UploadRejected):
        accept_plain_file(io.BytesIO(b"a\x00b"), "binary.tf", dest)
    with pytest.raises(UploadRejected):
        accept_plain_file(io.BytesIO(b"FROM a\n"), "Dockerfile", dest)  # takroriy nom


@pytest.mark.parametrize(
    ("name", "ok"),
    [
        ("main.tf", True), ("vars.tfvars", True), ("x.tf.json", True), ("k.yml", True), ("Dockerfile", True),
        ("Dockerfile.prod", True), ("web.dockerfile", True), ("Containerfile", True),
        ("app.py", False), ("id_rsa", False), (".env", False), ("x.zip", False),
    ],
)
def test_whitelist(name: str, ok: bool) -> None:
    assert is_allowed_name(name) is ok


def test_safe_relative_path_normalizes() -> None:
    assert str(safe_relative_path("./infra//prod/main.tf")) == "infra/prod/main.tf"
    assert str(safe_relative_path("infra\\prod\\main.tf")) == "infra/prod/main.tf"


def test_stage_directory_copies_only_whitelisted(tmp_path: Path, dest: Path) -> None:
    src = tmp_path / "project"
    (src / "infra").mkdir(parents=True)
    (src / ".git").mkdir()
    (src / "infra" / "main.tf").write_text("resource \"x\" \"y\" {}\n")
    (src / ".env").write_text("SECRET=1\n")
    (src / ".git" / "config.yaml").write_text("a: 1\n")
    (src / "notes.txt").write_text("x\n")
    if hasattr(os, "symlink"):
        try:
            os.symlink(src / "infra" / "main.tf", src / "link.tf")
        except OSError:
            pass
    res = stage_directory(src, dest)
    assert res.files == ["infra/main.tf"]
    assert ".env" in res.skipped and "notes.txt" in res.skipped
    assert not (dest / ".env").exists() and not (dest / ".git").exists() and not (dest / "link.tf").exists()


def _tar(path: Path, members: dict[str, bytes]) -> Path:
    with tarfile.open(path, "w") as tar:
        for name, data in members.items():
            info = tarfile.TarInfo(name)
            info.size = len(data)
            tar.addfile(info, io.BytesIO(data))
    return path


def test_validate_image_tar(tmp_path: Path) -> None:
    assert validate_image_tar(_tar(tmp_path / "d.tar", {"manifest.json": b"[]"}), 10**6) == "docker-archive"
    assert validate_image_tar(_tar(tmp_path / "o.tar", {"index.json": b"{}", "oci-layout": b"{}"}), 10**6) == "oci-archive"
    with pytest.raises(UploadRejected) as exc:
        validate_image_tar(_tar(tmp_path / "n.tar", {"readme.txt": b"x"}), 10**6)
    assert exc.value.code == "not_image"
    with pytest.raises(UploadRejected) as exc:
        validate_image_tar(_tar(tmp_path / "s.tar", {"manifest.json": b"[]", "../evil": b"x"}), 10**6)
    assert exc.value.code == "path_traversal"
    bad = tmp_path / "bad.tar"
    bad.write_bytes(b"bu tar emas" * 100)
    with pytest.raises(UploadRejected):
        validate_image_tar(bad, 10**6)
    with pytest.raises(UploadRejected) as exc:
        validate_image_tar(tmp_path / "d.tar", 10)
    assert exc.value.code == "too_large"


def test_workspace_is_removed_even_on_error(tmp_path: Path) -> None:
    root = tmp_path / "workdir"
    with pytest.raises(RuntimeError):
        with Workspace(root) as ws:
            (ws.input / "main.tf").write_text("x")
            ro = ws.input / "ro.tf"
            ro.write_text("x")
            ro.chmod(0o444)
            path = ws.path
            assert ws.input.is_dir() and ws.out.is_dir() and ws.scratch.is_dir()
            raise RuntimeError("tekshiruv xatosi")
    assert not path.exists()


def test_workspaces_are_separate(tmp_path: Path) -> None:
    with Workspace(tmp_path) as a, Workspace(tmp_path) as b:
        assert a.uid != b.uid and a.path != b.path


def test_purge_stale(tmp_path: Path) -> None:
    old = tmp_path / ("a" * 32)
    old.mkdir()
    os.utime(old, (0, 0))
    fresh = tmp_path / ("b" * 32)
    fresh.mkdir()
    assert purge_stale(tmp_path, max_age_s=3600) == ["a" * 32]
    assert fresh.exists() and not old.exists()

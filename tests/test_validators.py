"""Obraz nomini qat’iy tekshirish."""

import pytest

from bulutskan.security.validators import InvalidImageReference, is_valid_image_reference, parse_image_reference

DIGEST = "sha256:" + "a" * 64


@pytest.mark.parametrize(
    "ref",
    [
        "nginx",
        "nginx:1.21",
        "bkimminich/juice-shop:v15.0.0",
        "library/python:3.12-slim",
        "registry.example.uz/team/app:1.0",
        "registry.local:5000/team/app:2026.11",
        "localhost/app:dev",
        f"alpine@{DIGEST}",
        f"alpine:3.20@{DIGEST}",
        "a.b-c__d/e:TAG_1.x",
    ],
)
def test_valid_references(ref: str) -> None:
    assert is_valid_image_reference(ref)


@pytest.mark.parametrize(
    "ref",
    [
        "",
        "-v",
        "--privileged",
        "nginx;rm -rf /",
        "nginx && whoami",
        "$(id)",
        "`id`",
        "nginx:1.21\n",
        "nginx 1.21",
        "NGINX:1.21",
        "../etc/passwd",
        "nginx:",
        "nginx:-tag",
        "nginx@sha256:abc",
        "nginx:" + "a" * 129,
        "a" * 256,
        "nginx:1.21|cat",
        "nginx\x00",
        "/nginx",
        "nginx/",
        "registry.local:99999999/app",
    ],
)
def test_invalid_references(ref: str) -> None:
    assert not is_valid_image_reference(ref)
    with pytest.raises(InvalidImageReference):
        parse_image_reference(ref)


def test_parts_are_split() -> None:
    r = parse_image_reference("registry.local:5000/team/app:1.0")
    assert (r.domain, r.path, r.tag, r.digest) == ("registry.local:5000", "team/app", "1.0", None)
    r = parse_image_reference("bkimminich/juice-shop:v15.0.0")
    assert r.domain is None and r.path == "bkimminich/juice-shop" and r.tag == "v15.0.0"
    assert r.file_stem == "bkimminich_juice-shop_v15.0.0"

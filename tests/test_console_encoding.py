"""Windows PowerShell 5.1 da o‘zbekcha harflar buzilmasligi (UTF-8 chiqish)."""

import io
import os
import subprocess
import sys

from bulutskan.cli import configure_utf8_output

TEXT = "Jiddiylik bo‘yicha — noma’lum"


def test_cp1251_stream_is_switched_to_utf8() -> None:
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="cp1251")
    configure_utf8_output([stream])
    stream.write(TEXT)
    stream.flush()
    assert raw.getvalue().decode("utf-8") == TEXT


def test_symptom_from_windows_is_what_we_fix() -> None:
    """Sinovda ko‘rilgan belgilar: cp1251 baytlarini cp866 deb o‘qish."""
    assert "bo‘yicha".encode("cp1251").decode("cp866") == "boСyicha"
    assert "—".encode("cp1251").decode("cp866") == "Ч"


def test_utf8_stream_is_left_alone() -> None:
    raw = io.BytesIO()
    stream = io.TextIOWrapper(raw, encoding="utf-8", errors="strict")
    configure_utf8_output([stream])
    assert stream.errors == "strict"


def test_stream_without_reconfigure_is_ignored() -> None:
    configure_utf8_output([io.StringIO()])  # xato bermasligi kerak


def test_cli_writes_utf8_even_with_ansi_codepage() -> None:
    """Haqiqiy jarayon: PYTHONIOENCODING=cp1251 bo‘lsa ham CLI UTF-8 da yozadi."""
    env = {**os.environ, "PYTHONIOENCODING": "cp1251"}
    proc = subprocess.run(
        [sys.executable, "-m", "bulutskan", "scan"],
        capture_output=True,
        env=env,
        timeout=60,
        check=False,
    )
    assert proc.returncode == 2
    text = proc.stderr.decode("utf-8")
    assert "Bittasini ko‘rsating" in text

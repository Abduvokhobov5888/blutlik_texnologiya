# -*- mode: python ; coding: utf-8 -*-
"""PyInstaller: BulutSkan.exe (onedir).

Yig‘ish (loyiha ildizidan):
    pyinstaller packaging/bulutskan.spec --noconfirm --distpath dist --workpath build

Natija: dist/BulutSkan/BulutSkan.exe va dist/BulutSkan/_internal/ (Python,
kutubxonalar, shablonlar, III bob namoyish ma’lumotlari). Inno Setup shu
katalogni o‘rnatuvchiga joylaydi (packaging/bulutskan.iss).
"""

import re
import sys
from pathlib import Path

from PyInstaller.utils.hooks import collect_data_files, collect_submodules

ROOT = Path(SPECPATH).resolve().parent  # noqa: F821 - PyInstaller beradi
PKG = ROOT / "bulutskan"
VERSION = re.search(r'__version__ = "([^"]+)"', (PKG / "__init__.py").read_text(encoding="utf-8")).group(1)

datas = [
    (str(PKG / "resources"), "bulutskan/resources"),
    (str(PKG / "web" / "templates"), "bulutskan/web/templates"),
    (str(PKG / "web" / "static"), "bulutskan/web/static"),
    (str(PKG / "web" / "i18n"), "bulutskan/web/i18n"),
    # III bob eksperimentining real hisobotlari: Docker’siz namoyish rejimi uchun.
    (str(ROOT / "demo" / "sinov" / "natijalar"), "demo/sinov/natijalar"),
]
datas += collect_data_files("docx")  # python-docx shablonlari (default.docx)

hiddenimports = (
    collect_submodules("bulutskan")
    + collect_submodules("uvicorn")
    + ["sqlalchemy.dialects.sqlite", "multipart", "python_multipart"]
)

a = Analysis(  # noqa: F821
    [str(PKG / "launcher.py")],
    pathex=[str(ROOT)],
    binaries=[],
    datas=datas,
    hiddenimports=hiddenimports,
    hookspath=[],
    runtime_hooks=[],
    excludes=["tkinter", "pytest", "mypy", "IPython", "matplotlib", "numpy", "pandas"],
    noarchive=False,
)
pyz = PYZ(a.pure)  # noqa: F821

version_file = None
if sys.platform == "win32":
    from PyInstaller.utils.win32.versioninfo import (
        FixedFileInfo,
        StringFileInfo,
        StringStruct,
        StringTable,
        VarFileInfo,
        VarStruct,
        VSVersionInfo,
    )

    nums = tuple(int(x) for x in (VERSION.split(".") + ["0", "0", "0"])[:4])
    version_file = VSVersionInfo(
        ffi=FixedFileInfo(filevers=nums, prodvers=nums),
        kids=[
            StringFileInfo([StringTable("040904B0", [
                StringStruct("CompanyName", "Andijon davlat universiteti"),
                StringStruct("FileDescription", "BulutSkan — IaC va konteyner obrazlarini tekshirish"),
                StringStruct("FileVersion", VERSION),
                StringStruct("InternalName", "BulutSkan"),
                StringStruct("LegalCopyright", "MIT litsenziyasi"),
                StringStruct("OriginalFilename", "BulutSkan.exe"),
                StringStruct("ProductName", "BulutSkan"),
                StringStruct("ProductVersion", VERSION),
            ])]),
            VarFileInfo([VarStruct("Translation", [0x0409, 1200])]),
        ],
    )

exe = EXE(  # noqa: F821
    pyz,
    a.scripts,
    [],
    exclude_binaries=True,
    name="BulutSkan",
    console=True,  # oyna: server manzili va jurnal; oynani yopish dasturni to‘xtatadi
    icon=str(ROOT / "packaging" / "bulutskan.ico"),
    version=version_file,
    upx=False,
)
coll = COLLECT(  # noqa: F821
    exe,
    a.binaries,
    a.datas,
    upx=False,
    name="BulutSkan",
)

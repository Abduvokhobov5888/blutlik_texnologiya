"""O‘rnatilgan dastur (``BulutSkan.exe``) kirish nuqtasi.

Argumentsiz ishga tushirilsa (ish stolidagi belgi), veb-interfeys ochiladi:
``bulutskan serve``. Argument berilsa, oddiy CLI kabi ishlaydi:
``BulutSkan.exe scan --iac ...``.
"""

from __future__ import annotations

import multiprocessing
import sys


def main() -> None:
    multiprocessing.freeze_support()
    if len(sys.argv) == 1:
        sys.argv.append("serve")
    from bulutskan.cli import app

    app()


if __name__ == "__main__":
    main()

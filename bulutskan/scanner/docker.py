"""Docker buyruqlarini xavfsiz qurish va ishga tushirish.

Qoidalar:

* buyruq faqat argumentlar ro‘yxati sifatida yuboriladi, ``shell=True`` yo‘q;
* ``docker`` jarayoniga xost muhitining faqat zarur o‘zgaruvchilari beriladi;
* konteynerga muhit o‘zgaruvchisi faqat ``KALIT=qiymat`` ko‘rinishida beriladi
  (``--env KALIT`` xost qiymatini o‘tkazib yuborardi), ``--env-file`` yo‘q;
* har bir skaner: ``--rm --pull never --network none --read-only``,
  ``--cap-drop ALL``, ``no-new-privileges``, CPU, xotira va PID limitlari;
* ``docker.sock`` va xost kataloglari ulanmaydi: faqat aniq ko‘rsatilgan
  ``Mount`` lar.
"""

from __future__ import annotations

import json
import os
import re
import subprocess
import sys
import time
from collections.abc import Mapping, Sequence
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Protocol

_ENV_NAME = re.compile(r"^[A-Za-z_][A-Za-z0-9_]*$")
_CONTAINER_NAME = re.compile(r"^[a-z0-9][a-z0-9_.-]{0,127}$")
_TARGET = re.compile(r"^/[A-Za-z0-9_./-]*$")

#: Proksi o‘zgaruvchilari. Ular faqat bazalarni yangilash konteyneriga
#: (``network="bridge"``) beriladi.
#:
#: Tarmoqsiz skaner konteynerlariga bu o‘zgaruvchilar **umuman berilmaydi**,
#: hatto bo‘sh qiymat bilan ham. Checkov 3.3.26 proksini
#: ``os.environ['https_proxy']`` bilan o‘qiydi
#: (``checkov/common/bridgecrew/platform_integration.py``,
#: ``setup_http_manager``) va faqat o‘zgaruvchi yo‘q bo‘lsa (``KeyError``)
#: proksisiz ishlaydi. Bo‘sh qiymat ``urllib3.ProxyManager("")`` ni chaqiradi
#: va Checkov ``ProxySchemeUnknown`` bilan 2 kodida yiqiladi. Windows’dagi
#: sinovda aynan shunday bo‘lgan. ``run_tests.ps1`` ham bu o‘zgaruvchilarni
#: bermagan.
PROXY_VARS: tuple[str, ...] = ("HTTP_PROXY", "HTTPS_PROXY", "NO_PROXY", "http_proxy", "https_proxy", "no_proxy")

#: ``docker`` jarayoniga beriladigan xost o‘zgaruvchilari.
_HOST_ENV_ALLOW: tuple[str, ...] = (
    "PATH", "PATHEXT", "SYSTEMROOT", "SYSTEMDRIVE", "WINDIR", "COMSPEC", "TEMP", "TMP", "TMPDIR",
    "USERPROFILE", "APPDATA", "LOCALAPPDATA", "PROGRAMDATA", "PROGRAMFILES", "HOMEDRIVE", "HOMEPATH",
    "HOME", "LANG", "LC_ALL", "XDG_RUNTIME_DIR",
    "DOCKER_HOST", "DOCKER_CONTEXT", "DOCKER_CONFIG", "DOCKER_CERT_PATH", "DOCKER_TLS_VERIFY",
)


class DockerError(RuntimeError):
    """Docker buyrug‘i bajarilmadi."""


class DockerUnavailable(DockerError):
    """Docker ishlamayapti yoki o‘rnatilmagan."""


@dataclass(frozen=True)
class Mount:
    """Konteynerga ulanadigan xost katalogi yoki fayli."""

    source: Path
    target: str
    read_only: bool = True

    def argument(self) -> str:
        """``--mount`` qiymati.

        ``-v`` o‘rniga ``--mount`` ishlatiladi: Windows yo‘lidagi ``D:``
        ikki nuqtasi ``-v`` sintaksisini buzadi.
        """
        src = str(self.source)
        if not Path(src).is_absolute():
            raise ValueError(f"Mount manbasi absolyut yo‘l bo‘lishi kerak: {src}")
        if any(ch in src for ch in (",", '"', "\n", "\r", "\x00")):
            raise ValueError(f"Mount yo‘lida ruxsat etilmagan belgi bor (vergul yoki qo‘shtirnoq): {src}")
        if not _TARGET.fullmatch(self.target) or ".." in self.target.split("/"):
            raise ValueError(f"Noto‘g‘ri mount manzili: {self.target}")
        arg = f"type=bind,source={src},target={self.target}"
        return arg + ",readonly" if self.read_only else arg


@dataclass(frozen=True)
class ContainerSpec:
    """Skaner konteynerining tavsifi."""

    image: str
    args: tuple[str, ...]
    name: str
    mounts: tuple[Mount, ...] = ()
    env: Mapping[str, str] = field(default_factory=dict)
    network: str = "none"
    cpus: str = "2"
    memory: str = "2g"
    pids: int = 512
    tmpfs_size: str = "512m"


def build_run_command(docker_bin: str, spec: ContainerSpec) -> list[str]:
    """``docker run`` uchun to‘liq argumentlar ro‘yxati."""
    if not _CONTAINER_NAME.fullmatch(spec.name):
        raise ValueError(f"Noto‘g‘ri konteyner nomi: {spec.name}")
    if spec.network not in {"none", "bridge"}:
        raise ValueError("Tarmoq faqat 'none' yoki 'bridge' bo‘lishi mumkin")
    if spec.image.startswith("-") or not spec.image:
        raise ValueError("Noto‘g‘ri obraz havolasi")
    cmd = [
        docker_bin, "run",
        "--rm",
        "--pull", "never",
        "--name", spec.name,
        "--network", spec.network,
        "--read-only",
        "--tmpfs", f"/tmp:rw,nosuid,nodev,size={spec.tmpfs_size}",
        "--cap-drop", "ALL",
        "--security-opt", "no-new-privileges",
        "--cpus", spec.cpus,
        "--memory", spec.memory,
        "--memory-swap", spec.memory,
        "--pids-limit", str(spec.pids),
    ]
    if spec.network == "none":
        leaked = sorted(set(spec.env) & set(PROXY_VARS))
        if leaked:
            raise ValueError(f"Tarmoqsiz konteynerga proksi o‘zgaruvchisi berilmaydi: {', '.join(leaked)}")
    env: dict[str, str] = {"HOME": "/tmp"}
    env.update(spec.env)
    for key, value in env.items():
        if not _ENV_NAME.fullmatch(key):
            raise ValueError(f"Noto‘g‘ri muhit o‘zgaruvchisi nomi: {key}")
        if any(ch in value for ch in ("\n", "\r", "\x00")):
            raise ValueError(f"Muhit o‘zgaruvchisi qiymatida yangi qator bor: {key}")
        cmd += ["--env", f"{key}={value}"]
    for mount in spec.mounts:
        cmd += ["--mount", mount.argument()]
    cmd.append(spec.image)
    cmd.extend(spec.args)
    return cmd


def host_environment(source: Mapping[str, str] | None = None) -> dict[str, str]:
    """``docker`` jarayoni uchun minimal xost muhiti (maxfiy o‘zgaruvchilarsiz)."""
    src = os.environ if source is None else source
    return {k: src[k] for k in _HOST_ENV_ALLOW if k in src}


@dataclass
class RunResult:
    """Buyruq natijasi."""

    argv: list[str]
    returncode: int
    stdout: bytes
    stderr: bytes
    duration_s: float
    timed_out: bool = False

    @property
    def stderr_text(self) -> str:
        return self.stderr.decode("utf-8", errors="replace")

    @property
    def stdout_text(self) -> str:
        return self.stdout.decode("utf-8", errors="replace")


class CommandRunner(Protocol):
    """Buyruqni ishga tushiruvchi (testlarda soxtasi bilan almashtiriladi)."""

    def run(self, argv: Sequence[str], timeout: float, stdout_path: Path | None = None) -> RunResult: ...


class SubprocessRunner:
    """Haqiqiy ishga tushirgich: ``subprocess.run``, ``shell=False``."""

    def run(self, argv: Sequence[str], timeout: float, stdout_path: Path | None = None) -> RunResult:
        args = [str(a) for a in argv]
        start = time.monotonic()
        creationflags = 0x08000000 if sys.platform == "win32" else 0  # CREATE_NO_WINDOW
        try:
            if stdout_path is not None:
                with stdout_path.open("wb") as sink:
                    proc = subprocess.run(
                        args,
                        shell=False,
                        stdin=subprocess.DEVNULL,
                        stdout=sink,
                        stderr=subprocess.PIPE,
                        timeout=timeout,
                        env=host_environment(),
                        check=False,
                        creationflags=creationflags,
                    )
                stdout = b""
            else:
                proc = subprocess.run(
                    args,
                    shell=False,
                    stdin=subprocess.DEVNULL,
                    capture_output=True,
                    timeout=timeout,
                    env=host_environment(),
                    check=False,
                    creationflags=creationflags,
                )
                stdout = proc.stdout
        except FileNotFoundError as exc:
            raise DockerUnavailable(f"Buyruq topilmadi: {args[0]}") from exc
        except subprocess.TimeoutExpired as exc:
            partial = exc.stdout if isinstance(exc.stdout, bytes) else b""
            err = exc.stderr if isinstance(exc.stderr, bytes) else b""
            return RunResult(args, -1, partial, err, time.monotonic() - start, timed_out=True)
        return RunResult(args, proc.returncode, stdout, proc.stderr or b"", time.monotonic() - start)


class DockerClient:
    """Platformaga kerakli Docker amallari."""

    def __init__(self, runner: CommandRunner | None = None, docker_bin: str = "docker") -> None:
        self.runner: CommandRunner = runner or SubprocessRunner()
        self.docker_bin = docker_bin

    def _run(self, args: Sequence[str], timeout: float = 60, stdout_path: Path | None = None) -> RunResult:
        return self.runner.run([self.docker_bin, *args], timeout=timeout, stdout_path=stdout_path)

    def server_version(self) -> str:
        """Docker server versiyasi; ishlamasa :class:`DockerUnavailable`."""
        try:
            res = self._run(["version", "--format", "{{.Server.Version}}"], timeout=30)
        except DockerUnavailable:
            raise
        if res.returncode != 0 or not res.stdout_text.strip():
            raise DockerUnavailable(res.stderr_text.strip() or "Docker serveri javob bermadi")
        return res.stdout_text.strip()

    def available(self) -> bool:
        """Docker ishlayaptimi."""
        try:
            self.server_version()
        except DockerUnavailable:
            return False
        return True

    def image_inspect(self, ref: str) -> dict[str, Any] | None:
        """Obraz ma’lumotlari; obraz yo‘q bo‘lsa ``None``."""
        if ref.startswith("-"):
            raise ValueError("Noto‘g‘ri obraz havolasi")
        res = self._run(["image", "inspect", "--format", "{{json .}}", ref], timeout=60)
        if res.returncode != 0:
            return None
        try:
            data = json.loads(res.stdout_text)
        except json.JSONDecodeError:
            return None
        return data if isinstance(data, dict) else None

    def pull(self, ref: str, timeout: float) -> RunResult:
        """Obrazni yuklab oladi (tarmoqni Docker Desktop o‘zi boshqaradi)."""
        if ref.startswith("-"):
            raise ValueError("Noto‘g‘ri obraz havolasi")
        return self._run(["pull", "--quiet", ref], timeout=timeout)

    def save(self, ref: str, dest: Path, timeout: float) -> RunResult:
        """``docker save -o dest ref``."""
        if ref.startswith("-"):
            raise ValueError("Noto‘g‘ri obraz havolasi")
        return self._run(["save", "-o", str(dest), ref], timeout=timeout)

    def run_container(self, spec: ContainerSpec, timeout: float, stdout_path: Path | None = None) -> RunResult:
        """Konteynerni ishga tushiradi; vaqt tugasa uni majburan to‘xtatadi."""
        argv = build_run_command(self.docker_bin, spec)
        res = self.runner.run(argv, timeout=timeout, stdout_path=stdout_path)
        if res.timed_out:
            self.kill(spec.name)
        return res

    def remove_image(self, ref: str) -> None:
        """Foydalanuvchi obrazini o‘chiradi (server rejimi; xatolar e’tiborsiz)."""
        if ref and not ref.startswith("-"):
            self._run(["image", "rm", ref], timeout=120)

    def kill(self, name: str) -> None:
        """Konteynerni to‘xtatadi (xatolar e’tiborsiz)."""
        if _CONTAINER_NAME.fullmatch(name):
            self._run(["kill", name], timeout=30)

    def info_field(self, template: str) -> str:
        """``docker info --format`` qiymati (bo‘sh bo‘lishi mumkin)."""
        res = self._run(["info", "--format", template], timeout=30)
        return res.stdout_text.strip() if res.returncode == 0 else ""

    def build(self, dockerfile: Path, context: Path, tag: str, build_args: Mapping[str, str], timeout: float) -> RunResult:
        """``docker build`` (Checkov obrazini yig‘ish uchun)."""
        args = ["build", "-f", str(dockerfile), "-t", tag]
        for key, value in build_args.items():
            if not _ENV_NAME.fullmatch(key):
                raise ValueError(f"Noto‘g‘ri build-arg nomi: {key}")
            args += ["--build-arg", f"{key}={value}"]
        args.append(str(context))
        return self._run(args, timeout=timeout)

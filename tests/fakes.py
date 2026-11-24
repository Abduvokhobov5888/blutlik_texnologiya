"""Docker’siz testlar uchun soxta ``docker`` buyrug‘i.

:class:`FakeDocker` platformaning ``CommandRunner`` interfeysini amalga
oshiradi: ``docker run`` chaqiruvlarini qabul qiladi, argumentlarni yozib
boradi va eksperimentdagi real JSON hisobotlarni vosita chiqishi sifatida
qaytaradi. Shunday qilib butun quvur (skaner → parser → konsensus → CLI)
haqiqiy ma’lumotlar bilan, lekin Docker’siz tekshiriladi.
"""

from __future__ import annotations

import io
import json
import tarfile
from collections.abc import Sequence
from dataclasses import dataclass, field
from pathlib import Path

from bulutskan.config import Settings
from bulutskan.core.models import Tool
from bulutskan.scanner.docker import RunResult
from bulutskan.scanner.tools import load_tool_digests
from tests.conftest import IAC_RUN, IMAGES_DIR, file_stem

CHECKOV_ID = "sha256:" + "c" * 64


def make_docker_archive(path: Path) -> None:
    """``docker save`` natijasiga o‘xshash minimal arxiv (manifest.json bilan)."""
    with tarfile.open(path, "w") as tar:
        data = json.dumps([{"Config": "config.json", "RepoTags": ["x:1"], "Layers": []}]).encode()
        info = tarfile.TarInfo("manifest.json")
        info.size = len(data)
        tar.addfile(info, io.BytesIO(data))


@dataclass
class FakeDocker:
    """Soxta docker."""

    settings: Settings
    image_fixture: str = "nginx:1.21"
    available: bool = True
    proxy: str = ""
    images: dict[str, dict[str, object]] = field(default_factory=dict)
    fail: dict[Tool, tuple[int, str]] = field(default_factory=dict)
    readonly_fail: set[Tool] = field(default_factory=set)
    pull_fail: bool = False
    calls: list[list[str]] = field(default_factory=list)

    def __post_init__(self) -> None:
        self.registry = load_tool_digests(self.settings.tool_digests_file)
        self.ref_tool: dict[str, Tool] = {img.digest_ref: tool for tool, img in self.registry.images.items()}
        self.ref_tool[CHECKOV_ID] = Tool.CHECKOV

    # ---------------------------------------------------------- sozlash

    def install_tools(self) -> None:
        """Barcha vositalar obrazlari "bor" va Checkov qulflangan."""
        for img in self.registry.images.values():
            info: dict[str, object] = {"Id": "sha256:" + img.digest[7:], "RepoDigests": [img.digest_ref]}
            self.images[img.digest_ref] = info
            self.images[img.tag_ref] = info
        self.images[CHECKOV_ID] = {"Id": CHECKOV_ID, "RepoDigests": []}
        self.images[self.registry.checkov_tag] = {"Id": CHECKOV_ID, "RepoDigests": []}
        lock = self.settings.tool_lock_file
        lock.parent.mkdir(parents=True, exist_ok=True)
        lock.write_text(json.dumps({"checkov": {"image_id": CHECKOV_ID, "tag": self.registry.checkov_tag}}))

    def install_databases(self) -> None:
        """Bazalar fayllari (bo‘sh) mavjud."""
        (self.settings.trivy_cache / "db").mkdir(parents=True, exist_ok=True)
        (self.settings.trivy_cache / "db" / "trivy.db").write_bytes(b"")
        (self.settings.trivy_cache / "java-db").mkdir(parents=True, exist_ok=True)
        (self.settings.grype_cache / "6").mkdir(parents=True, exist_ok=True)
        (self.settings.grype_cache / "6" / "vulnerability.db").write_bytes(b"")

    # ---------------------------------------------------------- yordamchi

    def runs(self) -> list[list[str]]:
        """Faqat ``docker run`` chaqiruvlari."""
        return [c for c in self.calls if len(c) > 1 and c[1] == "run"]

    def run_for(self, tool: Tool) -> list[list[str]]:
        return [c for c in self.runs() if self._tool_of(c) is tool]

    def _tool_of(self, argv: Sequence[str]) -> Tool | None:
        for token in argv:
            if token in self.ref_tool:
                return self.ref_tool[token]
        return None

    @staticmethod
    def _mounts(argv: Sequence[str]) -> dict[str, tuple[Path, bool]]:
        out: dict[str, tuple[Path, bool]] = {}
        for i, token in enumerate(argv):
            if token == "--mount":
                parts: dict[str, str] = {}
                for p in argv[i + 1].split(","):
                    key, _, value = p.partition("=")
                    parts[key] = value
                out[parts["target"]] = (Path(parts["source"]), "readonly" in parts)
        return out

    @staticmethod
    def _ok(argv: Sequence[str], stdout: bytes = b"", code: int = 0, stderr: bytes = b"") -> RunResult:
        return RunResult(list(argv), code, stdout, stderr, 0.01)

    # ---------------------------------------------------------- runner

    def run(self, argv: Sequence[str], timeout: float, stdout_path: Path | None = None) -> RunResult:
        argv = [str(a) for a in argv]
        self.calls.append(argv)
        cmd = argv[1:]
        if not self.available:
            return self._ok(argv, code=1, stderr=b"Cannot connect to the Docker daemon")
        if cmd[:1] == ["version"]:
            return self._ok(argv, b"27.3.1\n")
        if cmd[:2] == ["image", "inspect"]:
            info = self.images.get(cmd[-1])
            return self._ok(argv, json.dumps(info).encode()) if info else self._ok(argv, code=1, stderr=b"No such image")
        if cmd[:1] == ["info"]:
            return self._ok(argv, (self.proxy + "\n").encode() if "HTTPSProxy" in cmd[-1] else b"\n")
        if cmd[:1] == ["pull"]:
            return self._ok(argv, code=1 if self.pull_fail else 0, stderr=b"pull access denied" if self.pull_fail else b"")
        if cmd[:1] == ["save"]:
            make_docker_archive(Path(cmd[cmd.index("-o") + 1]))
            return self._ok(argv)
        if cmd[:1] in (["kill"], ["build"]):
            return self._ok(argv)
        if cmd[:1] == ["run"]:
            return self._docker_run(argv, stdout_path)
        raise AssertionError(f"Kutilmagan docker buyrug‘i: {argv}")

    def _docker_run(self, argv: list[str], stdout_path: Path | None) -> RunResult:
        tool = self._tool_of(argv)
        assert tool is not None, f"Noma’lum obraz: {argv}"
        mounts = self._mounts(argv)
        args = argv[argv.index(next(t for t in argv if t in self.ref_tool)) + 1 :]

        if args == ["--version"]:
            return self._ok(argv, b"3.3.26\n")
        if tool in self.fail:
            code, err = self.fail[tool]
            return self._ok(argv, code=code, stderr=err.encode())
        if "--download-db-only" in args or "--download-java-db-only" in args:
            cache = mounts["/cache"][0]
            sub = "db" if "--download-db-only" in args else "java-db"
            (cache / sub).mkdir(parents=True, exist_ok=True)
            (cache / sub / ("trivy.db" if sub == "db" else "trivy-java.db")).write_bytes(b"")
            meta = {"Version": 2, "UpdatedAt": "2026-11-24T07:08:30Z", "NextUpdate": "2026-11-25T07:08:30Z",
                    "DownloadedAt": "2026-11-24T12:25:41Z"}
            (cache / sub / "metadata.json").write_text(json.dumps(meta))
            return self._ok(argv)
        if args[:2] == ["db", "update"]:
            cache = mounts["/cache"][0]
            (cache / "6").mkdir(parents=True, exist_ok=True)
            (cache / "6" / "vulnerability.db").write_bytes(b"")
            return self._ok(argv)
        if args[:2] == ["db", "status"]:
            return self._ok(argv, (IMAGES_DIR.parent / "grype_db_status.txt").read_bytes())

        if tool in self.readonly_fail and any(ro for target, (_, ro) in mounts.items() if target.startswith(("/cache", "/tmp/trivy"))):
            return self._ok(argv, code=1, stderr=b"FATAL: failed to open db: open /tmp/trivy/db/trivy.db: read-only file system")

        if tool is Tool.CHECKOV:
            report = (IAC_RUN / "checkov" / "results_json.json").read_text(encoding="utf-8-sig")
            (mounts["/out"][0] / "results_json.json").write_text(report.replace('"/iac/', '"/scan/'), encoding="utf-8")
            return self._ok(argv, code=1)
        if tool is Tool.KICS:
            report = (IAC_RUN / "kics" / "results.json").read_text(encoding="utf-8-sig")
            (mounts["/out"][0] / "results.json").write_text(report.replace("../../iac/", "../../scan/"), encoding="utf-8")
            return self._ok(argv, code=60)
        if tool is Tool.TRIVY and args[0] == "config":
            assert stdout_path is not None
            stdout_path.write_bytes((IAC_RUN / "trivy_config.json").read_bytes())
            return self._ok(argv)
        stem = file_stem(self.image_fixture)
        assert stdout_path is not None
        name = f"trivy_{stem}_run1.json" if tool is Tool.TRIVY else f"grype_{stem}_run1.json"
        stdout_path.write_bytes((IMAGES_DIR / name).read_bytes())
        return self._ok(argv)

"""IaC tekshiruvi: Checkov, KICS va Trivy (config rejimi).

Argumentlar eksperimentdagi ``run_tests.ps1`` dan olingan. Tekshiriladigan
fayllar ``/scan`` ga faqat o‘qish uchun ulanadi. Checkov va KICS natijani
faylga yozadi (eksperimentdagi kabi), shuning uchun ularga alohida bo‘sh
``out/`` katalogi yozish uchun ulanadi.
"""

from __future__ import annotations

import shutil
from pathlib import Path

from bulutskan.config import Settings
from bulutskan.core.models import Tool
from bulutskan.parsers import parse_checkov, parse_kics, parse_trivy_config
from bulutskan.scanner.docker import ContainerSpec, DockerClient, Mount, RunResult
from bulutskan.scanner.runs import ToolRun, finish_run
from bulutskan.scanner.tools import IntegrityReport
from bulutskan.security.workspace import Workspace

MOUNT = "scan"
SCAN_DIR = f"/{MOUNT}"

CHECKOV_ARGS: tuple[str, ...] = (
    "-d", SCAN_DIR, "--skip-download", "--quiet", "-o", "json", "--output-file-path", "/out",
)
KICS_ARGS: tuple[str, ...] = ("scan", "-p", SCAN_DIR, "-o", "/out", "--report-formats", "json", "--no-progress")
TRIVY_CONFIG_ARGS: tuple[str, ...] = ("config", "--skip-check-update", "--format", "json", SCAN_DIR)

IAC_TOOLS: tuple[Tool, ...] = (Tool.CHECKOV, Tool.KICS, Tool.TRIVY)


def _spec(settings: Settings, ws: Workspace, tool: Tool, image: str, args: tuple[str, ...], mounts: tuple[Mount, ...]) -> ContainerSpec:
    return ContainerSpec(
        image=image,
        args=args,
        name=f"bulutskan-{ws.uid[:16]}-{tool.value}",
        mounts=mounts,
        cpus=settings.container_cpus,
        memory=settings.container_memory,
        pids=settings.container_pids,
        tmpfs_size=settings.container_tmpfs,
    )


def _run_with_out_dir(
    client: DockerClient,
    settings: Settings,
    ws: Workspace,
    tool: Tool,
    image: str,
    args: tuple[str, ...],
    source: Mount,
    produced_name: str,
    raw: Path,
) -> RunResult:
    """Natijani ``/out`` ga yozadigan vositani ishga tushiradi va faylni ``raw`` ga ko‘chiradi."""
    out = ws.out / tool.value
    out.mkdir(parents=True, exist_ok=True)
    res = client.run_container(
        _spec(settings, ws, tool, image, args, (source, Mount(out, "/out", read_only=False))),
        settings.scan_timeout_s,
    )
    produced = out / produced_name
    if produced.is_file():
        shutil.copyfile(produced, raw)
    return res


def run_iac_tools(
    client: DockerClient,
    integrity: IntegrityReport,
    settings: Settings,
    ws: Workspace,
    report_dir: Path,
    tools: tuple[Tool, ...] = IAC_TOOLS,
) -> list[ToolRun]:
    """IaC fayllarini (``ws.input``) tanlangan vositalar bilan tekshiradi."""
    report_dir.mkdir(parents=True, exist_ok=True)
    source = Mount(ws.input, SCAN_DIR, read_only=True)
    runs: list[ToolRun] = []
    for tool in tools:
        image = integrity.run_ref(tool)
        if tool is Tool.CHECKOV:
            raw = report_dir / "checkov.json"
            res = _run_with_out_dir(client, settings, ws, tool, image, CHECKOV_ARGS, source, "results_json.json", raw)
            runs.append(finish_run(tool, image, res, raw, lambda d: parse_checkov(d, mount=MOUNT)))
        elif tool is Tool.KICS:
            raw = report_dir / "kics.json"
            res = _run_with_out_dir(client, settings, ws, tool, image, KICS_ARGS, source, "results.json", raw)
            runs.append(finish_run(tool, image, res, raw, lambda d: parse_kics(d, mount=MOUNT)))
        elif tool is Tool.TRIVY:
            raw = report_dir / "trivy_config.json"
            res = client.run_container(
                _spec(settings, ws, tool, image, TRIVY_CONFIG_ARGS, (source,)), settings.scan_timeout_s, stdout_path=raw
            )
            runs.append(finish_run(tool, image, res, raw, lambda d: parse_trivy_config(d, mount=MOUNT)))
        else:
            raise ValueError(f"{tool.value} IaC vositasi emas")
    return runs

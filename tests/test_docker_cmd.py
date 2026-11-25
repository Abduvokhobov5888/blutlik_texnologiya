"""Skaner konteyneri buyrug‘i: majburiy xavfsizlik bayroqlari va shell=False."""

import subprocess
from pathlib import Path

import pytest

from bulutskan.scanner.docker import (
    PROXY_VARS,
    ContainerSpec,
    Mount,
    SubprocessRunner,
    build_run_command,
    host_environment,
)

IMAGE = "aquasec/trivy@sha256:" + "a" * 64


def _spec(tmp_path: Path, **kw: object) -> ContainerSpec:
    data: dict[str, object] = {
        "image": IMAGE,
        "args": ("config", "/scan"),
        "name": "bulutskan-abc-trivy",
        "mounts": (Mount(tmp_path, "/scan"),),
    }
    data.update(kw)
    return ContainerSpec(**data)  # type: ignore[arg-type]


def _pairs(cmd: list[str]) -> set[tuple[str, str]]:
    return set(zip(cmd, cmd[1:], strict=False))


def test_mandatory_isolation_flags(tmp_path: Path) -> None:
    cmd = build_run_command("docker", _spec(tmp_path))
    assert cmd[:2] == ["docker", "run"]
    assert "--rm" in cmd and "--read-only" in cmd
    pairs = _pairs(cmd)
    for pair in [
        ("--pull", "never"),
        ("--network", "none"),
        ("--cap-drop", "ALL"),
        ("--security-opt", "no-new-privileges"),
        ("--cpus", "2"),
        ("--memory", "2g"),
        ("--memory-swap", "2g"),
        ("--pids-limit", "512"),
    ]:
        assert pair in pairs, pair
    assert any(c.startswith("/tmp:rw,nosuid,nodev,size=") for c in cmd)
    assert "--privileged" not in cmd
    assert not any("docker.sock" in c for c in cmd)
    # Obraz digest orqali va argumentlardan oldin.
    assert cmd[-3:] == [IMAGE, "config", "/scan"]


def test_scanned_files_are_mounted_read_only(tmp_path: Path) -> None:
    cmd = build_run_command("docker", _spec(tmp_path))
    mount = cmd[cmd.index("--mount") + 1]
    assert mount == f"type=bind,source={tmp_path},target=/scan,readonly"
    assert "-v" not in cmd and "--volume" not in cmd


def test_no_proxy_variables_without_network(tmp_path: Path) -> None:
    """Tarmoqsiz konteynerga proksi o‘zgaruvchisi umuman berilmaydi, bo‘sh qiymat bilan ham.

    Windows’dagi sinovda bo‘sh ``https_proxy=`` Checkov 3.3.26 ni
    ``ProxySchemeUnknown`` bilan yiqitgan: Checkov ``os.environ['https_proxy']``
    ni o‘qiydi va faqat o‘zgaruvchi yo‘q bo‘lsa proksisiz ishlaydi.
    ``run_tests.ps1`` ham bu o‘zgaruvchilarni bermagan.
    """
    cmd = build_run_command("docker", _spec(tmp_path))
    envs = [cmd[i + 1] for i, c in enumerate(cmd) if c == "--env"]
    names = {e.split("=", 1)[0] for e in envs}
    assert not names & set(PROXY_VARS)
    assert not any(e.lower().startswith(("http_proxy", "https_proxy", "no_proxy")) for e in envs)
    assert envs == ["HOME=/tmp"]
    # Har bir --env qiymati KALIT=qiymat ko‘rinishida: xost qiymati o‘tib ketmaydi.
    assert all("=" in e for e in envs)
    assert "--env-file" not in cmd


@pytest.mark.parametrize("var", PROXY_VARS)
def test_proxy_cannot_be_passed_to_offline_container(tmp_path: Path, var: str) -> None:
    with pytest.raises(ValueError, match="proksi"):
        build_run_command("docker", _spec(tmp_path, env={var: "http://proxy:3128"}))


def test_checkov_proxy_error_is_explained() -> None:
    from bulutskan.scanner.docker import RunResult
    from bulutskan.scanner.runs import explain_failure

    stderr = (
        b'File "/usr/local/lib/python3.12/site-packages/checkov/main.py", line 306\n'
        b"urllib3.exceptions.ProxySchemeUnknown: Proxy URL had no scheme, should start with http:// or https://"
    )
    msg = explain_failure(RunResult(["docker", "run"], 2, b"", stderr, 1.0))
    assert "sxemasiz" in msg and "http://" in msg and "Proxies" in msg


def test_bridge_network_keeps_given_proxy(tmp_path: Path) -> None:
    cmd = build_run_command(
        "docker", _spec(tmp_path, network="bridge", env={"HTTPS_PROXY": "http://proxy:3128"})
    )
    envs = [cmd[i + 1] for i, c in enumerate(cmd) if c == "--env"]
    assert "HTTPS_PROXY=http://proxy:3128" in envs
    assert "HTTPS_PROXY=" not in envs


@pytest.mark.parametrize(
    "kw",
    [
        {"name": "Bad Name"},
        {"network": "host"},
        {"image": "--privileged"},
        {"env": {"BAD-NAME": "x"}},
        {"env": {"X": "a\nb"}},
    ],
)
def test_invalid_specs_are_rejected(tmp_path: Path, kw: dict[str, object]) -> None:
    with pytest.raises(ValueError):
        build_run_command("docker", _spec(tmp_path, **kw))


@pytest.mark.parametrize("bad", ["relative/path", "/data/a,b", '/data/"x'])
def test_mount_rejects_unsafe_sources(bad: str) -> None:
    with pytest.raises(ValueError):
        Mount(Path(bad), "/scan").argument()


def test_mount_rejects_bad_target(tmp_path: Path) -> None:
    with pytest.raises(ValueError):
        Mount(tmp_path, "/scan/../etc").argument()
    with pytest.raises(ValueError):
        Mount(tmp_path, "relative").argument()


def test_mount_with_spaces_in_windows_like_path(tmp_path: Path) -> None:
    src = tmp_path / "Dissertatsiyaga oid" / "BulutSkan"
    src.mkdir(parents=True)
    assert Mount(src, "/scan", read_only=False).argument() == f"type=bind,source={src},target=/scan"


def test_host_environment_drops_secrets() -> None:
    env = host_environment(
        {
            "PATH": "/usr/bin",
            "DOCKER_HOST": "npipe:////./pipe/docker_engine",
            "AWS_SECRET_ACCESS_KEY": "maxfiy",
            "GITHUB_TOKEN": "maxfiy",
            "BULUTSKAN_SECRET_KEY": "maxfiy",
            "HTTPS_PROXY": "http://user:parol@proxy:3128",
        }
    )
    assert env == {"PATH": "/usr/bin", "DOCKER_HOST": "npipe:////./pipe/docker_engine"}


def test_subprocess_runner_uses_argument_list_without_shell(monkeypatch: pytest.MonkeyPatch, tmp_path: Path) -> None:
    captured: dict[str, object] = {}

    def fake_run(args: list[str], **kwargs: object) -> subprocess.CompletedProcess[bytes]:
        captured["args"] = args
        captured.update(kwargs)
        return subprocess.CompletedProcess(args, 0, b"ok", b"")

    monkeypatch.setenv("AWS_SECRET_ACCESS_KEY", "maxfiy")
    monkeypatch.setattr(subprocess, "run", fake_run)
    res = SubprocessRunner().run(["docker", "version"], timeout=5)
    assert res.returncode == 0 and res.stdout == b"ok"
    assert isinstance(captured["args"], list)
    assert captured["shell"] is False
    env = captured["env"]
    assert isinstance(env, dict) and "AWS_SECRET_ACCESS_KEY" not in env
    assert captured["stdin"] is subprocess.DEVNULL


def test_subprocess_runner_reports_timeout(monkeypatch: pytest.MonkeyPatch) -> None:
    def fake_run(args: list[str], **kwargs: object) -> None:
        raise subprocess.TimeoutExpired(args, 1)

    monkeypatch.setattr(subprocess, "run", fake_run)
    res = SubprocessRunner().run(["docker", "run"], timeout=1)
    assert res.timed_out and res.returncode == -1


def test_subprocess_runner_missing_binary() -> None:
    from bulutskan.scanner.docker import DockerUnavailable

    with pytest.raises(DockerUnavailable):
        SubprocessRunner().run(["bulutskan-mavjud-bolmagan-docker-xyz", "version"], timeout=5)

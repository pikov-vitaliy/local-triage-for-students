"""Плашка «Версия · коммит · сборка» внизу страниц и коммит в /healthz (app/build_info.py)."""

from __future__ import annotations

import re
import shutil
import subprocess
from pathlib import Path

import pytest

from app import __version__
from app import build_info as bi
from test_web import web  # noqa: F401

ROOT = Path(__file__).resolve().parents[1]


@pytest.fixture(autouse=True)
def fresh_cache():
    bi.build_info.cache_clear()
    yield
    bi.build_info.cache_clear()


def test_values_from_image_build(monkeypatch):
    monkeypatch.setenv("LT_BUILD_COMMIT", "45F6C35")
    monkeypatch.setenv("LT_BUILD_DIRTY", "1")
    monkeypatch.setenv("LT_BUILD_TIME", "21.10.2026 11:40")
    assert bi.build_info() == {"version": __version__, "commit": "45f6c35", "dirty": True, "built": "21.10.2026 11:40"}
    bi.build_info.cache_clear()
    monkeypatch.setenv("LT_BUILD_DIRTY", "0")
    assert bi.build_info()["dirty"] is False


def test_unknown_dirty_flag_is_not_reported_as_clean(monkeypatch):
    """Сборка не смогла проверить правки: признак «не проверено», а не «чисто»."""
    monkeypatch.setenv("LT_BUILD_COMMIT", "45f6c35")
    monkeypatch.setenv("LT_BUILD_DIRTY", "unknown")
    assert bi.build_info()["dirty"] is None


@pytest.mark.parametrize("commit", ["unknown", "", "<script>", "45f6c35; rm", "zzzzzzz"])
def test_unknown_or_odd_commit_falls_back_to_git_or_nothing(monkeypatch, commit):
    """Неизвестный или не похожий на коммит аргумент сборки не попадает в разметку: берётся git рабочей копии или ничего."""
    monkeypatch.setenv("LT_BUILD_COMMIT", commit)
    monkeypatch.setenv("LT_BUILD_TIME", "<b>вчера</b>")
    monkeypatch.setattr(bi, "_from_git", lambda root=None: ("", None))
    info = bi.build_info()
    assert info["commit"] == "" and info["dirty"] is None and info["built"] == ""


def test_working_copy_without_build_args_reads_git(monkeypatch):
    monkeypatch.delenv("LT_BUILD_COMMIT", raising=False)
    monkeypatch.setattr(bi, "_from_git", lambda root=None: ("abc1234", True))
    assert bi.build_info()["commit"] == "abc1234" and bi.build_info()["dirty"] is True


def _git(root: Path, *args: str) -> None:
    subprocess.run(["git", "-C", str(root), *args], check=True, capture_output=True)


@pytest.mark.skipif(shutil.which("git") is None, reason="нет git")
def test_real_git_clean_new_file_and_no_repo(tmp_path):
    """Настоящий git: чисто → False; новый файл в app/ (входит в образ) → True; файл вне образа не считается;
    без .git – ("", None)."""
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "x.py").write_text("x = 1\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", ".")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "init")
    commit, dirty = bi._from_git(repo)
    assert re.fullmatch(r"[0-9a-f]{7,40}", commit) and dirty is False
    (repo / "notes.txt").write_text("вне образа\n", encoding="utf-8")
    assert bi._from_git(repo)[1] is False
    (repo / "app" / "new.py").write_text("y = 2\n", encoding="utf-8")
    assert bi._from_git(repo)[1] is True
    assert bi._from_git(tmp_path / "copy-without-git") == ("", None)


@pytest.mark.skipif(shutil.which("git") is None, reason="нет git")
def test_new_file_is_dirty_even_when_untracked_files_are_hidden(tmp_path):
    """status.showUntrackedFiles=no в настройках репозитория не скрывает новый файл в app/; .dockerignore – тоже вход
    сборки."""
    repo = tmp_path / "repo"
    (repo / "app").mkdir(parents=True)
    (repo / "app" / "x.py").write_text("x = 1\n", encoding="utf-8")
    (repo / ".dockerignore").write_text(".git\n", encoding="utf-8")
    _git(repo, "init", "-q")
    _git(repo, "config", "status.showUntrackedFiles", "no")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "add", ".")
    _git(repo, "-c", "user.name=t", "-c", "user.email=t@example.invalid", "commit", "-q", "-m", "init")
    assert bi._from_git(repo)[1] is False
    (repo / "app" / "new.py").write_text("y = 2\n", encoding="utf-8")
    assert bi._from_git(repo)[1] is True
    (repo / "app" / "new.py").unlink()
    (repo / ".dockerignore").write_text(".git\napp/x.py\n", encoding="utf-8")
    assert bi._from_git(repo)[1] is True


@pytest.mark.parametrize("error", [FileNotFoundError("git"), subprocess.TimeoutExpired("git", 3)])
def test_missing_or_hanging_git_gives_unknown(monkeypatch, tmp_path, error):
    (tmp_path / ".git").mkdir()

    def broken(*args, **kwargs):
        raise error

    monkeypatch.setattr(bi.subprocess, "run", broken)
    assert bi._from_git(tmp_path) == ("", None)


def test_failed_status_is_not_clean(monkeypatch, tmp_path):
    (tmp_path / ".git").mkdir()
    calls = []

    def fake_git(root, *args):
        calls.append(args[0])
        code = 0 if args[0] == "rev-parse" else 128
        return subprocess.CompletedProcess(["git", *args], code, stdout="abc1234\n" if code == 0 else "", stderr="")

    monkeypatch.setattr(bi, "_git", fake_git)
    assert bi._from_git(tmp_path) == ("abc1234", None) and calls == ["rev-parse", "status"]


def test_build_scripts_pass_build_arguments():
    """Аргументы сборки доходят до образа: compose → Dockerfile ARG/ENV; start.ps1 ставит их без падения на ошибках git;
    сборка ВМ берёт коммит из ревизии подготовленных исходников."""
    compose = (ROOT / "docker-compose.yml").read_text(encoding="utf-8")
    dockerfile = (ROOT / "Dockerfile").read_text(encoding="utf-8")
    start = (ROOT / "start.ps1").read_bytes().decode("utf-8-sig")
    vm = (ROOT / "deploy" / "vm" / "build.sh").read_text(encoding="utf-8")
    for name in ("BUILD_COMMIT", "BUILD_DIRTY", "BUILD_TIME"):
        assert f"{name}: ${{{name}:-" in compose and f"ARG {name}=" in dockerfile and f"$env:{name} =" in start
        assert f"LT_{name}=${name}" in dockerfile
    assert "$ErrorActionPreference = 'Continue'" in start and "$ErrorActionPreference = $stopPreference" in start
    assert '"$BUILD/src/.revision"' in vm and 'BUILD_COMMIT=$commit' in vm and "rev-parse --short \"$REV\")\" \\" not in vm


def test_footer_pill_and_healthz(web):  # noqa: F811
    page = web.client.get("/").text
    pill = re.search(r'<p class="build-info" id="build-info">(.*?)</p>', page, re.S)
    assert pill and f"Версия {__version__} · коммит" in pill.group(1)
    health = web.client.get("/healthz").json()
    assert health["status"] == "ok" and health["version"] == __version__
    shown = re.search(r'коммит <span class="mono">([^<]*)</span>', pill.group(1)).group(1)
    assert shown == (health["commit"] or "неизвестен")

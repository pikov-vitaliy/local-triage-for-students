"""Сведения о сборке для плашки внизу страниц и /healthz: версия приложения, коммит и время сборки образа.

Коммит и время передаются при сборке образа (start.ps1, deploy/vm/build.sh → аргументы BUILD_COMMIT, BUILD_DIRTY,
BUILD_TIME → переменные LT_BUILD_*). Без них – при запуске из рабочей копии репозитория – коммит читается из git.
Значения проверяются по формату: в разметку попадает только то, что похоже на коммит и дату."""

from __future__ import annotations

import hashlib
import json
import os
import re
import subprocess
from functools import lru_cache
from pathlib import Path

from app import __version__

_STATIC_DIR = Path(__file__).resolve().parent / "static"

_COMMIT = re.compile(r"^[0-9a-f]{7,40}$")
_BUILT = re.compile(r"^\d{2}\.\d{2}\.\d{4} \d{2}:\d{2}$")


def _git(root: Path, *args: str) -> subprocess.CompletedProcess | None:
    try:
        return subprocess.run(["git", "-C", str(root), *args], capture_output=True, text=True, timeout=3)
    except (OSError, subprocess.SubprocessError):
        return None


# что определяет содержимое образа (Dockerfile, .dockerignore, COPY): правки в этом, включая новые файлы, –
# «правки вне коммита»
_IMAGE_PATHS = ("app", "Dockerfile", ".dockerignore", "requirements.lock", "examples/demo/demo-hub-report.xlsx",
                "examples/catalog")


def _from_git(root: Path | None = None) -> tuple[str, bool | None]:
    """Коммит рабочей копии и признак правок вне коммита в том, что входит в образ: True / False / None (проверить не
    удалось – это не «чисто»). Нет git или репозитория – ("", None)."""
    root = root or Path(__file__).resolve().parents[1]
    if not (root / ".git").exists():
        return "", None
    head = _git(root, "rev-parse", "--short", "HEAD")
    if head is None or head.returncode != 0:
        return "", None
    # новые файлы показываются явно: настройка status.showUntrackedFiles=no их бы скрыла
    status = _git(root, "status", "--porcelain", "--untracked-files=all", "--", *_IMAGE_PATHS)
    dirty = None if status is None or status.returncode != 0 else bool(status.stdout.strip())
    return head.stdout.strip(), dirty


def _from_file(root: Path | None = None) -> tuple[str, bool | None, str]:
    """Сведения о сборке пакета npm (ADR-0155): build.json рядом с папкой app – его пишет сборщик пакета, потому что в
    пакете нет .git. {"commit": "...", "dirty": bool, "time": "ДД.ММ.ГГГГ ЧЧ:ММ"}; нет файла или он испорчен – пусто."""
    root = root or Path(__file__).resolve().parents[1]
    try:
        data = json.loads((root / "build.json").read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return "", None, ""
    if not isinstance(data, dict):
        return "", None, ""
    commit = str(data.get("commit") or "").strip().lower()
    dirty = data.get("dirty") if isinstance(data.get("dirty"), bool) else None
    return commit, dirty, str(data.get("time") or "").strip()


@lru_cache(maxsize=1)
def build_info() -> dict:
    """{version, commit, dirty, built}: commit – "" если неизвестен; dirty – True / False / None (не проверено, в том
    числе при неизвестном коммите); built – время сборки образа «ДД.ММ.ГГГГ ЧЧ:ММ» или ""."""
    commit = os.environ.get("LT_BUILD_COMMIT", "").strip().lower()
    flag = os.environ.get("LT_BUILD_DIRTY", "").strip()
    dirty: bool | None = True if flag == "1" else (False if flag == "0" else None)
    built = os.environ.get("LT_BUILD_TIME", "").strip()
    if not _COMMIT.match(commit):
        commit, dirty = _from_git()
        commit = commit.lower() if _COMMIT.match(commit.lower()) else ""
    if not commit:  # пакет npm: git нет, сведения записаны при сборке пакета
        commit, dirty, file_built = _from_file()
        commit = commit if _COMMIT.match(commit) else ""
        built = built or file_built
    return {"version": __version__, "commit": commit, "dirty": dirty if commit else None,
            "built": built if _BUILT.match(built) else ""}


@lru_cache(maxsize=1)
def asset_version(static_dir: Path | None = None) -> str:
    """Версия для адресов статических файлов (`?v=` в base.html): версия приложения и отпечаток содержимого `app/static`,
    чтобы адрес менялся с каждой сборкой, где менялись скрипты или стили, и браузер не держал старый скрипт: при
    перезапусках с одним и тем же `?v=<версия>` Chrome оставлял прежний app.js, и новое поведение карточки не
    включалось. Отпечаток – SHA-256 по относительным именам и содержимому файлов, первые 10 знаков."""
    root = static_dir or _STATIC_DIR
    digest = hashlib.sha256()
    for path in sorted(p for p in root.rglob("*") if p.is_file()) if root.is_dir() else []:
        digest.update(path.relative_to(root).as_posix().encode("utf-8"))
        digest.update(b"\0")
        digest.update(path.read_bytes())
    return f"{__version__}-{digest.hexdigest()[:10]}"

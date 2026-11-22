"""Раздел «Проекты»: список проектов (действующие и архив) с ходом разбора, создание проекта и демо-проекта,
страница проекта (параметры, выгрузка, папка с репозиториями, кодовые базы, запуск триажа), обзор папок внутри
корня папок с репозиториями, «Продолжить» – к следующей непроверенной находке, архив и удаление проекта.

Шаблоны – templates/projects/: list.html (проекты и архив), project.html (проект), folders.html (обзор папок),
delete.html (подтверждение удаления).

Пути: папка проекта – путь от корня папок с репозиториями (REPOS_ROOT) настоящими именами папок через «/».
Обзор и выбор папки проверяют путь через context.resolve_repo (без «..», абсолютных путей и выхода за корень
по ссылкам) и обходят только обычные папки: скрытые, символические ссылки и точки соединения не показываются
и не выбираются.
"""

from __future__ import annotations

import hmac
import logging
import os
import re
import secrets
import stat
import tempfile
import threading
import time
from collections.abc import Iterator
from pathlib import Path

from fastapi import APIRouter, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool
from starlette.datastructures import UploadFile

from app import hub_onboarding, hub_state
from app.config import ConfigError, Settings, normalize_setting
from app.context import build_context, resolve_repo
from app.db import Database, ProjectBusy, case_signature, code_notice_version
from app.hub_import import ImportFailure, parse_workbook
from app.logsafe import log_failure
from app.models import Finding, ImportResult
from app.routes.common import (MAX_NAME, db_of, default_model, external_enabled, mask_key_of, metrics_of,
                               models_of, profile_for, project_or_404, redirect, register_messages, render,
                               runner_of, settings_of, with_reopened)
from app.settings_store import folder_display, repos_display
from app.context import file_presence
from app.triage import empty_dir, order_findings, save_snapshots, sync_revisions
from app.view import code_change_note, model_option, revision_note

log = logging.getLogger("local_triage.web")

router = APIRouter()

MAX_DIRS = 400  # сколько папок показывать в выборе и в обзоре
MAX_SCAN = 5000  # сколько записей папки просматривать в обзоре
MAX_CHECKS = 500  # сколько папок проверить на признаки клона при подборе папок кодовым базам
MAX_PATH = 1000  # знаков в пути к папке из адреса или формы

# Служебные папки Windows в корне диска: в обзоре папок не показываются
SERVICE_DIRS = frozenset(("system volume information", "recycler", "config.msi"))

# Признаки папки с кодом: клон git, файл сборки или папка src
CODEBASE_MARKERS = frozenset((".git", "src", "pom.xml", "build.gradle", "build.gradle.kts", "settings.gradle",
                              "package.json", "pyproject.toml", "setup.py", "requirements.txt", "go.mod", "Cargo.toml",
                              "composer.json", "Gemfile"))

# Демо: examples/demo в папке приложения – выгрузка demo-hub-report.xlsx и клоны в repos/
APP_ROOT = Path(__file__).resolve().parents[2]
DEMO_PARTS = ("examples", "demo")
DEMO_REPORT = "demo-hub-report.xlsx"
DEMO_CODEBASES = ("billing-core", "catalog-api")
DEMO_COPY = "local-triage-demo"  # папка с копией демо-репозиториев в папке для клонов (её создаёт start.ps1)
DEMO_SCAN_DIRS = 2000  # сколько папок корня (два уровня) просмотреть в поисках examples/demo
DEMO_SCAN_SECONDS = 3.0

# Выгрузки разбираются по одной: разбор большой книги занимает память и время
_IMPORT_SLOT = threading.BoundedSemaphore(1)
IMPORT_BUSY = "Сейчас загружается другая выгрузка. Дождитесь окончания и повторите."
# Срезы кода сохраняются по одному проекту за раз: повторное нажатие не запускает второй обход клонов
_SNAPSHOT_SLOT = threading.BoundedSemaphore(1)
SNAPSHOT_BUSY = "Срезы кода уже сохраняются. Дождитесь окончания и обновите страницу."
SNAPSHOT_RUNNING = "У проекта идёт прогон: сохраните срезы кода после него – разобранные находки сохранят их сами."

_NAME_JUNK = re.compile(r"[\W_]+")

register_messages({
    "created": "Проект создан. Загрузите выгрузку из AppSec.Hub.",
    "imported": "Выгрузка загружена.",
    "repos": "Папка с репозиториями выбрана, кодовые базы подобраны заново.",
    "mapped": "Соответствие кодовых баз и папок сохранено.",
    "automapped": "Пустые и подобранные автоматически строки подобраны заново по именам; ручной выбор не тронут.",
    "reset": "Ручные соответствия сброшены, папки подобраны по именам.",
    "snapshots": "Срезы кода сохранены в базе приложения. Сколько находок со срезом – в блоке «Срезы кода в базе».",
    "snapshots_none": "Новых срезов нет: у находок без среза нет клона на месте или кода для разбора.",
    "clones_attached": "Клоны снова читаются. Если в их папках теперь другой код, срезы этих кодовых баз сбросятся.",
    "project_saved": "Параметры проекта сохранены.",
    "external_marked": "Отметка «код не секретный» поставлена: внешний профиль можно выбрать профилем модели проекта. "
                       "Код находок уйдёт провайдеру только прогоном на таком профиле.",
    "external_cleared": "Отметка «код не секретный» снята: код проекта внешнему провайдеру больше не отправляется; "
                        "идущий прогон на внешнем профиле встанет на паузу перед следующей находкой.",
    "provider_changed": "Профиль модели проекта изменён: список моделей – с сервера этого профиля. Готовые вердикты "
                        "не тронуты – чтобы разобрать их моделью нового профиля, отметьте «Спросить модель заново».",
    "project_archived": "Проект убран в архив. Вернуть его можно из раздела «Архив».",
    "project_restored": "Проект возвращён из архива.",
    "project_deleted": "Проект удалён.",
    "project_all_reviewed": "Непроверенных находок SAST и SCA в проекте нет.",
    "project_demo": "Демо-проект создан: выгрузка загружена, папка с демо-репозиториями выбрана. Запустите триаж.",
    "project_demo_nocode": "Демо-проект создан и выгрузка загружена, но демо-репозитории лежат вне корня папок "
                           "с репозиториями: без них модель увидит только строки кода из выгрузки.",
})


# ============================================================================ папки с репозиториями

def _subdirs(path: Path) -> list[os.DirEntry]:
    """Подпапки по имени – те же обычные папки, что в обзоре (_plain_dir): без скрытых и системных, без ссылок
    и точек соединения. Для надёжности настоящий путь каждой подпапки сверяется с путём родителя: папка, которая
    на деле ведёт в другое место, не предлагается."""
    try:
        parent = os.path.normcase(os.path.realpath(path))
        with os.scandir(path) as entries:
            dirs = [e for e in entries if _plain_dir(e)
                    and os.path.normcase(os.path.realpath(e.path)) == os.path.join(parent, os.path.normcase(e.name))]
    except OSError:
        return []
    return sorted(dirs, key=lambda e: e.name.casefold())


def _is_codebase(path: str | Path) -> bool:
    """Папка похожа на клон или исходники проекта: есть .git, файл сборки или папка src."""
    return bool(_codebase_kind(path))


def _codebase_kind(path: str | Path) -> str:
    """"git" – клон git, "src" – исходники (файл сборки или папка src), "" – ни то ни другое."""
    try:
        with os.scandir(path) as entries:
            names = {e.name for e in entries if e.name in CODEBASE_MARKERS}
    except OSError:
        return ""
    if ".git" in names:
        return "git"
    return "src" if names else ""


def list_project_dirs(root: Path) -> list[str]:
    """Папки внутри REPOS_ROOT (до двух уровней), которые можно выбрать как папку проекта; сами клоны
    не предлагаются."""
    result = [""]
    for d1 in _subdirs(root):
        if _is_codebase(d1.path):
            continue
        result.append(d1.name)
        for d2 in _subdirs(Path(d1.path)):
            if not _is_codebase(d2.path):
                result.append(f"{d1.name}/{d2.name}")
            if len(result) >= MAX_DIRS:
                return result
    return result


def list_codebase_dirs(base: Path) -> list[str]:
    """Папки с клонами в папке проекта: подпапки первого уровня и клоны во вложенных папках-группах. Проверка
    признаков клона ограничена MAX_CHECKS папками: корнем папок с репозиториями бывает целый диск."""
    result: list[str] = []
    checks = 0
    for d1 in _subdirs(base):
        result.append(d1.name)
        if len(result) >= MAX_DIRS:
            break
        checks += 1
        if checks > MAX_CHECKS or _is_codebase(d1.path):
            continue
        for d2 in _subdirs(Path(d1.path)):
            checks += 1
            if checks > MAX_CHECKS:
                break
            if _is_codebase(d2.path):
                result.append(f"{d1.name}/{d2.name}")
                if len(result) >= MAX_DIRS:
                    break
    return result[:MAX_DIRS]


def norm_name(value: str) -> str:
    """Имя для сравнения: без регистра, пробелов, дефисов, точек и подчёркиваний."""
    return _NAME_JUNK.sub("", str(value).casefold())


def auto_folder(codebase: str, candidates: list[str]) -> str:
    """Папка для кодовой базы по имени (без регистра и разделителей); неоднозначно или не найдено – ""."""
    tail = str(codebase).replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
    keys = {norm_name(codebase), norm_name(tail)} - {""}
    hits = sorted((c for c in candidates if norm_name(c.rsplit("/", 1)[-1]) in keys),
                  key=lambda c: (c.count("/"), c.casefold()))
    if not hits or (len(hits) > 1 and hits[0].count("/") == hits[1].count("/")):
        return ""
    return hits[0]


def repos_missing(settings: Settings) -> str:
    """Текст, когда корня папок с репозиториями нет: приложение запущено не с той папкой."""
    if settings.stand == "npm":  # учебный стенд (ADR-0155): папку кода создаёт окно стенда при запуске
        return (f"Папка кода {repos_display(settings)} не найдена: её удалили или переименовали. Закройте окно стенда и "
                "запустите стенд снова – он создаст папку заново и положит в неё демо-проект.")
    return (f"Папка с репозиториями не подключена: {repos_display(settings)} не найдена. Перезапустите приложение "
            "через start.ps1 – он подключает диск с папкой приложения; другой корень – параметр -ReposRoot.")


def repos_base(settings: Settings, project: dict) -> tuple[Path | None, str]:
    """Папка проекта с клонами внутри REPOS_ROOT: (путь, "") или (None, что не так)."""
    if not settings.repos_root.is_dir():
        return None, repos_missing(settings)
    try:
        path = resolve_repo(settings.repos_root, project.get("repos_dir") or "")
    except ValueError as e:
        return None, str(e)
    if not path.is_dir():
        return None, "Выбранная папка проекта не найдена внутри папки с репозиториями."
    return path, ""


def auto_map(settings: Settings, db: Database, project: dict, overwrite_manual: bool) -> int:
    """Подбирает папки кодовым базам по именам: пустым и подобранным автоматически строкам; ручной выбор
    меняется, только если overwrite_manual (кнопка «Сбросить ручные соответствия» с подтверждением).
    Сопоставление кодовой базы, у которой уже есть срезы кода в базе, подбор не меняет (ADR-0072): смена папки
    удалила бы срезы, а клон после разбора могли удалить целиком или частично. Сменить такую папку можно только
    явно – в таблице кодовых баз. Возвращает, у скольких находок снята отметка «проверено» (у их кодовой базы
    сменилась папка)."""
    base, _ = repos_base(settings, project)
    return sum(db.set_codebase_folder(project["id"], codebase, folder, manual=False)
               for codebase, folder in auto_map_plan(db, project["id"], base, overwrite_manual))


def auto_map_plan(db: Database, project_id: int, base: Path | None,
                  overwrite_manual: bool) -> list[tuple[str, str]]:
    """Те же папки для предпросмотра потерь и применения подбора; ничего не записывает."""
    candidates = list_codebase_dirs(base) if base else []
    current = db.get_codebase_map(project_id, with_detached=True)
    with_cases = db.codebases_with_cases(project_id)
    changes = []
    for row in db.codebase_counts(project_id):
        codebase = row["codebase"]
        if not codebase:
            continue
        entry = current.get(codebase)
        if entry and entry["manual"] and not overwrite_manual:
            continue
        if entry and entry.get("folder") and (entry.get("detached") or (not overwrite_manual
                                                                          and codebase in with_cases)):
            continue  # у кодовой базы есть срезы кода или клон отвязан: папку меняет только человек
        folder = auto_folder(codebase, candidates)
        if not folder and entry and entry.get("folder") and not clone_present(base, entry["folder"]):
            # Подбор не нашёл папку, а сопоставленной папки нет на диске: клон удалён после разбора (ADR-0072).
            # Пустое сопоставление удалило бы срезы кода в базе и сняло отметки – оставляем прежнее
            continue
        changes.append((codebase, folder))
    return changes


def clone_present(base: Path | None, folder: str) -> bool:
    """Папка клона на месте и не пуста (пустая папка на месте удалённого клона – клона нет, ADR-0072)."""
    if base is None or not folder:
        return False
    path = base / folder
    return path.is_dir() and not empty_dir(path)


def upgradable(db: Database, project_id: int, base: Path | None, present: set[str], cmap: dict[str, dict]) -> int:
    """Сколько неполных срезов можно заменить полноценными: файл находки теперь есть
    в клоне, который на месте, и читается («Сохранить срезы кода», ADR-0073). Проверяется не больше 500 находок."""
    if base is None:
        return 0
    found = 0
    for row in db.line_only_cases(project_id):
        folder = (cmap.get(row["codebase"]) or {}).get("folder") or ""
        if row["codebase"] not in present or not folder:
            continue
        repo = base / folder
        if not row["file"] or file_presence(repo, row["file"]) != "found":
            continue
        source = db.case_input(project_id, row["hub_id"])
        # Наличие файла ещё не обещает полноценного среза: он может не читаться или быть короче нужной строки.
        if source and build_context(repo, Finding.from_dict(source["data"])).status == "ok":
            found += 1
    return found


def snapshot_summary(counts: dict[str, dict[str, int]], mapped: set[str], present: set[str],
                     detached: set[str] | None = None) -> dict:
    """Срезы кода в базе по проекту (ADR-0072): находок SAST, из них со срезом кода из файла, со срезом из строки
    выгрузки, со срезом без строк, без среза. Из находок без среза: can_save – клон их кодовой базы на месте
    («Сохранить срезы кода»), unmapped – их кодовой базе папка не выбрана (клона не было: удалять нечего, модель
    увидит строку из выгрузки). ready – срез есть у всех находок кодовых баз с папкой и хотя бы в одном срезе код
    из файла клона, неполных срезов нет: клоны больше не нужны (без клонов, по одним строкам выгрузки, это не так)."""
    total = {"sast": 0, "code": 0, "line": 0, "empty": 0, "none": 0, "can_save": 0, "unmapped": 0,
             "detached_none": 0, "can_upgrade": 0, "incomplete": 0, "missing": 0}
    for codebase, n in counts.items():
        for key in ("sast", "code", "line", "empty", "none", "incomplete", "missing"):
            total[key] += n.get(key, 0)
        if codebase in present:
            total["can_save"] += n["none"]
        if codebase not in mapped:
            total["unmapped"] += n["none"]
        elif codebase in (detached or set()):
            total["detached_none"] += n["none"]  # новые находки отвязанной кодовой базы: клон не читается
    total["ready"] = total["code"] > 0 and total["none"] == total["unmapped"] and total["incomplete"] == 0
    return total


def codebase_rows(db: Database, project: dict, base: Path | None) -> dict:
    """Таблица «Кодовые базы из выгрузки» для шага 2 и то, что из неё следует.

    Строке без сохранённой папки (и не выбранной вручную как «не выбрана») подставляется папка, которую нашёл
    бы подбор по имени, – «найдена, не сохранено»: применяется кнопкой «Сохранить соответствие», при показе
    страницы в базу ничего не пишется. «Клонировать только эти» – кодовые базы с находками SAST, для которых нет
    ни сохранённой папки, ни найденной. reset – что пропадёт при сбросе ручных соответствий."""
    pid = project["id"]
    candidates = list_codebase_dirs(base) if base else []
    from app.routes.examples import example_of_project, link_folders, project_link
    # проект из примера: папки сервисов из связи тоже выбираются (у crAPI – третий уровень от папки проекта)
    candidates = candidates + sorted(f for f in link_folders(db, pid, base) if f not in candidates)
    example_key = example_of_project(db, pid)
    example_map = dict(((project_link(db, example_key) or {}) if example_key else {}).get("codebases") or {})
    from app import examples as examples_module
    from_examples = str(project.get("repos_dir") or "") == examples_module.EXAMPLES_FOLDER
    cmap = db.get_codebase_map(pid, with_detached=True)
    snapshots = db.snapshot_counts(pid)
    rows, nameless = [], None
    reset_changes = {cb for cb, folder in auto_map_plan(db, pid, base, overwrite_manual=True)
                     if folder != (cmap.get(cb) or {}).get("folder", "")}
    reset = {"mappings": sum(bool((cmap.get(cb) or {}).get("manual")) for cb in reset_changes),
             "warning": reset_warning(db, pid, reset_changes)}
    for row in db.codebase_counts(pid):
        if not row["codebase"]:
            nameless = row
            continue
        entry = cmap.get(row["codebase"]) or {}
        folder, manual = entry.get("folder") or "", bool(entry.get("manual"))
        exists = clone_present(base, folder)
        found = auto_folder(row["codebase"], candidates)
        suggestion = found if not folder and not manual else ""
        snap = snapshots.get(row["codebase"]) or {"sast": 0, "code": 0, "line": 0, "empty": 0, "none": 0}
        # Клон удалён после разбора (или отвязан), а срез есть у каждой находки SAST: код берётся из базы (ADR-0072)
        detached = bool(entry.get("detached"))
        stored = bool(folder and (detached or not exists) and row["sast"] and snap["none"] == 0)
        if detached and snap["none"]:
            state, tone = f"клон отвязан, без среза: {snap['none']}", "warn"
        elif detached:
            state, tone = ("клон удалён, срезы в базе" if not exists else "клон не читается, срезы в базе"), "ok"
        elif exists:
            state, tone = ("из примера" if manual and example_map.get(row["codebase"]) == folder and from_examples
                           else "указана вручную" if manual else "найдена"), "ok"
        elif stored:
            state, tone = "клон удалён, срезы в базе", "ok"
        elif suggestion:
            state, tone = "найдена, не сохранено", "accent"
        elif folder:
            state, tone = "папки нет", "warn"
        else:
            state, tone = "не найдена", "warn"
        selected = folder or suggestion
        rows.append({**row, "folder": folder, "selected": selected, "suggestion": suggestion, "exists": exists,
                     "manual": manual, "state": state, "tone": tone, "stored": stored, "snapshots": snap,
                     "detached": detached,
                     "options": candidates if selected in candidates or not selected else [selected, *candidates]})
    to_clone = [r["codebase"] for r in rows if r["sast"] and not r["exists"] and not r["suggestion"]
                and not r["stored"] and not r["detached"]]
    present = {r["codebase"] for r in rows if r["exists"] and not r["detached"]}
    mapped = {r["codebase"] for r in rows if r["folder"]}
    detached = {r["codebase"] for r in rows if r["detached"]}
    summary = snapshot_summary({cb: n for cb, n in snapshots.items() if cb}, mapped, present, detached)
    summary["can_upgrade"] = upgradable(db, pid, base, present, cmap) if summary["line"] or summary["empty"] else 0
    reasons = {"ambiguous": "несколько подходящих файлов", "too_large": "больше 2 МБ", "binary": "двоичный",
               "unreadable": "не читается", "no_repo": "клон был недоступен при сохранении среза",
               "line_out_of_range": "строка за концом файла – клон, похоже, не на коммите скана",
               "": "сохранён прежней версией"}
    incomplete = [{**row, "reason_text": reasons.get(row["reason"], row["reason"])}
                  for row in db.incomplete_snapshots(pid)]
    return {"codebases": rows, "nameless": nameless, "to_clone": to_clone, "reset": reset,
            "unsaved": sum(1 for r in rows if r["suggestion"]),
            "detached": [r["codebase"] for r in rows if r["detached"]],
            "snapshots": summary, "incomplete_snapshots": incomplete,
            "snapshot_reasons": db.snapshot_reasons(pid)}


def refresh_sources(settings: Settings, db: Database, project_id: int) -> None:
    """После сохранения папок или загрузки выгрузки: прежнее пояснение о ревизиях клонов снимается, ревизии
    сверяются заново (у кодовой базы, сменившей папку, ревизия новой папки просто запоминается)."""
    db.clear_revision_notice(project_id)
    project = db.get_project(project_id)
    if project is not None:
        sync_revisions(db, settings, project)


# ============================================================================ обзор папок

def _plain_dir(entry: os.DirEntry) -> bool:
    """Обычная папка: не скрытая и не служебная, не символическая ссылка и не точка повторного анализа Windows
    (точка соединения и т. п.) – путь через ссылку мог бы вести не туда, куда показывает имя."""
    name = entry.name
    if name.startswith((".", "$")) or name.casefold() in SERVICE_DIRS:
        return False
    try:
        if not entry.is_dir(follow_symlinks=False) or entry.is_symlink():
            return False
        info = entry.stat(follow_symlinks=False)
    except OSError:
        return False
    attrs = getattr(info, "st_file_attributes", 0)
    hidden = stat.FILE_ATTRIBUTE_HIDDEN | stat.FILE_ATTRIBUTE_SYSTEM | stat.FILE_ATTRIBUTE_REPARSE_POINT
    return not getattr(info, "st_reparse_tag", 0) and not attrs & hidden


def browse_dirs(path: Path) -> tuple[list[os.DirEntry], bool]:
    """Подпапки для обзора – обычные папки по имени: (папки, показаны не все)."""
    dirs: list[os.DirEntry] = []
    more = False
    try:
        with os.scandir(path) as entries:
            for seen, entry in enumerate(entries):
                if seen >= MAX_SCAN:
                    more = True
                    break
                if _plain_dir(entry):
                    dirs.append(entry)
    except OSError:
        return [], False
    dirs.sort(key=lambda e: e.name.casefold())
    return dirs[:MAX_DIRS], more or len(dirs) > MAX_DIRS


def _child_dir(parent: Path, name: str) -> os.DirEntry | None:
    """Подпапка с таким именем (имя – буква в букву), если это обычная папка."""
    try:
        with os.scandir(parent) as entries:
            for entry in entries:
                if entry.name == name:
                    return entry if _plain_dir(entry) else None
    except OSError:
        return None
    return None


def resolve_folder(settings: Settings, raw: str) -> tuple[str | None, Path | None, str]:
    """Папка внутри корня папок с репозиториями из адреса или формы -> (путь от корня – имена папок через «/»,
    полный путь, "") или (None, None, что не так). Отказ: путь не от корня, «..», выход за корень по ссылке,
    скрытая папка, ссылка или точка соединения на пути, папки нет."""
    if not settings.repos_root.is_dir():
        return None, None, repos_missing(settings)
    text = str(raw or "").strip()
    if len(text) > MAX_PATH:
        return None, None, "Слишком длинный путь к папке."
    try:
        resolve_repo(settings.repos_root, text)
    except ValueError as e:
        return None, None, str(e)
    parts = [p for p in text.replace("\\", "/").split("/") if p not in ("", ".")]
    if any(p.startswith(".") for p in parts):
        return None, None, "Скрытые папки (имя начинается с точки) не выбираются."
    current = settings.repos_root
    for part in parts:
        entry = _child_dir(current, part)
        if entry is None:
            return None, None, "Такой папки нет внутри корня папок с репозиториями (или это ссылка)."
        current = Path(entry.path)
    return "/".join(parts), current, ""


def check_project_folder(settings: Settings, raw: str) -> tuple[str | None, str]:
    """Папка проекта из формы -> (путь от корня, "") или (None, что не так). Сам клон одной кодовой базы папкой
    проекта не выбирается: папка проекта – та, в которой лежат клоны (корень – всегда можно)."""
    rel, path, error = resolve_folder(settings, raw)
    if error:
        return None, error
    if rel and path is not None and _is_codebase(path):
        return None, ("Это папка одного клона (в ней .git, файл сборки или src). Папка проекта – та, в которой лежат "
                      "клоны кодовых баз: выберите папку уровнем выше.")
    return rel, ""


def folders_context(request: Request, project: dict, raw_path: str) -> dict:
    """Обзор папок: хлебные крошки, подпапки с пометками (клон git, исходники, имя кодовой базы из выгрузки),
    можно ли выбрать текущую папку и сколько кодовых баз выгрузки в ней найдётся по имени."""
    settings = settings_of(request)
    db = db_of(request)
    base = {"project": project, "root": repos_display(settings), "selected": project.get("repos_dir") or "",
            "selected_display": folder_display(settings, project.get("repos_dir") or ""), "path": "", "crumbs": [],
            "parent": None, "subfolders": [], "more": False, "is_clone": False, "can_select": False, "matches": [],
            "codebase_total": 0, "path_display": repos_display(settings), "error": "", "root_ok": False}
    if not settings.repos_root.is_dir():
        return {**base, "error": repos_missing(settings)}
    rel, path, error = resolve_folder(settings, raw_path)
    if error:  # неверный путь – показывается корень с пояснением
        rel, path = "", settings.repos_root
    parts = rel.split("/") if rel else []
    codebases = [row["codebase"] for row in db.codebase_counts(project["id"]) if row["codebase"]]
    keys = set()
    for codebase in codebases:
        tail = codebase.replace("\\", "/").rstrip("/").rsplit("/", 1)[-1]
        keys |= {norm_name(codebase), norm_name(tail)} - {""}
    entries, more = browse_dirs(path)
    subfolders = [{"name": e.name, "rel": "/".join([*parts, e.name]), "kind": _codebase_kind(e.path),
                   "codebase": norm_name(e.name) in keys} for e in entries]
    kind = _codebase_kind(path) if rel else ""
    matches = []
    if codebases and not kind:
        candidates = list_codebase_dirs(path)
        matches = [(codebase, folder) for codebase in codebases
                   if (folder := auto_folder(codebase, candidates))]
    crumbs = [{"label": part, "rel": "/".join(parts[:k + 1])} for k, part in enumerate(parts)]
    # открыт клон одной кодовой базы, а у проекта ровно одна кодовая база без папки (бэклог 95): предложить сделать
    # папку выше папкой проекта и назначить этот клон кодовой базе – одной транзакцией
    clone_offer = None
    if kind and parts:
        mapped = db.get_codebase_map(project["id"])
        free = [cb for cb in codebases if not (mapped.get(cb) or {}).get("folder")]
        if len(free) == 1:
            counts = db.clone_reset_counts(project["id"], free[0], "/".join(parts[:-1]))
            clone_offer = {"codebase": free[0], "parent": "/".join(parts[:-1]), "folder": parts[-1],
                           "parent_display": folder_display(settings, "/".join(parts[:-1])),
                           "warning": clone_reset_warning(counts), "counts": f"{counts[0]}:{counts[1]}"}
    return {**base, "path": rel, "crumbs": crumbs, "parent": "/".join(parts[:-1]) if parts else None,
            "clone_offer": clone_offer,
            "subfolders": subfolders, "more": more, "is_clone": bool(kind), "can_select": not kind,
            "matches": matches, "codebase_total": len(codebases), "path_display": folder_display(settings, rel),
            "error": error, "root_ok": True,
            "reset_warning": reset_warning(db, project["id"]) if rel != (project.get("repos_dir") or "") else ""}


def reset_warning(db: Database, project_id: int, codebases: set[str] | None = None) -> str:
    """Цена смены папок: предупреждение появляется только при удалении сохранённых срезов."""
    affected = db.codebases_with_cases(project_id)
    if codebases is not None:
        affected &= codebases
    if not affected:
        return ""
    counts = db.case_reset_counts(project_id)
    selected = set(counts) if codebases is None else codebases
    cases = sum(counts.get(cb, {}).get("cases", 0) for cb in selected)
    mapped = db.get_codebase_map(project_id)
    reviewed = sum(counts.get(cb, {}).get("reviewed", 0) for cb in selected
                   if codebases is not None or (mapped.get(cb) or {}).get("folder"))
    return (f"Будет удалено срезов кода: {cases}; отметок «Проверено»: {reviewed}. "
            "После удаления клонов это единственная копия кода. Подтвердите удаление.")


def clone_reset_warning(counts: tuple[int, int]) -> str:
    """Цена «Сделать папку выше папкой проекта и назначить этот клон» (бэклог 95): обе записи
    set_repos_dir_and_folder вместе (Database.clone_reset_counts). Предупреждение – при любом ненулевом числе срезов
    или отметок «Проверено» (ревью Kimi, выпуск dev18: отметки снимаются и у базы без срезов)."""
    cases, reviewed = counts
    if not cases and not reviewed:
        return ""
    return (f"Будет удалено срезов кода: {cases}; отметок «Проверено»: {reviewed}. "
            "После удаления клонов это единственная копия кода. Подтвердите удаление.")


def parse_counts(raw: object) -> tuple[int, int] | None:
    """Показанная цена из формы: «срезы:отметки»; иначе None."""
    parts = str(raw or "").split(":")
    if len(parts) != 2 or not all(p.isdigit() for p in parts):
        return None
    return int(parts[0]), int(parts[1])


# ============================================================================ выгрузка

def import_mismatch(db: Database, project_id: int, result: ImportResult) -> str:
    """Повторная выгрузка, похожая на выгрузку другой системы: другое название системы в сводке или ни один ID
    находки не совпал с прежними. Тогда прежние находки молча получили бы пометку «нет в новой выгрузке», а чужие
    добавились бы к ним: выгрузка не применяется без подтверждения. Первая выгрузка проекта не проверяется."""
    previous = db.latest_import(project_id)
    old_ids = db.hub_ids(project_id)
    if previous is None or not old_ids:
        return ""
    skipped = int((result.summary or {}).get('skipped_findings') or 0)
    if skipped:
        return (f'При разборе пропущено строк без ID: {skipped}. Повторная выгрузка неполна: прежние находки '
                'могут ложно получить отметку «нет в выгрузке». Проверьте файл или явно подтвердите '
                '«Загрузить всё равно». До подтверждения данные проекта не меняются.')
    old_app = str((previous.get("summary") or {}).get("application") or "").strip()
    new_app = str((result.summary or {}).get("application") or "").strip()
    new_ids = {f.hub_id for f in result.findings}
    problems = []
    if old_app and new_app and old_app.casefold() != new_app.casefold():
        problems.append(f"в новой выгрузке система «{new_app}», а в проекте – «{old_app}»")
    if not new_ids:
        problems.append("в новой выгрузке нет ни одной находки – все прежние получили бы пометку «нет в выгрузке»")
    elif not new_ids & old_ids:
        problems.append("ни один ID находки не совпал с прежними")
    detached = db.detached_codebases(project_id)
    if detached:
        # Клоны удалены после разбора (ADR-0072): новые и изменённые находки этих кодовых баз разобрать не по чему
        old = {row["hub_id"]: case_signature(row["data"])
               for row in db.findings_data(project_id, kinds=("SAST",), include_missing=True)}
        fresh = [f for f in result.findings if f.kind == "SAST" and f.codebase in detached
                 and old.get(f.hub_id) != case_signature(f.to_dict())]
        if fresh:
            problems.append(f"клоны кодовых баз {', '.join(sorted({f.codebase for f in fresh}))} удалены, а у "
                            f"{len(fresh)} новых или изменённых находок SAST кода нет – для новой выгрузки создайте "
                            "новый проект")
    if not problems:
        return ""
    return ("Похоже, это выгрузка другой системы: " + "; ".join(problems) + ". Выгрузка не загружена. Если это "
            "всё же выгрузка этого проекта, выберите файл ещё раз и отметьте «Загрузить всё равно»: прежние находки "
            "получат пометку «нет в новой выгрузке».")


def store_import(settings: Settings, db: Database, project_id: int, filename: str, result: ImportResult,
                 after=None) -> int:
    """Сохраняет разобранную выгрузку в проект: порядок разбора, находки (решения и отметки по совпадающим ID
    сохраняются, новые добавляются, пропавшие помечаются «нет в новой выгрузке»), подбор папок кодовым базам
    и сверка ревизий клонов. Возвращает, у скольких находок снята отметка «Проверено» из-за смены папки."""
    warnings = list(result.warnings)
    seen: set[str] = set()
    repeated = sorted({f.hub_id for f in result.findings if f.hub_id in seen or seen.add(f.hub_id)})
    if repeated:
        warnings.append(f"ID находок повторяются ({len(repeated)}): {', '.join(repeated[:10])}"
                        + (" …" if len(repeated) > 10 else "") + ". Взята первая строка каждого ID.")
    rows = order_findings(result.findings, settings.sca_urgent_cvss)
    from app.sca_research_net import composition_change
    with composition_change():  # состав проекта меняется не между проверкой и отправкой исследования
        db.save_import(project_id, filename, result.format, result.sheets, result.summary, warnings, rows, after=after)
    project = db.get_project(project_id)
    reopened = auto_map(settings, db, project, overwrite_manual=False) if project is not None else 0
    refresh_sources(settings, db, project_id)
    return reopened


# ============================================================================ демо

def _is_demo_dir(path: Path) -> bool:
    """Папка с демо-данными: выгрузка и клоны кодовых баз демо в repos/."""
    return (path / DEMO_REPORT).is_file() and _is_demo_repos(path / "repos")


def _is_demo_repos(path: Path) -> bool:
    return all((path / name).is_dir() for name in DEMO_CODEBASES)


def _rel_inside(root: Path, path: Path) -> str | None:
    """Путь от корня до папки (обе раскрыты realpath) или None, если папка не внутри корня."""
    real_root, real = os.path.realpath(root), os.path.realpath(path)
    try:
        rel = os.path.relpath(real, real_root)
    except ValueError:  # другой диск
        return None
    if rel == ".":
        return ""
    if rel == ".." or rel.startswith(".." + os.sep) or os.path.isabs(rel):
        return None
    return rel.replace(os.sep, "/")


def _demo_candidates(root: Path) -> Iterator[Path]:
    """Где может лежать examples/demo: рядом с приложением, сам корень, examples/demo в корне и в папках корня
    на глубине до двух уровней (корень – диск, а приложение лежит в одной из его папок). Просмотр ограничен
    числом папок и временем."""
    yield APP_ROOT.joinpath(*DEMO_PARTS)
    yield root
    yield root.joinpath(*DEMO_PARTS)
    deadline = time.monotonic() + DEMO_SCAN_SECONDS
    seen = 0
    level = [root]
    for _ in range(2):
        deeper = []
        for folder in level:
            for entry in browse_dirs(folder)[0]:
                seen += 1
                if seen > DEMO_SCAN_DIRS or time.monotonic() > deadline:
                    return
                yield Path(entry.path).joinpath(*DEMO_PARTS)
                deeper.append(Path(entry.path))
        level = deeper


def find_demo(settings: Settings) -> dict:
    """Демо-данные для кнопки «Создать демо-проект»: {"report": путь к демо-выгрузке или None, "repos_dir": папка
    демо-репозиториев от корня папок с репозиториями или None, если они вне корня}."""
    root = settings.repos_root
    report: Path | None = None
    repos_dir: str | None = None
    app_report = APP_ROOT.joinpath(*DEMO_PARTS, DEMO_REPORT)
    # Копия демо-репозиториев, которую start.ps1 кладёт в папку для клонов (корень – отдельная папка, а не диск
    # с приложением): находится сразу, при любой глубине папки приложения
    if root.is_dir() and _is_demo_repos(root / DEMO_COPY) and app_report.is_file():
        checked, _ = check_project_folder(settings, DEMO_COPY)
        if checked is not None:
            return {"report": app_report, "repos_dir": checked}
    if root.is_dir():
        for folder in _demo_candidates(root):
            if not (folder / DEMO_REPORT).is_file() or not _is_demo_dir(folder):
                continue
            rel = _rel_inside(root, folder / "repos")
            if rel is None:
                report = report or folder / DEMO_REPORT
                continue
            checked, _ = check_project_folder(settings, rel)
            if checked is not None:
                return {"report": folder / DEMO_REPORT, "repos_dir": checked}
            report = report or folder / DEMO_REPORT
        if _is_demo_repos(root):  # корень – сами демо-репозитории, выгрузка – рядом с ними или в образе
            repos_dir = ""
            neighbour = root.parent / DEMO_REPORT
            if report is None and neighbour.is_file():
                report = neighbour
    if report is None and app_report.is_file():
        report = app_report
    return {"report": report, "repos_dir": repos_dir}


def unique_name(db: Database, name: str) -> str:
    """Название, которого ещё нет среди проектов (с номером, если есть)."""
    taken = {p["name"] for p in db.list_projects(archived=None)}
    if name not in taken:
        return name
    n = 2
    while f"{name} ({n})" in taken:
        n += 1
    return f"{name} ({n})"


# ============================================================================ список проектов

def project_row(p: dict) -> dict:
    """Проект для списка: ход разбора SAST и SCA вместе и по отдельности, внесено в Hub."""
    total = int(p.get("sast") or 0) + int(p.get("sca") or 0)
    done = int(p.get("reviewed") or 0) + int(p.get("sca_reviewed") or 0)
    entered = int(p.get("entered") or 0) + int(p.get("sca_entered") or 0)
    if not p.get("findings") and not p.get("missing"):
        action = "upload"
    elif done < total:
        action = "continue"
    else:
        action = "open"
    return {**p, "total": total, "done": done, "entered_total": entered, "action": action}


def list_response(request: Request, archived: bool = False, error: str = "", status_code: int = 200) -> HTMLResponse:
    db = db_of(request)
    projects = [project_row(p) for p in db.list_projects(archived=archived)]
    settings = settings_of(request)
    default_profile, profiles = None, {}
    for p in projects:  # модель без своей – из профиля, которым пойдёт разбор (как на странице проекта)
        if p.get("model"):
            continue
        pid = p.get("provider_id")
        if pid and pid not in profiles:
            profiles[pid] = db.get_provider(int(pid))
        profile = profiles.get(pid) if pid else None
        if profile is None:
            default_profile = default_profile or profile_for(request)
            profile = default_profile
        p["model_shown"], p["model_source"] = fallback_model(settings, profile)
    other = db.count_projects(archived=not archived)
    context = {"projects": projects, "archived": archived, "active_count": other if archived else len(projects),
               "archive_count": len(projects) if archived else other, "error": error}
    return render(request, "projects/list.html", context, status_code)


# ============================================================================ страница проекта

def model_listed(name: str, models: list[dict], profile: dict | None) -> bool:
    """Модель есть в списке сервера профиля: у Ollama – без учёта регистра и «:latest», у удалённых API – имя как есть
    (executors.same_model): так же её выберет форма запуска."""
    from app.executors import same_model

    key = same_model(str((profile or {}).get("kind") or "ollama"))
    return bool(name) and any(key(m.get("name")) == key(name) for m in models)


def fallback_model(settings: Settings, profile: dict | None) -> tuple[str, str]:
    """Модель проекта без своей модели и откуда она: модель профиля, которым пойдёт разбор (common.default_model), иначе
    модель из «Настроек». Второе – «из настроек» или «из профиля «…»» (у профиля 1 – «из настроек»)."""
    from app.db import DEFAULT_PROVIDER_ID

    model = str((profile or {}).get("default_model") or "")
    if model and (profile or {}).get("id") != DEFAULT_PROVIDER_ID:
        return model, f"из профиля «{profile.get('name') or ''}»"
    return model or settings.default_model, "из настроек"


def model_options(settings: Settings, models: list[dict], project: dict, profile: dict | None = None) -> list[dict]:
    """Варианты модели проекта: «как в профиле» (или «как в настройках») и модели сервера профиля (с объёмом и пометкой
    рассуждения, view.model_option); модель проекта, которой нет в Ollama, остаётся в списке с пометкой."""
    current = project.get("model") or ""
    fallback, source = fallback_model(settings, profile)
    label = f"Как в настройках: {fallback}" if source == "из настроек" else f"Как в профиле: {fallback}"
    options = [{"value": "", "label": label, "selected": not current}]
    from app.executors import same_model

    key = same_model(str((profile or {}).get("kind") or "ollama"))
    if current and not model_listed(current, models, profile):
        options.append({"value": current, "label": f"{current} – нет на сервере профиля", "selected": True})
    options += [{"value": m["name"], "label": model_option(m), "selected": bool(current) and key(m["name"]) == key(current)}
                for m in models]
    return options


def provider_number(raw: str) -> int | None:
    """Номер профиля из формы или адреса: только ASCII-цифры, не длиннее 9 знаков; иначе None (отказ 400, а не
    ValueError на «²» или переполнение параметра SQLite)."""
    raw = str(raw or "").strip()
    return int(raw) if raw.isascii() and raw.isdigit() and len(raw) <= 9 else None


CODE_PROFILE_REFUSED = ("Этот профиль не разбирает код: разбор кода – Ollama на этом компьютере или сервер в сети "
                        "организации; внешний провайдер – только проекту с отметкой «код не секретный».")


NOT_FOR_CODE_YET = "для разбора кода недоступен"
NOT_WITHOUT_MARK = "нужна отметка «код не секретный»"
NOT_FOR_CODE_NOTE = ("Внешнему провайдеру код уходит только проекту с отметкой «код не секретный» – она ставится "
                     "ниже, после предпросмотра. Сервер удалённого API (чат-завершения или Messages) не в интернете "
                     "код не разбирает.")


def code_profile_ok(profile: dict, project: dict | None = None) -> bool:
    """Профиль годится для разбора кода этого проекта (executors.code_profile_fits): Ollama своего контура – всегда,
    внешний профиль удалённого API – при отметке «код не секретный»."""
    from app.executors import code_profile_fits
    return code_profile_fits(profile, project)


def provider_options(db: Database, settings: Settings, project: dict) -> list[dict]:
    """Варианты профиля модели проекта: «как в настройках» (профиль по умолчанию) и включённые профили для разбора
    кода; выбранный, но выключенный профиль остаётся в списке с пометкой. Профиль, который для разбора кода в этой
    версии не годится (внешний провайдер без отметки, удалённый API не в интернете), виден неактивным с причиной –
    молча скрытый, он выглядел пропавшим; выбрать его запрос в обход формы по-прежнему не
    может."""
    from app.db import DEFAULT_PROVIDER_ID
    from app.executors import REMOTE_KINDS
    current = project.get("provider_id")
    default = db.get_provider(settings.default_provider_id or DEFAULT_PROVIDER_ID) or {}
    options = [{"value": "", "label": f"Как в настройках: {default.get('name') or 'профиль по умолчанию'}",
                "selected": not current}]
    for p in db.list_providers():
        if not p["enabled"] and p["id"] != current:
            continue
        where = {"local": "этот компьютер", "lan": "сеть организации", "external": "интернет"}.get(
            str(p["trust"]), str(p["trust"]))
        if not code_profile_ok(p, project):
            # негодный профиль (внешний без отметки проекта, сервер удалённого API не в интернете, профиль, ставший
            # негодным после смены протокола) – виден неактивным с причиной, выбранный раньше – выбранным
            why = (NOT_WITHOUT_MARK if str(p["trust"]) == "external" and str(p.get("kind")) in REMOTE_KINDS
                   else NOT_FOR_CODE_YET)
            options.append({"value": str(p["id"]), "label": f"{p['name']} ({where}) – {why}",
                            "selected": p["id"] == current, "disabled": True})
            continue
        label = f"{p['name']} ({where})" + ("" if p["enabled"] else " – выключен")
        options.append({"value": str(p["id"]), "label": label, "selected": p["id"] == current})
    return options


def project_context(request: Request, project: dict) -> dict:
    db = db_of(request)
    settings = settings_of(request)
    pid = project["id"]
    imp = db.latest_import(pid)
    counts = db.count_findings(pid)
    counts.update(db.sast_hub_classes(pid))  # охват прогона «живые в Hub» (бэклог 104)
    base, base_error = repos_base(settings, project)
    mapping = codebase_rows(db, project, base)
    profile = profile_for(request, project)
    models = models_of(request, profile=profile)
    gpu = metrics_of(request, profile).get("gpu")  # у профиля lan – видеокарты этого компьютера нет
    vram_total = gpu["mem_total_mb"] if gpu and gpu.get("mem_total_mb") else None
    summary_rows = []
    if imp:
        # Сверку листа со сводкой делает разбор выгрузки (hub_import): по практике листа и по числу находок
        # без повторов. expected – число в сводке, match – True, False или None (сверить нельзя).
        for sheet in imp["sheets"]:
            summary_rows.append({**sheet, "expected": sheet.get("expected"), "match": sheet.get("match"),
                                 "count": sheet.get("findings", sheet.get("rows", 0))})
    mismatch = any(s["match"] is False for s in summary_rows)
    stats = db.review_stats(pid)
    active = db.active_runs(pid)
    first_unreviewed = db.neighbor_unreviewed(pid, -1, "next")
    sca_unreviewed = db.neighbor_unreviewed(pid, -1, "next", kinds=("SCA",))
    # Акцент – только у кнопки следующего шага
    if not imp:
        next_step = "upload"
    elif (not (project.get("repos_dir") or "") and mapping["to_clone"]
          and not any(c["exists"] or c["suggestion"] for c in mapping["codebases"])):
        next_step = "folder"  # папка проекта не выбрана, и в корне не нашлось ни одного клона
    elif mapping["unsaved"]:
        next_step = "map"
    elif stats.get("with_verdict"):
        next_step = "review"
    else:
        next_step = "run"
    if base_error and project.get("repos_dir") and mapping["snapshots"]["ready"]:
        # Папку проекта с клонами удалили после разбора, а срезы есть у всех находок SAST: это не ошибка (ADR-0072)
        base_error = ""
    notices = [text for text in (revision_note(db.revision_notice(pid)),) if text]
    code_notice = db.code_change_notice(pid)
    code_change_text = code_change_note(code_notice, db.reviewed_among(pid, (code_notice or {}).get("hub_ids") or []))
    repos_dir = project.get("repos_dir") or ""
    model_name = project.get("model") or ""
    from app.routes.examples import DEMO_KEY, example_of_project
    example_key = example_of_project(db, pid)
    catalog_example = bool(example_key)
    example_restorable = bool(example_key) and example_key != DEMO_KEY
    return {
        "catalog_example": catalog_example, "example_restorable": example_restorable,
        "project": project, "imp": imp, "counts": counts, "summary_rows": summary_rows, "mismatch": mismatch,
        "first_import": db.import_count(pid) <= 1,
        "repos_root": repos_display(settings), "repos_base": str(base) if base else "",
        "folder_display": folder_display(settings, repos_dir),
        "clone_into": folder_display(settings, repos_dir),
        # предупреждение о демо – только когда start.ps1 подключил демо-папку приложения (бэклог 94): папки
        # демо-комплекта рядом с рабочими клонами признаком демо не считаются; источник не определён – нейтрально
        "demo_repos_root": settings.repos_root_is_demo == "1",
        "repos_source_unknown": settings.repos_root_is_demo == "",
        "repos_error": base_error, **mapping,
        "models": models["models"], "ollama_version": models["version"],
        "ollama_error": models["error"], "ollama_url": settings.ollama_url,
        "default_model": default_model(settings, models["models"], project, profile),
        "traffic_log_on": settings.model_traffic_log == "on",  # ADR-0083: предупреждение у выбора модели
        "project_model": model_name or fallback_model(settings, profile)[0], "model_from_settings": not model_name,
        "model_source": fallback_model(settings, profile)[1],
        "model_missing": bool(models["models"]) and not model_listed(model_name or fallback_model(settings, profile)[0],
                                                                      models["models"], profile),
        "model_options": model_options(settings, models["models"], project, profile),
        "provider_options": provider_options(db, settings, project), "not_for_code_note": NOT_FOR_CODE_NOTE,
        "run_profile": profile,
        "vram_total_mb": vram_total, "runs": db.list_runs(pid, 10), "active_runs": active,
        "review_stats": stats, "first_unreviewed": first_unreviewed, "sca_unreviewed": sca_unreviewed,
        "revision_notices": notices, "code_change_text": code_change_text,
        "code_change_at": code_notice_version(code_notice) if code_notice else "", "next_step": next_step, "reset_counts": db.case_reset_counts(pid),
        # ADR-0096 п. 10: компоненты отдельно от находок SCA – только строки текущей выгрузки
        "component_stats": component_stats(db, pid, settings.sca_internal_prefixes) if stats.get("sca") else None,
        # шаг «Состояние Hub» (0.10.0.dev13): дефекты и статусы из Hub – синхронизацией, до начала работы
        "hub_step": hub_onboarding.state(db, project, settings.hub_url),
        # строка «Синхронизация с Hub» (dev15, бэклог 88): та же функция, что у синхронизации
        "hub_sync_summary": hub_state.project_states(db, project, settings.hub_url)["summary"],
        # ?open=params – ссылка «исправить номер приложения» открывает свёрнутые параметры (dev13)
        "params_open": request.query_params.get("open") == "params",
    }


def component_stats(db, project_id: int, prefixes) -> dict:
    """Счётчики компонентов для обзора: пакеты текущей выгрузки (те же, что строки задания) – исследовано, с решением,
    требуют пересмотра; коротким чтением базы, без построения представлений."""
    from app import sca
    from app.sca_contract import input_ref
    # тот же отбор, что у строк задания: с подтверждёнными человеком сомнительными именами
    packages, _ = sca.package_report(db.sca_components(project_id), prefixes, db.sca_confirmed(project_id))
    refs = {input_ref(p["ecosystem"], p["component"], p["version"]) for p in packages}
    return db.component_counts(project_id, refs)


def project_response(request: Request, project_id: int, error: str = "", status_code: int = 200,
                     extra: dict | None = None):
    """Страница проекта; error – сообщение об ошибке над страницей (например, прогон не запустился); extra –
    дополнительные значения для шаблона."""
    project = project_or_404(request, project_id)
    context = project_context(request, project)
    context["error"] = error
    context.update(extra or {})
    return render(request, "projects/project.html", context, status_code)


def delete_context(request: Request, project: dict) -> dict:
    """Что пропадёт при удалении проекта."""
    db = db_of(request)
    pid = project["id"]
    active = db.active_runs(pid)
    return {"project": project, "counts": db.count_findings(pid), "stats": db.review_stats(pid),
            "runs_count": len(db.list_runs(pid, 100000)), "imports_count": db.import_count(pid),
            "snapshots_count": sum(n["code"] for n in db.snapshot_counts(pid).values()),
            "running": any(r["state"] == "running" for r in active)}


# ============================================================================ адреса: список

@router.get("/", response_class=HTMLResponse)
def projects_page(request: Request):
    return list_response(request)


@router.get("/projects/archive", response_class=HTMLResponse)
def archive_page(request: Request):
    return list_response(request, archived=True)


@router.post("/projects")
async def create_project(request: Request):
    form = await request.form()
    name = " ".join(str(form.get("name") or "").split())[:MAX_NAME]
    if not name:
        return await run_in_threadpool(list_response, request, False, "Укажите название проекта.", 400)
    # флажок «маскировать при показе» (dev14, ADR-0141): снят – в карточках код без масок, модели – всегда с масками
    mask = form.get("mask_secrets") == "1" if form.get("mask_form") == "1" else False  # поля нет – без масок
    project_id = await run_in_threadpool(lambda: db_of(request).create_project(name, mask_secrets=mask))
    return redirect(f"/projects/{project_id}?ok=created")


@router.post("/projects/demo")
async def create_demo(request: Request):
    """Демо-проект: демо-выгрузка из examples/demo и папка с демо-репозиториями, если она внутри корня."""

    def apply():
        if not _IMPORT_SLOT.acquire(blocking=False):
            return list_response(request, error=IMPORT_BUSY, status_code=409)
        try:
            made = make_demo(request)
            if not isinstance(made, tuple):
                return made
            project_id, ok = made
            return redirect(f"/projects/{project_id}?ok={ok}")
        finally:
            _IMPORT_SLOT.release()

    return await run_in_threadpool(apply)


DEMO_MARK_REASON = "Демо-пример: выдуманный код, написанный для приложения, без секретов и реальных данных"


def make_demo(request: Request, after=None, import_after=None, project_id: int | None = None):
    """Демо-проект (вызывающий держит _IMPORT_SLOT): (номер проекта, ключ сообщения) или ответ с ошибкой. after(c, id)
    – запись в транзакции создания проекта, import_after(c, import_id) – в транзакции импорта (связь записи № 0
    каталога примеров, ADR-0156); project_id – продолжить уже созданный проект после обрыва."""
    settings = settings_of(request)
    db = db_of(request)
    demo = find_demo(settings)
    if demo["report"] is None:
        where = ("Установка стенда повреждена: запустите его заново с ключом --reinstall." if settings.stand == "npm"
                 else "Запустите приложение через start.ps1 из папки приложения – он подключает весь диск с ней.")
        return list_response(request, error=(
            "Демо-выгрузка examples/demo/demo-hub-report.xlsx приложению не видна: её нет ни рядом "
            "с приложением, ни внутри корня папок с репозиториями. " + where), status_code=404)
    try:
        result = parse_workbook(demo["report"], settings.max_upload_bytes)
    except ImportFailure as e:
        return list_response(request, error=str(e), status_code=400)
    except Exception as e:
        eid = log_failure(log, "демо-выгрузка не прочитана", e)
        return list_response(request, error=f"Не удалось прочитать демо-выгрузку (ошибка {eid}).",
                             status_code=500)
    application = str(result.summary.get("application") or "").strip() or "Demo Library"
    created_now = project_id is None
    if project_id is None:
        project_id = db.create_project(unique_name(db, f"Демо: {application}"[:MAX_NAME]), after=after)
    if demo["repos_dir"] is not None:
        db.set_repos_dir(project_id, demo["repos_dir"])
    store_import(settings, db, project_id, DEMO_REPORT, result, after=import_after)
    if created_now:
        # код демо выдуманный, написан для приложения (examples/demo, с первого коммита 15.10.2026): отметка «код не
        # секретный» по умолчанию – слово владельца 22.11.2026; действует, только когда внешние провайдеры включены;
        # снимается в параметрах проекта
        db.set_external_mark(project_id, DEMO_MARK_REASON)
    ok = "project_demo" if demo["repos_dir"] is not None else "project_demo_nocode"
    return project_id, ok


# ============================================================================ адреса: проект

@router.get("/projects/{project_id}", response_class=HTMLResponse)
def project_page(request: Request, project_id: int):
    return project_response(request, project_id)


HUB_APP_ID_REFUSED = ("Приложение в Hub: укажите номер приложения – целое число из адреса его страницы в Hub "
                      "(…/#/appprofile/<номер>/…) или вставьте эту ссылку целиком – или оставьте поле пустым.")
_HUB_APP_LINK = re.compile(r"https?://[A-Za-z0-9](?:[A-Za-z0-9.-]*[A-Za-z0-9])?(?::[0-9]{1,5})?(?:/\S*?)?/appprofile/([0-9]{1,12})(?:[/?#]\S*)?")


CATALOG_HUB_REFUSED = "Проект из каталога учебных примеров с Hub не связывается: его выгрузка – выгрузка примера."


def catalog_hub_refused(db: Database, project_id: int) -> bool:
    """Проект из каталога с Hub не связывается: новая находка из Hub добавила бы в промпт путь и правило вне выгрузки
    примера (план стенда, раздел 6; ADR-0157)."""
    from app.routes.examples import is_catalog_project
    return is_catalog_project(db, project_id)


def hub_app_number(raw: str) -> int | None:
    """Номер приложения Hub из поля: число или ссылка на любую страницу приложения в Hub (…/#/appprofile/<номер>/…).
    Пусто или не разобрать – None."""
    text = raw.strip()
    if text.isascii() and text.isdigit():
        number = int(text)
    elif match := _HUB_APP_LINK.fullmatch(text):  # ссылка целиком, без окружающего текста (ревью dev13)
        number = int(match.group(1))
    else:
        return None
    return number if 0 < number < 10**12 else None


@router.post("/projects/{project_id}/params")
async def save_params(request: Request, project_id: int):
    """Параметры проекта: название, модель («» – модель из настроек), профиль модели, номер приложения в Hub
    (ADR-0114; «» – запись в Hub для проекта выключена; поля нет в форме – не меняется)."""
    form = await request.form(max_fields=10, max_files=0)
    name = " ".join(str(form.get("name") or "").split())[:MAX_NAME]
    raw_model = str(form.get("model") or "")
    raw_provider = str(form.get("provider_id") or "").strip()
    raw_hub_app = str(form.get("hub_app_id") or "").strip() if "hub_app_id" in form else None
    # флажок «маскировать при показе» (dev14, ADR-0141): поля нет в форме – не меняется
    mask_secrets = (form.get("mask_secrets") == "1") if form.get("mask_form") == "1" else None

    def apply():
        project = project_or_404(request, project_id)
        if not name:
            return project_response(request, project_id, "Укажите название проекта.", 400)
        try:
            model = normalize_setting("default_model", raw_model)
        except ConfigError:
            return project_response(request, project_id, "Модель проекта: неверное имя модели.", 400)
        db = db_of(request)
        provider_id: int | None | bool = False if "provider_id" not in form else None
        if raw_provider:
            profile = db.get_provider(number) if (number := provider_number(raw_provider)) is not None else None
            if profile is None or (not profile["enabled"] and profile["id"] != project.get("provider_id")):
                return project_response(request, project_id, "Профиль модели: выберите включённый профиль.", 400)
            if not code_profile_ok(profile, project):
                return project_response(request, project_id, CODE_PROFILE_REFUSED, 400)
            provider_id = int(profile["id"])
        hub_app_id: int | None | bool = False
        if raw_hub_app is not None:
            number = hub_app_number(raw_hub_app)
            if raw_hub_app and number is None:
                return project_response(request, project_id, HUB_APP_ID_REFUSED, 400)
            if number is not None and catalog_hub_refused(db, project_id):
                return project_response(request, project_id, CATALOG_HUB_REFUSED, 400)
            hub_app_id = number
        db.update_project(project_id, name=name, model=model, provider_id=provider_id, mask_secrets=mask_secrets)
        if hub_app_id is not False:
            # смена назначения Hub – операция п. 4.5 плана dev17: если она что-то меняет (сведения Hub о
            # библиотеках, решения из Hub прежнего назначения), сначала подтверждение с итогом; совпадает ли номер с
            # действующим, решает её транзакция, а не прочитанный раньше проект (ревью Codex шага 4, круг 3)
            target = "" if hub_app_id is None else str(hub_app_id)
            preview = db.change_hub_assignment(project_id, hub_app_id, dry=True)
            if preview.get("affects"):
                return redirect(f"/projects/{project_id}/hub-assignment?app={target}")
            try:  # без последствий – сразу, но по отпечатку расчёта: изменилось между ними – подтверждение
                db.change_hub_assignment(project_id, hub_app_id, expect=preview.get("token"))
            except ValueError:
                return redirect(f"/projects/{project_id}/hub-assignment?app={target}")
        return redirect(f"/projects/{project_id}?ok=project_saved")

    return await run_in_threadpool(apply)


@router.get("/projects/{project_id}/hub-assignment", response_class=HTMLResponse)
def hub_assignment_preview(request: Request, project_id: int, app: str = ""):
    """Подтверждение смены номера приложения Hub (план dev17, п. 4.5): что произойдёт – сведения о библиотеках
    сбрасываются, решения из Hub прежнего назначения уходят в историю, переход к идентичности файла. Только чтение:
    итог считается в откатываемой транзакции."""
    project = project_or_404(request, project_id)
    db = db_of(request)
    number = hub_app_number(app) if app else None
    if app and number is None:
        return project_response(request, project_id, HUB_APP_ID_REFUSED, 400)
    if number is not None and catalog_hub_refused(db, project_id):
        return project_response(request, project_id, CATALOG_HUB_REFUSED, 400)
    try:
        result = db.change_hub_assignment(project_id, number, dry=True)
    except ValueError as e:
        return project_response(request, project_id, str(e), 409)
    if result.get("unchanged"):  # назначение уже такое – подтверждать нечего (ревью Codex, круг 2)
        return redirect(f"/projects/{project_id}?ok=project_saved")
    from app.package_transition import TABLE_LABELS, entity_rows
    summary = result.get("summary") or {}
    return render(request, "projects/hub_assignment.html", {
        "project": project, "counts": db.count_findings(project_id), "review_stats": db.review_stats(project_id),
        "new_app": number, "token": result.get("token", ""), "summary": summary,
        "entity_rows": entity_rows(summary), "table_labels": TABLE_LABELS})


@router.post("/projects/{project_id}/hub-assignment")
async def hub_assignment_apply(request: Request, project_id: int):
    """Смена номера приложения Hub по подтверждению: отпечаток входов из страницы подтверждения сверяется в той же
    транзакции; изменилось что-либо – отказ, ничего не записано."""
    form = await request.form(max_fields=4, max_files=0)
    raw = str(form.get("app") or "").strip()
    token = str(form.get("token") or "")

    def apply():
        project_or_404(request, project_id)
        number = hub_app_number(raw) if raw else None
        if raw and number is None:
            return project_response(request, project_id, HUB_APP_ID_REFUSED, 400)
        if number is not None and catalog_hub_refused(db_of(request), project_id):
            return project_response(request, project_id, CATALOG_HUB_REFUSED, 400)
        try:
            if db_of(request).change_hub_assignment(project_id, number, expect=token).get("unchanged"):
                return redirect(f"/projects/{project_id}?ok=project_saved")  # уже такое – сброса нет
        except ValueError as e:
            return project_response(request, project_id, str(e), 409)
        log.info("проект %d: назначение Hub сменено (номер приложения %s)", project_id, number)
        return redirect(f"/projects/{project_id}?ok=project_saved")

    return await run_in_threadpool(apply)


@router.get("/projects/{project_id}/models.json")
def project_models(request: Request, project_id: int, provider_id: str = ""):
    """Варианты «Модели проекта» для профиля, выбранного в «Параметрах проекта», до сохранения (иначе
    при выборе внешнего профиля список оставался бы списком прежнего профиля, пока не нажать «Сохранить»).
    Профиль проверяется так же, как при сохранении; профиль и модель проекта не меняются. «» – как в настройках."""
    project = project_or_404(request, project_id)
    db, settings = db_of(request), settings_of(request)
    raw = str(provider_id or "").strip()
    if raw:
        profile = db.get_provider(number) if (number := provider_number(raw)) is not None else None
        if profile is None or (not profile["enabled"] and profile["id"] != project.get("provider_id")):
            return JSONResponse({"detail": "Профиль модели: выберите включённый профиль."}, status_code=400)
        if not code_profile_ok(profile, project):
            return JSONResponse({"detail": CODE_PROFILE_REFUSED}, status_code=400)
    else:
        profile = profile_for(request, {**project, "provider_id": None})
    models = models_of(request, profile=profile)
    return {"options": model_options(settings, models["models"], project, profile), "error": models["error"] or "",
            "profile": profile["name"]}


@router.post("/projects/{project_id}/provider")
async def save_provider(request: Request, project_id: int):
    """Профиль модели проекта из шага «Триаж» («» – как в настройках): только профиль, название и модель не меняются.
    После смены список моделей шага – с сервера нового профиля."""
    form = await request.form(max_fields=4, max_files=0)
    raw_provider = str(form.get("provider_id") or "").strip()

    def apply():
        project = project_or_404(request, project_id)
        db = db_of(request)
        provider_id: int | None = None
        if raw_provider:
            profile = db.get_provider(number) if (number := provider_number(raw_provider)) is not None else None
            if profile is None or (not profile["enabled"] and profile["id"] != project.get("provider_id")):
                return project_response(request, project_id, "Профиль модели: выберите включённый профиль.", 400)
            if not code_profile_ok(profile, project):
                return project_response(request, project_id, CODE_PROFILE_REFUSED, 400)
            provider_id = int(profile["id"])
        db.update_project(project_id, provider_id=provider_id)
        return redirect(f"/projects/{project_id}?ok=provider_changed#step3")

    return await run_in_threadpool(apply)


# ------------------------------------------------------------------ отметка «код не секретный» (ADR-0104 п. 3, К9)

EXTERNAL_REASON_MIN, EXTERNAL_REASON_MAX = 10, 1000
EXTERNAL_PROBLEMS = {
    "external_off": "Отправка в интернет в этой установке выключена (LLM_EXTERNAL): отметку ставить не к чему.",
    "external_confirm": "Отметка не поставлена: нужно подтвердить отправку флажком.",
    "external_preview": "Отметка не поставлена: форма не со страницы предпросмотра или то, что уйдёт провайдеру, с тех "
                        "пор изменилось – посмотрите предпросмотр заново и подтвердите ещё раз.",
    "external_reason": f"Отметка не поставлена: обоснование – от {EXTERNAL_REASON_MIN} до {EXTERNAL_REASON_MAX} знаков.",
    "external_busy": "Отметка не снята: отправка внешнему провайдеру не закончилась – повторите через минуту.",
}


def external_preview_context(request: Request, project: dict) -> dict:
    """Предпросмотр перед отметкой: промпт первой находки SAST целиком – той же сборкой и с тем же маскированием, что
    в прогоне (срез из сохранённого среза или клона); внешние профили, которым код может уйти."""
    from app import sca_research_net as net
    from app.prompts import build_sast_messages
    from app.triage import CONTEXT_CHARS, repo_dir_for, snapshot_code, source_codebases
    db, settings, pid = db_of(request), settings_of(request), project["id"]
    hub_ids = db.sast_queue(pid, "all")
    messages: list[dict] = []
    hub_id, note = "", ""
    if hub_ids:
        hub_id = hub_ids[0]
        source = db.case_input(pid, hub_id)
        if source is not None:
            f = Finding.from_dict(source["data"])
            stored = db.get_case(pid, hub_id)
            snapshot = snapshot_code(settings, source, stored)
            if snapshot is not None:
                ctx = snapshot[0]
            else:
                repo_dir, why = repo_dir_for(settings, {"repos_dir": source["repos_dir"]}, source_codebases(source, f), f)
                ctx = build_context(repo_dir, f, max_chars=CONTEXT_CHARS, mask_key=mask_key_of(request), no_repo_note=why)
            from app import affiliation
            # как уйдёт модели: второй проход маскирования и маска принадлежности (ADR-0118)
            messages = affiliation.mask_messages(
                runner_of(request)._masked(build_sast_messages(f, ctx, mask_key=mask_key_of(request))))
    if not messages:
        note = ("В проекте нет находок SAST текущей выгрузки – показать промпт не из чего, а отметка ставится только "
                "после предпросмотра: загрузите выгрузку с находками SAST и откройте эту страницу снова.")
    from app.executors import REMOTE_KINDS
    externals = [p for p in db.list_providers()
                 if p["enabled"] and str(p["trust"]) == "external" and str(p.get("kind")) in REMOTE_KINDS]
    nonce = secrets.token_hex(8)
    from app.routes.examples import pending_profile, root_of
    pending = pending_profile(db, pid, root_of(settings))  # один расчёт: показ, подпись предпросмотра и назначение
    promised = pending
    signed = externals + ([{"id": -int(promised["id"]), "version": promised.get("version") or 0}] if promised else [])
    fingerprint = external_fingerprint(project, messages, signed, db.external_mark_revision(pid))
    token = (net.preview_token(request.app.state.research_secret, fingerprint, nonce)
             if messages and external_enabled() else "")
    from app.routes.examples import example_reason, is_catalog_project
    # проект из каталога: обоснование – только по целой связи с примером; прежнее (после чужого импорта) не подставляется
    from app.routes.examples import root_of
    reason_default = (example_reason(db, pid, root_of(settings)) if is_catalog_project(db, pid)
                      else project.get("external_reason"))
    return {"project": project, "messages": messages, "hub_id": hub_id, "note": note, "externals": externals,
            "reason_default": reason_default, "pending_profile": pending,
            "counts": db.count_findings(pid), "review_stats": db.review_stats(pid), "external_on": external_enabled(),
            "reason_min": EXTERNAL_REASON_MIN, "reason_max": EXTERNAL_REASON_MAX, "nonce": nonce, "token": token,
            "error": EXTERNAL_PROBLEMS.get(request.query_params.get("err", ""), "")}


def external_fingerprint(project: dict, messages: list[dict], externals: list[dict], revision: int = 0) -> str:
    """Что подписывает метка предпросмотра: проект, ревизия отметки (растёт при каждой постановке и снятии – форма,
    открытая до отметки или пока она стояла, после любого изменения недействительна, даже если два цикла уложились в
    одну секунду), показанный промпт (сообщения целиком) и внешние профили."""
    from app.sca_contract import canonical, sha256
    return sha256(canonical([int(project["id"]), int(revision), int(project.get("external_allowed") or 0),
                             str(project.get("external_confirmed_at") or ""),
                             [[str(m.get("role")), str(m.get("content"))] for m in messages],
                             sorted((int(p["id"]), int(p.get("version") or 0)) for p in externals)]))


@router.get("/projects/{project_id}/hub-text-rules", response_class=HTMLResponse)
def hub_text_rules(request: Request, project_id: int):
    """Масштаб смены правил текста для Hub в 0.10.0.dev21: решения, у которых текст по прежним
    правилам отличается от нынешнего, с отметками «Внесено в Hub». Только чтение: аренды Hub не истекают, дефекты не
    сверяются, ничего не пишется."""
    from app import hub_text_scale
    from app.routes.feeds import store_of
    project = project_or_404(request, project_id)
    db = db_of(request)
    return render(request, "projects/hub_text_rules.html", {
        "project": project, "counts": db.count_findings(project_id), "review_stats": db.review_stats(project_id),
        "report": hub_text_scale.report(db, settings_of(request), project_id, store_of(request))})


@router.get("/projects/{project_id}/external", response_class=HTMLResponse)
def external_preview(request: Request, project_id: int):
    """Страница предпросмотра и отметки «код не секретный»."""
    project = project_or_404(request, project_id)
    return render(request, "projects/external.html", external_preview_context(request, project))


@router.post("/projects/{project_id}/external")
async def external_mark(request: Request, project_id: int):
    """Поставить отметку: только со страницы предпросмотра, с обоснованием и явным подтверждением флажком."""
    from app import sca_research_net as net
    form = await request.form(max_fields=8, max_files=0)
    reason = " ".join(str(form.get("reason") or "").split())
    confirmed = str(form.get("confirm") or "") == "1"
    nonce = str(form.get("nonce") or "")
    token = str(form.get("token") or "")

    from app.executors import project_gate

    outcome = "none"

    def apply():
        nonlocal outcome
        project_or_404(request, project_id)
        if not external_enabled():
            return redirect(f"/projects/{project_id}/external?err=external_off")
        if not confirmed:
            return redirect(f"/projects/{project_id}/external?err=external_confirm")
        if not EXTERNAL_REASON_MIN <= len(reason) <= EXTERNAL_REASON_MAX:
            return redirect(f"/projects/{project_id}/external?err=external_reason")
        # серверная метка предпросмотра (как у согласия на исследование): подписаны проект, показанный промпт, внешние
        # профили, состояние и время прежней отметки – прямой POST без страницы, после смены промпта или после снятия
        # отметки не проходит; без находки SAST (промпт показать не из чего) отметка не ставится. Чтение состояния,
        # проверка и запись – под исключительной блокировкой проекта: снятие отметки между ними не вклинится
        try:
            with project_gate(project_id).write():
                project = project_or_404(request, project_id)
                shown = external_preview_context(request, project)
                revision = db_of(request).external_mark_revision(project_id)
                promised = shown.get("pending_profile")
                signed = shown["externals"] + ([{"id": -int(promised["id"]), "version": promised.get("version") or 0}]
                                               if promised else [])
                expected = (net.preview_token(request.app.state.research_secret,
                                              external_fingerprint(project, shown["messages"], signed, revision),
                                              nonce)
                            if nonce and shown["messages"] else "")
                if not token or not expected or not hmac.compare_digest(expected, token):
                    return redirect(f"/projects/{project_id}/external?err=external_preview")
                db_of(request).set_external_mark(project_id, reason)
                # проект из каталога с целой связью: внешний профиль для примеров – теперь, после отметки (ADR-0157)
                from app.routes.examples import finish_pending_profile, remember_mark_root, root_of
                remember_mark_root(db_of(request), project_id, settings_of(request))
                promised = shown.get("pending_profile")
                outcome = finish_pending_profile(db_of(request), project_id, root_of(settings_of(request)),
                                                 int(promised["id"]) if promised else None)
        except TimeoutError:
            return project_response(request, project_id, EXTERNAL_PROBLEMS["external_busy"], 409)
        log.info("проект %d: отметка «код не секретный» поставлена", project_id)
        if outcome == "assigned":
            return redirect(f"/projects/{project_id}?ok=external_marked_example#params")
        if outcome not in ("none", "needs_mark"):
            return redirect(f"/projects/{project_id}?ok=project_example_noprofile_{outcome}#params")
        return redirect(f"/projects/{project_id}?ok=external_marked#params")

    return await run_in_threadpool(apply)


@router.post("/projects/{project_id}/code-change/clear")
async def code_change_clear(request: Request, project_id: int):
    """«Понятно» у пояснения о смене кода (бэклог 115): показанное пояснение больше не показывается; если прогон с тех
    пор его дополнил, оно остаётся (ревью Codex). Отметки «Проверено» не возвращаются – их ставит человек."""
    form = await request.form(max_fields=4, max_files=0)
    shown_at = str(form.get("shown_at") or "")

    def apply():
        project_or_404(request, project_id)
        db_of(request).clear_code_change_notice(project_id, shown_at)
        return redirect(f"/projects/{project_id}#params")

    return await run_in_threadpool(apply)


@router.post("/projects/{project_id}/external/clear")
async def external_clear(request: Request, project_id: int):
    """Снять отметку – сразу, под исключительной блокировкой проекта (К2): начатая отправка внешнему провайдеру
    дописывает байты, следующая уже не проходит; идущий прогон встанет на паузу перед следующей находкой."""
    from app.executors import project_gate

    def apply():
        project_or_404(request, project_id)
        try:
            with project_gate(project_id).write():
                db_of(request).clear_external_mark(project_id)
        except TimeoutError:
            return project_response(request, project_id, EXTERNAL_PROBLEMS["external_busy"], 409)
        log.info("проект %d: отметка «код не секретный» снята", project_id)
        return redirect(f"/projects/{project_id}?ok=external_cleared#params")

    return await run_in_threadpool(apply)


@router.get("/projects/{project_id}/continue")
def continue_review(request: Request, project_id: int):
    """«Продолжить»: непроверенные SAST, затем SCA, лицензии и DAST.
    Без выгрузки или когда проверять нечего – страница проекта."""
    project_or_404(request, project_id)
    db = db_of(request)
    if not db.import_count(project_id):
        return redirect(f"/projects/{project_id}#step1")
    finding = db.neighbor_unreviewed(project_id, -1, "next")
    if finding is not None:
        return redirect(f"/projects/{project_id}/findings/{finding}")
    finding = db.neighbor_unreviewed(project_id, -1, "next", kinds=("SCA",))
    if finding is not None:
        return redirect(f"/projects/{project_id}/sca/findings/{finding}")
    finding = db.neighbor_unreviewed(project_id, -1, "next", kinds=("SCA-license", "DAST"))
    if finding is not None:
        return redirect(f"/projects/{project_id}/findings/{finding}")
    return redirect(f"/projects/{project_id}?ok=project_all_reviewed")


@router.post("/projects/{project_id}/archive")
async def archive_project(request: Request, project_id: int):
    form = await request.form(max_fields=5, max_files=0)
    restore = str(form.get("action") or "") == "restore"

    def apply():
        project_or_404(request, project_id)
        db_of(request).set_project_archived(project_id, not restore)
        return redirect("/?ok=project_restored" if restore else "/?ok=project_archived")

    return await run_in_threadpool(apply)


@router.get("/projects/{project_id}/delete", response_class=HTMLResponse)
def delete_page(request: Request, project_id: int):
    project = project_or_404(request, project_id)
    return render(request, "projects/delete.html", delete_context(request, project))


@router.post("/projects/{project_id}/delete")
async def delete_project(request: Request, project_id: int):
    form = await request.form(max_fields=5, max_files=0)
    confirmed = str(form.get("confirm") or "") == "yes"

    def apply():
        project = project_or_404(request, project_id)
        if not confirmed:
            return render(request, "projects/delete.html",
                          {**delete_context(request, project), "error": "Подтвердите удаление кнопкой ниже."}, 400)
        try:
            db_of(request).delete_project(project_id)
        except ProjectBusy as e:
            return render(request, "projects/delete.html", {**delete_context(request, project), "error": str(e)}, 409)
        return redirect("/?ok=project_deleted")

    return await run_in_threadpool(apply)


@router.get("/projects/{project_id}/folders", response_class=HTMLResponse)
def folders_page(request: Request, project_id: int, path: str = ""):
    project = project_or_404(request, project_id)
    return render(request, "projects/folders.html", folders_context(request, project, path))


@router.post("/projects/{project_id}/import")
async def upload_export(request: Request, project_id: int):
    await run_in_threadpool(project_or_404, request, project_id)
    settings = await run_in_threadpool(settings_of, request)
    form = await request.form(max_files=1, max_fields=10)
    if not _IMPORT_SLOT.acquire(blocking=False):
        await form.close()
        return await run_in_threadpool(project_response, request, project_id, IMPORT_BUSY, 409)
    try:
        upload = form.get("file")
        confirmed = str(form.get("confirm_other") or "") == "1"
        try:
            if not isinstance(upload, UploadFile) or not upload.filename:
                raise ImportFailure("Выберите файл выгрузки (.xlsx или .csv).")
            filename = Path(upload.filename.replace("\\", "/")).name[:MAX_NAME]
            suffix = Path(filename).suffix.lower()
            if suffix not in (".xlsx", ".csv"):
                raise ImportFailure("Поддерживаются выгрузки .xlsx (отчёт AppSec.Hub) и .csv.")
            settings.tmp_dir.mkdir(parents=True, exist_ok=True)
            fd, tmp_name = tempfile.mkstemp(dir=settings.tmp_dir, suffix=suffix)
            tmp = Path(tmp_name)
            try:
                size = 0
                with os.fdopen(fd, "wb") as out:
                    while chunk := await upload.read(1024 * 1024):
                        size += len(chunk)
                        if size > settings.max_upload_bytes:
                            raise ImportFailure(f"Файл больше {settings.max_upload_mb} МБ – это предел приложения.")
                        out.write(chunk)
                result = await run_in_threadpool(parse_workbook, tmp, settings.max_upload_bytes)
            finally:
                tmp.unlink(missing_ok=True)
        except ImportFailure as e:
            return await run_in_threadpool(project_response, request, project_id, str(e), 400)
        except Exception as e:
            eid = log_failure(log, "выгрузка не прочитана", e)
            return await run_in_threadpool(project_response, request, project_id,
                                           "Не удалось прочитать файл: он повреждён или это не выгрузка AppSec.Hub "
                                           f"(ошибка {eid}).", 400)
        finally:
            await form.close()
        if not confirmed:
            problem = await run_in_threadpool(import_mismatch, db_of(request), project_id, result)
            if problem:
                return await run_in_threadpool(project_response, request, project_id, problem, 409,
                                               {"reupload_confirm": True})
        reopened = await run_in_threadpool(store_import, settings, db_of(request), project_id, filename, result)
    finally:
        _IMPORT_SLOT.release()
    return redirect(with_reopened(f"/projects/{project_id}?ok=imported#step1", reopened))


@router.post("/projects/{project_id}/repos")
async def set_repos(request: Request, project_id: int):
    form = await request.form(max_fields=10, max_files=0)
    raw = str(form.get("repos_dir") or "")

    def apply():
        project = project_or_404(request, project_id)
        settings = settings_of(request)
        repos_dir, error = check_project_folder(settings, raw)
        if repos_dir is None:
            return project_response(request, project_id, error, 400)
        db = db_of(request)
        if repos_dir != (project.get("repos_dir") or "") and str(form.get("confirm_reset") or "") != "1":
            warning = reset_warning(db, project_id)
            if warning:
                context = folders_context(request, project, repos_dir)
                return render(request, "projects/folders.html", {**context, "error": warning}, 409)
        reopened = db.set_repos_dir(project_id, repos_dir)
        reopened += auto_map(settings, db, {**project, "repos_dir": repos_dir}, overwrite_manual=False)
        refresh_sources(settings, db, project_id)
        return redirect(with_reopened(f"/projects/{project_id}?ok=repos#step2", reopened))

    return await run_in_threadpool(apply)


@router.post("/projects/{project_id}/repos-clone")
async def set_repos_and_clone(request: Request, project_id: int):
    """Бэклог 95: папка выше открытого клона – папка проекта, этот клон – папка единственной кодовой базы без папки;
    одна транзакция (set_repos_dir_and_folder), прежнее состояние проверяется."""
    form = await request.form(max_fields=10, max_files=0)
    clone_rel = str(form.get("clone") or "")
    codebase = str(form.get("codebase") or "")
    expect = str(form.get("expect_repos_dir") or "")

    def apply():
        project = project_or_404(request, project_id)
        settings = settings_of(request)
        db = db_of(request)
        rel, path, error = resolve_folder(settings, clone_rel)
        if error or not rel or path is None or not _is_codebase(path):
            return project_response(request, project_id, error or "Это не клон кодовой базы.", 400)
        parent, folder = (rel.rsplit("/", 1) if "/" in rel else ("", rel))
        repos_dir, error = check_project_folder(settings, parent)
        if repos_dir is None:
            return project_response(request, project_id, error, 400)
        offer = folders_context(request, project, rel).get("clone_offer")
        if not offer or offer["codebase"] != codebase:
            return project_response(request, project_id, "Назначить клон можно, когда у проекта ровно одна кодовая база "
                                    "без папки: откройте страницу выбора папки заново.", 409)
        counts = db.clone_reset_counts(project_id, codebase, repos_dir)
        if str(form.get("confirm_reset") or "") == "1":
            shown = parse_counts(form.get("expect_reset"))  # цена, которую видел и подтвердил оператор
            if shown is None:
                return render(request, "projects/folders.html", {**folders_context(request, project, rel),
                              "error": "Откройте страницу заново и подтвердите назначение ещё раз."}, 409)
        else:
            if clone_reset_warning(counts):
                return render(request, "projects/folders.html", {**folders_context(request, project, rel),
                              "error": clone_reset_warning(counts)}, 409)
            shown = (0, 0)  # без подтверждения – только когда удалять нечего; проверяется и в транзакции
        try:
            reopened = db.set_repos_dir_and_folder(project_id, repos_dir, codebase, folder, expect, shown)
        except ValueError as e:
            return project_response(request, project_id, str(e), 409)
        refresh_sources(settings, db, project_id)
        return redirect(with_reopened(f"/projects/{project_id}?ok=repos#step2", reopened))

    return await run_in_threadpool(apply)


@router.post("/projects/{project_id}/snapshots")
async def store_snapshots(request: Request, project_id: int):
    """«Сохранить срезы кода» (ADR-0072): срезы находок SAST без среза – из клонов, которые на месте, без модели."""
    await request.form(max_fields=10, max_files=0)

    def apply():
        project = project_or_404(request, project_id)
        db = db_of(request)
        if any(r["state"] == "running" for r in db.active_runs(project_id)):
            # находка, которую прогон разбирает сейчас, сохранит свой срез сама: параллельная запись не нужна
            return project_response(request, project_id, SNAPSHOT_RUNNING, 409)
        if not _SNAPSHOT_SLOT.acquire(blocking=False):
            return project_response(request, project_id, SNAPSHOT_BUSY, 409)
        try:
            settings = settings_of(request)
            sync_revisions(db, settings, project)  # ревизии клонов сверяются до записи срезов
            result = save_snapshots(db, settings, project, mask_key_of(request))
        finally:
            _SNAPSHOT_SLOT.release()
        return redirect(f"/projects/{project_id}?ok={'snapshots' if result['saved'] else 'snapshots_none'}#step2")

    return await run_in_threadpool(apply)


@router.post("/projects/{project_id}/clones/attach")
async def attach_clones(request: Request, project_id: int):
    """«Подключить клоны снова» (ADR-0072): отвязанные клоны снова читаются. Сверка ревизий идёт сразу: клон с другим
    кодом сбросит срезы своей кодовой базы, удалённый клон с полными срезами отвяжется снова."""
    await request.form(max_fields=10, max_files=0)

    def apply():
        project = project_or_404(request, project_id)
        db = db_of(request)
        db.clear_detached(project_id)
        db.clear_revision_notice(project_id)
        reopened = sync_revisions(db, settings_of(request), project)["reopened"]
        return redirect(with_reopened(f"/projects/{project_id}?ok=clones_attached#step2", reopened))

    return await run_in_threadpool(apply)


@router.post("/projects/{project_id}/codebases")
async def set_codebases(request: Request, project_id: int):
    form = await request.form(max_fields=4000)
    action = str(form.get("action") or "save")
    pairs = []
    for key, value in form.multi_items():
        if key.startswith("cb-"):
            pairs.append((str(value), str(form.get("folder-" + key[3:]) or "").strip().strip("/")))

    def apply():
        project = project_or_404(request, project_id)
        settings = settings_of(request)
        db = db_of(request)
        if action in ("auto", "reset"):
            # «Подобрать заново» не трогает ручной выбор; «Сбросить ручные» – только после подтверждения
            if action == "reset" and str(form.get("confirm_reset") or "") != "1":
                base, _ = repos_base(settings, project)
                current = db.get_codebase_map(project_id)
                changed = {cb for cb, folder in auto_map_plan(db, project_id, base, overwrite_manual=True)
                           if folder != (current.get(cb) or {}).get("folder", "")}
                warning = reset_warning(db, project_id, changed)
                if warning:
                    return project_response(request, project_id, warning, 409)
            reopened = auto_map(settings, db, project, overwrite_manual=action == "reset")
            refresh_sources(settings, db, project_id)
            ok = "reset" if action == "reset" else "automapped"
            return redirect(with_reopened(f"/projects/{project_id}?ok={ok}#step2", reopened))
        base, base_error = repos_base(settings, project)
        listed = list_codebase_dirs(base) if base else []
        from app.routes.examples import link_folders
        candidates = set(listed) | link_folders(db, project_id, base)  # у примера – и папки связи (crAPI: 3-й уровень)
        current = db.get_codebase_map(project_id)
        known = {row["codebase"] for row in db.codebase_counts(project_id)}
        changes = []
        for codebase, folder in pairs:
            if codebase not in known or (current.get(codebase) or {}).get("folder", "") == folder:
                continue  # строка без изменений (в том числе папка, которой уже нет на диске)
            if folder and folder not in candidates:
                return project_response(request, project_id, base_error or f"Папка «{folder}» не найдена в папке "
                                                                           "проекта.", 400)
            if folder and base is not None:
                try:  # настоящий путь папки – внутри папки проекта (не ссылка и не точка соединения наружу)
                    resolve_repo(base, folder)
                except ValueError as e:
                    return project_response(request, project_id, str(e), 400)
            # папка, которую подставил подбор по имени, остаётся «подобранной»: её поправит «Подобрать заново»
            changes.append((codebase, folder, folder != auto_folder(codebase, listed)))
        if str(form.get("confirm_reset") or "") != "1":
            warning = reset_warning(db, project_id, {codebase for codebase, _, _ in changes})
            if warning:
                return project_response(request, project_id, warning, 409)
        reopened = sum(db.set_codebase_folder(project_id, codebase, folder, manual=manual)
                       for codebase, folder, manual in changes)
        refresh_sources(settings, db, project_id)
        return redirect(with_reopened(f"/projects/{project_id}?ok=mapped#step2", reopened))

    return await run_in_threadpool(apply)

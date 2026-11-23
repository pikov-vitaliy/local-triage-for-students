"""Страница каталога учебных примеров /examples (ADR-0156): карточки, скачивание, создание проекта из примера,
восстановление соответствий; «Профиль для примеров» и панель «Начало работы» (ADR-0157); справка /help."""

from __future__ import annotations

import logging
import os
import re
import threading
from pathlib import Path

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse
from starlette.concurrency import run_in_threadpool

from app import examples, i18n
from app.hub_import import ImportFailure, parse_workbook
from app.logsafe import log_failure
from app.routes.common import db_of, project_or_404, redirect, register_messages, render, settings_of
from app.routes.projects import _IMPORT_SLOT, IMPORT_BUSY, make_demo, store_import, unique_name

router = APIRouter()
log = logging.getLogger(__name__)
LINK_KEY = "examples_projects"  # связи «пример@коммит → проект» в таблице settings
PROFILE_KEY = "examples_provider_id"  # «Профиль для примеров» (ADR-0157)
DEMO_KEY = "demo-library@builtin"
_CREATE_LOCK = threading.Lock()
register_messages({
    "example_fetched": "Исходники примера скачаны и сверены по хешу. Теперь можно создать проект.",
    "example_refetched": "Чистая копия исходников скачана и сверена по хешу – рядом с прежней папкой.",
    "example_refetched_project": "Чистая копия исходников скачана и сверена по хешу – рядом с прежней папкой. Проект "
                                 "по-прежнему работает с прежней папкой, решения сохранены.",
    "example_restored": "Исходники примера скачаны снова и сверены по хешу: проект работает с ними, решения сохранены.",
    "project_example": "Проект из примера создан: выгрузка загружена, кодовые базы связаны с папками примера. "
                       "Запустите триаж или разбирайте находки сами.",
    "example_mapping": "Соответствия кодовых баз примера восстановлены.",
    "examples_profile": "Профиль для примеров сохранён. Он назначается проектам, которые создаются из каталога.",
    "project_example_profile": "Проект из примера создан, профиль для примеров назначен проекту.",
    "project_example_noprofile_deleted": "Проект из примера создан, но профиль для примеров не назначен: выбранный "
                                         "профиль удалён. Проект разбирает профиль по умолчанию.",
    "project_example_noprofile_disabled": "Проект из примера создан, но профиль для примеров не назначен: профиль "
                                          "выключен. Проект разбирает профиль по умолчанию.",
    "project_example_noprofile_unfit": "Проект из примера создан, но профиль для примеров не назначен: он не годится "
                                       "для разбора кода. Проект разбирает профиль по умолчанию.",
    "project_example_noprofile_link": "Проект из примера создан, но профиль для примеров не назначен: связь проекта с "
                                      "примером изменилась.",
    "project_example_noprofile_external_off": "Проект из примера создан с профилем по умолчанию: внешние модели на "
                                              "этой установке выключены (стенд запущен с --local-only или Docker – "
                                              "без LLM_EXTERNAL=1). Если профиль по умолчанию тоже внешний, для "
                                              "разбора выберите локальный профиль в «Параметрах проекта».",
    "external_marked_example": "Отметка поставлена, профиль для примеров назначен проекту.",
})


# ============================================================================ связь «пример → проект»

def link_key(entry: dict) -> str:
    """Ключ связи – пример и полная ревизия: проект на прежнем коммите сохраняет свою связь (ревью сборки Б)."""
    if entry.get("builtin") == "demo":
        return DEMO_KEY
    return f"{entry['id']}@{entry['source']['commit']}"


def _links(db) -> dict:
    value = db.get_settings().get(LINK_KEY)
    return value if isinstance(value, dict) else {}


def project_link(db, key: str) -> dict | None:
    """Связь по ключу; проект удалён штатно – связи нет."""
    record = _links(db).get(key)
    if not isinstance(record, dict) or db.get_project(int(record.get("project_id") or 0)) is None:
        return None
    return record


def example_of_project(db, project_id: int) -> str:
    """Ключ связи проекта или пусто – проект не из каталога."""
    for key, record in _links(db).items():
        if isinstance(record, dict) and int(record.get("project_id") or 0) == int(project_id):
            return key
    return ""


def last_import_id(db, project_id: int) -> int:
    rows = db._all("SELECT max(id) AS n FROM imports WHERE project_id = ?", (project_id,))
    return int(rows[0]["n"] or 0) if rows else 0


def _root_id(repos_root: Path, host_root: str = "") -> str:
    """Путь папки примеров на этом компьютере: в Docker-установке все корни видны как /repos, поэтому берётся путь
    хоста (REPOS_ROOT_HOST); в стенде – физический путь (план стенда, Д10)."""
    if host_root:
        path = host_root.replace("\\", "/").rstrip("/")
        if re.match(r"^[A-Za-z]:/", path):  # путь Windows – без учёта регистра; POSIX – как есть
            path = path.lower()
        return "host:" + path + "/examples"
    return os.path.normcase(os.path.realpath(examples.examples_root(repos_root)))


def root_of(settings) -> str:
    return _root_id(settings.repos_root, getattr(settings, "repos_root_host", "") or "")


def link_intact(db, project_id: int, root: str | None = None) -> dict | None:
    """Связь проекта с примером цела: папка проекта, физический корень примеров, вся карта кодовых баз и текущий
    импорт – те, что записаны при создании (план стенда, раздел 6). Цела – запись связи с ключом; иначе None. Demo
    Library – не открытый пример: удобств каталога у неё нет."""
    key = example_of_project(db, project_id)
    link = project_link(db, key) if key and key != DEMO_KEY else None
    project = db.get_project(project_id)
    if not link or project is None or link.get("state") != "ready":
        return None
    if str(project.get("repos_dir") or "") != examples.EXAMPLES_FOLDER:
        return None
    if not link.get("root") or (root is not None and link["root"] != root):
        return None  # корень неизвестен или другой – связь не подтверждена
    current = {k: str(v.get("folder") or "") for k, v in (db.get_codebase_map(project_id) or {}).items()}
    if current != dict(link.get("codebases") or {}):
        return None  # вся карта, включая кодовые базы без папки
    if int(link.get("import_id") or 0) != last_import_id(db, project_id):
        return None
    return {"key": key, **link}


def link_folders(db, project_id: int, base: Path | None = None) -> set[str]:
    """Папки кодовых баз из связи примера, которые есть на диске (base – папка проекта): допустимы в форме
    соответствий (у crAPI – третий уровень)."""
    key = example_of_project(db, project_id)
    link = project_link(db, key) if key else None
    folders = set((link or {}).get("codebases", {}).values())
    return {f for f in folders if base is not None and (base / f).is_dir()}


def is_catalog_project(db, project_id: int) -> bool:
    """Проект создан из каталога (и Demo Library из каталога): с Hub не связывается (план стенда, раздел 6)."""
    return bool(example_of_project(db, project_id))


# ============================================================================ страницы

def cards(request: Request) -> list[dict]:
    settings = settings_of(request)
    db = db_of(request)
    catalog = examples.load_catalog()
    result = []
    for entry in catalog["examples"]:
        state = examples.status(entry, settings.repos_root)
        link = project_link(db, link_key(entry))
        folders = state.get("folders") or []
        usable = [f for f in folders if isinstance((examples.read_marker(f) or {}).get("lines"), dict)]
        folder = (examples.examples_root(settings.repos_root) / link["folder"] if link and link.get("folder")
                  else (usable or folders or [None])[0])
        result.append({"entry": entry, "state": state, "link": link,
                       "folder": str(folder) if folder else "",
                       "folder_missing": bool(folder) and not Path(folder).is_dir(),
                       "command": i18n._("python -m app.examples fetch {id} --repos-root <корень клонов>",
                                         id=entry['id'])})
    return result


@router.get("/help", response_class=HTMLResponse)
def help_page(request: Request):
    """Справка стенда с оглавлением и глоссарием; из шапки открывается в новой вкладке."""
    return render(request, "help.html", {})


@router.get("/examples", response_class=HTMLResponse)
def examples_page(request: Request):
    settings = settings_of(request)
    error = request.query_params.get("error", "")[:500]
    try:
        items = cards(request)
    except examples.ExampleError as e:
        items, error = [], str(e)
    return render(request, "examples/index.html", {"cards": items, "error": error, "stand": settings.stand == "npm",
                                                   "root": str(examples.examples_root(settings.repos_root)),
                                                   "start": start_panel(request)})


@router.get("/examples/status")
def examples_status(request: Request):
    """Ход скачивания для окна запуска стенда: {id: состояние, сообщение}."""
    settings = settings_of(request)
    out = {}
    try:
        entries = examples.load_catalog()["examples"]
    except examples.ExampleError:
        entries = []
    for entry in entries:
        if examples.is_downloadable(entry):
            try:
                st = examples.status(entry, settings.repos_root)
            except (KeyError, TypeError, OSError) as e:
                st = {"phase": "failed", "message": i18n._("запись каталога не читается ({error})",
                                                           error=e.__class__.__name__)}
            out[entry["id"]] = {"phase": st["phase"], "message": st.get("message", ""), "fresh": bool(st.get("fresh"))}
    return JSONResponse(out)


def _entry(example_id: str) -> dict:
    try:
        return examples.entry_of(examples.load_catalog(), example_id)
    except examples.ExampleError:
        raise HTTPException(404, i18n._("Такого примера нет в каталоге.")) from None


def _q(text: str) -> str:
    from urllib.parse import quote

    return quote(text[:400], safe="")


@router.post("/examples/{example_id}/fetch")
async def fetch_example(request: Request, example_id: str):
    """Скачать (или «Скачать заново» – новая копия рядом); в Docker-установке корень клонов только для чтения."""
    form = await request.form(max_fields=5, max_files=0)
    again = form.get("again") == "1"
    entry = _entry(example_id)
    settings = settings_of(request)

    def apply():
        try:
            examples.download(entry, settings.repos_root, settings.tmp_dir, again=again)
        except examples.ExampleError as e:
            return redirect(f"/examples?error={_q(str(e))}#ex-{example_id}")
        except OSError as e:
            message = i18n._("Папка примеров недоступна на запись: {error}", error=e.__class__.__name__)
            return redirect(f"/examples?error={_q(message)}")
        linked = project_link(db_of(request), link_key(entry)) is not None
        if again:
            done = "example_refetched_project" if linked else "example_refetched"
        else:
            done = "example_restored" if linked else "example_fetched"
        return redirect(f"/examples?ok={done}#ex-{example_id}")

    return await run_in_threadpool(apply)


# ============================================================================ создание проекта

def _prepared_import(settings, entry: dict, tree: Path):
    """Выгрузка примера с заполненным Source code, разобранная парсером приложения (до любой записи в базу)."""
    filled, warnings = examples.filled_export(entry, tree, settings.tmp_dir)
    try:
        result = parse_workbook(filled, settings.max_upload_bytes)
    finally:
        filled.unlink(missing_ok=True)
    result.warnings.extend(warnings[:20])
    return result


# хранимый текст: в базу пишется русский msgid, перевод – при показе (projects.mark_reason_shown, ADR-0158)
EXAMPLE_MARK_REASON = i18n.N_("Учебный пример: открытый исходный код из публичного репозитория GitHub")


def create_example_project(settings, db, entry: dict) -> tuple[int, bool]:
    """Проект из примера: (номер, только что доведён до готовности). Сначала всё, что может сорваться (выгрузка, папка,
    разбор), затем запись. Проект создаётся в одной транзакции со связью («создаётся»), номер импорта пишется в связь в
    транзакции импорта. Повторное нажатие после обрыва продолжает тот же проект без второго импорта."""
    folders = examples.downloaded_folders(entry, settings.repos_root)
    if not folders:
        raise examples.ExampleError(i18n._("Исходники примера ещё не скачаны: нажмите «Скачать»."))
    key = link_key(entry)
    link = project_link(db, key)
    if link and link.get("state") == "ready":
        return int(link["project_id"]), False
    if link and not link.get("import_id") and operator_worked(db, int(link["project_id"])):
        # Н1 круга 4: в незавершённом проекте оператор уже работал (своя выгрузка, своя папка) – проект остаётся его,
        # связь снимается, учебный проект создаётся заново
        db.update_json_entry(LINK_KEY, key, None)
        link = None
    usable = [f for f in folders if isinstance((examples.read_marker(f) or {}).get("lines"), dict)]
    tree = usable[0] if usable else folders[0]
    if link and link.get("folder") and (examples.examples_root(settings.repos_root) / link["folder"]).is_dir():
        tree = examples.examples_root(settings.repos_root) / link["folder"]
    mapping = {cb["name"]: "/".join(p for p in (tree.name, cb["path"]) if p) for cb in entry["codebases"]}
    result = _prepared_import(settings, entry, tree) if not (link and link.get("import_id")) else None
    if not link:
        src = entry["source"]
        record = {"example_id": entry["id"], "commit": src["commit"], "tree_sha256": src["tree_sha256"],
                  "export_sha256": entry["export"]["sha256"], "repo_url": src.get("repo_url", ""),
                  "license": src.get("license", ""), "title": entry["title"], "root": root_of(settings),
                  "codebases": mapping, "folder": tree.name, "import_id": 0, "state": "creating"}

        def link_project(c, pid: int) -> None:
            db.set_json_entry_in(c, LINK_KEY, key, {**record, "project_id": pid})

        project_id = db.create_project(unique_name(db, i18n._("Пример: {title}", title=i18n._(entry['title']))[:200]),
                                       after=link_project)
        link = {**record, "project_id": project_id}
        created_now = True
    else:
        created_now = False
    project_id = int(link["project_id"])
    if result is not None:
        # до импорта у проекта нет находок и срезов: папка проекта и карта ставятся без потерь; после импорта
        # продолжение их не меняет – оператор мог уже выбрать свои папки (ревью сборки Б, круг 3, Н1)
        db.set_repos_dir(project_id, examples.EXAMPLES_FOLDER)
        db.restore_codebase_map(project_id, mapping)
        current = dict(link)

        def mark_import(c, import_id: int) -> None:
            current["import_id"] = import_id
            db.set_json_entry_in(c, LINK_KEY, key, current)

        store_import(settings, db, project_id, f"{entry['id']}-export.xlsx", result, after=mark_import)
        link = current
        db.restore_codebase_map(project_id, mapping)  # подбор при импорте – только для незаполненных строк
    from app.triage import sync_revisions

    try:
        project = db.get_project(project_id)
        if project is not None:
            sync_revisions(db, settings, project)
    except Exception as e:  # noqa: BLE001 – сверка ревизий не мешает созданию
        log_failure(log, "сверка ревизий примера", e)
    if result is None and link.get("codebases"):  # импорт был в прошлый раз: исходная копия и карта не меняются
        mapping = dict(link["codebases"])
    db.update_json_entry(LINK_KEY, key, {**link, "codebases": mapping, "state": "ready"})
    if created_now:
        # учебный пример – открытый код с GitHub: отметка «код не секретный» по умолчанию (слово владельца 21.11.2026);
        # действует, только когда внешние провайдеры включены на установке; снимается в параметрах проекта
        db.set_external_mark(project_id, EXAMPLE_MARK_REASON)
        remember_mark_root(db, project_id, settings)
    return project_id, True


def operator_worked(db, project_id: int, allowed: str = examples.EXAMPLES_FOLDER) -> bool:
    """В незавершённом проекте из каталога оператор уже работал: есть импорт или папка проекта – не та, что ставит
    само создание (allowed: «examples» у примера, демо-папка у Demo Library)."""
    project = db.get_project(project_id) or {}
    return last_import_id(db, project_id) > 0 or str(project.get("repos_dir") or "") not in ("", allowed)


def _create_demo(request: Request, db) -> object:
    """Запись № 0 – Demo Library прежней раскладкой: «создаётся» → импорт с номером в той же транзакции → «готов»;
    повтор после обрыва продолжает тот же проект, готовый – открывается."""
    link = project_link(db, DEMO_KEY)
    if link and link.get("state") == "ready":
        return redirect(f"/projects/{link['project_id']}")
    from app.routes.projects import find_demo
    demo_dir = find_demo(settings_of(request)).get("repos_dir") or ""
    if link and not link.get("import_id") and operator_worked(db, int(link["project_id"]), allowed=demo_dir):
        # оператор уже работал в незавершённом демо-проекте: он остаётся его, демо создаётся заново (круг 5)
        db.update_json_entry(LINK_KEY, DEMO_KEY, None)
        link = None
    if link and link.get("import_id"):  # импорт уже был: подбор папок и источники, затем «готов»
        from app.routes.projects import auto_map, refresh_sources
        settings = settings_of(request)
        project = db.get_project(int(link["project_id"]))
        if project is not None:
            auto_map(settings, db, project, overwrite_manual=False)
            refresh_sources(settings, db, int(link["project_id"]))
        db.update_json_entry(LINK_KEY, DEMO_KEY, {**link, "state": "ready"})
        return redirect(f"/projects/{link['project_id']}")
    record = {"example_id": "demo-library", "state": "creating", "import_id": 0}

    def link_project(c, pid: int) -> None:
        db.set_json_entry_in(c, LINK_KEY, DEMO_KEY, {**record, "project_id": pid})

    def mark_import(c, import_id: int) -> None:
        current = project_link(db, DEMO_KEY) or {}
        pid = current.get("project_id") or (link or {}).get("project_id")
        db.set_json_entry_in(c, LINK_KEY, DEMO_KEY, {**record, "project_id": pid, "import_id": import_id})

    made = make_demo(request, after=link_project, import_after=mark_import,
                     project_id=int(link["project_id"]) if link else None)
    if not isinstance(made, tuple):
        return made
    done = project_link(db, DEMO_KEY) or {}
    db.update_json_entry(LINK_KEY, DEMO_KEY, {**done, "state": "ready"})  # после импорта и подбора папок
    if link is None and (db.get_project(int(made[0])) or {}).get("external_allowed"):
        remember_mark_root(db, int(made[0]), settings_of(request))  # отметка демо (make_demo) – для этого корня
    return redirect(f"/projects/{made[0]}?ok={made[1]}")


@router.post("/examples/{example_id}/project")
async def create_project(request: Request, example_id: str):
    entry = _entry(example_id)
    settings = settings_of(request)
    db = db_of(request)

    def apply():
        if not _IMPORT_SLOT.acquire(blocking=False):
            return redirect(f"/examples?error={_q(i18n._(IMPORT_BUSY))}")
        try:
            with _CREATE_LOCK:
                if entry.get("builtin") == "demo":
                    return _create_demo(request, db)
                project_id, _fresh = create_example_project(settings, db, entry)
        except (examples.ExampleError, ImportFailure) as e:
            return redirect(f"/examples?error={_q(str(e))}#ex-{example_id}")
        except Exception as e:  # noqa: BLE001
            eid = log_failure(log, "проект из примера не создан", e)
            message = i18n._("Проект не создан (ошибка {eid}).", eid=eid)
            return redirect(f"/examples?error={_q(message)}#ex-{example_id}")
        finally:
            _IMPORT_SLOT.release()
        link = project_link(db, link_key(entry)) or {}
        if link.get("profile_done") or link.get("profile_pending"):  # назначение уже было: выбор студента не меняется
            return redirect(f"/projects/{project_id}")
        outcome = apply_examples_profile(db, project_id, root_of(settings))
        from app.routes.common import external_enabled
        if outcome == "needs_mark" and not external_enabled():
            outcome = "external_off"  # внешние модели выключены (--local-only): предпросмотр был бы тупиком
        db.update_json_entry(LINK_KEY, link_key(entry), {**link, "profile_done": outcome != "needs_mark",
                                                         "profile_pending": outcome == "needs_mark",
                                                         "profile_outcome": outcome})
        if outcome == "assigned":
            return redirect(f"/projects/{project_id}?ok=project_example_profile")
        if outcome == "needs_mark":
            return redirect(f"/projects/{project_id}/external?example=1")
        if outcome != "none":
            log.info("проект %d из примера: %s", project_id, outcome)
            return redirect(f"/projects/{project_id}?ok=project_example_noprofile_{outcome}")
        return redirect(f"/projects/{project_id}?ok=project_example")

    return await run_in_threadpool(apply)


# ============================================================================ восстановление соответствий

def mapping_problem(db, settings, project_id: int, changes: dict[str, str]) -> str:
    """Почему восстановление сейчас не вернёт пример: другая папка проекта или нет папок примера на диске."""
    project = db.get_project(project_id) or {}
    if str(project.get("repos_dir") or "") != examples.EXAMPLES_FOLDER:
        return i18n._("Папка проекта сейчас «{folder}», а пример лежит в папке «{examples}». Сначала верните папку "
                      "проекта «{examples}».", folder=project.get('repos_dir') or i18n._('не выбрана'),
                      examples=examples.EXAMPLES_FOLDER)
    key = example_of_project(db, project_id)
    link = project_link(db, key) if key else None
    if link and link.get("root") and link["root"] != root_of(settings):
        return i18n._("Папка примеров на этом компьютере другая, чем при создании проекта: восстановление вернуло "
                      "бы соответствия на чужие папки. Создайте проект из примера заново.")
    base = examples.examples_root(settings.repos_root)
    targets = (link or {}).get("codebases") or changes
    missing = [folder for folder in targets.values()
               if not (base / folder).is_dir() or not any((base / folder).iterdir())]
    if missing:
        return i18n._("Папок примера нет на диске или они пусты: {folders}. Скачайте пример заново.",
                      folders=", ".join(missing[:3]))
    return ""


def mapping_changes(db, project_id: int) -> tuple[str, dict[str, str]]:
    """(ключ связи, {кодовая база: папка из связи}) – только отличающиеся от текущих; ключа нет – ("", {})."""
    key = example_of_project(db, project_id)
    link = project_link(db, key) if key and key != DEMO_KEY else None
    if not link:
        return "", {}
    current = {k: str(v.get("folder") or "") for k, v in (db.get_codebase_map(project_id) or {}).items()}
    return key, {cb: folder for cb, folder in (link.get("codebases") or {}).items() if current.get(cb) != folder}


@router.get("/projects/{project_id}/example-mapping", response_class=HTMLResponse)
def example_mapping_page(request: Request, project_id: int):
    """Подтверждение восстановления: какие соответствия изменятся и что при этом сбросится; отпечаток показанного
    сверяется в транзакции восстановления."""
    project = project_or_404(request, project_id)
    db = db_of(request)
    key, changes = mapping_changes(db, project_id)
    if not key:
        raise HTTPException(404, i18n._("Проект не из каталога учебных примеров."))
    preview = db.restore_preview(project_id, changes)  # строки, последствия и отпечаток – из одного снимка
    current, effects = preview["current"], preview["effects"]
    rows = [{"codebase": cb, "now": current.get(cb, ""), "then": folder} for cb, folder in sorted(changes.items())
            if current.get(cb, "") != folder]
    parts = []
    if effects["cases"]:
        parts.append(i18n._("удалятся сохранённые срезы кода: {n}", n=effects['cases']))
    if effects["reviewed"]:
        parts.append(i18n._("снимутся отметки «Проверено»: {n} (решения и комментарии останутся)",
                            n=effects['reviewed']))
    return render(request, "examples/mapping.html", {
        "project": project, "rows": rows, "expect": preview["expect"],
        "problem": mapping_problem(db, settings_of(request), project_id, changes),
        "warning": i18n._("При восстановлении {effects}.", effects="; ".join(parts)) if parts else "",
        "stale": request.query_params.get("stale") == "1"})


@router.post("/projects/{project_id}/example-mapping")
async def restore_example_mapping(request: Request, project_id: int):
    form = await request.form(max_fields=4, max_files=0)
    expect = str(form.get("expect") or "")
    db = db_of(request)

    def apply():
        project_or_404(request, project_id)
        key, changes = mapping_changes(db, project_id)
        if not key:
            raise HTTPException(404, i18n._("Проект не из каталога учебных примеров."))
        if changes and mapping_problem(db, settings_of(request), project_id, changes):
            return redirect(f"/projects/{project_id}/example-mapping")
        if changes:
            try:  # показанное на странице подтверждения сверяется в транзакции восстановления
                db.restore_codebase_map(project_id, changes, expect=expect)
            except (ValueError, TimeoutError):
                return redirect(f"/projects/{project_id}/example-mapping?stale=1")
        return redirect(f"/projects/{project_id}?ok=example_mapping#step2")

    return await run_in_threadpool(apply)


# ============================================================================ профиль для примеров (ADR-0157)

def examples_profile_state(db) -> tuple[dict | None, str]:
    """(профиль, состояние): none – не выбран, deleted – выбран, но удалён, ok – есть."""
    value = db.get_settings().get(PROFILE_KEY)
    if not isinstance(value, int) or isinstance(value, bool):
        return None, "none"
    profile = db.get_provider(value)
    return (profile, "ok") if profile else (None, "deleted")


def apply_examples_profile(db, project_id: int, root: str | None = None) -> str:
    """Профиль для примеров – проекту из каталога. Профиль заново читается из базы и проходит обе проверки штатного
    обработчика (включён и годится для разбора кода этого проекта). Профиль исследования назначается отдельно – только
    если годится для исследования. Возврат: assigned, needs_mark (внешний профиль – сначала предпросмотр и отметка
    студента), none (не выбран), deleted, disabled, external_off (внешние модели выключены, --local-only), link (связь
    нарушена), unfit (не годится для кода)."""
    from app.routes.components import research_profile_ok
    from app.routes.projects import code_profile_ok

    profile, state = examples_profile_state(db)
    if state == "none":
        return "none"
    if profile is None:
        return "deleted"
    if not profile.get("enabled"):
        return "disabled"
    from app.routes.common import external_enabled
    if str(profile.get("trust")) == "external" and not external_enabled():
        # стенд с --local-only (бэклог 140): внешний профиль не назначается и у проекта с отметкой – разбор им
        # откажет; проект остаётся с профилем по умолчанию, студент видит причину
        return "external_off"
    if link_intact(db, project_id, root) is None:
        return "link"
    project = db.get_project(project_id)
    if code_profile_ok(profile, project):
        research = int(profile["id"]) if research_profile_ok(profile) else False
        db.update_project(project_id, provider_id=int(profile["id"]), research_provider_id=research)
        return "assigned"
    if str(profile.get("trust")) == "external":
        return "needs_mark"
    return "unfit"


def pending_profile(db, project_id: int, root: str | None = None) -> dict | None:
    """Профиль для примеров, который назначится проекту после отметки (для страницы предпросмотра)."""
    key = example_of_project(db, project_id)
    link = project_link(db, key) if key and key != DEMO_KEY else None
    if not link or not link.get("profile_pending"):
        return None
    profile, _ = examples_profile_state(db)
    if not profile or not profile.get("enabled") or str(profile.get("trust")) != "external" or \
            link_intact(db, project_id, root) is None:
        return None
    return profile


def finish_pending_profile(db, project_id: int, root: str, promised_id: int | None = None) -> str:
    """После отметки «код не секретный»: внешний профиль для примеров назначается один раз – только если назначение
    ожидало этой отметки и это тот профиль, что был показан и подписан на предпросмотре (promised_id); повторная
    отметка выбор студента не меняет."""
    key = example_of_project(db, project_id)
    link = project_link(db, key) if key and key != DEMO_KEY else None
    if not link or not link.get("profile_pending"):
        return "none"
    now = pending_profile(db, project_id, root)
    if promised_id is None or now is None or int(now["id"]) != int(promised_id):
        return "none"  # профиль для примеров сменили после предпросмотра – ничего не назначается без нового показа
    outcome = apply_examples_profile(db, project_id, root)
    if outcome != "needs_mark":
        db.update_json_entry(LINK_KEY, key, {**link, "profile_pending": False, "profile_done": True,
                                             "profile_outcome": outcome})
    return outcome


def example_reason(db, project_id: int, root: str | None = None) -> str:
    """Заполненное обоснование отметки для проекта из каталога с целой связью; иначе пусто. Адрес, коммит и лицензия
    – из записи связи (ревизия проекта, а не нынешняя карточка каталога)."""
    link = link_intact(db, project_id, root)
    if not link:
        return ""
    return i18n._("Учебный пример «{title}» из каталога стенда: открытый код, {repo_url}, коммит {commit}, "
                  "лицензия {license}.", title=link.get('title') or link.get('example_id'),
                  repo_url=link.get('repo_url', ''), commit=str(link.get('commit', ''))[:7],
                  license=link.get('license', ''))


@router.post("/examples/profile")
async def save_examples_profile(request: Request):
    """«Профиль для примеров»: включённый профиль или пусто (снять)."""
    form = await request.form(max_fields=4, max_files=0)
    raw = str(form.get("provider_id") or "").strip()
    db = db_of(request)

    def apply():
        if not raw:
            db.set_settings({PROFILE_KEY: None})
            return redirect("/examples?ok=examples_profile")
        profile = db.get_provider(int(raw)) if raw.isdigit() else None
        if profile is None or not profile.get("enabled"):
            return redirect(f"/examples?error={_q(i18n._('Профиль для примеров: выберите включённый профиль.'))}")
        db.set_settings({PROFILE_KEY: int(profile["id"])})
        return redirect("/examples?ok=examples_profile")

    return await run_in_threadpool(apply)


def external_on() -> bool:
    from app.routes.common import external_enabled
    return external_enabled()


def revoke_marks_on_root_change(db, settings) -> int:
    """При запуске: у проектов из каталога, чей корень примеров сменился (в Docker – другой -ReposRoot с той же базой),
    отметка «код не секретный» снимается – разрешение давалось на код другой папки (ревью сборки Б, круг 4)."""
    root = root_of(settings)
    revoked = 0
    for record in _links(db).values():
        if not isinstance(record, dict):
            continue
        project = db.get_project(int(record.get("project_id") or 0))
        if project and project.get("external_allowed") and record.get("mark_root") != root:
            from app.executors import project_gate
            with project_gate(int(project["id"])).write():
                db.clear_external_mark(int(project["id"]))
            revoked += 1
    examples.ROOT_NOW["value"] = root  # сверка прошла: допуск отправки сравнивает корень согласия с этим
    return revoked


def remember_mark_root(db, project_id: int, settings) -> None:
    """После отметки «код не секретный» у проекта из каталога – корень примеров, для которого она дана."""
    key = example_of_project(db, project_id)
    link = project_link(db, key) if key else None  # и у Demo Library из каталога (ревью круга 7)
    if link is not None:
        root = root_of(settings)
        db.update_json_entry(LINK_KEY, key, {**link, "mark_root": root})


def common_research(request: Request) -> str:
    """Фактический режим исследования по общей настройке – как его выберет страница исследования."""
    from app.routes.components import research_profile

    profile = research_profile(db_of(request), settings_of(request), {})
    if profile:
        return i18n._("через общий профиль исследования «{name}»", name=profile['name'])
    return i18n._("файловый режим (ZIP-задание и answer.json)")


def start_panel(request: Request) -> dict:
    """Панель «Начало работы» на странице примеров: профиль для примеров, заготовки, что получится."""
    from app.executors import code_profile_fits
    from app.routes.components import research_profile_ok

    db = db_of(request)
    profiles = [p for p in db.list_providers() if p["enabled"]]
    chosen, state = examples_profile_state(db)
    trust = str((chosen or {}).get("trust") or "")
    if state == "none":
        from app.routes.common import profile_for
        mode = i18n._("Профиль для примеров не выбран: проекты из каталога разбирает профиль по умолчанию «{name}».",
                      name=profile_for(request).get('name') or '')
    elif state == "deleted":
        mode = i18n._("Выбранный профиль для примеров удалён: выберите другой. Пока проекты получают профиль по "
                      "умолчанию.")
    elif not chosen.get("enabled"):
        mode = i18n._("Профиль «{name}» выключен: проекты из каталога получат профиль по умолчанию.",
                      name=chosen['name'])
    elif trust == "external" and not external_on():
        mode = i18n._("Профиль «{name}» – модель в интернете, но внешние модели сейчас выключены (стенд запущен с "
                      "--local-only): проекты из каталога получат профиль по умолчанию.", name=chosen['name'])
    elif trust == "external":
        research = (i18n._("Исследование компонентов – через этот же профиль.") if research_profile_ok(chosen) else
                    i18n._("Исследование компонентов – {mode}: в профиле не включено назначение «исследование».",
                           mode=common_research(request)))
        mode = i18n._("Профиль «{name}» – модель в интернете: проекты десяти скачиваемых примеров получают отметку "
                      "«код не секретный» при создании, и профиль назначается сразу; Demo Library – тоже с отметкой. "
                      "{research}", name=chosen['name'], research=research)
    elif code_profile_fits(chosen, {"external_allowed": 0}):
        if trust == "lan":
            mode = i18n._("Профиль «{name}» работает в локальной сети: назначается проекту сразу. Исследование "
                          "компонентов – {research}.", name=chosen['name'], research=common_research(request))
        else:
            mode = i18n._("Профиль «{name}» работает на этом компьютере: назначается проекту сразу. Исследование "
                          "компонентов – {research}.", name=chosen['name'], research=common_research(request))
    else:
        mode = i18n._("Профиль «{name}» не годится для разбора кода (для кода в локальной сети принимается только "
                      "Ollama): проекты из каталога получат профиль по умолчанию.", name=chosen['name'])
    checks = []
    if chosen is not None:
        from app.routes.providers import check_state
        words = {"passed": i18n._("прошёл"), "failed": i18n._("не прошёл"),
                 "none": i18n._("не проверялся после последней правки профиля")}
        checks.append(i18n._("Пробный ответ: {state}", state=words[check_state(db, chosen, 'probe')]))
        if trust == "external":
            checks.append(i18n._("Проверка поиска: {state}", state=words[check_state(db, chosen, 'search')]))
    return {"profiles": profiles, "chosen": chosen, "mode": mode, "checks": checks}


def start_background(settings) -> None:
    """Стенд npm: после готовности приложения фоновое скачивание всех недостающих примеров. Любой сбой каталога
    приложению запуститься не мешает: причина видна на странице «Примеры»."""
    if settings.stand != "npm":
        return
    try:
        examples.examples_root(settings.repos_root).mkdir(parents=True, exist_ok=True)
        examples.fetch_all_background(settings.repos_root, Path(settings.tmp_dir))
    except Exception as e:  # noqa: BLE001 – каталог повреждён или папка недоступна: приложение работает дальше
        log.warning("фоновое скачивание примеров не запущено: %s", e)

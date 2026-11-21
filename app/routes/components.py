"""Раздел «Компоненты»: исследование пакетов внешним агентом и решение человека.

Маршруты этого раздела не трогают прежний разбор SAST и прежние ответы агента по пакетам (сценарии 1 и 2):
они читают и пишут только свои таблицы (sca2_*). Факты ответа агента и решение человека хранятся раздельно:
решение не переписывает факты, а помечается устаревшим, если после него пришла новая ревизия исследования.

Шаблоны страниц (app/templates/components/) делает фронтенд; здесь собирается контекст, описанный в
docs с интерфейсом (backend-interface.md). Тяжёлые операции – разбор ответа и сборка архива – выполняются
в пуле потоков, чтобы не держать замок единственного соединения с базой.
"""

from __future__ import annotations

import logging
import hmac
import json
import secrets
import re
from collections.abc import Iterable, Mapping
from datetime import date, datetime
from typing import Any
from urllib.parse import parse_qsl, quote, urlencode, urlsplit

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import HTMLResponse, JSONResponse, Response
from starlette.concurrency import run_in_threadpool

from app import sca_research as research, worklists
from app import osv
from app.config import Settings
from app.db import SAVED_FILTERS_MAX, Database, DecisionStale, SelectionChanged, TaskSuperseded
from app.routes.common import db_of, project_or_404, query, redirect, render, settings_of
from app.llm_net import external_enabled
from app.sca_contract import ANSWER_CONTRACT, VALIDATOR_VERSION, canonical, schema

log = logging.getLogger("local_triage.web")

router = APIRouter()

INPUT_REF = re.compile(r"^[a-z][a-z0-9]*:[0-9a-f]{16}$")
PAGE_SIZE = research.PAGE_SIZE

#: сообщения после действия: код в адресе – текст на странице
NOTICES = {
    "task": "Задание собрано: строк {n}.",
    "task_same": "Состав не изменился: задание прежнее, строк {n}.",
    "answers": "Ответ сохранён: строк {n} с новой ревизией.",
    "answers_same": "Ответ не изменился: новых ревизий нет, строк {n}.",
    "decision": "Решение сохранено.",
    "applied": "Решение записано находкам этой версии: {n}. Вывод «обновить», обоснование и отметка «Проверено» стоят у каждой.",
    "research_provider_saved": "Профиль исследования сохранён.",
    "research_stopping": "Получение останавливается: текущее обращение завершится, новые не начнутся.",
    "research_resumed": "Получение продолжено по тому же согласию.",
    "research_requeued": "Новое получение по оставшимся строкам: {n}.",
    "filter_saved": "Отбор сохранён.",
    "filter_updated": "Отбор с этим именем обновлён: условия заменены.",
    "filter_deleted": "Сохранённый отбор удалён.",
}
PROBLEMS = {
    "task_empty": "В выгрузке нет находок SCA Security: собирать задание не из чего.",
    "task_gone": "Задание устарело: состав проекта изменился, соберите задание заново.",
    "research_profile": "Исследование провайдером недоступно: выберите для проекта или приложения включённый профиль "
                        "«API чат-завершений» или «Anthropic Messages API» с назначением «исследование» – на странице "
                        "«Провайдеры моделей».",
    "research_profile_unfit": "Профиль исследования: выберите включённый профиль «API чат-завершений» или «Anthropic "
                              "Messages API».",
    "research_running": "По проекту уже идёт получение: дождитесь его конца или остановите.",
    "research_selection": "Выбор строк не распознан.",
    "apply_no_decision": "Решение находкам не записано: по компоненту нет действующего решения.",
    "apply_action": "Решение находкам не записано: находкам записывается только решение «обновить».",
    "apply_no_findings": "Решение находкам не записано: в текущей выгрузке находок этой версии нет.",
    "apply_changed": "Решение находкам не записано: пока страница была открыта, решение компонента, находки этой версии, ответ агента или исследование изменились. Страница обновлена – проверьте и нажмите ещё раз.",
    "apply_failed": "Решение находкам не записано: база была занята или недоступна. Решение компонента сохранено. Обновите страницу и нажмите «Применить решение к находкам этой версии».",
    "apply_internal": "Решение находкам не записано: внутренняя ошибка приложения, подробности в его журнале. Решение компонента сохранено. Откройте находку из списка «Где используется» и сохраните решение в её карточке.",
    "apply_unknown": "Исход записи решения находкам неизвестен: связь с базой оборвалась в момент записи. Решение компонента сохранено. Откройте находки из списка «Где используется» и проверьте, стоит ли у них решение; если нет – примените ещё раз.",
    "apply_rejected": "Решение находкам не записано: приложение отклонило запись для этой версии. Откройте находку из списка «Где используется» и сохраните решение в её карточке – там будет названа причина.",
    "research_empty": "Для выбранного отбора строк нет.",
    "research_confirm": "Подтвердите предпросмотр: без отметки согласия исследование не запускается.",
    "research_changed": "Состав, профиль или инструкции изменились после предпросмотра: откройте предпросмотр заново.",
    "research_resume": "Продолжить не удалось.",
    "research_nothing": "Строк для доисследования нет: не получившихся строк нет, строки с неизвестным результатом "
                        "берутся только по отметке, а строки, исследованные более поздним получением, не предлагаются.",
    "answers_no_task": "Сначала соберите задание: без него ответ некуда положить.",
    "decision_stale": "Страница устарела: решение не сохранено, проверьте данные и подтвердите снова.",
    "decision_unbound": "Страница не показывает, какое исследование человек видел",
}


def _wants_json(request: Request) -> bool:
    return "application/json" in request.headers.get("accept", "")


def _notice(request: Request) -> tuple[str, str]:
    """Сообщение и ошибка из адреса страницы: коды известны, лишние игнорируются."""
    codes = {item for item in (request.query_params.get("ok", ""), request.query_params.get("err", "")) if item}
    count = request.query_params.get("n", "")
    number = int(count) if count.isdigit() else 0
    ok = NOTICES.get(request.query_params.get("ok", ""), "")
    error = PROBLEMS.get(request.query_params.get("err", ""), "")
    return (ok.format(n=number) if ok and number else ok), (error if codes else "")


def _integer(value: Any, fallback: int = 0) -> int:
    try:
        return int(str(value).strip())
    except (TypeError, ValueError):
        return fallback


def _task_id_ok(task_id: str) -> bool:
    return bool(task_id) and "/" not in task_id and len(task_id) <= 64


# ------------------------------------------------------------------ сборка строк

def _live_rows(db: Database, project_id: int, prefixes: Iterable[str] = ()) -> list[dict]:
    """Текущий состав выгрузки – те же строки, что собирает кнопка задания, но без сохранения задания.

    Раздел показывает пакеты проекта и до того, как задание собрано: пустой список в этом случае врал."""
    rows, _ = research.task_rows(db.sca_components(project_id), prefixes, db.sca_confirmed(project_id))
    return rows


def _live_row(db: Database, project_id: int, input_ref: str, prefixes: Iterable[str] = ()) -> dict | None:
    """Строка текущего состава по её input_ref или None – такого пакета в выгрузке нет."""
    return next((item for item in _live_rows(db, project_id, prefixes) if item["input_ref"] == input_ref), None)


def _sources(db: Database, project_id: int, prefixes: Iterable[str] = ()) -> tuple[list[dict], dict | None]:
    """Строки раздела: текущий состав выгрузки плюс строки прежних заданий.

    Строка, ушедшая из состава, не исчезает: её факты и решение человека остаются видимыми с пометкой
    export_missing и task_stale. Это и есть история: решение не должно пропадать вместе с пакетом из выгрузки.
    Состав при этом не сохраняется – задание по-прежнему собирает человек, а страница только показывает."""
    task = db.current_task(project_id)
    live = {item["input_ref"]: item for item in _live_rows(db, project_id, prefixes)}
    saved = {row["input_ref"] for row in db.task_rows(task["id"])} if task is not None else set()
    rows: dict[str, dict] = {}
    for ref, item in live.items():
        rows[ref] = {**item, "task_id": task["task_id"] if ref in saved else "", "task_state": "current",
                     "live": True, "in_task": ref in saved, "export_missing": False}
    for older in db.tasks(project_id):  # новые задания первыми: по строке видна та, что её сняла последней
        for row in db.task_rows(older["id"]):
            rows.setdefault(row["input_ref"], {**row, "task_id": older["task_id"], "task_state": "superseded",
                                               "live": False, "in_task": False, "export_missing": True})
    # История решений не ограничена двадцатью заданиями шапки страницы.
    historical = set(db.decisions(project_id)) | set(db.research(project_id))
    # прежние группы, чьи исследования и решения сняты переходом идентичности пакетов, – строкой истории с пометкой
    # «архив» (план dev17, п. 4.6); перенесённая и не живая группа строкой не показывается: её адрес ведёт на новую
    # карточку, и очередь «Сохранить и дальше» не возвращается через неё (ревью Codex, круг 2)
    marks = db.latest_group_marks(project_id)
    archived = db.archived_refs(project_id, marks)
    moved_away = {ref for ref, m in marks.items() if m["to_ref"]} - live.keys()
    for ref in moved_away:
        rows.pop(ref, None)
    for ref in archived & rows.keys():
        rows[ref]["archived"] = not rows[ref]["live"]
    missing = (historical | archived) - rows.keys() - moved_away
    saved_rows = db.historical_task_rows(project_id, missing)
    for ref in sorted(missing):
        source = saved_rows.get(ref)
        if source:
            rows[ref] = {**source, 'task_state':'superseded', 'live':False,
                         'in_task':False, 'export_missing':True, 'archived': ref in archived}
        elif ref in archived:
            # решение без задания: состава строки нет – прежняя тройка по отметке группы (ревью Codex, круг 2)
            eco, name, version = (list((marks.get(ref) or {}).get("triple") or []) + ["", "", ""])[:3]
            rows[ref] = {"input_ref": ref, "ecosystem": eco, "name": name, "version": version,
                         "identity_kind": "short_name", "input_sig": "", "hub_fix_candidate": "",
                         "finding_count": 0, "codebase_count": 0, "position": 0, "vulnerability_ids": "[]",
                         "task_id": "", "task_state": "superseded", "live": False, "in_task": False,
                         "export_missing": True, "archived": True}
    order = {ref: index for index, ref in enumerate(live)}
    sources = sorted(rows.values(), key=lambda item: (not item["live"], order.get(item["input_ref"], len(order)),
                                                      item["name"].casefold()))
    return sources, task


def defects_by_component(db: Database, project_id: int) -> dict[str, list[dict]]:
    """Дефекты приложения по компонентам (в каких дефектах компоненты уже участвуют): строки
    `hub_defects` вида SCA, кроме отменённых и не принятых Hub, – по input_ref пакета, в который входят находки их
    состава (пакет – как у task_rows: экосистема, имя, версия из текущей выгрузки, включая отсутствующие находки).
    У семьи записи – состав всех её строк, подпись – по владельцу. {input_ref: [{id, number, hub_defect_id, state,
    label, done, card_url}]}, дефекты – по возрастанию номера строки."""
    from app import defect_links, sca
    from app.sca_contract import input_ref
    by = defect_links.by_hub_id(db, project_id, kind="SCA")
    out: dict[str, list[dict]] = {}
    for comp in db.sca_components(project_id, include_missing=True):
        ref = input_ref(*sca.package_key(comp))  # тот же ключ, что у строк задания (очистка имени, ревью dev17)
        found = defect_links.merge(by.get(str(h), []) for h in comp.get("hub_ids") or [])
        if found:
            out[ref] = defect_links.merge([out.get(ref, []), found])
    return out


def views(db: Database, project_id: int, prefixes: Iterable[str] = ()) -> tuple[list[dict], dict | None]:
    """Строки раздела вместе с принятыми фактами, решениями человека и дефектами (defects_by_component)."""
    from app import defect_links
    sources, task = _sources(db, project_id, prefixes)
    research_rows = db.research(project_id)
    decisions = db.decisions(project_id)
    defects = defects_by_component(db, project_id)
    # признаки происхождения строки (live, in_task, export_missing) добавляются поверх представления сценария:
    # он отвечает за факты и решение, а откуда строка – свойство раздела
    return [{**research.row_view(source, research_rows.get(source["input_ref"]),
                                 decisions.get(source["input_ref"]), source["task_state"]),
             "live": source["live"], "in_task": source["in_task"], "export_missing": source["export_missing"],
             "archived": bool(source.get("archived")),
             "defects": defects.get(source["input_ref"], []),
             "in_defect": defect_links.in_defect(defects.get(source["input_ref"], []))}
            for source in sources], task


def task_view(db: Database, project_id: int, task: dict | None) -> dict | None:
    """Действующее задание для шапки страницы: строки, исследовано, решений, номер ревизии."""
    if task is None:
        return None
    research_rows = db.research(project_id)
    decisions = db.decisions(project_id)
    refs = {row['input_ref'] for row in db.task_rows(task['id'])}
    revisions = [int(item["revision"]) for ref,item in research_rows.items() if ref in refs]
    return {**task, "researched": len(refs & research_rows.keys()), "decided": len(refs & decisions.keys()),
            "revisions": max(revisions) if revisions else 0}


def task_history(db: Database, project_id: int) -> list[dict]:
    """Прежние задания: подпись, число строк, состояние и время, когда они перестали быть актуальными."""
    return [{key: task.get(key, "") for key in ("id", "task_id", "state", "row_count", "created_at",
                                                "superseded_at", "imported_at", "manifest_sha256")}
            for task in db.tasks(project_id)]


def _filters(request: Request) -> dict[str, str]:
    """Значения фильтров из адреса. Неизвестное значение отбрасывается, а не отбирает молча."""
    def pick(name: str, allowed: tuple[str, ...] = ()) -> str:
        value = request.query_params.get(name, "")
        return value if value in allowed else ""

    def bound(name: str) -> str:
        value = request.query_params.get(name, "")
        return value if research._bound(value) is not None else ""

    return {"status": pick("status", research.STATUS_FILTERS), "decision": pick("decision", ("set", "unset")),
            "stale": pick("stale", ("1",)), "ecosystem": request.query_params.get("ecosystem", "")[:64],
            "q": request.query_params.get("q", "")[:120],
            # ADR-0096: CVSS по версии шкалы и границам, вид строки без балла, поддержка, совет, действие, свежесть
            "cvss_ver": pick("cvss_ver", research.CVSS_VERSIONS), "cvss_op": pick("cvss_op", ("ge", "gt")),
            "cvss_from": bound("cvss_from"), "cvss_to": bound("cvss_to"),
            "score": pick("score", tuple(research.SCORE_KINDS)), "support": pick("support", research.SUPPORT_FILTERS),
            "advice": pick("advice", research.contract.ADVICE_ACTIONS), "action": pick("action", research.ACTION_FILTERS),
            "review_due": pick("review_due", ("1",)), "age": pick("age", research.AGE_FILTERS),
            "gaps": pick("gaps", ("1",)), "defect": pick("defect", research.DEFECT_FILTERS),
            **worklists.options(request.query_params, ("name_asc", "name_desc", "applicable_desc", "support_asc", "decision_asc"))}


# ------------------------------------------------------------------ сохранённые отборы (В14, ADR-0110)

SAVED_NAME_CHARS = 60
# предметные условия списка (что отбирает) и параметры представления (как показать); номер страницы не сохраняется
SAVED_SUBJECT = ("status", "decision", "stale", "ecosystem", "q", "cvss_ver", "cvss_op", "cvss_from", "cvss_to",
                 "score", "support", "advice", "action", "review_due", "age", "gaps", "defect", "family")
SAVED_VIEW = ("sort", "group_by", "page_size")
_CVSS_ACTIVE = ("cvss_ver", "cvss_from", "cvss_to", "score")  # cvss_op сам по себе ничего не отбирает


def _query_request(text: str) -> Request:
    """Запрос только со строкой параметров – для _filters вне текущего адреса (сохранённый или присланный отбор)."""
    return Request({"type": "http", "query_string": str(text or "").encode("utf-8")})


def _query_text(request: Request) -> str:
    """Строка параметров показанного списка – из тех же query_params, что читает _filters."""
    params = getattr(request, "query_params", None) or {}
    items = params.multi_items() if hasattr(params, "multi_items") else list(params.items())
    return urlencode(items)


def saved_query(text: str) -> tuple[str, bool]:
    """Каноническая строка отбора для сохранения и признак «есть хоть одно действующее условие»: условия – через
    _filters (неизвестное и неверное отброшено), поиск и экосистема без внешних пробелов, границы CVSS – числом в
    одном виде, cvss_op – только с действующим условием CVSS; family, sort, group_by и действующий размер страницы
    (по правилу worklists.table, без значения по умолчанию); без номера страницы, back и уведомлений; ключи по
    порядку. Условие без совпадений – тоже условие."""
    filters = _filters(_query_request(text))
    pairs: list[tuple[str, str]] = []
    for key in SAVED_SUBJECT:
        value = str(filters.get(key) or "").strip()
        if key in ("cvss_from", "cvss_to") and value:
            value = f"{research._bound(value):g}"
        if key == "cvss_op" and not any(str(filters.get(k) or "").strip() for k in _CVSS_ACTIVE):
            value = ""
        if value:
            pairs.append((key, value))
    active = bool(pairs)
    size = worklists.integer(filters.get("page_size"), PAGE_SIZE)
    if size in worklists.SIZES and size != PAGE_SIZE:
        pairs.append(("page_size", str(size)))
    pairs += [(key, str(filters[key])) for key in ("sort", "group_by") if filters.get(key)]
    return urlencode(sorted(pairs)), active


def _with_page(text: str, page: object) -> str:
    """Строка показанного списка с его номером страницы: отказ формы, сохранение и удаление отбора возвращают на ту
    же страницу (сохраняемые условия номера страницы не содержат)."""
    number = max(1, worklists.integer(page, 1))
    return "&".join(x for x in (text, f"page={number}" if number > 1 else "") if x)


def _with_page(text: str, page: object) -> str:
    """Строка показанного списка с его номером страницы: отказ формы, сохранение и удаление отбора возвращают на ту
    же страницу (сохраняемые условия номера страницы не содержат)."""
    number = max(1, worklists.integer(page, 1))
    return "&".join(x for x in (text, f"page={number}" if number > 1 else "") if x)


def lost_conditions(stored: str) -> list[str]:
    """Условия сохранённого отбора, которые сейчас не действуют: сохранённые пары, которых нет в канонизации той же
    строки сейчас (параметр убран или значение больше не принимается). Смену смысла прежнего ключа с прежним
    значением так не увидеть."""
    current = dict(parse_qsl(saved_query(stored)[0], keep_blank_values=True))
    return [f"{key}={value}" for key, value in parse_qsl(stored, keep_blank_values=True)
            if current.get(key) != value]


def saved_filters_view(db: Database, project_id: int) -> list[dict]:
    rows = []
    for item in db.saved_component_filters(project_id):
        lost = lost_conditions(item["query"])
        rows.append({**item, "url": f"/projects/{project_id}/components" + (f"?{item['query']}" if item["query"] else ""),
                     "lost": lost, "all_lost": bool(lost) and not saved_query(item["query"])[1]})
    return rows


def selected_rows(rows, filters):
    """Общий порядок списка и перехода после решения; страницы не меняют очередь."""
    filtered = research.sort_rows(research.filter_rows(rows, filters))
    sort = filters["sort"]
    if sort:
        key = {"name_asc": lambda r: (r["name"].casefold(), r["ecosystem"]),
               "name_desc": lambda r: (r["name"].casefold(), r["ecosystem"]),
               "applicable_desc": lambda r: r["applicable"],
               "support_asc": lambda r: ({"eol": 0, "unsupported": 0, "unknown": 1, "supported": 2}.get(r["support_state"], 1), r["name"]),
               "decision_asc": lambda r: (r["decided"], r["name"])}[sort]
        filtered = sorted(filtered, key=key, reverse=sort.endswith("desc"))
    return filtered


def next_component_url(request, project_id, input_ref, rows):
    back = worklists.return_url(request, f"/projects/{project_id}/components")
    selection = Request({"type": "http", "query_string": urlsplit(back).query.encode("utf-8")})
    filters = _filters(selection)
    selected = selected_rows(rows, filters)
    if filters.get("family"):
        selected = [r for r in selected if worklists.family(r, "components")[0] == filters["family"]]
    index = next((i for i, r in enumerate(selected) if r["input_ref"] == input_ref), -1)
    if index >= 0 and index + 1 < len(selected):
        return f"/projects/{project_id}/components/{quote(selected[index + 1]['input_ref'])}?" + urlencode({"back": back})
    return back


def list_context(request: Request, project: dict, *, error_report: dict | None = None,
                 error: str = "", shown_query: str | None = None, saved_name: str = "") -> dict:
    """Контекст страницы списка (docs: backend-interface.md, п. 3). shown_query – условия списка не из адреса, а из
    формы (отказ сохранения отбора показывает тот же список); saved_name – введённое имя отбора."""
    db = db_of(request)
    pid = project["id"]
    rows, task = views(db, pid, settings_of(request).sca_internal_prefixes)
    filters = _filters(_query_request(shown_query) if shown_query is not None else request)
    filtered = selected_rows(rows, filters)
    w = worklists.table(filtered, filters, path=f"/projects/{pid}/components", kind="components", default_size=PAGE_SIZE,
                        sorts={"": "По приоритету", "name_asc": "Имя ↑", "name_desc": "Имя ↓",
                               "applicable_desc": "Уязвимости ↓", "support_asc": "Поддержка", "decision_asc": "Сначала без решения"})
    page, pages, total, shown = w["page"], w["pages"], w["total"], w["rows"]
    # балл CVSS строки по выбранной версии шкалы (ADR-0096 пп. 3–6) – для столбца «Публичные уязвимости»
    shown = [{**r, "score_view": research.row_score(r, filters["cvss_ver"])} for r in shown]
    ok_message, notice_error = _notice(request)
    base = w["params"]
    from app.package_transition import pending_count
    return {"project": project, "imp": db.latest_import(pid), "counts": db.count_findings(pid),
            "identity_pending": pending_count(db, project, settings_of(request).hub_url),
            "identity_known": bool(project.get("identity_rev")) or db.identity_known(pid) > 0,
            "stats": db.review_stats(pid), "task": task_view(db, pid, task),
            "task_history": task_history(db, pid), "filters": filters, "worklist": w,
            "filters_url": query(base), "prev_url": f"?{query(base, page=page - 1)}" if page > 1 else "",
            "next_url": f"?{query(base, page=page + 1)}" if page < pages else "",
            "page": page, "pages": pages, "total": total, "shown": len(shown), "rows": shown,
            "ecosystems": sorted({item["ecosystem"] for item in rows if item["ecosystem"]}),
            "summary": research.summaries(rows), "labels": research.LABELS, "error_report": error_report,
            "score_kinds": research.SCORE_KINDS, "cvss_versions": research.CVSS_VERSIONS,
            "support_filters": research.SUPPORT_FILTERS, "advice_filters": research.contract.ADVICE_ACTIONS,
            "action_filters": research.ACTION_FILTERS, "score_spec": research.score_filter(filters),
            "ok_message": ok_message, "error": error or notice_error,
            "net": research_view(request, project, task, rows),
            # В14: сохранённые отборы и показанный отбор в каноническом виде (его и сохраняет форма)
            "saved_filters": saved_filters_view(db, pid), "saved_name": saved_name,
            "saved_current": saved_query(shown_query if shown_query is not None else _query_text(request)),
            "saved_max": SAVED_FILTERS_MAX}


def _revision_source(db: Database, project_id: int, input_ref: str) -> dict:
    """Источник текущей ревизии: провайдер из профиля (снимок исполнителя – имя, где, модель, поиск использован /
    без поиска по источникам) или файловый ответ агента."""
    from app.executors import executor_info
    row = db.research_row(project_id, input_ref)
    if not row or not row.get("execution_id"):
        return {"kind": "file", "label": "ответ внешнего агента (файл)"}
    execution = db.get_execution(row["execution_id"])
    info = executor_info(db, execution)
    available = False
    try:
        available = bool((json.loads(str((execution or {}).get("options_json") or "{}")).get("chat") or {}).get("search"))
    except ValueError:
        pass
    # фактические вызовы инструментов строки получения, давшей ревизию, – не настройка профиля (ревью B4)
    tools = db.research_revision_tools(project_id, input_ref, int(row.get("revision") or 0)) or []
    searches = sum(1 for t in tools if t.get("tool") == "search" and t.get("status") == "ok")
    pages = sum(1 for t in tools if t.get("tool") == "fetch" and t.get("status") == "ok")
    failed = sum(1 for t in tools if t.get("tool") in ("search", "fetch") and t.get("status") not in ("ok", "empty"))
    if searches or pages:
        search = f"поиск по источникам: запросов {searches}, страниц {pages}" + (f", сбоев {failed}" if failed else "")
    elif failed:
        search = f"без результатов поиска: вызовов со сбоем {failed} – модель отвечала по своим знаниям"
    elif available:
        search = "без поиска по источникам: поиск был доступен, модель им не воспользовалась"
    else:
        search = "без поиска по источникам: поиск в профиле не настроен"
    return {"kind": "provider", "label": f"провайдер «{info['name']}»" + (f" ({info['where']})" if info["where"] else ""),
            "model": str((execution or {}).get("model") or ""), "date": str(row.get("imported_at") or "")[:10],
            "search": search}


ARCHIVE_WHAT = {"sca2_research": "исследование", "sca2_decisions": "решение человека"}


def _ref_label(db: Database, project_id: int, ref: str, triples: Mapping[str, list]) -> str:
    """Прежняя тройка группы для подписи архива: по отметке группы, иначе по последнему составу строки."""
    triple = triples.get(ref)
    if not triple:
        source = db.historical_task_row(project_id, ref) or {}
        triple = [source.get("ecosystem", ""), source.get("name", ""), source.get("version", "")]
    eco, name, version = (list(triple) + ["", "", ""])[:3]
    return f"{eco} {name}@{version}".strip() if name else ref


def archive_view(db: Database, project_id: int, input_ref: str) -> list[dict]:
    """Архив перехода идентичности для карточки (план dev17, п. 4.6): снятые исследования и решения самой группы
    и групп, перенесённых в неё, – с прежней тройкой, датой и причиной. В главный ответ и действующее решение не
    входят: их читают только живые таблицы."""
    marks = db.latest_group_marks(project_id)
    # архив своей группы и всей цепочки групп, перенесённых в неё (ревью Codex, круг 2)
    refs = [input_ref, *db.moved_from(project_id, input_ref, marks)]
    triples = {ref: m["triple"] for ref, m in marks.items()}
    out = []
    for a in db.identity_archive(project_id, refs):
        row = a["row"]
        fields: list[str] = []
        if a["table"] == "sca2_decisions":
            view = research.decision_view(row) or {}
            text = " – ".join(x for x in (str(view.get("action_label") or ""), str(row.get("rationale") or "")) if x)
            # поля решения – как в обычной истории (decision_details; ревью Codex, круг 2)
            if view.get("target_version"):
                fields.append(f"целевая версия: {view['target_version']}")
            if view.get("replacement_name"):
                fields.append("замена: " + str(view["replacement_name"]) + (f"@{view['replacement_version']}"
                                                                    if view.get("replacement_version") else ""))
            if row.get("review_at"):
                fields.append(f"пересмотр: {row['review_at']}")
            if row.get("decided_at"):
                fields.append(f"принято: {str(row['decided_at'])[:10]}")
        else:
            parts = [f"ревизия {row.get('revision', '')}", str(row.get("status") or ""),
                     f"загружено {str(row.get('imported_at') or '')[:10]}" if row.get("imported_at") else ""]
            text = " · ".join(x for x in parts if x)
        out.append({"what": ARCHIVE_WHAT.get(a["table"], a["table"]), "old_ref": a["input_ref"],
                    "old_label": _ref_label(db, project_id, a["input_ref"], triples),
                    "archived_at": a["archived_at"], "reason": a["reason"], "text": text, "fields": fields})
    return out


def detail_context(request: Request, project: dict, input_ref: str, *, form: dict | None = None,
                   error: str = "") -> dict:
    """Контекст карточки строки (backend-interface.md, п. 4). Отдельный словарь: его можно проверить и
    отдать шаблону, не поднимая HTTP."""
    db = db_of(request)
    pid = project["id"]
    rows, task = views(db, pid, settings_of(request).sca_internal_prefixes)
    row = next((item for item in rows if item["input_ref"] == input_ref), None)
    if row is None:
        raise HTTPException(status_code=404, detail="Строка не найдена.")
    history = db.decision_history(pid, input_ref)
    from app.routes.capec import component_context
    capec_context = component_context(request,pid,row)
    decision = history[0] if history else None
    ok_message, notice_error = _notice(request)
    if form is None:
        form = research.decision_form(research.decision_view(decision) or {}, int(decision["revision"]) if decision else 0,
                                      input_sig=row["input_sig"], research_sig=row["answer_sig"],
                                      research_revision=row["revision"])
    stale_note = ""
    if row["decision_stale"]:
        parts = []
        if "research_changed" in row["decision_reasons"]:
            parts.append("исследование обновилось после решения: факты изменились")
        if "review_date" in row["decision_reasons"]:
            parts.append("наступил срок пересмотра " + str((decision or {}).get("review_at", "")))
        stale_note = "; ".join(parts) + ". Решение человека остаётся в истории; подтвердите его заново после проверки."
    elif decision and not row["researched"]:
        stale_note = "исследования по строке ещё нет: решение принято без ответа агента"
    return {"project": project, "imp": db.latest_import(pid), "counts": db.count_findings(pid),
            "stats": db.review_stats(pid), "row": row, "capec_context": capec_context,
            "back_url": worklists.return_url(request, f"/projects/{pid}/components"),
            "next_component_url": next_component_url(request, pid, input_ref, rows),
            "review_clock": datetime.now().astimezone().strftime("%d.%m.%Y, %Z"),
            # форма решения компонента: быстрый срок пересмотра от даты приложения (вариант
            # А) и черновик по фактам исследования для пустых полей (вариант Б)
            "review_presets": research.review_presets(date.today()),
            "research_draft": research.decision_draft(row, date.today()),
            # неверная дата, возвращённая после отказа 422, в поле type=date браузер показал бы пустой – поле текстовое,
            # чтобы введённое осталось видно (ревью Codex, круг 20)
            "review_at_text": bool(str(form.get("review_at") or "").strip()) and not research.iso_date(form.get("review_at")),
            "siblings": [r for r in rows if worklists.family(r,"components")[0] == worklists.family(row,"components")[0]],
            "research": {"revision": row["revision"], "answer_sig": row["answer_sig"],
                         "imported_at": row["imported_at"], "validator_version": row['validator_version'],
                         "manifest_sha256": (task or {}).get("manifest_sha256", ""),
                         "task_id": row["task_id"], "task_state": row["task_state"],
                         "source": _revision_source(db, pid, input_ref)},
            "identity": row["identity"], "latest": row["latest"], "support": row["support"],
            "update_status": row["update_status"], "findings": row["findings"],
            "coverage": row["coverage_items"], "gaps": row["gaps_items"],
            "evidence": row["evidence_items"], "advice": row["advice_detail"],
            "decision": row["decision"], "decisions": [research.decision_view(item) for item in history],
            "decision_stale": row["decision_stale"], "decision_note": stale_note,
            "revision": int(decision["revision"]) if decision else 0, "form": form,
            "labels": research.LABELS,
            "report_urls": {"json": f"/projects/{pid}/components/{quote(input_ref)}/report?format=json",
                            "md": f"/projects/{pid}/components/{quote(input_ref)}/report?format=md"},
            "ok_message": ok_message, "error": error or notice_error,
            "history": db.research_history(pid, input_ref),
            "archive": archive_view(db, pid, input_ref),
            # где используется эта версия (OR-04): находки выгрузки по кодовым базам – контекст решения
            "usages": (usages := db.sca_usages(pid, input_ref)),
            # из места использования – назад сюда же, с отбором списка компонентов, из которого открыта карточка
            "self_back": quote(f"/projects/{pid}/components/{input_ref}"
                               + (f"?{urlencode(list(request.query_params.items()))}" if request.query_params else ""),
                               safe=""),
            "usage_codebases": len({u["codebase"] for u in usages}),
            # пометки идентичности пакета по находкам этой версии (план dev17, п. 4.6)
            "identity_marks": _identity_marks(db, pid, usages),
            # запуск исследования провайдером по одной этой строке
            "research_one": research_one_view(request, project, row, task),
            # решение компонента – находкам версии (ADR-0153): по тому решению, которое показано выше
            "apply": _component_apply(db, pid, input_ref, row["decision"], usages,
                                      (row["answer_sig"], row["revision"])),
            # итог записи находкам – ещё и внутри блока, к которому ведёт переход: сообщение наверху страницы
            # на длинной карточке остаётся выше экрана
            "apply_notice": _apply_notice(request, ok_message, error or notice_error)}


def _identity_marks(db: Database, project_id: int, usages: Iterable[Mapping[str, Any]]) -> list[str]:
    """Пометки идентичности пакета по находкам версии – один запрос пометок проекта на карточку."""
    marks = db.package_marks(project_id)
    return sorted({t for u in usages for t in marks.get(str(u["hub_id"]), [])})


def _seen_stale(form: Mapping[str, Any], row: dict | None, research_row: dict | None) -> str:
    """Решение привязывается к тому, что человек видел на странице. Если по строке уже есть ответ агента, а
    форма не несёт его отпечатка или отпечаток не тот, решение не сохраняется: привязывать его молча к новому
    ответу нельзя, человек новый ответ не читал. Пустая строка – всё в порядке."""
    seen_sig = str(form.get("expected_research_sig") or "").strip()
    seen_revision = _integer(form.get("expected_research_revision"), 0)
    if research_row is None:
        return ""
    if not seen_sig or not seen_revision:
        return (PROBLEMS["decision_unbound"]
                + ": решение сохраняется только по ответу агента, который человек видел на этой странице")
    if seen_sig != research_row.get("answer_sig", "") or seen_revision != int(research_row.get("revision") or 0):
        return (PROBLEMS["decision_stale"]
                + ": ответ агента изменился после того, как страницу открыли")
    seen_input = str(form.get("expected_input_sig") or "").strip()
    if row is not None and seen_input and seen_input != row.get("input_sig", ""):
        return PROBLEMS["decision_stale"] + ": строка задания изменилась после того, как страницу открыли"
    return ""


def detail_response(request: Request, project: dict, input_ref: str, *, form: dict | None = None, error: str = "",
                    status_code: int = 200) -> HTMLResponse:
    context = detail_context(request, project, input_ref, form=form, error=error)
    context["decision_conflict"] = status_code == 409
    context["error_field"] = research.decision_problem(form or {})[0] if status_code == 422 else ""
    return render(request, "components/detail.html", context, status_code=status_code)


def list_response(request: Request, project: dict, *, error_report: dict | None = None, error: str = "",
                  status_code: int = 200, shown_query: str | None = None, saved_name: str = "") -> HTMLResponse:
    return render(request, "components/index.html",
                  list_context(request, project, error_report=error_report, error=error, shown_query=shown_query,
                               saved_name=saved_name), status_code=status_code)


@router.post("/projects/{project_id}/components/filters", response_class=HTMLResponse)
async def save_component_filter(request: Request, project_id: int):
    """Сохранить показанный отбор под именем (В14, ADR-0110): условия – из скрытого поля страницы, на сервере снова
    через канонизацию; то же имя – замена условий. Отказ – тот же список с введённым именем."""
    project = project_or_404(request, project_id)
    form = await request.form()
    raw = str(form.get("name") or "")
    name = " ".join("".join(ch for ch in raw if ch.isprintable() or ch.isspace()).split())
    shown = str(form.get("query") or "")
    canonical, active = saved_query(shown)
    problem = ""
    if not name:
        problem = "Назовите отбор: имя видно в списке сохранённых."
    elif len(name) > SAVED_NAME_CHARS:
        problem = f"Имя отбора длиннее {SAVED_NAME_CHARS} знаков."
    elif not active:
        problem = "В отборе нет условий – это весь список, сохранять его не нужно."
    if not problem:
        saved = await run_in_threadpool(db_of(request).save_component_filter, project_id, name, canonical)
        if saved["state"] == "limit":
            problem = f"Сохранено уже {SAVED_FILTERS_MAX} отборов: удалите ненужный и сохраните снова."
        else:
            code = "filter_saved" if saved["state"] == "created" else "filter_updated"
            return redirect(f"/projects/{project_id}/components?"
                            + "&".join(x for x in (_with_page(canonical, form.get("page")), f"ok={code}") if x))
    return await run_in_threadpool(list_response, request, project, error=problem, status_code=422,
                                   shown_query=_with_page(canonical, form.get("page")), saved_name=name)


@router.post("/projects/{project_id}/components/filters/{filter_id}/delete")
async def delete_component_filter(request: Request, project_id: int, filter_id: int):
    """Удалить сохранённый отбор (только этого проекта); показанный список остаётся прежним."""
    project_or_404(request, project_id)
    form = await request.form()
    canonical, _ = saved_query(str(form.get("query") or ""))
    if not await run_in_threadpool(db_of(request).delete_component_filter, project_id, filter_id):
        raise HTTPException(status_code=404, detail="Сохранённый отбор не найден.")
    return redirect(f"/projects/{project_id}/components?"
                    + "&".join(x for x in (_with_page(canonical, form.get("page")), "ok=filter_deleted") if x))


# ------------------------------------------------------------------ адреса

@router.get("/projects/{project_id}/components", response_class=HTMLResponse)
def components_page(request: Request, project_id: int):
    """Список строк задания с фильтрами."""
    return list_response(request, project_or_404(request, project_id))


@router.post("/projects/{project_id}/components/task")
async def build_task(request: Request, project_id: int):
    """Собрать задание из текущей выгрузки. Состав не изменился – прежнее задание остаётся прежним."""
    project_or_404(request, project_id)
    db = db_of(request)
    settings = settings_of(request)
    rows, _ = await run_in_threadpool(research.task_rows, db.sca_components(project_id),
                                      settings.sca_internal_prefixes, db.sca_confirmed(project_id))
    if not rows:
        if _wants_json(request):
            return JSONResponse({"detail": PROBLEMS["task_empty"]}, status_code=409)
        return redirect(f"/projects/{project_id}/components?err=task_empty")
    digest = research.sha256(research.composition(rows))
    task = db.current_task(project_id)
    if (task is not None and str(task.get("contract")) == research.CONTRACT
            and research.sha256(research.composition(db.task_rows(task['id']))) == digest):
        return redirect(f"/projects/{project_id}/components?ok=task_same&n={len(rows)}")
    imp = db.latest_import(project_id)
    try:
        created = db.insert_task(project_id, int((imp or {}).get("id") or 0), research.new_task_id(), rows,
                                 sorted({item["ecosystem"] for item in rows if item["ecosystem"]}), digest, "",
                                 research.CONTRACT, ANSWER_CONTRACT, VALIDATOR_VERSION)
    except TaskSuperseded:
        # состав сменился между чтением строк и записью: прежнее задание и его строки остаются в силе
        log.info("component research task for project %d refused: the composition changed", project_id)
        if _wants_json(request):
            return JSONResponse({"detail": PROBLEMS["task_gone"]}, status_code=409)
        return redirect(f"/projects/{project_id}/components?err=task_gone")
    log.info("component research task for project %d: %s, rows %d", project_id, created["task_id"], len(rows))
    return redirect(f"/projects/{project_id}/components?ok=task&n={len(rows)}")


# ------------------------------------------------------------------ исследование провайдером (ADR-0105, B4)

def research_profile(db: Database, settings: Settings, project: dict) -> dict | None:
    """Профиль исследования: проекта, иначе приложения; годен только включённый профиль удалённого API (чат-завершения
    или Messages) с назначением «исследование» (К7: у Ollama в этой версии исполнителя исследования нет)."""
    from app.db import DEFAULT_PROVIDER_ID
    chosen = project.get("research_provider_id") or settings.default_research_provider_id or DEFAULT_PROVIDER_ID
    profile = db.get_provider(int(chosen))
    return profile if profile and research_profile_ok(profile) else None


def research_profile_ok(profile: dict) -> bool:
    from app.executors import REMOTE_KINDS
    if not profile.get("enabled") or str(profile.get("kind")) not in REMOTE_KINDS:
        return False
    try:
        purposes = json.loads(str(profile.get("purposes_json") or "[]"))
    except ValueError:
        purposes = []
    return "research" in purposes


def research_options(db: Database, project: dict) -> list[dict]:
    """Варианты профиля исследования проекта: «как в настройках» и включённые совместимые профили; несовместимые –
    неактивные с причиной."""
    current = project.get("research_provider_id")
    options = [{"value": "", "label": "Как в настройках приложения", "selected": not current}]
    for p in db.list_providers():
        if not p["enabled"] and p["id"] != current:
            continue
        ok = research_profile_ok(p)
        where = {"local": "этот компьютер", "lan": "сеть организации", "external": "интернет"}.get(str(p["trust"]), "")
        label = f"{p['name']} ({where})" + ("" if ok else " – исследование только профилем удалённого API")
        options.append({"value": str(p["id"]), "label": label, "selected": p["id"] == current, "disabled": not ok})
    return options


def _apply_notice(request: Request, ok_message: str, error: str) -> dict | None:
    """Итог записи решения находкам для блока карточки: {text, ok} по кодам адреса страницы или None."""
    if str(request.query_params.get("err", "")).startswith("apply_") and error:
        return {"text": error, "ok": False}
    if request.query_params.get("ok") == "applied" and ok_message:
        return {"text": ok_message, "ok": True}
    return None


def _component_apply(db: Database, project_id: int, input_ref: str, decision: dict | None, usages: list[dict],
                     research: tuple[str, int]) -> dict:
    """Блок «Решение – находкам этой версии»: по тем решению, находкам и исследованию, которые показывает карточка."""
    from app.routes.sca import component_apply_view  # маршруты SCA подключаются позже этого модуля
    return component_apply_view(db, project_id, input_ref, decision, usages,
                                (str(research[0] or ""), int(research[1] or 0)))


def _apply_after_save(db: Database, project_id: int, input_ref: str, revision: int, token: str) -> tuple[int, str]:
    """«Сохранить и применить к находкам»: только что сохранённая редакция решения – находкам версии. Возвращает
    (число находок, код отказа): решение компонента уже сохранено, отказ записи находкам – отдельное сообщение.
    Сбой самой записи (база занята или недоступна, исход COMMIT неизвестен) тоже возвращается кодом: ответ формы
    обязан назвать сохранённую редакцию компонента, иначе повторное сохранение упрётся в конфликт редакций."""
    from app.routes.sca import ComponentApplyRefused, apply_component_decision
    from app.logsafe import log_failure
    from app.storage.postgresql import CommitUnknown, DatabaseBusy
    try:
        return apply_component_decision(db, project_id, input_ref, decision_revision=revision, token=token), ""
    except ComponentApplyRefused as refused:
        return 0, str(refused.args[0])
    except CommitUnknown:  # обрыв на самом COMMIT: записаны находки или нет – неизвестно
        log.warning("решение компонента %s проекта %d сохранено, исход записи находкам неизвестен", input_ref,
                    project_id)
        return 0, "apply_unknown"
    except DatabaseBusy as busy:  # база занята или недоступна (DatabaseUnavailable – её подкласс)
        log.warning("решение компонента %s проекта %d сохранено, запись находкам не прошла: %s", input_ref,
                    project_id, type(busy).__name__)
        return 0, "apply_failed"
    except Exception as failed:  # noqa: BLE001 – ошибка программы: решение компонента уже записано, ответ это называет
        # без текста исключения: в нём могут быть данные находок (REVIEW.md) – только вид ошибки и место
        log_failure(log, "решение компонента проекта %s сохранено, запись находкам упала", failed, project_id)
        return 0, "apply_internal"


APPLY_FAILURES = ("apply_failed", "apply_unknown", "apply_internal")  # сбой самой записи находкам, а не отказ


def _apply_failure_page(card_url: str, revision: int, message: str) -> str:
    """Ответ обычной формы «Сохранить и применить», когда запись находкам сорвалась: оба итога на странице, которая
    не обращается к базе (она может быть ещё недоступна)."""
    from html import escape
    return ('<!doctype html><html lang="ru"><head><meta charset="utf-8"><title>Решение сохранено</title></head>'
            f'<body><main><h1>Решение компонента сохранено</h1><p>Редакция решения: {int(revision)}.</p>'
            f'<p role="alert">{escape(message)}</p>'
            f'<p><a href="{escape(card_url, quote=True)}">Вернуться к карточке компонента</a></p></main></body></html>')


def research_one_view(request: Request, project: dict, row: Mapping[str, Any], task: dict | None) -> dict:
    """Карточка компонента: можно ли запустить исследование провайдером по одной этой строке, и если нет – почему.
    Запуск – та же форма предпросмотра с выбором «отмеченные в таблице» и одной строкой: состав, согласие и отпечаток
    считаются как у запуска с вкладки. Условия те же, что у кнопок вкладки: строка есть в текущем задании, профиль
    исследования годен, получение по проекту не идёт."""
    db, settings = db_of(request), settings_of(request)
    profile = research_profile(db, settings, project)
    run = db.active_research_run(project["id"])
    if not row.get("live"):
        why = "Компонента нет в текущей выгрузке: исследовать его провайдером нельзя."
    elif task is None or not row.get("in_task"):
        why = "Строки нет в текущем задании: обновите задание на вкладке «Компоненты», затем вернитесь сюда."
    elif not db.task_composition_current(project["id"], task["id"]):
        # состав проекта изменился после сборки задания: запуск всё равно отклонит согласие (ревью dev26)
        why = ("Состав проекта изменился после сборки задания: обновите задание на вкладке «Компоненты», затем "
               "вернитесь сюда.")
    elif profile is None:
        why = ("Профиль исследования не выбран или не годится: выберите его на вкладке «Компоненты», блок "
               "«Исследование провайдером».")
    elif run is not None:
        why = f"По проекту идёт получение №{run['id']}: дождитесь его конца."
    else:
        why = ""
    return {"can": not why, "why": why, "profile": profile, "run": run}


def research_view(request: Request, project: dict, task: dict | None, component_rows: Iterable[dict] = ()) -> dict:
    """Блок «Исследование провайдером» для страницы «Компоненты»: профиль, последнее получение, строки.
    component_rows – строки раздела (views): по ним считается, сколько строк задания без дефекта."""
    db, settings = db_of(request), settings_of(request)
    profile = research_profile(db, settings, project)
    run = db.latest_research_run(project["id"])
    rows = db.research_run_rows(run["id"]) if run else []
    counts = {s: sum(1 for r in rows if r["state"] == s) for s in ("queued", "sending", "saved", "unchanged", "failed",
                                                                     "unknown")}
    alive = bool(run and run["state"] == "running" and request.app.state.research.running(run["id"]))
    no_defect = len(without_defect(db.task_rows(task["id"]), component_rows)) if task else 0
    return {"profile": profile, "run": run, "rows": rows, "counts": counts, "alive": alive, "no_defect": no_defect,
            "current_task": bool(run and task and run["task_id"] == task["id"]),
            "options": research_options(db, project), "external_on": external_enabled(),
            "state_labels": RUN_STATE_LABELS, "row_labels": ROW_STATE_LABELS}


RUN_STATE_LABELS = {"running": "идёт", "done": "завершено", "stopped": "остановлено", "interrupted": "прервано"}
ROW_STATE_LABELS = {"queued": "в очереди", "sending": "отправлено", "saved": "сохранена", "unchanged": "без изменений",
                    "failed": "не получена", "unknown": "результат неизвестен"}
SELECTION_LABELS = {"all": "все строки задания", "unresearched": "без исследования",
                    "review_due": "требующие пересмотра", "no_defect": "без дефекта",
                    "picked": "отмеченные в таблице", "followup": "доисследование оставшихся"}
PICKED_MAX = 1000  # отмеченных строк в одной форме: страница таблицы показывает не больше 200


def selection_rows(db: Database, settings: Settings, project_id: int, task: dict, selection: str,
                   picked: Iterable[str] = ()) -> list[dict]:
    """Строки текущего задания по выбору оператора – одна функция для предпросмотра и запуска, чтобы состав не
    расходился. «Без дефекта»: компоненты, у которых ни одна находка не привязана к дефекту
    приложения, – тот же признак, что у отбора «Дефект: не входит» вкладки (views, in_defect); по остальным решение
    уже занесено в дефекты, и тратить на них провайдера незачем. «Отмеченные в таблице» – строки задания, которые
    оператор отметил галочками на вкладке (picked – их input_ref из формы; чужие и незнакомые значения просто не
    находят строку задания)."""
    rows = db.task_rows(task["id"])
    if selection == "picked":
        keep = set(picked)
        return [r for r in rows if r["input_ref"] in keep]
    if selection == "unresearched":
        researched = db.research(project_id)
        return [r for r in rows if r["input_ref"] not in researched]
    if selection in ("review_due", "no_defect"):
        all_rows, _ = views(db, project_id, settings.sca_internal_prefixes)
        if selection == "review_due":
            keep = {r["input_ref"] for r in all_rows if r.get("review_due")}
            return [r for r in rows if r["input_ref"] in keep]
        return without_defect(rows, all_rows)
    return rows


def without_defect(task_rows: Iterable[dict], component_rows: Iterable[dict]) -> list[dict]:
    """Строки задания, у компонентов которых нет находок в дефекте (component_rows – строки раздела, views). Один
    расчёт для предпросмотра, запуска и числа в списке выбора."""
    keep = {r["input_ref"] for r in component_rows if not r.get("in_defect")}
    return [r for r in task_rows if r["input_ref"] in keep]


@router.post("/projects/{project_id}/components/research/preview", response_class=HTMLResponse)
async def research_preview(request: Request, project_id: int):
    """Предпросмотр и согласие (К7): строки, полный системный текст, первое сообщение целиком, инструменты,
    профиль, модель, рассуждение, поиск, оценка числа обращений, куда уходит, что раскрывается косвенно."""
    from app import sca_research_net as net
    from app.executors import chat_settings, execution_values
    form = await request.form(max_fields=PICKED_MAX + 12, max_files=0)
    selection = str(form.get("selection") or "all")
    picked = [str(v) for v in form.getlist("input_ref")][:PICKED_MAX]

    def apply():
        project = project_or_404(request, project_id)
        db, settings = db_of(request), settings_of(request)
        task = db.current_task(project_id)
        if task is None:
            return redirect(f"/projects/{project_id}/components?err=task_empty")
        profile = research_profile(db, settings, project)
        if profile is None:
            return redirect(f"/projects/{project_id}/components?err=research_profile")
        if db.active_research_run(project_id):
            return redirect(f"/projects/{project_id}/components?err=research_running")
        if selection not in SELECTION_LABELS or selection == "followup":  # followup – только маршрут /requeue
            return redirect(f"/projects/{project_id}/components?err=research_selection")
        rows = selection_rows(db, settings, project_id, task, selection, picked)
        if not rows:
            return redirect(f"/projects/{project_id}/components?err=research_empty")
        chat = chat_settings(profile)
        search = chat.get("search")
        search_mode = "tools" if search else "none"
        system = net.instructions(bool(search), settings.osv_url)
        model = str(profile.get("default_model") or "")
        execution = execution_values(profile, model, "ask", settings.num_ctx, settings.model_json_schema,
                                     purpose="research")
        tool_steps = int(chat.get("tool_steps") or 12)
        cutoff = net.today_cutoff()
        components_sha256 = str(task.get("components_sha256") or task.get("manifest_sha256") or "")
        fingerprint = net.consent_fingerprint(system, cutoff, [r["input_ref"] for r in rows], model, search_mode,
                                              tool_steps, components_sha256, execution, project_id, task["task_id"])
        nonce = secrets.token_hex(8)  # одноразовый номер страницы: метка – только с этого предпросмотра
        token = net.preview_token(request.app.state.research_secret, fingerprint, nonce)
        preview = {"rows": [{**research.row_text(r), "name": r["name"]} for r in rows], "system": system,
                   "first_message": net.row_message(rows[0], cutoff, osv.PREVIEW if settings.osv_url else None),
                   "osv_url": settings.osv_url, "tools": net.TOOLS if search else net.TOOLS_NO_SEARCH,
                   "profile": profile, "model": model, "chat": chat, "search": search, "tool_steps": tool_steps,
                   "cutoff": cutoff, "selection": selection, "selection_label": SELECTION_LABELS[selection],
                   "picked": [r["input_ref"] for r in rows] if selection == "picked" else [],
                   "calls_max": net.calls_estimate(len(rows), tool_steps), "sends_per_row": tool_steps + net.EXTRA_STEPS_MAX + net.ROW_SENDS_MAX,
                   "steps_max": tool_steps + net.EXTRA_STEPS_MAX, "extra_steps": net.EXTRA_STEPS_MAX,
                   "fingerprint": fingerprint, "nonce": nonce, "token": token,
                   "where": str(profile.get("base_url") or ""), "trust": str(profile.get("trust") or ""),
                   "execution": execution, "components_sha256": components_sha256, "task": task}
        return render(request, "components/research_preview.html", {"project": project, "preview": preview,
                                                                     "counts": db.count_findings(project_id),
                                                                     "stats": db.review_stats(project_id)})

    return await run_in_threadpool(apply)


@router.post("/projects/{project_id}/components/research/start")
async def research_start(request: Request, project_id: int):
    """Согласие подтверждено: согласие и получение одной операцией, исполнитель запускается. Отпечаток из формы
    должен совпасть с пересчитанным: состав, профиль или инструкции изменились после предпросмотра – новое
    согласие (К7)."""
    from app import sca_research_net as net
    from app.executors import chat_settings, execution_values
    form = await request.form(max_fields=PICKED_MAX + 12, max_files=0)
    selection = str(form.get("selection") or "all")
    picked = [str(v) for v in form.getlist("input_ref")][:PICKED_MAX]
    shown = str(form.get("fingerprint") or "")
    nonce = str(form.get("nonce") or "")
    token = str(form.get("token") or "")
    confirmed = str(form.get("confirm") or "") == "1"

    def apply():
        project = project_or_404(request, project_id)
        db, settings = db_of(request), settings_of(request)
        if not confirmed:
            return redirect(f"/projects/{project_id}/components?err=research_confirm")
        task = db.current_task(project_id)
        profile = research_profile(db, settings, project)
        if task is None or profile is None:
            return redirect(f"/projects/{project_id}/components?err=research_profile")
        if selection not in SELECTION_LABELS or selection == "followup":  # как в предпросмотре (ревью Codex, круг 32)
            return redirect(f"/projects/{project_id}/components?err=research_selection")
        rows = selection_rows(db, settings, project_id, task, selection, picked)
        chat = chat_settings(profile)
        search = chat.get("search")
        search_mode = "tools" if search else "none"
        system = net.instructions(bool(search), settings.osv_url)
        model = str(profile.get("default_model") or "")
        tool_steps = int(chat.get("tool_steps") or 12)
        cutoff = net.today_cutoff()
        components_sha256 = str(task.get("components_sha256") or task.get("manifest_sha256") or "")
        execution = execution_values(profile, model, "ask", settings.num_ctx, settings.model_json_schema,
                                     purpose="research")
        fingerprint = net.consent_fingerprint(system, cutoff, [r["input_ref"] for r in rows], model, search_mode,
                                              tool_steps, components_sha256, execution, project_id, task["task_id"])
        expected = net.preview_token(request.app.state.research_secret, fingerprint, nonce) if nonce else ""
        # метка предпросмотра: выдана этим экземпляром для этого отпечатка – прямой POST без страницы или после смены
        # состава, профиля или инструкций не проходит; та же метка – ключ согласия (повтор формы – прежнее получение)
        if not rows or fingerprint != shown or not token or not expected or not hmac.compare_digest(expected, token):
            return redirect(f"/projects/{project_id}/components?err=research_changed")
        try:
            consent = db.create_research_consent(project_id, task["id"], execution, {
                "components_sha256": components_sha256, "cutoff_date": cutoff, "instructions": system,
                "instructions_sha256": research.sha256(system), "rows": [r["input_ref"] for r in rows],
                "selection": selection, "model": model, "search_mode": search_mode, "tool_steps": tool_steps},
                consent_key=token,
                recheck=lambda: [r["input_ref"] for r in selection_rows(db, settings, project_id, task, selection,
                                                                         picked)])
            run = db.start_research_run(consent["id"])
        except SelectionChanged:  # выбор стал другим между чтением строк и записью согласия
            return redirect(f"/projects/{project_id}/components?err=research_changed")
        except TaskSuperseded:
            return redirect(f"/projects/{project_id}/components?err=task_gone")
        except RuntimeError:
            return redirect(f"/projects/{project_id}/components?err=research_running")
        request.app.state.research.start(run["id"])
        log.info("исследование провайдером: проект %d, получение %d, строк %d", project_id, run["id"], len(rows))
        return redirect(f"/projects/{project_id}/components/research/{run['id']}")

    return await run_in_threadpool(apply)


@router.get("/projects/{project_id}/components/research/{run_id}", response_class=HTMLResponse)
def research_run_page(request: Request, project_id: int, run_id: int):
    project = project_or_404(request, project_id)
    db = db_of(request)
    run = db.research_run(run_id)
    if run is None or run["project_id"] != project_id:
        raise HTTPException(status_code=404, detail="Получение не найдено.")
    consent = db.research_consent(run["consent_id"])
    execution = db.get_execution(run["execution_id"])
    from app.executors import executor_label
    rows = db.research_run_rows(run_id)
    names = {r["input_ref"]: r["name"] for r in db.task_rows(run["task_id"])}
    for row in rows:
        row["name"] = names.get(row["input_ref"], row["input_ref"])
        row["tools_text"] = tools_text(row["tools"], int((row.get("usage") or {}).get("sends") or 0))
    live = request.app.state.research.live(run_id)
    if live:
        live["text"] = tools_text(live["tools"], live["sends"])
    ok_message, notice_error = _notice(request)
    try:  # расход получения – сумма по строкам (сколько обращений и токенов ушло)
        usage = {k: int(v) for k, v in (json.loads(run.get("usage_json") or "{}") or {}).items() if isinstance(v, (int, float))}
    except ValueError:
        usage = {}
    from app import sca_research_net as net
    nonce = secrets.token_hex(8)
    token = net.preview_token(request.app.state.research_secret, requeue_fingerprint(project_id, run_id), nonce)
    return render(request, "components/research_run.html", {
        "project": project, "run": run, "consent": consent, "rows": rows, "executor": executor_label(db, execution),
        "live": live, "requeue_nonce": nonce, "requeue_token": token,
        "usage": usage,
        "alive": request.app.state.research.running(run_id), "state_labels": RUN_STATE_LABELS,
        "row_labels": ROW_STATE_LABELS, "selection_labels": SELECTION_LABELS,
        "counts": db.count_findings(project_id), "stats": db.review_stats(project_id),
        "ok_message": ok_message, "error": notice_error,
        # в доисследование не идут строки, уже сохранённые более поздним получением (later_saved)
        "unknown": sum(1 for r in rows if r["state"] == "unknown" and not r.get("later_saved")),
        "failed": sum(1 for r in rows if r["state"] == "failed" and not r.get("later_saved"))})


@router.get("/projects/{project_id}/components/research/{run_id}/status")
def research_run_status(request: Request, project_id: int, run_id: int):
    db = db_of(request)
    run = db.research_run(run_id)
    if run is None or run["project_id"] != project_id:
        raise HTTPException(status_code=404, detail="Получение не найдено.")
    rows = db.research_run_rows(run_id)
    live = request.app.state.research.live(run_id)
    return JSONResponse({"run": {**run, "state_label": RUN_STATE_LABELS.get(run["state"], run["state"])},
                         "alive": request.app.state.research.running(run_id),
                         "live": {**live, "text": tools_text(live["tools"], live["sends"])} if live else None,
                         "rows": [{"input_ref": r["input_ref"], "state": r["state"], "later_saved": bool(r.get("later_saved")),
                                   "state_label": ROW_STATE_LABELS.get(r["state"], r["state"]), "reason": r["reason"],
                                   "revision": r["revision"], "tools": len(r["tools"]),
                                   "tools_text": tools_text(r["tools"], int((r.get("usage") or {}).get("sends") or 0)),
                                   "sending_at": r["sending_at"]} for r in rows]})


TOOL_STATUS = {"ok": "выполнен", "error": "ошибка", "unknown": "результат неизвестен", "empty": "пусто",
               "unavailable": "недоступен", "unsupported": "экосистема не поддерживается", "partial": "неполный ответ"}


def tools_text(tools: list, sends: int = 0) -> str:
    """Ход строки словами: обращений к модели, вызовов поиска и страниц с исходом каждого шага."""
    parts = [f"обращений к модели {sends}"] if sends else []
    for t in tools:
        name = {"search": "поиск", "fetch": "страница", "osv": "запрос OSV"}.get(str(t.get("tool")), str(t.get("tool")))
        status = TOOL_STATUS.get(str(t.get("status") or ""), str(t.get("status") or "…"))
        extra = f" ({t['results']})" if t.get("tool") in ("search", "osv") and t.get("status") == "ok" else ""
        parts.append(f"шаг {t.get('step')}: {name} – {status}{extra}")
    return "; ".join(parts)


@router.post("/projects/{project_id}/components/research/{run_id}/stop")
async def research_stop(request: Request, project_id: int, run_id: int):
    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        run = db.research_run(run_id)
        if run is None or run["project_id"] != project_id:
            raise HTTPException(status_code=404, detail="Получение не найдено.")
        request.app.state.research.stop(run_id)
        if not request.app.state.research.running(run_id):  # исполнителя нет (перезапуск): состояние – в базе
            db.finish_research_run(run_id, "stopped", "остановлено оператором")
        return redirect(f"/projects/{project_id}/components/research/{run_id}?ok=research_stopping")

    return await run_in_threadpool(apply)


@router.post("/projects/{project_id}/components/research/{run_id}/resume")
async def research_resume(request: Request, project_id: int, run_id: int):
    """«Продолжить» остановленное или прерванное получение по тому же согласию (дата среза и текст – сохранённые);
    строки с неизвестным результатом не отправляются (К11)."""
    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        run = db.research_run(run_id)
        if run is None or run["project_id"] != project_id:
            raise HTTPException(status_code=404, detail="Получение не найдено.")
        task = db.current_task(project_id)
        if task is None or task["id"] != run["task_id"]:
            return redirect(f"/projects/{project_id}/components/research/{run_id}?err=task_gone")
        try:
            db.resume_research_run(run_id)
        except RuntimeError as e:
            return redirect(f"/projects/{project_id}/components/research/{run_id}?err=research_resume&why="
                            + str(e)[:120])
        request.app.state.research.start(run_id)
        return redirect(f"/projects/{project_id}/components/research/{run_id}?ok=research_resumed")

    return await run_in_threadpool(apply)


def requeue_fingerprint(project_id: int, run_id: int) -> str:
    """Что подписывает метка формы «Доисследовать оставшиеся»: проект и получение."""
    return f"requeue:{int(project_id)}:{int(run_id)}"


@router.post("/projects/{project_id}/components/research/{run_id}/requeue")
async def research_requeue(request: Request, project_id: int, run_id: int):
    """«Доисследовать оставшиеся»: новое согласие и получение по тем же дате среза и тексту инструкций – только на не
    получившиеся строки; с неизвестным результатом – по явной отметке (запрос мог быть оплачен). Прежнее получение
    остаётся историей."""
    from app import sca_research_net as net
    form = await request.form(max_fields=6, max_files=0)
    include_unknown = str(form.get("include_unknown") or "") == "1"
    nonce = str(form.get("nonce") or "")
    token = str(form.get("token") or "")

    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        run = db.research_run(run_id)
        if run is None or run["project_id"] != project_id:
            raise HTTPException(status_code=404, detail="Получение не найдено.")
        if run["state"] == "running":
            return redirect(f"/projects/{project_id}/components/research/{run_id}?err=research_running")
        # метка страницы хода: доисследование – только с неё; та же форма повторно – прежнее согласие и получение
        expected = net.preview_token(request.app.state.research_secret, requeue_fingerprint(project_id, run_id),
                                     nonce) if nonce else ""
        if not token or not expected or not hmac.compare_digest(expected, token):
            return redirect(f"/projects/{project_id}/components/research/{run_id}?err=research_changed")
        try:  # отбор строк и запуск – одной транзакцией (ревью Codex, круг 30)
            pair = db.start_followup_research(run_id, include_unknown=include_unknown,
                                              consent_key=f"{token}:{int(include_unknown)}")
        except TaskSuperseded:
            return redirect(f"/projects/{project_id}/components/research/{run_id}?err=task_gone")
        except RuntimeError:
            return redirect(f"/projects/{project_id}/components/research/{run_id}?err=research_running")
        if pair is None:
            return redirect(f"/projects/{project_id}/components/research/{run_id}?err=research_nothing")
        _consent, fresh = pair
        request.app.state.research.start(fresh["id"])
        return redirect(f"/projects/{project_id}/components/research/{fresh['id']}?ok=research_requeued&n={fresh['rows_total']}")

    return await run_in_threadpool(apply)


@router.post("/projects/{project_id}/components/research-provider")
async def research_provider_save(request: Request, project_id: int):
    """Профиль исследования проекта («» – как в настройках приложения): только совместимый включённый профиль."""
    form = await request.form(max_fields=4, max_files=0)
    raw = str(form.get("research_provider_id") or "").strip()

    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        chosen: int | None = None
        if raw:
            profile = db.get_provider(int(raw)) if raw.isdigit() else None
            if profile is None or not research_profile_ok(profile):
                return redirect(f"/projects/{project_id}/components?err=research_profile_unfit")
            chosen = int(profile["id"])
        db.update_project(project_id, research_provider_id=chosen)
        return redirect(f"/projects/{project_id}/components?ok=research_provider_saved#component-research")

    return await run_in_threadpool(apply)


@router.get("/projects/{project_id}/components/task.json")
def task_manifest(request: Request, project_id: int):
    """Манифест действующего задания: что ушло агенту (для проверки и для разбора инцидента)."""
    project_or_404(request, project_id)
    db = db_of(request)
    task = db.current_task(project_id)
    if task is None:
        raise HTTPException(status_code=404, detail=PROBLEMS["task_empty"])
    rows = db.task_rows(task["id"])
    return JSONResponse(research.manifest(task, rows, task["created_at"]))


@router.get("/projects/{project_id}/components/answer.schema.json")
def answer_schema(request: Request, project_id: int):
    """Схема ответа агента: та же, что валидатор проверяет."""
    project_or_404(request, project_id)
    return JSONResponse(schema())


@router.get("/projects/{project_id}/components/task/{task_id}.zip")
async def download_kit(request: Request, project_id: int, task_id: str):
    """Комплект задания для агента: задание, манифест, таблица строк, заготовка, схема и валидатор."""
    project_or_404(request, project_id)
    if not _task_id_ok(task_id):
        raise HTTPException(status_code=404, detail="Задание не найдено.")
    db = db_of(request)
    task = db.task(project_id, task_id)
    if task is None:
        raise HTTPException(status_code=404, detail="Задание не найдено.")
    if task["state"] != "current":
        raise HTTPException(status_code=409, detail=PROBLEMS["task_gone"])
    rows = db.task_rows(task["id"])
    body = await run_in_threadpool(research.kit, task, rows, task["created_at"])
    name = research.ZIP_NAME.format(task_id=task["task_id"])
    return Response(body, media_type="application/zip",
                    headers={"Content-Disposition": f'attachment; filename="{name}"'})


@router.post("/projects/{project_id}/components/answers")
async def import_answers(request: Request, project_id: int):
    """Загрузить ответ агента. Проверяет общий валидатор; негодный ответ не сохраняется ни одной строкой."""
    project = project_or_404(request, project_id)
    db = db_of(request)
    form = await request.form()
    upload = form.get("file")
    if hasattr(upload, "read"):
        raw = await upload.read()
    else:
        raw = str(form.get("text") or "").encode("utf-8")
    task = db.current_task(project_id)
    if task is None:
        if _wants_json(request):
            return JSONResponse({"detail": PROBLEMS["answers_no_task"], "ok": False,
                                 "errors": [{"code": "SCA-T002", "path": "task_id",
                                             "message": PROBLEMS["answers_no_task"]}]}, status_code=409)
        return redirect(f"/projects/{project_id}/components?err=answers_no_task")
    rows = db.task_rows(task["id"])
    report = await run_in_threadpool(research.check_answer, raw, task, rows)
    if not report.ok:
        log.info("component research answer rejected for project %d: %d errors", project_id, len(report.errors))
        if _wants_json(request):
            return JSONResponse(report.as_dict(), status_code=422)
        return list_response(request, project, error_report=report.as_dict(), error="Ответ не принят.",
                             status_code=422)
    results = await run_in_threadpool(research.research_results, report.answer, rows)
    try:
        saved = await run_in_threadpool(db.save_research, project_id, task["id"], results)
    except TaskSuperseded:
        # между проверкой и записью сменилась выгрузка или собрано другое задание: ответ уже не по тому составу
        log.info("component research answer discarded for project %d: task %s is not current",
                 project_id, task["task_id"])
        if _wants_json(request):
            return JSONResponse({"detail": PROBLEMS["task_gone"], "ok": False, "errors": [
                {"code": "SCA-T002", "path": "task_id", "message": PROBLEMS["task_gone"]}]}, status_code=409)
        return list_response(request, project, error=PROBLEMS["task_gone"], status_code=409)
    log.info("component research answer for project %d: %d new revisions, %d unchanged", project_id, saved["saved"],
             saved["unchanged"])
    if _wants_json(request):
        return JSONResponse({"ok": True, "saved": saved["saved"], "unchanged": saved["unchanged"],
                             "answer_sha256": report.answer_sha256, "summary": report.summary,
                             "task_id": task["task_id"]})
    ok = "answers" if saved["saved"] else "answers_same"
    n = saved["saved"] if saved["saved"] else saved["unchanged"]
    return redirect(f"/projects/{project_id}/components?ok={ok}&n={n}")


@router.post("/projects/{project_id}/components/{input_ref}/decision")
async def save_decision(request: Request, project_id: int, input_ref: str):
    """Решение человека по строке. Не меняет факты ответа агента и не пишется по устаревшей странице."""
    project = project_or_404(request, project_id)
    if not INPUT_REF.match(input_ref):
        raise HTTPException(status_code=404, detail="Строка не найдена.")
    db = db_of(request)
    prefixes = settings_of(request).sca_internal_prefixes
    form = await request.form()
    form = {key: str(value) for key, value in form.items()}
    revision = _integer(form.get("revision"), -1)
    # строка может ещё не входить в задание (состав виден до сборки) – тогда берём её из текущей выгрузки
    row = db.task_row(project_id, input_ref) or _live_row(db, project_id, input_ref, prefixes)
    research_row = db.research_row(project_id, input_ref)
    next_url = next_component_url(request, project_id, input_ref, views(db, project_id, prefixes)[0])
    values = research.decision_form(form, revision, input_sig=(row or {}).get("input_sig", ""),
                                    research_sig=(research_row or {}).get("answer_sig", ""),
                                    research_revision=int((research_row or {}).get("revision") or 0))
    error_field, error = research.decision_problem(values)
    if error:
        if _wants_json(request):
            return JSONResponse({"detail": error, "error_field": error_field, "form": values}, status_code=422)
        return detail_response(request, project, input_ref, form=values, error=error, status_code=422)
    if row is None and research_row is None:
        # строки нет ни в действующем, ни в прежнем составе и по ней не было ответа: сохранять нечего
        raise HTTPException(status_code=404, detail="Строка не найдена.")
    stale = _seen_stale(form, row, research_row)
    if stale:
        if _wants_json(request):
            return JSONResponse({"detail": stale, "form": values, "revision": revision}, status_code=409)
        return detail_response(request, project, input_ref, form=values, error=stale, status_code=409)
    # решение помнит, по какой строке и по какому ответу принято: так его можно признать устаревшим
    input_signature = (row or research_row or {}).get("input_sig", "")
    research_signature = (research_row or {}).get("answer_sig", "")
    try:
        saved = await run_in_threadpool(db.save_decision, project_id, input_ref, values["action"], values["rationale"],
                                values["target_version"], values["replacement_name"], values["replacement_version"],
                                values["review_at"], input_signature, research_signature, revision,
                                str(form.get("expected_research_sig") or ""),
                                _integer(form.get("expected_research_revision"), 0),
                                str(form.get("expected_input_sig") or ""))
    except DecisionStale as conflict:
        if _wants_json(request):
            return JSONResponse({"detail": PROBLEMS["decision_stale"], "revision": int(conflict.args[0])},
                                status_code=409)
        return detail_response(request, project, input_ref, form=values, error=PROBLEMS["decision_stale"],
                               status_code=409)
    back = worklists.return_url(request, f"/projects/{project_id}/components") if "back" in request.query_params else ""
    target = (next_url if form.get("after") == "next" else
              f"/projects/{project_id}/components/{quote(input_ref)}?" + query({"ok": "decision", "back": back}))
    applied, apply_error = 0, ""
    if form.get("after") == "apply":  # «Сохранить и применить к находкам»: сохранённая редакция – находкам версии
        applied, apply_error = await run_in_threadpool(_apply_after_save, db, project_id, input_ref,
                                                       int(saved["revision"]), str(form.get("apply_token") or ""))
        target = (f"/projects/{project_id}/components/{quote(input_ref)}?"
                  + query({"ok": "applied", "n": str(applied), "back": back} if not apply_error else
                          {"ok": "decision", "err": apply_error, "back": back}) + "#component-apply")
    # сбой самой записи находкам: ответ называет оба итога сам, без перехода на страницу, которой нужна база
    apply_message = PROBLEMS.get(apply_error, "") if apply_error in APPLY_FAILURES else ""
    if _wants_json(request):
        return JSONResponse({"ok": True, "input_ref": input_ref, "action": values["action"],
                             "revision": saved["revision"], "redirect": target,
                             **({"applied": applied, "apply_error": apply_error, "apply_message": apply_message}
                                if form.get("after") == "apply" else {})})
    if apply_message:
        return HTMLResponse(_apply_failure_page(target, int(saved["revision"]), apply_message))
    return redirect(target)


def _batch_context(request, project, rows, entries, values=None, error=""):
    db = db_of(request)
    form = values or {}
    return {"project": project, "counts": db.count_findings(project["id"]),
            "stats": db.review_stats(project["id"]), "rows": rows, "labels": research.LABELS,
            "snapshots": json.dumps(entries, ensure_ascii=False), "form": form, "error": error,
            "back_url": worklists.return_url(request, f"/projects/{project['id']}/components"),
            # как в карточке компонента: календарь и быстрый срок пересмотра от даты
            # приложения, черновик по исследованию для пустых полей
            "review_clock": datetime.now().astimezone().strftime("%d.%m.%Y, %Z"),
            "review_presets": research.review_presets(date.today()),
            "research_draft": research.batch_decision_draft(rows, date.today()),
            "review_at_text": bool(str(form.get("review_at") or "").strip()) and not research.iso_date(form.get("review_at"))}


def _batch_rows(request, project, refs):
    if not refs or len(refs) > 200 or len(set(refs)) != len(refs):
        raise HTTPException(422, "Выберите от 1 до 200 разных версий на этой странице.")
    rows, _ = views(db_of(request), project["id"], settings_of(request).sca_internal_prefixes)
    lookup = {r["input_ref"]: r for r in rows if r["live"]}
    picked = [lookup[ref] for ref in refs if ref in lookup]
    if len(picked) != len(refs):
        raise HTTPException(409, "Состав изменился. Обновите список и выберите версии снова.")
    if len({worklists.family(r, "components")[0] for r in picked}) != 1:
        raise HTTPException(422, "Для общего решения выберите версии одного компонента и экосистемы.")
    return picked


@router.post("/projects/{project_id}/components/decisions/preview", response_class=HTMLResponse)
async def preview_decisions(request: Request, project_id: int):
    project = project_or_404(request, project_id)
    form = await request.form(max_fields=1000)
    rows = _batch_rows(request, project, [str(x) for x in form.getlist("input_ref")])
    entries = [{"input_ref": r["input_ref"], "expected_input_sig": r["input_sig"],
                "expected_research_sig": r["answer_sig"], "expected_research_revision": r["revision"],
                "revision": (r["decision"] or {}).get("revision", 0)} for r in rows]
    return render(request, "components/batch.html", _batch_context(request, project, rows, entries))


@router.post("/projects/{project_id}/components/decisions/apply", response_class=HTMLResponse)
async def apply_decisions(request: Request, project_id: int):
    project = project_or_404(request, project_id)
    form = {k: str(v) for k, v in (await request.form(max_fields=1000)).items()}
    try:
        raw = json.loads(form.get("snapshots", ""))
        keys = {"input_ref", "expected_input_sig", "expected_research_sig", "expected_research_revision", "revision"}
        if (not isinstance(raw, list) or not 1 <= len(raw) <= 200 or any(
                not isinstance(e, dict) or set(e) != keys or
                any(type(e[k]) is not int or e[k] < 0 for k in ("revision", "expected_research_revision")) or
                any(not isinstance(e[k], str) for k in ("input_ref", "expected_input_sig", "expected_research_sig")) or
                not e["expected_input_sig"] for e in raw)):
            raise ValueError
    except (ValueError, TypeError, RecursionError):
        raise HTTPException(422, "Предпросмотр отсутствует или повреждён. Выберите версии снова.") from None
    rows = _batch_rows(request, project, [e["input_ref"] for e in raw])
    values = research.decision_form(form, 0)
    error = research.check_decision(values)
    if form.get("confirm") != "1":
        error = "Подтвердите применение решения ко всем перечисленным версиям."
    if error:
        return render(request, "components/batch.html", _batch_context(request, project, rows, raw, values, error), 422)
    try:
        await run_in_threadpool(db_of(request).save_decisions, project_id, raw, values)
    except DecisionStale:
        return render(request, "components/batch.html", _batch_context(request, project, rows, raw, values,
                      "Одна из версий изменилась. Ни одно решение не сохранено. Вернитесь в список и повторите выбор."), 409)
    return redirect(worklists.return_url(request, f"/projects/{project_id}/components") + "#component-list")


def _report_rows(db: Database, project: dict, prefixes: Iterable[str] = ()) -> tuple[list[dict], dict | None]:
    """Строки для отчёта: исследованные (неисследованной строке нечего сообщать) и действующее задание."""
    rows, task = views(db, project["id"], prefixes)
    return [item for item in rows if item["researched"]], task


@router.get("/projects/{project_id}/components/report")
async def project_report(request: Request, project_id: int):
    """Отчёт по проекту: публичные факты и решения по исследованным строкам. Никуда не отправляется."""
    project = project_or_404(request, project_id)
    db = db_of(request)
    rows, task = _report_rows(db, project, settings_of(request).sca_internal_prefixes)
    archive = db.identity_archive(project_id)
    document = await run_in_threadpool(research.report, project=project, task=task, rows=rows, archive=archive)
    return _report_response(request, document)


@router.get("/projects/{project_id}/identity-report", response_class=HTMLResponse)
def identity_report_page(request: Request, project_id: int):
    """Отчёт перехода идентичности пакетов (план dev17, шаг 5): только чтение базы – операций Hub, их аренды и
    сверки страница не запускает."""
    from app.package_transition import TABLE_LABELS
    project = project_or_404(request, project_id)
    db = db_of(request)
    return render(request, "projects/identity_report.html", {
        "project": project, "counts": db.count_findings(project_id), "stats": db.review_stats(project_id),
        "report": db.identity_report(project_id), "table_labels": TABLE_LABELS})


@router.get("/projects/{project_id}/components/{input_ref}/report")
async def component_report(request: Request, project_id: int, input_ref: str):
    """Отчёт по одной строке в том же виде, что и отчёт по проекту."""
    project = project_or_404(request, project_id)
    if not INPUT_REF.match(input_ref):
        raise HTTPException(status_code=404, detail="Строка не найдена.")
    db = db_of(request)
    rows, task = _report_rows(db, project, settings_of(request).sca_internal_prefixes)
    picked = [item for item in rows if item["input_ref"] == input_ref]
    archive = db.identity_archive(project_id, [input_ref, *db.moved_from(project_id, input_ref)])
    if not picked and not archive:  # пустой отчёт не выдаётся; факт снятия – не пустой (ревью Codex, круг 2)
        raise HTTPException(status_code=404, detail="По строке нет исследования: отчёт пустым не выдаётся.")
    document = await run_in_threadpool(research.report, project=project, task=task, rows=picked, archive=archive)
    return _report_response(request, document)


@router.get("/projects/{project_id}/components/{input_ref}", response_class=HTMLResponse)
def component_page(request: Request, project_id: int, input_ref: str):
    """Карточка строки: принятые факты, доказательства, охват и решение человека."""
    project = project_or_404(request, project_id)
    if not INPUT_REF.match(input_ref):
        raise HTTPException(status_code=404, detail="Строка не найдена.")
    db = db_of(request)
    # группа перенесена переходом идентичности пакетов и сейчас не живая – прежний адрес ведёт на новую карточку
    # (план dev17, п. 4.6); живую группу с тем же адресом открывает её собственная карточка
    live = {item["input_ref"] for item in _live_rows(db, project_id, settings_of(request).sca_internal_prefixes)}
    target = "" if input_ref in live else db.moved_ref(project_id, input_ref, live)
    if target and target != input_ref:
        return redirect(f"/projects/{project_id}/components/{quote(target, safe=':')}")
    # группа только в архиве и без сохранённого состава задания – карточка для чтения (п. 4.6): решения по ней не
    # принимаются, у прежней строки задания – обычная карточка истории с разделом архива
    archive = []
    if input_ref not in live and input_ref in db.archived_refs(project_id) \
            and db.historical_task_row(project_id, input_ref) is None:
        archive = archive_view(db, project_id, input_ref)
    if not archive:
        try:
            return render(request, "components/detail.html", detail_context(request, project, input_ref))
        except HTTPException as e:
            archive = archive_view(db, project_id, input_ref) if e.status_code == 404 else []
            if not archive:
                raise
    return render(request, "components/archived.html", {
        "project": project, "counts": db.count_findings(project_id), "stats": db.review_stats(project_id),
        "label": archive[0]["old_label"], "archive": archive})


def _serialisable(value: Any) -> bool:
    """Годится ли значение для JSON без преобразований (для понятной ошибки вместо TypeException в ответе)."""
    try:
        canonical(value)
        return True
    except (TypeError, ValueError):
        return False


def _unsupported(value: Any, path: str = "отчёт") -> str:
    """Путь до первого значения, которое нельзя положить в JSON: "" – всё годится."""
    if _serialisable(value):
        return ""
    if isinstance(value, dict):
        for key, item in value.items():
            if not isinstance(key, str):
                return f"{path}: ключ {key!r} не строка"
            found = _unsupported(item, f"{path}.{key}")
            if found:
                return found
    elif isinstance(value, list):
        for index, item in enumerate(value):
            found = _unsupported(item, f"{path}[{index}]")
            if found:
                return found
    return f"{path}: значение типа {type(value).__name__} не годится для JSON"


def _report_response(request: Request, document: dict) -> Response:
    """Формат по ?format= (json по умолчанию): markdown с content_type text/markdown, чтобы браузер показал текст."""
    if request.query_params.get("format", "json") == "md":
        return Response(research.report_text(document).encode("utf-8"), media_type="text/markdown; charset=utf-8")
    try:
        body = canonical(document)
    except (TypeError, ValueError) as exc:
        place = _unsupported(document)
        log.info("отчёт по проекту %s не собран в JSON: %s (%s)", request.url.path, exc, place)
        return JSONResponse({"detail": "отчёт не удалось привести к JSON", "поле": place}, status_code=500)
    return Response(body, media_type="application/json",
                    headers={"Content-Disposition": 'inline; filename="sca-components-report.json"'})

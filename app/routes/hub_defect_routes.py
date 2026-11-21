"""Дефект в Hub из карточки (этап 3, ADR-0120): «Создать дефект в Hub» в карточке SAST («Подтверждаю дефект» –
находка и её группа «та же строка, категория и код» с тем же решением и текстом) и SCA (дефект набора). Цепочка
операций через исполнителя (ADR-0114): заготовка `GET /defects/blank` → предпросмотр в карточке → `POST /defects` →
подтверждение чтением `GET /defects/{id}` (при расхождении – `POST /defects/{id}/link` и чтение снова). Статусы
находок не меняются; отметку «Внесено в Hub» (часть «тело дефекта») ставит подтверждённое чтение (app/hub_defects.py).

  POST /projects/{id}/findings/{finding_id}/hub-defect      – SAST: заготовка (операция defect_blank, при первом
                                                              обращении – и справочник serviceInfo)
  POST /projects/{id}/sca/findings/{finding_id}/hub-defect  – SCA
  POST /projects/{id}/hub/defects/{defect_id}/create        – «Создать» из предпросмотра (приоритет, серьёзность)
  POST /projects/{id}/hub/defects/{defect_id}/verify        – «Сверить» «результат неизвестен»
  POST /projects/{id}/findings/{finding_id}/hub-defect-link – SAST: новая находка группы – «Привязать к дефекту №…»
                                                              (ADR-0121 п. 5, операция defect_link)
  POST /projects/{id}/hub/defects/{defect_id}/recheck       – «Проверить в Hub» у созданного дефекта (ADR-0121 п. 6)
  GET  /projects/{id}/hub/defects/{defect_id}               – состояние для опроса из карточки (JSON)
  GET  /projects/{id}/defects                               – вкладка «Дефекты» проекта

«Занести из Hub» и «Pull из Hub» (ADR-0124) – только чтение `GET /defects/{id}`, вкладка «Дефекты»:

  POST /projects/{id}/defects/import                        – номера или ссылки дефектов Hub: строки чтения
  POST /projects/{id}/hub/defects/{defect_id}/import        – «Занести» из предпросмотра (одна транзакция)
  POST /projects/{id}/hub/defects/{defect_id}/import-cancel – «Отменить» предпросмотр занесения
  POST /projects/{id}/hub/defects/{defect_id}/import-retry  – «Повторить чтение» у не удавшегося или отменённого
  POST /projects/{id}/hub/defects/{defect_id}/sync          – «Pull из Hub» у занесённого дефекта
  POST /projects/{id}/hub/defects/{defect_id}/sync-apply    – «Применить» предпросмотр сверки (только добавление)
  POST /projects/{id}/hub/defects/{defect_id}/sync-cancel   – «Отменить» предпросмотр сверки

«Push в Hub» (ADR-0125) – заголовок и описание занесённого дефекта запросом `PUT /defects/{id}`:

  POST /projects/{id}/hub/defects/{defect_id}/update        – «Подготовить обновление»: чтение для предпросмотра
  POST /projects/{id}/hub/defects/{defect_id}/update-put    – «Push в Hub»: второе чтение, затем PUT и подтверждение
  POST /projects/{id}/hub/defects/{defect_id}/update-cancel – «Отменить» предпросмотр обновления
  POST /projects/{id}/hub/defects/{defect_id}/update-verify – «Сверить» при неизвестном исходе PUT (только чтение)
  POST /projects/{id}/hub/defects/{defect_id}/update-reread – «Повторить чтение» подтверждения
"""

from __future__ import annotations

import dataclasses
import json

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app import defect, defect_check, defect_drafts, defect_where, hub_defects, hub_onboarding, hub_ops, hub_status, hub_sync
from app.db import Database, finding_data_sig, hub_verdict, loads, text_hash
from app.models import Finding
from app.routes.common import db_of, project_or_404, redirect, register_messages, render, settings_of, web_of
from app.routes.feeds import store_of
from app.routes.hub_status_routes import (
    NOT_REVIEWED,
    STALE_REVISION,
    TEXT_CHANGED,
    TEXT_NOT_SHOWN,
    StaleTarget,
    _finding_of,
    _json_error,
    _refused,
    _target,
    hub_target_check,
    send_blocker,
    wants_json,
)

router = APIRouter()

PREVIEW_OPEN = ("Предпросмотр дефекта уже открыт: создайте дефект кнопкой «Создать» или нажмите «Отменить "
                "предпросмотр» и запросите заготовку заново.")
# предпросмотр собран для прежних приложения или адреса Hub (KIMI-12): дефект туда не создаётся, обновление карточки
# предпросмотр не пересобирает – нужна новая заготовка
PREVIEW_TARGET_CHANGED = ("Приложение Hub или адрес Hub изменились после предпросмотра («Параметры проекта» или "
                          "«Настройки»): дефект не создаётся – обновите карточку, нажмите «Отменить предпросмотр» и "
                          "запросите заготовку заново.")

register_messages({
    "hub_defect_cancelled": "Предпросмотр отменён: заготовку дефекта можно запросить заново.",
    "hub_defect_queued": "Поставлено в очередь исполнителю: заготовка дефекта – состояние в блоке «Создать дефект в Hub».",
    "hub_defect_create_queued": "Поставлено в очередь исполнителю: создание дефекта – состояние в блоке «Создать дефект в Hub».",
    "hub_defect_verify_queued": "Сверка поставлена в очередь исполнителю: итог – в блоке «Создать дефект в Hub».",
    "hub_defect_link_queued": "Поставлено в очередь исполнителю: привязка к дефекту – состояние в блоке «Создать дефект в "
                              "Hub».",
    "hub_defect_recheck_queued": "Проверка поставлена в очередь исполнителю: итог – в блоке дефекта и во вкладке "
                                 "«Дефекты».",
    # «Занести из Hub» и «Pull из Hub» (ADR-0124)
    "hub_import_queued": "Поставлено в очередь исполнителю: чтение дефектов из Hub – состояние в строках таблицы.",
    "hub_import_done": "Дефект занесён из Hub: его находки защищены, как у созданного в приложении; номер ID<n> – резерв.",
    "hub_import_cancelled": "Предпросмотр занесения отменён: в Hub ничего не уходило.",
    "hub_import_retry": "Чтение дефекта из Hub поставлено в очередь исполнителю заново.",
    "hub_sync_queued": "Сверка с Hub поставлена в очередь исполнителю: итог – в строке дефекта.",
    "hub_sync_applied": "Сверка применена: находки добавлены в дефект, заголовок и текст – из Hub.",
    "hub_sync_cancelled": "Предпросмотр сверки отменён: дефект в приложении прежний.",
})

# занесение и сверка читают дефект из приложения и адреса Hub строки (KIMI-12): их сменили – отказ до записи
IMPORT_START_TARGET_CHANGED = ("Приложение Hub или адрес Hub изменились, пока собирался запрос (в другой вкладке – "
                               "«Параметры проекта» или «Настройки»): чтение не поставлено – обновите вкладку и повторите.")
IMPORT_TARGET_CHANGED = ("Приложение Hub или адрес Hub изменились после чтения («Параметры проекта» или «Настройки»): "
                         "дефект не заносится – нажмите «Отменить», затем «Синхронизировать» на вкладке «Дефекты» и «Принять состояние Hub».")
IMPORT_RETRY_TARGET_CHANGED = ("Приложение Hub или адрес Hub изменились после первого чтения («Параметры проекта» или "
                               "«Настройки»): повторное чтение не ставится – дефект занесёт «Синхронизировать» на вкладке «Дефекты» и «Принять состояние Hub».")
SYNC_TARGET_CHANGED = ("Приложение Hub или адрес Hub изменились после занесения («Параметры проекта» или «Настройки»): "
                       "сверка с Hub этого дефекта не ставится и не применяется.")

TEXT_SHOWN_HINT = "Карточка не показала текст дефекта (решение не сохранено или не готово): сохраните решение и обновите карточку."
SCA_CHANGED = ("Набор SCA изменился после предпросмотра (текст, исследование или состав): нажмите «Отменить "
               "предпросмотр» и запросите заготовку заново.")


DefectRefused = hub_defects.DefectRefused


# ============================================================================ требования команды к тексту (ADR-0123)


def _finding_ids(db: Database, project_id: int, text: str, c=None) -> set[str]:
    """Номера находок Hub проекта среди чисел, на которые текст ссылается реквизитом или перечнем (п. 3.7); c –
    транзакция постановки, которая повторяет проверку."""
    wanted = defect_check.number_candidates(text)
    if not wanted:
        return set()
    return Database.hub_ids_among_in(c, project_id, wanted) if c is not None else db.hub_ids_among(project_id, wanted)


def sast_text_problems(db: Database, settings, project_id: int, text: str, c=None) -> list[str]:
    """Нарушения требований команды в теле дефекта SAST (ADR-0123 п. 3): стандартная фраза – из настройки названия
    команды (defect.sast_phrase), номера находок – проекта."""
    return defect_check.sast_problems(text, team_phrase=defect.sast_phrase(settings.team_name),
                                      finding_ids=_finding_ids(db, project_id, text, c))


def sca_expect(view: dict, component: str) -> dict:
    """Ожидания проверки текста SCA из представления набора (sca_defect) того же снимка, по которому собран текст:
    строки «Описания», компонент, целевая версия, режим «Исправленной версии нет» (ADR-0123 п. 4)."""
    description = view.get("description") or {}
    return {"expected_hub": list(description.get("hub") or []),
            "expected_research": list(description.get("research") or []),
            "component": str(component or ""), "target": str(view.get("target") or ""),
            "no_fix": bool(view.get("no_fix"))}


def sca_text_problems(db: Database, project_id: int, text: str, expect: dict, c=None) -> list[str]:
    """Нарушения требований команды в тексте дефекта SCA (ADR-0123 п. 4); expect – sca_expect."""
    return defect_check.sca_problems(text, **expect, finding_ids=_finding_ids(db, project_id, text, c))


def text_problems(db: Database, settings, project_id: int, kind: str, text: str, expect: dict | None,
                  c=None) -> list[str]:
    return (sast_text_problems(db, settings, project_id, text, c) if kind == "SAST"
            else sca_text_problems(db, project_id, text, expect or {}, c))


def _text_check(request: Request, db: Database, settings, project_id: int, kind: str, text: str, expect: dict | None,
                at_create: bool = False):
    """Повтор проверки текста внутри транзакции постановки (ADR-0123 п. 5): номера находок и название команды
    (стандартная фраза SAST) читаются на её соединении – название сменили в «Настройках» между проверкой до
    транзакции и постановкой – отказ S2. Действующее название – как у settings_of: сохранённое в базе поверх значения
    из окружения. at_create – отказ «Создать» (defect_check.refusal)."""
    base = web_of(request).base

    def check(c) -> None:
        current = settings
        if kind == "SAST":
            team = base.with_stored(Database.settings_in(c, ("team_name",))).team_name
            current = dataclasses.replace(settings, team_name=team)
        problems = text_problems(db, current, project_id, kind, text, expect, c)
        if problems:
            raise DefectRefused(defect_check.refusal(problems, at_create))
    return check


# ============================================================================ блок карточки и вкладка


def _card_url_of(db: Database, project_id: int, hub_id: str) -> str:
    row = db.get_finding_by_hub_id(project_id, str(hub_id)) if hub_id else None
    return _finding_url(project_id, row)


def _finding_url(project_id: int, row: dict | None) -> str:
    """Адрес карточки находки по строке {id, kind}; нет строки – ""."""
    if row is None:
        return ""
    section = "findings" if row["kind"] == "SAST" else "sca/findings"
    return f"/projects/{project_id}/{section}/{int(row['id'])}"


def _context(db: Database, settings, project: dict, row: dict | None) -> dict:
    pid = int(project["id"])
    view = hub_defects.view(row)
    # признак восстановления закрывает начало новой записи: строку о готовом дефекте показывать надо
    blocker = send_blocker(settings, project) or (hub_sync.resync_blocker(db, pid) if not row or row["state"] == "failed" else "")
    return {"blocker": blocker, "row": row, "view": view,
            "preview": hub_defects.preview(db, row, lambda h: _card_url_of(db, pid, h)) if row else None,
            "poll_url": f"/projects/{pid}/hub/defects/{row['id']}" if row and not view["final"] else ""}


def card_context(request: Request, project: dict, hub_id: str, current_hash: str = "") -> dict:
    """Блок «Создать дефект в Hub» карточки: доступна ли отправка, последняя строка дефекта по этой находке (в том числе
    созданного из карточки соседа по группе), её состояние и предпросмотр. С 0.9.23 (ADR-0121): дефект, к которому
    привязана находка (bound, bound_label), текст подтверждения снятия отметки (unenter), пометка «решение изменено
    после создания дефекта» (decision_changed; current_hash – отпечаток текста по сохранённому решению, как у отметки
    «Внесено в Hub») и для новой находки группы – «Привязать к дефекту» (link)."""
    db = db_of(request)
    db.hub_expire_leases()
    pid = int(project["id"])
    settings = settings_of(request)
    row = db.hub_defect_for(pid, [str(hub_id)])
    if row is not None:
        row = hub_defects.sync(db, row, update_preparer(request))
    context = _context(db, settings, project, row)
    bound = db.hub_defect_bound(pid, str(hub_id))
    from app import defect_links
    context.update(bound=bound, bound_label=hub_defects.bound_label(bound) if bound else "",
                   bound_summary=defect_links.summary(bound, pid) if bound else None,
                   unenter=hub_defects.bound_text(bound, hub_defects.UNENTER_QUESTION) if bound else "",
                   decision_changed=decision_changed(db, pid, str(hub_id), bound, current_hash), link=None)
    if bound is None and not context["blocker"] and (row is None or row["state"] == "failed"):
        context["link"] = link_offer(db, settings, pid, str(hub_id), project.get("hub_app_id"))
        found = db.get_finding_by_hub_id(pid, str(hub_id))
        review = db.get_review(pid, str(hub_id)) or {}
        if (found is not None and found["kind"] == "SAST" and not found.get("missing") and review.get("reviewed")
                and hub_verdict(review.get("decision") or "", review.get("final_verdict") or "") == "true_positive"):
            from urllib.parse import urlencode
            context["add_url"] = f"/projects/{pid}/hub/add-to-defect?" + urlencode({"hub_id": str(hub_id)})
    return context


def decision_changed(db: Database, project_id: int, hub_id: str, bound: dict | None, current_hash: str) -> bool:
    """Решение изменено после создания дефекта (ADR-0121 п. 2): редакция решения новее редакции этой находки в строке
    дефекта, и текст по сохранённому решению (current_hash) другой, чем у цели: повторное сохранение того же и отметка
    «Проверено» (редакция растёт, текст тот же) пометку не ставят."""
    if bound is None or not current_hash:
        # у занесённого из Hub дефекта цели без отпечатка текста: текст в Hub – прежний, его обновляет ADR-0125
        return False
    target = next((t for t in loads(bound.get("targets_json"), []) if str(t.get("hub_id") or "") == hub_id), None)
    review = db.get_review(project_id, hub_id)
    if target is None or not review:
        return False
    expected = str(target.get("decision_hash", target.get("entered_hash")) or "")
    return (bool(expected) and int(review.get("revision") or 0) > int(target.get("revision") or 0)
            and current_hash != expected)


DEFECT_PAGE_SIZES = (25, 50, 100, 200)  # как у таблицы находок (worklists.SIZES), по умолчанию 200


@router.get("/projects/{project_id}/defects")
def defects_page(request: Request, project_id: int, page: int = 1, q: str = "", sort: str = "", kind: str = "",
                 state: str = "", origin: str = "", page_size: int = 200):
    """Вкладка «Дефекты»: дефекты, созданные из карточек запросом, их состояние, находки, ссылка на дефект в Hub; с
    0.9.23.dev3 – и занесённые из Hub (ADR-0124): предпросмотр занесения и сверки; с 0.10.0.dev13 дефекты Hub заносит
    синхронизация («Синхронизировать», «Принять состояние Hub»), формы номеров на вкладке нет."""
    project = project_or_404(request, project_id)
    db = db_of(request)
    settings = settings_of(request)
    db.hub_expire_leases()
    from urllib.parse import urlencode
    sort = sort if sort in Database.HUB_DEFECT_ORDERS else ""
    size = page_size if page_size in DEFECT_PAGE_SIZES else 200
    # закрытые операции доводятся до отбора: иначе фильтр по состоянию видел бы прежнее (ревью 31.10)
    preparer = update_preparer(request)
    for row in db.hub_defects_to_sync(project_id, hub_defects.OPEN_STATES):
        hub_defects.sync(db, row, preparer)
    facets = db.hub_defect_facets(project_id)
    kind = kind if kind in facets["kind"] else ""
    state = state if state in hub_defects.STATE_LABELS else ""
    origin = origin if origin in ("app", "import") else ""
    rows = db.hub_defects_total(project_id, q, kind=kind, state=state, origin=origin)  # строки таблицы – для страниц

    # «Всего» – дефекты, а не строки: семья из нескольких строк – один дефект, как в Hub (бэклог 106).
    # Неудавшиеся попытки в таблице остаются (с них повторяют), но в «Всего» не считаются: число на вкладке их тоже не считает
    total = db.hub_defect_families(project_id, q, kind=kind, state=state, origin=origin, live=not state)
    attempts = db.hub_defects_total(project_id, q, kind=kind, state="failed", origin=origin) if state == "" else 0
    last = max(1, (rows + size - 1) // size)
    page = min(max(1, page), last)
    base = f"/projects/{project_id}/defects?"

    def keep(**values) -> dict:
        """Параметры адреса вкладки: страница, поиск, порядок, отборы и размер страницы; пустые не пишутся."""
        params = {"page": page, "q": q, "sort": sort, "kind": kind, "state": state, "origin": origin,
                  "page_size": size, **values}
        return {k: v for k, v in params.items()
                if v not in ("", None) and not (k == "page" and v == 1) and not (k == "page_size" and v == 200)}

    def chips(key: str, label: str, values: list[tuple[str, str]]) -> dict:
        # число у фишки – с учётом остальных отборов и поиска; значения самих фишек – по всем дефектам проекта.
        # Считаются дефекты (семьи строк), вместе с неудавшимися попытками: они есть в таблице под этим отбором
        current = {"kind": kind, "state": state, "origin": origin}[key]
        others = {"kind": kind, "state": state, "origin": origin}
        return {"key": key, "label": label, "chips": [
            {"label": text, "href": base + urlencode(keep(page=1, **{key: value})), "active": value == current,
             "count": db.hub_defect_families(project_id, q, **{**others, key: value}) if value else None}
            for value, text in values]}

    filter_groups = [
        chips("kind", "Вид", [("", "все")] + [(k, k) for k in sorted(facets["kind"]) if k]),
        chips("state", "Состояние", [("", "все")] + [(k, hub_defects.STATE_LABELS.get(k, k))
                                                      for k in sorted(facets["state"],
                                                                      key=lambda k: hub_defects.STATE_LABELS.get(k, k))]),
        chips("origin", "Происхождение", [("", "все"), ("app", "создан в приложении"), ("import", "занесён из Hub")]),
    ]
    active_filters = sum(1 for v in (kind, state, origin) if v)
    pagination = {"page": page, "last": last, "total": total, "attempts": attempts,
                  "attempts_url": base + urlencode(keep(page=1, state="failed")), "query": q, "sort": sort, "size": size,
                  "sizes": DEFECT_PAGE_SIZES, "hidden": [(k, v) for k, v in keep(page=1).items() if k != "page_size"],
                  "previous": base + urlencode(keep(page=page - 1)),
                  "next": base + urlencode(keep(page=page + 1)),
                  "sort_url": {key: base + urlencode(keep(page=1, sort=f"{key}_{'asc' if sort == key + '_desc' else 'desc'}"))
                               for key in ("number", "kind")},
                  "reset": base + urlencode(keep(page=1, kind="", state="", origin="")),
                  # пустой отбор: кнопка снимает и отборы, и поиск (ревью dev22)
                  "reset_all": base + urlencode(keep(page=1, q="", kind="", state="", origin=""))}
    items = []
    rows = db.hub_defects(project_id, limit=size, offset=(page - 1) * size, query=q, order=sort, kind=kind,
                          state=state, origin=origin)
    # адреса карточек якорей и целей всей страницы – одним запросом, а не по запросу на цель (бэклог 123)
    refs = db.finding_refs(project_id, [h for row in rows for h in (
        str(row.get("anchor_hub_id") or ""), *(str(t.get("hub_id") or "") for t in loads(row.get("targets_json"), [])))])

    def card_url(hub_id: str) -> str:
        return _finding_url(project_id, refs.get(hub_id)) if hub_id else ""
    for row in rows:
        targets = loads(row.get("targets_json"), [])
        retry = retry_context(db, project_id, row)
        items.append({"row": row, "view": hub_defects.view(row), "note": "",  # итог «Проверить в Hub» не выводится (dev33)
                      "retry": retry,
                      "card_url": f"/projects/{project_id}/defects/{row['id']}"
                          + ("?" + urlencode(keep()) if keep() else ""),
                      # строка привязки – история дефекта: действия у владельца (ADR-0136)
                      "owner_url": (f"/projects/{project_id}/defects/{row['draft_owner_id']}"
                                    if row.get("draft_owner_id") and int(row["draft_owner_id"]) != int(row["id"]) else ""),
                      "label": ("заменена" if retry and retry.get("superseded")
                                else hub_defects.STATE_LABELS.get(row["state"], row["state"])),
                      "anchor_url": card_url(str(row.get("anchor_hub_id") or "")),
                      "targets": [{"hub_id": str(t.get("hub_id") or ""),
                                   "url": card_url(str(t.get("hub_id") or ""))} for t in targets],
                      "hub_update": update_context(db, row, not send_blocker(settings, project)
                          and _same_hub(row, settings.hub_url, project.get("hub_app_id")),
                          bool(loads(row.get("sync_json"), {}).get("read"))),
                      "imported": import_context(db, settings, project, row)})
    return render(request, "projects/defects.html", {
        "project": project, "items": items, "labels": hub_defects.STATE_LABELS, "pagination": pagination,
        "filter_groups": filter_groups, "active_filters": active_filters,
        "dropped_total": len(db.dropped_findings(project_id)),
        "sync_runs": db._all("SELECT id,state,created_at FROM hub_defect_sync_runs WHERE project_id=? ORDER BY id DESC", (project_id,)),
        "resync_note": hub_sync.resync_blocker(db, project_id),
        "hub_step": hub_onboarding.state(db, project, settings.hub_url, light=True),  # напоминание (0.10.0.dev13)
        "counts": db.count_findings(project_id), "review_stats": db.review_stats(project_id)})


# ============================================================================ «Занести из Hub» и «Pull из Hub» (ADR-0124)


def import_form_problems(db: Database, settings, project_id: int, kind: str, text: str) -> list[str]:
    """Проверка формы ADR-0123 выделенного текста команды – справочно (занесение текст в Hub не отправляет): SAST –
    полная (sast_problems); SCA – только то, что не требует данных набора (разделы, ничего до «Описания», «Объяснение»
    не пусто, адреса «Источников», номера AST, служебные строки прежнего формата): строки уязвимостей и строку обновления
    сверять не с чем – снимка набора у занесённого дефекта нет."""
    if not str(text or "").strip():
        return []
    if kind == "SAST":
        return sast_text_problems(db, settings, project_id, text)
    if kind == "SCA":
        problems = defect_check.sca_problems(text, expected_hub=[], expected_research=[], component="", target="",
                                             no_fix=False, finding_ids=_finding_ids(db, project_id, text))
        return [p for p in problems if p.split(":", 1)[0] in ("A1", "A4", "A8") or "внутренний номер уязвимости" in p]
    return []


def _with_urls(db: Database, project_id: int, entries: list[dict]) -> list[dict]:
    return [{**e, "url": _card_url_of(db, project_id, str(e.get("hub_id") or ""))} for e in entries or []]


def import_context(db: Database, settings, project: dict, row: dict) -> dict | None:
    """Строка, занесённая из Hub, для вкладки «Дефекты»: предпросмотр занесения (import_preview – снимок, показанный
    отпечаток shown, операция чтения op, проверка формы и занятость номера ID<n> другим – справочно; ключи
    собственных находок – own_number_keys – не в счёт) и предпросмотр сверки
    (sync_json у done); у остальных строк – None. «Повторить чтение» и «Pull из Hub» – только когда чтение можно
    поставить: нет блокировки отправки (send_blocker) и строка того же Hub и приложения, что сейчас у проекта
    (_same_hub); «Повторить чтение» – ещё и когда у того же Hub, приложения и номера нет другой живой строки
    (hub_defect_live, своя не в счёт) – иначе маршрут всё равно откажет."""
    # контекст сверки – у занесённых строк и у строк-владельцев дефектов из приложения (dev34: Pull и у них)
    if row.get("origin") != "import" and not hub_defects.pull_allowed(row):
        return None
    project_id = int(project["id"])
    can_read = (not send_blocker(settings, project)
                and _same_hub(row, settings.hub_url, project.get("hub_app_id")))
    retry = can_read and row["state"] in ("failed", "cancelled")
    if retry and db.hub_defect_live(str(row.get("hub_url") or ""), row.get("app_id"),
                                    str(row.get("hub_defect_id") or ""), exclude_id=int(row["id"])) is not None:
        retry = False  # тот же дефект уже занесён или читается другой строкой: повтор откажет «уже есть в приложении»
    out: dict = {"preview": None, "sync": None, "sync_error": "", "sync_matches": "", "retry": retry,
                 "can_sync": can_read and row["state"] == "done" and not row.get("sync_op_id")}
    if row["state"] == "import_preview":
        snap = loads(row.get("import_json"), {}) or {}
        out["preview"] = {**snap, "shown": text_hash(str(row.get("import_json") or "")), "op": row.get("read_op_id"),
                          "accepted": _with_urls(db, project_id, snap.get("accepted")),
                          "conflicts": _with_urls(db, project_id, snap.get("conflicts")),
                          "form_problems": import_form_problems(db, settings, project_id, str(snap.get("kind") or ""),
                                                                str(snap.get("command_text") or "")),
                          "number_taken": hub_defects.number_note(
                              db, row, snap.get("number") if isinstance(snap.get("number"), int) else None,
                              hub_defects.own_number_keys(db, row, snap.get("accepted"), snap.get("absent")))}
    if row["state"] == "done" and not row.get("sync_op_id"):
        state = loads(row.get("sync_json"), {}) or {}
        if isinstance(state, dict) and state.get("read"):
            read = state["read"]
            out["sync"] = {**state, "shown": text_hash(str(row.get("sync_json") or "")),
                           "added": _with_urls(db, project_id, state.get("added")),
                           "unobserved": _with_urls(db, project_id, state.get("unobserved")),
                           "unobserved_diff": _with_urls(db, project_id, state.get("unobserved_diff", state.get("unobserved"))),
                           "form_problems": import_form_problems(db, settings, project_id, str(row.get("kind") or ""),
                                                                 str(read.get("command_text") or ""))}
        elif isinstance(state, dict) and state.get("matches"):
            out["sync_matches"] = state.get("read_at") or ""
            out["sync_extra"] = int(state.get("extra_lines") or 0)
        elif isinstance(state, dict) and state.get("error"):
            out["sync_error"] = str(state["error"])
    # ключ – не «update»: в шаблоне imp.update – метод словаря
    out["hub_update"] = update_context(db, row, can_read, bool(out["sync"]))
    # идёт «Push в Hub» или запись принята без подтверждения (unconfirmed, ADR-0125 п. 2): «Pull из Hub» отказала бы
    if out["hub_update"]["busy"] or hub_defects.update_unconfirmed(row):
        out["can_sync"] = False
    return out


def update_context(db: Database, row: dict, can_read: bool, sync_preview: bool) -> dict:
    """«Push в Hub» (ADR-0125) для строки вкладки: фаза, поколение и показанный отпечаток (shown – text_hash
    update_json: формы предпросмотра сверяют их в транзакции), кнопки по таблице п. 3 – «Подготовить обновление» (не
    идёт, предпросмотр не открыт, сверка не идёт и не ждёт «Применить»), «Сверить» (неизвестный исход), «Повторить
    чтение» (запись принята, подтверждение не прочитано) – и предпросмотр: новый заголовок и текст, предупреждения,
    находки. Кнопки – только когда чтение можно поставить (can_read, как у «Pull из Hub»)."""
    state = hub_defects.update_state(row)
    phase = str(state.get("phase") or "")
    busy = hub_defects.update_busy(row)
    idle = row["state"] == "done" and not row.get("update_op_id")
    # у строки привязки своего Push и Pull нет: действия – у владельца (ADR-0136), старая форма получит отказ сервера
    can_read = can_read and int(row.get("draft_owner_id") or row["id"]) == int(row["id"])
    out = {"phase": phase, "busy": busy, "generation": int(state.get("generation") or 0),
           "shown": text_hash(str(row.get("update_json") or "")), "preview": None,
           # конфликт состава – обновление откажет «неразрешённые конфликты»: кнопки нет ни во вкладке, ни в карточке
           "can_prepare": (can_read and idle and not busy and phase != "preview" and not row.get("sync_op_id")
                           and not sync_preview and bool(row.get("hub_defect_id"))
                           and not loads(row.get("conflicts_json"), [])
                           # место целей в наборах ждёт выбора после слияния пакетов (план dev17, п. 4.5): тот же
                           # предикат, что у сервера перед шагами обновления; без базы (разбор строки в тестах
                           # таблицы действий) – ожидания нет
                           and not (db is not None
                                    and db.on_connection(lambda c: hub_defects.pending_place_problem(c, row)))),
           "can_verify": can_read and idle and phase == "unknown",
           "can_reread": can_read and idle and phase in ("confirming", "unconfirmed")}
    if idle and phase == "preview":
        new, first = state.get("new") or {}, state.get("first") or {}
        out["preview"] = {"summary": str(new.get("summary") or ""), "command_text": str(new.get("command_text") or ""),
                          "old_summary": str(first.get("summary") or ""), "note": str(state.get("note") or ""),
                          "warnings": [str(w) for w in state.get("warnings") or []],
                          "field_diff": state.get("field_diff", []), "candidate": state.get("candidate"),
                          # предпросмотр без признака (до правки подписи) – по сохранённому кандидату PUT
                          "kept_description": bool(state.get("kept_description", str(
                              (state.get("candidate") or {}).get("description") or "")
                              == str((state.get("first") or {}).get("description") or ""))),
                          "block_mode": str(state.get("block_mode") or ""),  # что будет с блоком Hub (dev30)
                          "block_version": state.get("block_version") or {},  # замена версии в блоке (dev7)
                          "where_added": bool(state.get("where_added")),  # дописан раздел «Где исправлять» (dev7)
                          "block_built": bool(state.get("block_built")),  # блок собран приложением (ADR-0139)
                          "blank_fetched": bool(state.get("blank_fetched")),  # заготовка запрошена шагом blank (dev31)
                          "references": state.get("references", {}), "hub_url": row["hub_url"], "app_id": row["app_id"],
                          "targets": _with_urls(db, int(row["project_id"]),
                                                [{"hub_id": str(t.get("hub_id") or "")} for t in new.get("targets") or []]),
                          "can_put": can_read}
    return out


def _pull_row(request: Request, project_id: int, defect_id: int) -> tuple[dict, dict]:
    """Строка для «Pull из Hub», «Применить» и «Отменить» сверки: занесённая из Hub или созданная приложением
    строка-владелец «создан» с номером в Hub (dev34)."""
    project, row = _project_row(request, project_id, defect_id)
    if not hub_defects.pull_allowed(row):
        raise LookupError(hub_defects.PULL_ONLY)
    return project, row


def _import_row(request: Request, project_id: int, defect_id: int) -> tuple[dict, dict]:
    project, row = _project_row(request, project_id, defect_id)
    if row.get("origin") != "import":
        raise LookupError("Дефект, занесённый из Hub, не найден.")
    return project, row


async def _card_refused(request: Request, project_id: int, detail: str, status: int = 409):
    """Отказ действия, начатого в карточке дефекта: карточка с сообщением и прежними кнопками, а не страница ошибки
    с одной кнопкой «К проектам»."""
    from app.routes import defect_card_routes
    defect_id = int(request.path_params.get("defect_id") or 0)

    def page():
        context = defect_card_routes.page_context(request, project_id, defect_id)
        context["error"] = detail
        return render(request, "projects/defect_card.html", context, status_code=status)

    try:
        return await run_in_threadpool(page)
    except (HTTPException, ValueError, LookupError):  # карточку не собрать (строку удалили и т. п.) – прежний отказ
        return await _refused(request, False, detail, status)


async def _tab_action(request: Request, project_id: int, apply, ok: str, message: str):
    """Действие вкладки «Дефекты» (занесение и сверка): без скрипта – возврат во вкладку с сообщением, со скриптом – JSON
    с перезагрузкой; отказы – как у остальных действий дефекта."""
    as_json = wants_json(request)
    # предпросмотр занесения и его кнопки есть только во вкладке – отказы занесения остаются прежними (ревью 31.10)
    to_card = (not as_json and bool(request.path_params.get("defect_id"))
               and not request.url.path.endswith(("/import", "/import-cancel", "/import-retry")))
    try:
        result = await run_in_threadpool(apply)
    except HTTPException as e:
        return await _refused(request, as_json, str(e.detail), e.status_code)
    except hub_status.StatusRefused as e:
        if to_card:
            return await _card_refused(request, project_id, str(e), 400)  # и из вкладки: карточка объясняет
        return await _refused(request, as_json, str(e), 400)
    except LookupError as e:
        return await _refused(request, as_json, str(e), 404)
    except ValueError as e:  # состояние или состав изменились, очередь отказала, дефект уже есть
        if to_card:
            # отказ действия над дефектом – его карточка с сообщением, не страница ошибки
            return await _card_refused(request, project_id, str(e))
        return await _refused(request, as_json, str(e), 409)
    if not as_json:
        form = await request.form()
        if form.get("back") == "defect-card" and isinstance(result, dict) and result.get("id"):
            owner_id = result.get("draft_owner_id") or result["id"]
            return redirect(_card_url(project_id, owner_id, form, ok=ok))
        return redirect(f"/projects/{project_id}/defects?ok={ok}")
    return {"ok": True, "done": True, "reload": True, "message": message}


@router.post("/projects/{project_id}/defects/import")
async def import_start(request: Request, project_id: int):
    """«Занести из Hub» (ADR-0124 п. 3): до 20 номеров или ссылок дефектов Hub – на каждый строка «чтение из Hub» и
    операция `GET /defects/{id}` одной транзакцией (нет другой живой строки этого Hub, приложения и номера; приложение
    и адрес Hub – те же, что прочитаны здесь)."""
    form = await request.form(max_fields=5, max_files=0)
    text = str(form.get("numbers") or "")

    def apply():
        project = project_or_404(request, project_id)
        settings, db = settings_of(request), db_of(request)
        blocker = send_blocker(settings, project)
        if blocker:
            raise DefectRefused(blocker)
        try:
            numbers = hub_defects.import_numbers(text)
        except ValueError as e:
            raise DefectRefused(str(e)) from None
        app_id = int(project["hub_app_id"])
        return db.hub_defect_import_start(
            project_id, numbers=numbers, hub_url=settings.hub_url, app_id=app_id,
            item_of=hub_defects.import_item, link_of=lambda n: hub_defects.defect_link(settings.hub_url, app_id, n),
            check=hub_target_check(request, project_id, settings.hub_url, app_id, IMPORT_START_TARGET_CHANGED),
            label_of=hub_defects.STATE_LABELS.get)

    return await _tab_action(request, project_id, apply, "hub_import_queued",
                             "Поставлено в очередь исполнителю: чтение дефектов из Hub.")


@router.post("/projects/{project_id}/hub/defects/{defect_id}/import")
async def import_accept(request: Request, project_id: int, defect_id: int):
    """«Занести» (ADR-0124 п. 5): поля op – операция чтения и shown – отпечаток снимка, которые показал предпросмотр."""
    form = await request.form(max_fields=5, max_files=0)
    shown_op, shown = str(form.get("op") or ""), str(form.get("shown") or "")

    def apply():
        project, row = _import_row(request, project_id, defect_id)
        if not shown_op.isdigit():
            raise DefectRefused("Предпросмотр не передал операцию чтения: обновите страницу.")
        if not _same_hub(row, settings_of(request).hub_url, project.get("hub_app_id")):
            raise StaleTarget(IMPORT_TARGET_CHANGED)
        return hub_defects.accept_import(db_of(request), row, op_id=int(shown_op), shown=shown,
                                         target_check=hub_target_check(request, project_id, str(row.get("hub_url") or ""),
                                                                       row.get("app_id"), IMPORT_TARGET_CHANGED))

    return await _tab_action(request, project_id, apply, "hub_import_done", "Дефект занесён из Hub.")


@router.post("/projects/{project_id}/hub/defects/{defect_id}/import-cancel")
async def import_cancel(request: Request, project_id: int, defect_id: int):
    """«Отменить» предпросмотр занесения: строка отменена, в Hub ничего не уходило."""
    def apply():
        _, row = _import_row(request, project_id, defect_id)
        return hub_defects.cancel_import(db_of(request), row)

    return await _tab_action(request, project_id, apply, "hub_import_cancelled", "Предпросмотр занесения отменён.")


@router.post("/projects/{project_id}/hub/defects/{defect_id}/import-retry")
async def import_retry(request: Request, project_id: int, defect_id: int):
    """«Повторить чтение» у не удавшегося или отменённого занесения (ADR-0124 п. 3)."""
    def apply():
        project, row = _import_row(request, project_id, defect_id)
        blocker = send_blocker(settings_of(request), project)
        if blocker:
            raise DefectRefused(blocker)
        if not _same_hub(row, settings_of(request).hub_url, project.get("hub_app_id")):
            raise StaleTarget(IMPORT_RETRY_TARGET_CHANGED)
        return hub_defects.retry_import(db_of(request), row, hub_target_check(
            request, project_id, str(row.get("hub_url") or ""), row.get("app_id"), IMPORT_RETRY_TARGET_CHANGED))

    return await _tab_action(request, project_id, apply, "hub_import_retry", "Чтение поставлено в очередь заново.")


@router.post("/projects/{project_id}/hub/defects/{defect_id}/sync")
async def import_sync(request: Request, project_id: int, defect_id: int):
    """«Pull из Hub» у занесённого или созданного приложением дефекта (ADR-0124 п. 6, dev34): чтение
    `GET /defects/{id}`, состояние строки не меняется."""
    def apply():
        project, row = _pull_row(request, project_id, defect_id)
        blocker = send_blocker(settings_of(request), project)
        if blocker:
            raise DefectRefused(blocker)
        if not _same_hub(row, settings_of(request).hub_url, project.get("hub_app_id")):
            raise StaleTarget(SYNC_TARGET_CHANGED)
        return hub_defects.start_import_sync(db_of(request), row, hub_target_check(
            request, project_id, str(row.get("hub_url") or ""), row.get("app_id"), SYNC_TARGET_CHANGED))

    return await _tab_action(request, project_id, apply, "hub_sync_queued", "Сверка с Hub поставлена в очередь.")


@router.post("/projects/{project_id}/hub/defects/{defect_id}/sync-apply")
async def import_sync_apply(request: Request, project_id: int, defect_id: int):
    """«Применить» предпросмотр сверки (ADR-0124 п. 6): поле shown – отпечаток показанного снимка сверки."""
    form = await request.form(max_fields=5, max_files=0)
    shown = str(form.get("shown") or "")

    def apply():
        project, row = _pull_row(request, project_id, defect_id)
        if not _same_hub(row, settings_of(request).hub_url, project.get("hub_app_id")):
            raise StaleTarget(SYNC_TARGET_CHANGED)
        return hub_defects.apply_import_sync(db_of(request), row, shown=shown, target_check=hub_target_check(
            request, project_id, str(row.get("hub_url") or ""), row.get("app_id"), SYNC_TARGET_CHANGED))

    return await _tab_action(request, project_id, apply, "hub_sync_applied", "Сверка применена.")


@router.post("/projects/{project_id}/hub/defects/{defect_id}/sync-cancel")
async def import_sync_cancel(request: Request, project_id: int, defect_id: int):
    """«Отменить» предпросмотр сверки: поле shown – отпечаток показанного снимка сверки; тот же – sync_json очищается,
    другой (новая сверка из другой вкладки) – отказ, новый предпросмотр цел."""
    form = await request.form(max_fields=5, max_files=0)
    shown = str(form.get("shown") or "")

    def apply():
        _, row = _pull_row(request, project_id, defect_id)
        return hub_defects.cancel_import_sync(db_of(request), row, shown=shown)

    return await _tab_action(request, project_id, apply, "hub_sync_cancelled", "Предпросмотр сверки отменён.")


# ============================================================================ «Push в Hub» (ADR-0125)

UPDATE_TARGET_CHANGED = ("Приложение Hub или адрес Hub изменились после занесения («Параметры проекта» или «Настройки»): "
                         "обновление этого дефекта не ставится.")
SCA_UPDATE_CHANGED = ("Набор SCA изменился после подготовки обновления (текст, исследование или состав): снова "
                      "нажмите «Push в Hub».")

register_messages({
    "hub_update_queued": "Поставлено в очередь исполнителю: чтение дефекта для предпросмотра обновления – состояние в "
                         "строке дефекта.",
    "hub_update_put_queued": "Поставлено в очередь исполнителю: дефект перечитывается и записывается в Hub – состояние в "
                             "строке дефекта.",
    "hub_update_cancelled": "Подготовка обновления отменена: в Hub ничего не уходило.",
    "hub_update_verify_queued": "Сверка поставлена в очередь исполнителю: итог – в строке дефекта.",
    "hub_update_reread_queued": "Подтверждающее чтение поставлено в очередь исполнителю: итог – в строке дефекта.",
})


def _update_target(request: Request, project_id: int, row: dict):
    """Приложение и адрес Hub строки – те же, что у проекта сейчас (KIMI-12): сверка в транзакции каждой постановки."""
    return hub_target_check(request, project_id, str(row.get("hub_url") or ""), row.get("app_id"),
                            UPDATE_TARGET_CHANGED)


def _update_sast(request: Request, db: Database, settings, project_id: int, row: dict, targets: list[dict],
                 same_text: bool = True) -> dict:
    """Подготовка дефекта SAST (п. 2): все цели – «Подтверждаю дефект» с «Проверено», карточка готова (как
    _prepare_sast: решение действует по текущему коду, обоснование, рекомендация, название команды, происхождение
    комментария); при явной сборке текст решения у всех один. Заголовок – sast_title опорной находки с номером строки."""
    from app.routes import findings as card
    refusals: list[str] = []
    warnings: list[str] = []
    ready: list[tuple] = []
    hub_targets: list[dict] = []  # цели с решением «из Hub»: текст – черновик как есть
    old_hash = {str(t.get("hub_id") or ""): str(t.get("decision_hash", t.get("entered_hash")) or "") for t in targets}
    number = row.get("number") if isinstance(row.get("number"), int) and not isinstance(row.get("number"), bool) else None
    defect_lines: dict[str, set[int] | None] = {}  # срезы всех находок дефекта – один обход на подготовку
    for target in targets:
        hub_id = str(target.get("hub_id") or "")
        source = db.case_input(project_id, hub_id)
        if source is None or source.get("missing"):
            refusals.append(f"находки {hub_id} нет в текущей выгрузке")
            continue
        sig = db.finding_sig(project_id, hub_id)  # до чтения данных: обновление выгрузки поймает транзакция
        f = Finding.from_dict(source["data"])
        review = db.get_review(project_id, hub_id)
        if (not review or not review.get("decision")
                or hub_verdict(review["decision"], review.get("final_verdict") or "") != "true_positive"):
            refusals.append(f"у находки {hub_id} нет решения «Подтверждаю дефект»")
            continue
        if str(review.get("decision") or "") == defect_drafts.HUB_DECISION:
            # решение «из Hub»: без «Проверено» и сверки кода – «Push в Hub» отправляет текст
            # черновика как есть; «Текст из решений» по нему не собрать – обоснования и рекомендации оператора нет
            if same_text:
                refusals.append(f"у находки {hub_id} решение принято из Hub, обоснования и рекомендации оператора нет – "
                                "сохраните решение в карточке или отправьте текст как есть («Push в Hub»)")
                continue
            hub_targets.append({"hub_id": hub_id, "issue_id": hub_status.issue_id(hub_id),
                                "issue_type": hub_status.issue_type(f.kind), "revision": int(review.get("revision") or 0),
                                "decision_hash": old_hash.get(hub_id, ""), "entered_hash": "", "entered_parts": "",
                                "sig": sig})
            continue
        if not review.get("reviewed"):
            refusals.append(f"у находки {hub_id} нет отметки «Проверено»")
            continue
        case = db.get_case(project_id, hub_id)
        assessment = card.sast_assess(request, project_id, review, case, source)
        if assessment["state"] != "ok":
            refusals.append(f"находка {hub_id}: "
                            + card.sast_state_hint(assessment["state"], review, card.SAST_DEFECT_NOT_READY))
            continue
        if "all" not in defect_lines:
            defect_lines["all"] = card.defect_shown_lines(request, project_id, f, case, also=[str(t.get("hub_id") or "") for t in targets])
        view = card.sast_defect(db, settings, store_of(request), project_id, f, review, None, number=number,
                                shown=defect_lines["all"], state="ok", source=source)
        if not view["ready"]:
            refusals.append(f"находка {hub_id}: {view['hint']}")
            continue
        origin = card.comment_origin(db, case, review, review.get("final_comment") or "", project_id=project_id,
                                     hub_id=hub_id)
        if origin and origin != "true_positive":
            refusals.append(f"находка {hub_id}: обоснование – текст модели к другому вердикту (поправьте комментарий в "
                            "карточке и сохраните решение)")
            continue
        warnings += [f"находка {hub_id}: {w}" for w in view.get("warnings") or []]
        ready.append((f, review, view, sig))
    if refusals:
        return {"refusals": refusals}
    if same_text and len({text_hash(view["body"]) for _, _, view, _ in ready}) > 1:
        return {"refusals": ["у находок дефекта разный текст решения (обоснование или рекомендация): "
                             + ", ".join(f.hub_id for f, _, _, _ in ready) + " – сделайте решения одинаковыми"]}
    new_targets = [_defect_target(f, review, view["body"], defect_parts(settings, review), sig) for f, review, view, sig in ready]
    if ready:
        anchor = next((x for x in ready if x[0].hub_id == str(row.get("anchor_hub_id") or "")), ready[0])
        summary, body, anchor_id = anchor[2]["title"], anchor[2]["body"], anchor[0].hub_id
    else:  # все решения – «из Hub»: заголовок и текст – черновик владельца (prepare_update)
        summary, body, anchor_id = "", "", str(hub_targets[0]["hub_id"])
    new_targets += hub_targets
    return {"kind": "SAST", "summary": summary, "command_text": body, "targets": new_targets,
            "number_keys": [defect.defect_key_sast(str(t["hub_id"])) for t in new_targets], "warnings": warnings,
            "anchor": anchor_id, "fingerprint": "", "expect": None, "require_reviewed": True}


def _update_sca(request: Request, db: Database, project_id: int, row: dict, targets: list[dict],
                strict: bool = True) -> dict:
    """Подготовка дефекта SCA (п. 2): цели – находки одной версии одного компонента («разные версии» – отказ, бэклог
    49), набор готов (sca_defect: view["ready"]) и его участники равны целям; заголовок и подпись – с номером строки."""
    from app.routes import sca as sca_card
    hub_ids = [str(t.get("hub_id") or "") for t in targets]
    found = db.import_findings(project_id, hub_ids)
    gone = [h for h in hub_ids if h not in found or found[h]["missing"]]
    if gone:
        return {"refusals": ["находок " + ", ".join(gone) + " нет в текущей выгрузке"]}
    versions = list(dict.fromkeys(f"{found[h]['component']} {found[h]['version']}".strip() for h in hub_ids))
    if len(versions) > 1:
        return {"refusals": ["находки разных версий: " + ", ".join(versions) + " – решение по такому дефекту – за "
                             "владельцем после синхронизации (бэклог 49)"]}
    anchor = str(row.get("anchor_hub_id") or "") if str(row.get("anchor_hub_id") or "") in hub_ids else hub_ids[0]
    snap = db.sca_snapshot(project_id, anchor)
    if snap.row is None:
        return {"refusals": [f"находки {anchor} нет в текущей выгрузке"]}
    f = Finding.from_dict(snap.row["data"])
    review = snap.review
    if not review or not (review.get("decision") or review.get("final_verdict")):
        return {"refusals": [f"у находки {anchor} нет решения «Обновить»"]}
    number = row.get("number") if isinstance(row.get("number"), int) and not isinstance(row.get("number"), bool) else None
    view = sca_card.sca_defect(snap, store_of(request), project_id, f, review, number=number)
    warnings: list[str] = []
    # решение «из Hub»: заготовка набора по нему не собирается – «Push в Hub» отправляет
    # текст черновика как есть, «Текст из решений» отказывает
    # (ревью dev23, круг 1: decision 'hub' пишет и Pull статусов – с итогом «ложное срабатывание» или «риск принят»)
    from_hub = (str(review.get("decision") or "") == defect_drafts.HUB_DECISION
                and hub_verdict(review.get("decision") or "", review.get("final_verdict") or "") == "true_positive")
    if from_hub and strict:
        return {"refusals": [f"у находки {anchor} решение принято из Hub, обоснования оператора нет – сохраните "
                             "решение в карточке или отправьте текст как есть («Push в Hub»)"]}
    # «Push в Hub» отправляет текст дефекта, который сейчас в приложении, как есть (если
    # ничего не меняли – никаких разниц): заготовка набора, не доведённая до шаблона (Объяснение не сохранено,
    # остаточный риск не отмечен), и комментарии находок к другому выводу – предупреждение; отказ – только при
    # «Тексте из решений» (strict) и если набор не собран вовсе
    lenient = not strict and (view.get("state") == "text" or from_hub)
    if not view["ready"] and not lenient:
        return {"refusals": [f"дефект набора не готов: {view['hint'] or 'набор SCA не готов'}"]}
    if not view["ready"]:
        warnings.append(f"заготовка набора не готова, уйдёт текст дефекта как есть: {view['hint']}")
    if view.get("comment_stale") and strict:
        return {"refusals": ["в наборе находки, где комментарий – текст агента к другому выводу: "
                             + ", ".join(str(x) for x in view["comment_stale"][:10])
                             + " (поправьте комментарий в их карточках и сохраните)"]}
    members = [str(x) for x in view.get("members") or []]
    by_row = not members or (from_hub and not view["ready"])
    if by_row:
        members = hub_ids  # заготовка не собрана: состав – цели строки, как в Hub; решение каждой проверяется ниже
    extra, lacking = sorted(set(hub_ids) - set(members)), sorted(set(members) - set(hub_ids))
    if extra or lacking:
        parts = ([f"в дефекте, но не в наборе: {', '.join(extra)}"] if extra else []) + (
            [f"в наборе, но не в дефекте: {', '.join(lacking)}"] if lacking else [])
        return {"refusals": ["состав набора не равен находкам дефекта (" + "; ".join(parts) + ")"]}
    new_targets = []
    # заготовка не готова – отметки находок не переписываются отпечатком неготовой заготовки: прежний отпечаток цели
    old_hash = {str(t.get("hub_id") or ""): str(t.get("decision_hash", t.get("entered_hash")) or "") for t in targets}
    for hub_id in members:
        member_review = review if hub_id == f.hub_id else db.get_review(project_id, hub_id)
        member_sig = db.finding_sig(project_id, hub_id)
        member = _finding_of(db, project_id, hub_id)
        if member is None or not member_review:
            return {"refusals": [f"находка {hub_id} набора изменилась: обновите вкладку"]}
        if by_row and hub_verdict(member_review.get("decision") or "", member_review.get("final_verdict") or "") != "true_positive":
            # состав взят из строки, а не из готового набора: отложенное, ложное срабатывание и принятый риск в дефект
            # не уходят (ревью dev23, круг 1)
            return {"refusals": [f"у находки {hub_id} решение не «Обновить»"]}
        new_targets.append({"hub_id": hub_id, "issue_id": hub_status.issue_id(hub_id),
                            "issue_type": hub_status.issue_type(member.kind),
                            "revision": int(member_review.get("revision") or 0),
                            "decision_hash": str(view["text_sig"]) if view["ready"] else old_hash.get(hub_id, ""),
                            "entered_hash": "", "entered_parts": "", "sig": member_sig})
    return {"kind": "SCA", "summary": view["title"], "command_text": view["body"], "targets": new_targets,
            "number_keys": [sca_card.set_key(f, view["set_no"])],
            "warnings": warnings + list(view.get("warnings") or []),
            "anchor": f.hub_id, "fingerprint": snap.fingerprint, "expect": sca_expect(view, f.package_display_name),
            "require_reviewed": False}


def prepare_update(request: Request, row: dict, *, from_decisions: bool = False) -> dict:
    """Подготовка «Push в Hub» из черновика (ADR-0126, dev1): {refusals, warnings, kind, summary,
    command_text, targets (с новыми редакциями и отпечатками, как при создании – ADR-0120), number_keys, fingerprint,
    anchor, tx_check}. Текст берётся у владельца; from_decisions=True явно собирает его генератором.
    Нарушение формы ADR-0123 даёт отказ. tx_check(c) –
    повтор в транзакции постановки `PUT`: приложение и адрес Hub, редакции решений и данные целей (у SAST – и
    «Проверено»), отпечаток набора SCA, ADR-0123 по тому же тексту (название команды и номера находок – на соединении
    транзакции)."""
    db, settings = db_of(request), settings_of(request)
    project_id = int(row["project_id"])
    targets = loads(row.get("targets_json"), [])
    if not targets:
        return {"refusals": ["в дефекте нет находок – обновлять нечего"]}
    kind = str(row.get("kind") or "")
    if kind == "SAST":
        prep = _update_sast(request, db, settings, project_id, row, targets, same_text=from_decisions)
    elif kind == "SCA":
        prep = _update_sca(request, db, project_id, row, targets, strict=from_decisions)
    else:
        return {"refusals": [f"вид дефекта «{kind or '–'}» не поддерживается"]}
    if prep.get("refusals"):
        return prep
    owner = db.on_connection(lambda c: defect_drafts.owner_in(c, row))
    members = db.on_connection(lambda c: defect_drafts.members_in(c, row))
    draft_state = {k: owner[k] for k in ("draft_revision", "draft_fields_json", "draft_fields_basis_json", "conflicts_json")}
    if not from_decisions:
        prep.update(summary=owner["draft_summary"], command_text=owner["draft_command_text"])
        number, why = hub_defects.title_number(prep["summary"])
        if not str(prep["summary"] or "").strip():
            return {**prep, "refusals": ["Заголовок черновика пуст: заполните его."]}
        # номера в заголовке нет – его вернёт подготовка Push (ADR-0138)
        if why != hub_defects.NO_NUMBER and (why or number != row.get("number")):
            return {**prep, "refusals": ["Заголовок черновика должен содержать ровно один ID, равный резерву дефекта."]}
    prep.update(**draft_state, members_snapshot=members)
    # собрать текст из решений («Текст из решений») – строго по требованиям команды; «Push в Hub» отправляет текст,
    # который сейчас в приложении, как есть, формат – предупреждение (всё взято из Hub,
    # изменённое сохраняется обратно в Hub)
    strict = from_decisions
    if not str(prep.get("command_text") or "").strip():  # пустое описание запись в Hub не подтвердит – отказ сразу
        return {**prep, "refusals": ["текст дефекта пуст – заполните его или соберите «Текст из решений»"]}
    problems = text_problems(db, settings, project_id, kind, prep["command_text"], prep.get("expect"))
    listed = ("; ".join(problems[:3]) + (f"; и ещё {len(problems) - 3}" if len(problems) > 3 else "")) if problems else ""
    if problems and strict:
        return {**prep, "refusals": ["текст не по требованиям команды (ADR-0123): " + listed]}
    if problems:
        prep["warnings"] = [*(prep.get("warnings") or []), "текст не по шаблону команды (ADR-0123), отправится как есть: "
                            + listed]
    hub_target = _update_target(request, project_id, row)
    fresh_targets = _fresh_check(project_id, prep["targets"], prep["require_reviewed"])
    text_ok = (_text_check(request, db, settings, project_id, kind, prep["command_text"], prep.get("expect"))
               if strict else (lambda c: None))
    anchor, fingerprint = str(prep.get("anchor") or ""), str(prep.get("fingerprint") or "")

    def tx_check(c) -> None:
        current = defect_drafts.owner_in(c, row)
        if (any(current[k] != v for k, v in draft_state.items())
                or defect_drafts.members_in(c, row) != members):
            raise StaleTarget("Черновик, конфликты или состав дефекта изменились: обновите страницу.")
        from app import defect_fields, defect_references
        defect_references.check_selected(c, current, defect_fields.basis_of(current)["references"])
        hub_target(c)
        fresh_targets(c)
        if kind == "SCA" and db._sca_defect_fingerprint(c, project_id, anchor) != fingerprint:
            raise StaleTarget(SCA_UPDATE_CHANGED)
        text_ok(c)

    return {**prep, "tx_check": tx_check}


def update_preparer(request: Request):
    """Подготовка обновления для последствий ответа исполнителя и показа вкладки (hub_defects.after_op, sync)."""
    return lambda row: prepare_update(request, row)


def _update_row(request: Request, project_id: int, defect_id: int) -> tuple[dict, dict]:
    project, row = _project_row(request, project_id, defect_id)
    blocker = send_blocker(settings_of(request), project)
    if blocker:
        raise DefectRefused(blocker)
    if not _same_hub(row, settings_of(request).hub_url, project.get("hub_app_id")):
        raise StaleTarget(UPDATE_TARGET_CHANGED)
    return project, row


@router.post("/projects/{project_id}/hub/defects/{defect_id}/update")
async def update_start(request: Request, project_id: int, defect_id: int):
    """«Подготовить обновление» (ADR-0125 п. 3, шаг 1): чтение `GET /defects/{id}` для предпросмотра; только у дефекта,
    занесённого из Hub (дефект приложения – отказ «обновляются только занесённые»)."""
    def apply():
        _, row = _update_row(request, project_id, defect_id)
        return hub_defects.start_update(db_of(request), row, _update_target(request, project_id, row))

    return await _tab_action(request, project_id, apply, "hub_update_queued",
                             "Поставлено в очередь исполнителю: чтение дефекта для обновления.")


@router.post("/projects/{project_id}/hub/defects/{defect_id}/update-put")
async def update_put(request: Request, project_id: int, defect_id: int):
    """«Push в Hub» (п. 3, шаг 2): поля generation и shown – поколение и отпечаток показанного предпросмотра;
    подготовка по текущим решениям сверяется с предпросмотром, затем второе чтение (запись `PUT` ставит ответ на него)."""
    form = await request.form(max_fields=5, max_files=0)
    generation, shown = str(form.get("generation") or ""), str(form.get("shown") or "")

    def apply():
        _, row = _update_row(request, project_id, defect_id)
        blocker = hub_sync.resync_blocker(db_of(request), project_id)
        if blocker:
            raise DefectRefused(blocker)
        return hub_defects.request_put(db_of(request), row, generation=generation, shown=shown,
                                       prep=prepare_update(request, row),
                                       target_check=_update_target(request, project_id, row))

    return await _tab_action(request, project_id, apply, "hub_update_put_queued",
                             "Поставлено в очередь исполнителю: проверка дефекта и запись в Hub.")


@router.post("/projects/{project_id}/hub/defects/{defect_id}/update-cancel")
async def update_cancel(request: Request, project_id: int, defect_id: int):
    """«Отменить» предпросмотр обновления (п. 3, шаг 1а): поля generation и shown; в Hub ничего не уходило."""
    form = await request.form(max_fields=5, max_files=0)
    generation, shown = str(form.get("generation") or ""), str(form.get("shown") or "")

    def apply():
        _, row = _project_row(request, project_id, defect_id)
        return hub_defects.cancel_update(db_of(request), row, generation=generation, shown=shown)

    return await _tab_action(request, project_id, apply, "hub_update_cancelled", "Подготовка обновления отменена.")


@router.post("/projects/{project_id}/hub/defects/{defect_id}/update-verify")
async def update_verify(request: Request, project_id: int, defect_id: int):
    """«Сверить» при неизвестном исходе `PUT` (п. 3, шаг 5): чтение `GET /defects/{id}`; повторно запрос не уходит."""
    def apply():
        _, row = _update_row(request, project_id, defect_id)
        return hub_defects.verify_update(db_of(request), row, _update_target(request, project_id, row))

    return await _tab_action(request, project_id, apply, "hub_update_verify_queued", "Сверка поставлена в очередь.")


@router.post("/projects/{project_id}/hub/defects/{defect_id}/update-reread")
async def update_reread(request: Request, project_id: int, defect_id: int):
    """«Повторить чтение» (п. 3, шаг 4): подтверждающее чтение снова – запись принята Hub, подтверждения ещё нет."""
    def apply():
        _, row = _update_row(request, project_id, defect_id)
        return hub_defects.reread_update(db_of(request), row, _update_target(request, project_id, row))

    return await _tab_action(request, project_id, apply, "hub_update_reread_queued",
                             "Подтверждающее чтение поставлено в очередь.")


# ============================================================================ состав дефекта


def _defect_target(f, review, text, parts="", sig=""):
    target = _target(f, review, text, parts, sig)
    return {**target, "decision_hash": target["entered_hash"], "entered_hash": ""}


def defect_parts(settings, review: dict | None) -> str:
    """Части отметки «Внесено в Hub» у дефекта, созданного запросом: как у карточки (entered_parts – обоснование,
    рекомендация, команда, версия) с признаком defect (часть «тело дефекта»)."""
    from app.routes import findings as card
    parts = json.loads(card.entered_parts(settings, review))
    parts["defect"] = 1
    return json.dumps(parts, sort_keys=True)


def _busy_reason(db: Database, project_id: int, hub_id: str, own_row_id: int | None = None) -> str:
    """Находка уже занята другим дефектом из карточки: почему; «» – свободна."""
    other = db.hub_defect_for(project_id, [hub_id])
    if other is None or (own_row_id is not None and int(other["id"]) == own_row_id):
        return ""
    if other["state"] == "done":
        return f"дефект уже создан в Hub (№{other['hub_defect_id']})"
    if other["state"] in hub_defects.BUSY_STATES:
        return f"уже в другом дефекте из карточки ({hub_defects.STATE_LABELS.get(other['state'], other['state'])})"
    return ""


def sast_defect_targets(db: Database, settings, project_id: int, f: Finding, review: dict, sig: str, body: str
                        ) -> tuple[list[dict], list[dict]]:
    """Цели дефекта SAST: эта находка и находки её группы «та же строка, категория и код» с тем же сохранённым
    решением «Подтверждаю дефект» и тем же итоговым текстом (обоснование и пункты рекомендации – как сравнивает выдача
    дефекта). Второе значение – соседи, которые не вошли, с причиной (предпросмотр показывает окончательный состав)."""
    from app.routes import findings as card
    mine = defect.sast_effective("true_positive", review.get("final_comment") or "", str(review.get("final_fix") or ""))
    targets = [_defect_target(f, review, body, defect_parts(settings, review), sig)]
    left_out: list[dict] = []
    mine_cmp = card.own_code_cmp(db, project_id, f.hub_id)
    for row in card.same_code(db.group_rows(project_id, card.group_key(f), f.hub_id), mine_cmp):
        hub_id = str(row["hub_id"])
        if row.get("missing"):
            left_out.append({"hub_id": hub_id, "why": "нет в текущей выгрузке"})
            continue
        other_review = db.get_review(project_id, hub_id)
        if not other_review or other_review.get("decision") not in ("agree", "disagree"):
            left_out.append({"hub_id": hub_id, "why": "решения нет"})
            continue
        if hub_verdict(other_review["decision"], other_review.get("final_verdict") or "") != "true_positive":
            left_out.append({"hub_id": hub_id, "why": "решение – не «Подтверждаю дефект»"})
            continue
        if not other_review.get("reviewed"):
            left_out.append({"hub_id": hub_id, "why": "нет отметки «Проверено»"})
            continue
        # то же правило, что у опорной находки и Push: иначе дефект создастся, а Push откажет из-за этого соседа
        origin = card.comment_origin(db, db.get_case(project_id, hub_id), other_review, other_review.get("final_comment") or "",
                                     project_id=project_id, hub_id=hub_id)
        if origin and origin != "true_positive":
            left_out.append({"hub_id": hub_id, "why": "обоснование – текст модели к другому вердикту"})
            continue
        theirs = defect.sast_effective("true_positive", other_review.get("final_comment") or "",
                                       str(other_review.get("final_fix") or ""))
        if theirs != mine:
            left_out.append({"hub_id": hub_id, "why": "другой текст решения (обоснование или рекомендация)"})
            continue
        if other_review.get("entered_hub") and other_review.get("entered_text_hash") == text_hash(body):
            left_out.append({"hub_id": hub_id, "why": "дефект с этим текстом уже внесён в Hub (отметка стоит)"})
            continue
        busy = _busy_reason(db, project_id, hub_id)
        if busy:
            left_out.append({"hub_id": hub_id, "why": busy})
            continue
        other_sig = db.finding_sig(project_id, hub_id)  # до чтения данных: обновление выгрузки поймает транзакция
        other = _finding_of(db, project_id, hub_id)
        if other is None:
            left_out.append({"hub_id": hub_id, "why": "нет в текущей выгрузке"})
            continue
        targets.append(_defect_target(other, other_review, body, defect_parts(settings, other_review), other_sig))
    return targets, left_out


def retry_context(db: Database, project_id: int, row: dict) -> dict | None:
    """Попытка создания, которую Hub не принял: если тот же номер потом создан другой
    строкой – «заменена» со ссылкой на неё; иначе – куда пойти, чтобы подготовить дефект заново (у «Дефекта из
    выбранных» – та же форма с тем же составом, у карточки – карточка опорной находки). Запросов к Hub нет."""
    if row.get("state") != "failed" or row.get("origin") == "import":
        return None
    if row.get("number"):
        # «заменена» – только созданием, подтверждённым чтением (номер Hub есть), в том же Hub и приложении Hub
        # (ревью dev12): незавершённая попытка или дефект другого приложения – не замена
        newer = next((r for r in db._all(
            "SELECT id, state, hub_defect_id, hub_url, app_id FROM hub_defects WHERE project_id=? AND number=?"
            " AND kind=? AND id>? AND state IN ('done','mismatch') AND hub_defect_id != ''"
            " AND id = COALESCE(draft_owner_id, id) ORDER BY id",
            (project_id, row["number"], row["kind"], int(row["id"])))
            if _same_hub(r, row.get("hub_url") or "", row.get("app_id"))), None)
        if newer:
            number = str(newer.get("hub_defect_id") or "")
            return {"superseded": {"id": newer["id"], "hub_defect_id": number,
                                   "card_url": f"/projects/{project_id}/defects/{newer['id']}"}}
    from app.routes import defect_selected
    targets = [str(t.get("hub_id") or "") for t in loads(row.get("targets_json"), []) if t.get("hub_id")]
    if defect_selected.attempt(row) and targets:
        from urllib.parse import urlencode
        return {"retry_url": f"/projects/{project_id}/hub/defect-selected?"
                             + urlencode([("hub_id", h) for h in targets])}
    anchor = str(row.get("anchor_hub_id") or "") or (targets[0] if targets else "")
    url = _card_url_of(db, project_id, anchor) if anchor else ""
    return {"retry_url": url} if url else None


def _same_hub(row: dict, hub_url: str, app_id) -> bool:
    """Строка дефекта – того же Hub и того же приложения Hub (как область ключа операции и IN_HUB_SQL): дефект,
    созданный в другом приложении (номер приложения проекта сменили), в запрете второго дефекта не учитывается и к
    привязке не предлагается (номер ID<n> группы он держит по-прежнему – бэклог 42)."""
    return (str(row.get("hub_url") or "") == hub_ops.hub_base(hub_url)
            and int(row.get("app_id") or 0) == int(app_id or 0))


def shown_targets(targets: list[dict]) -> str:
    """Состав привязки так, как его видит оператор и передаёт форма «Привязать» (поле targets): номера находок через
    запятую по порядку."""
    return ",".join(sorted(str(t["hub_id"]) for t in targets))


def link_parent(db: Database, settings, project_id: int, f: Finding, review: dict, app_id) -> dict | None:
    """Готовый дефект группы для находки (ADR-0121 п. 5): у соседа «та же строка, категория и код» – строка дефекта
    SAST того же Hub и приложения Hub (app_id – номер приложения проекта) с известным номером в Hub в состоянии
    «создан» или «привязка неполная», и её текст команды (command_text – тело, ушедшее в Hub) тот же, что тело дефекта
    этой находки по её сохранённому решению (тело от находки не зависит). Текущее решение соседа не сравнивается: его
    могли сменить после создания дефекта. Несколько – самая ранняя строка; нет – None. Дефект, занесённый из Hub
    (origin 'import', ADR-0124 п. 7), не выбирается никогда, и после «Push в Hub» тоже (ADR-0125 п. 4, вариант
    A): находки к нему привязывают в Hub и добавляют «Pull из Hub»."""
    from app.routes import findings as card
    mine = text_hash(defect_where.body_of(card.sast_entered_text(db, settings, project_id, f, review)))
    found = None
    for row in card.same_code(db.group_rows(project_id, card.group_key(f), f.hub_id),
                              card.own_code_cmp(db, project_id, f.hub_id)):
        if row.get("missing"):
            continue
        bound = db.hub_defect_bound(project_id, str(row["hub_id"]))
        if (bound is None or bound.get("origin") == "import" or db.imported_defect(project_id, bound)
                or hub_defects.update_unconfirmed(bound) or hub_defects.update_busy(bound)
                or bound["state"] not in ("done", "mismatch")
                or bound["kind"] != "SAST"
                or not bound.get("hub_defect_id") or not _same_hub(bound, settings.hub_url, app_id)
                or text_hash(defect_where.body_of(bound.get("command_text"))) != mine):
            continue
        if found is None or int(bound["id"]) < int(found["id"]):
            found = bound
    return found


def group_defect_check(db: Database, project_id: int, hub_id: str, body: str, exclude=(), *, hub_url: str, app_id,
                       in_preview: bool = False, selected_owner: int | None = None):
    """Проверка в транзакции заготовки и «Создать» дефекта SAST (ADR-0121 п. 5): соседи находки hub_id по подгруппе
    «та же строка, категория и код» читаются на соединении транзакции (Database._group_neighbor_ids); сосед, кроме
    exclude (свои цели), привязан к строке дефекта того же Hub и приложения Hub (hub_url, app_id – куда уйдёт этот
    дефект) с тем же текстом команды, что тело этого дефекта, – второй дефект по группе не ставится: «создан» и
    «привязка неполная» – «привяжите к дефекту №…», «результат неизвестен» – «сверьте дефект №… в карточке …» (без
    номера в Hub – и ручной путь, если сверка дефект не нашла: бэклог 41), «создаётся», «проверка привязки», «привязка
    находок» – «дождитесь итога дефекта №…». in_preview – проверка из «Создать» (у находки открыт предпросмотр, кнопки
    «Привязать» нет): отказ советует «Отменить предпросмотр». Готовый дефект мог быть удалён в Hub – в отказе назван
    ручной путь (бэклог 39). Дефект, занесённый из Hub (ADR-0124 п. 7), текстом не сравнивается: достаточно членства в
    группе – «привяжите находку к нему в Hub и нажмите «Pull из Hub» во вкладке «Дефекты» – находка добавится»; при
    открытом предпросмотре (in_preview) – сначала «Отменить предпросмотр»: предпросмотр держит находку целью, и сверка её
    не добавит. Так и после «Push в Hub» (ADR-0125 п. 4, вариант A); пока по дефекту идёт обновление или запись
    ждёт подтверждения, отказ называет сначала его итог: «Pull из Hub» в это время сама отказывает. selected_owner –
    оператор сам выбрал дефект («Добавить в дефект», ADR-0136): сосед в этой семье не мешает и текст с ним не
    сравнивается, сосед в другом дефекте – отказ с названием этого дефекта."""
    expected = text_hash(defect_where.body_of(body))  # раздел «Где исправлять» – не текст решения
    skip = {str(h or "") for h in exclude}

    def check(c) -> None:
        for neighbor in db._group_neighbor_ids(c, project_id, hub_id):
            if neighbor in skip:
                continue
            row = Database.hub_defect_bound_in(c, project_id, neighbor)
            if row is None or row["kind"] != "SAST" or not _same_hub(row, hub_url, app_id):
                continue
            if selected_owner is not None:
                if int(row.get("draft_owner_id") or row["id"]) != int(selected_owner):
                    raise DefectRefused(f"Находка {neighbor} той же строки и категории уже в дефекте "
                                        f"{hub_defects.bound_label(row) or 'из карточки'}: добавьте находку в него.")
                continue
            if (row.get("origin") != "import" and not Database.imported_defect_in(c, project_id, row)
                    and (hub_defects.update_unconfirmed(row) or hub_defects.update_busy(row))):
                raise DefectRefused("В группе есть дефект: обновление не подтверждено или ещё выполняется. "
                                    "Сначала завершите его; второй дефект по группе не создаётся.")
            if row.get("origin") == "import" or Database.imported_defect_in(c, project_id, row):
                name = hub_defects.bound_label(row) or "из Hub"
                # «Pull из Hub» сама отказывает, пока идёт обновление или запись ждёт подтверждения (ADR-0125 п. 2)
                if hub_defects.update_unconfirmed(row):
                    raise DefectRefused(f"В группе есть дефект {name} (занесён из Hub), запись в Hub по нему принята, "
                                        "но не подтверждена: во вкладке «Дефекты» сначала «Повторить чтение» или "
                                        "заново «Push в Hub»; второй дефект по группе не создаётся.")
                if (not row.get("update_op_id")
                        and hub_defects.update_state(row).get("phase") == "unknown"):  # ждать нечего – нужна сверка
                    raise DefectRefused(f"В группе есть дефект {name} (занесён из Hub), результат «Push в Hub» по "
                                        "нему неизвестен: во вкладке «Дефекты» нажмите «Сверить» в его строке; второй "
                                        "дефект по группе не создаётся.")
                if hub_defects.update_busy(row):
                    raise DefectRefused(f"В группе есть дефект {name} (занесён из Hub), по нему идёт «Push в Hub»: "
                                        "дождитесь его итога во вкладке «Дефекты»; второй дефект по группе не "
                                        "создаётся.")
                first = "нажмите «Отменить предпросмотр», затем привяжите" if in_preview else "привяжите"
                raise DefectRefused(f"В группе есть дефект {name} (занесён из Hub): "
                                    f"{first} находку к нему в Hub и нажмите «Pull из Hub» во вкладке «Дефекты» – "
                                    "находка добавится; второй дефект по группе не создаётся.")
            if text_hash(defect_where.body_of(row.get("command_text"))) != expected:
                continue
            name = hub_defects.bound_label(row) or "из карточки"
            if row["state"] in ("done", "mismatch") and row.get("hub_defect_id"):
                how = ("нажмите «Отменить предпросмотр», затем «Привязать к дефекту»" if in_preview
                       else "кнопка «Привязать к дефекту»")
                raise DefectRefused(f"В группе уже есть дефект {name} с тем же текстом решения: привяжите к дефекту "
                                    f"{name} ({how}) – второй дефект не создаётся. Если дефект {name} удалён в Hub "
                                    "(проверьте его в Hub или «Синхронизировать» во вкладке «Дефекты»), привязка не пройдёт: создайте дефект вручную по "
                                    "панели «Дефект для Hub» и нажмите «Отметить: дефект создан в Hub».")
            if row["state"] in ("unknown", "unconfirmed"):
                # без номера в Hub «Сверить» может не найти дефект – строка остаётся «результат неизвестен», кнопки
                # привязки не будет (бэклог 41): называется ручной путь, который есть в карточке
                manual = ("" if row.get("hub_defect_id") else
                          " Если «Сверить» дефект в Hub не нашла, исход остаётся неизвестным и привязки в приложении "
                          "не будет: проверьте дефект в Hub сами, привяжите к нему находку там или создайте дефект "
                          "вручную по панели «Дефект для Hub» и нажмите «Отметить: дефект создан в Hub» – отметка этот "
                          "запрет не снимает.")
                raise DefectRefused(f"В группе есть дефект {name} с тем же текстом решения и неясным исходом: сверьте "
                                    f"дефект {name} в карточке находки {row.get('anchor_hub_id')} («Сверить»), затем "
                                    "привяжите к нему находку – второй дефект не создаётся." + manual)
            raise DefectRefused(f"В группе уже идёт дефект {name} с тем же текстом решения (состояние «"
                                f"{hub_defects.STATE_LABELS.get(row['state'], row['state'])}»): дождитесь итога "
                                f"дефекта {name} и привяжите к нему находку – второй дефект не создаётся.")
    return check


def link_group_check(db: Database, project_id: int, hub_id: str, parent_id: int):
    """Проверка в транзакции привязки (ADR-0121 п. 5): строка готового дефекта – дефект группы находки hub_id, то есть
    среди её целей есть сосед по подгруппе «та же строка, категория и код», прочитанный на соединении транзакции."""
    def check(c) -> None:
        row = c.execute("SELECT targets_json FROM hub_defects WHERE id = ?", (int(parent_id),)).fetchone()
        own = {str(t.get("hub_id") or "") for t in loads(row["targets_json"] if row else "", [])}
        if not own & set(db._group_neighbor_ids(c, project_id, hub_id)):
            raise StaleTarget("Состав группы изменился, пока карточка была открыта: готовый дефект уже не дефект группы "
                              "этой находки – обновите карточку.")
    return check


def _in_defect(db: Database, project_id: int, hub_id: str, defect_id: str) -> bool:
    """Находка уже привязана к дефекту defect_id (номер в Hub) – в «не войдут» привязки она не называется."""
    bound = db.hub_defect_bound(project_id, str(hub_id))
    return bound is not None and str(bound.get("hub_defect_id") or "") == defect_id


def link_offer(db: Database, settings, project_id: int, hub_id: str, app_id) -> dict | None:
    """«Привязать к дефекту №…» для новой находки группы (ADR-0121 п. 5): находка SAST не привязана, сохранено
    «Подтверждаю дефект» с «Проверено», у соседа того же кода – созданный дефект того же Hub и приложения Hub (app_id)
    с тем же текстом решения (link_parent). Кто войдёт – эта находка и непривязанные соседи с тем же текстом,
    «Проверено», без занятости (как у заготовки, sast_defect_targets); кто нет – с причиной; уже привязанные к этому
    дефекту не перечисляются; shown – состав для формы (shown_targets: маршрут сверяет его с собранным заново). Нет –
    None."""
    from app.routes import findings as card
    found = db.get_finding_by_hub_id(project_id, hub_id)
    if found is None or found["kind"] != "SAST" or found.get("missing"):
        return None
    review = db.get_review(project_id, hub_id)
    if (not review or not review.get("reviewed")
            or hub_verdict(review.get("decision") or "", review.get("final_verdict") or "") != "true_positive"):
        return None
    f = _finding_of(db, project_id, hub_id)
    parent = link_parent(db, settings, project_id, f, review, app_id) if f is not None else None
    if parent is None:
        return None
    try:
        targets, left_out = sast_defect_targets(db, settings, project_id, f, review,
                                                db.finding_sig(project_id, hub_id),
                                                card.sast_entered_text(db, settings, project_id, f, review))
    except hub_status.StatusRefused:
        # нечисловой номер Hub у находки или соседа: при показе карточки предложения нет (не 500); отправка такой
        # группы получает отказ 400, как и до изменения (круг 4 ревью 0.9.23.dev1)
        return None
    defect_id = str(parent["hub_defect_id"])
    return {"parent": parent, "label": hub_defects.bound_label(parent), "shown": shown_targets(targets),
            "targets": [{"hub_id": str(t["hub_id"]), "url": _card_url_of(db, project_id, str(t["hub_id"]))}
                        for t in targets],
            "left_out": [e for e in left_out if not _in_defect(db, project_id, e["hub_id"], defect_id)]}


def _fresh_check(project_id: int, targets: list[dict], require_reviewed: bool, row_id: int | None = None,
                 expect_state: str = ""):
    """Проверка в транзакции постановки: у всех целей та же редакция решения, те же данные находки, находка в выгрузке
    (у SAST – и отметка «Проверено»); строка дефекта ещё в ожидаемом состоянии."""
    def check(c) -> None:
        if row_id is not None:
            state = c.execute("SELECT state FROM hub_defects WHERE id = ?", (row_id,)).fetchone()
            if state is None or state["state"] != expect_state:
                raise StaleTarget("Состояние дефекта изменилось в другой вкладке: обновите карточку.")
        for target in targets:
            review = c.execute("SELECT revision, reviewed, decision FROM reviews WHERE project_id = ? AND hub_id = ?",
                               (project_id, str(target["hub_id"]))).fetchone()
            data = c.execute("SELECT data_json, missing FROM findings WHERE project_id = ? AND hub_id = ?",
                             (project_id, str(target["hub_id"]))).fetchone()
            # «Проверено» – у решений оператора; у решения «из Hub» отметки нет
            fresh = (review is not None and int(review["revision"] or 0) == int(target["revision"])
                     and (review["reviewed"] or not require_reviewed or review["decision"] == defect_drafts.HUB_DECISION)
                     and data is not None and not data["missing"]
                     and finding_data_sig(data["data_json"]) == target.get("sig"))
            if not fresh:
                raise StaleTarget(f"Решение или данные находки {target['hub_id']} изменились, пока собирался запрос: "
                                  "обновите карточку и повторите.")
    return check


# ============================================================================ заготовка


def _answer(project_id: int, row: dict, message: str = "", reload: bool = False) -> dict:
    view = hub_defects.view(row)
    return {"ok": True, "defect_id": row["id"], "status_url": f"/projects/{project_id}/hub/defects/{row['id']}",
            "done": view["final"], "text": {"hub-defect-status": view["text"]},
            "show": ["hub-defect-status"] + (["hub-defect-verify-form"] if view["verify"] else []),
            "hide": ([] if view["verify"] else ["hub-defect-verify-form"]),
            **({"message": message} if message else {}), **({"reload": True} if reload else {})}


def _back(request: Request, suffix: str, ok: str) -> str:
    path = request.url.path[: -len(suffix)] if request.url.path.endswith(suffix) else request.url.path
    query = "&".join(p for p in request.url.query.split("&") if p and not p.startswith("ok="))
    return f"{path}?{query + '&' if query else ''}ok={ok}#hub-defect"


def _prepare_sast(request: Request, project: dict, finding_id: int, shown_revision: str, shown_hash: str) -> dict:
    """Состав и текст дефекта SAST по сохранённому решению карточки (как выдача «Скопировать полный текст дефекта»)."""
    from app.routes import findings as card
    db, settings, pid = db_of(request), settings_of(request), int(project["id"])
    row = db.get_finding(pid, finding_id)
    if row is None or row["kind"] != "SAST":
        raise LookupError("Находка не найдена.")
    source = db.case_input(pid, row["hub_id"])
    if source is None or source.get("missing"):
        raise DefectRefused("Находки нет в текущей выгрузке: дефект по ней не готовится.")
    sig = db.finding_sig(pid, row["hub_id"])
    f = Finding.from_dict(source["data"])
    review = db.get_review(pid, f.hub_id)
    if not review or not review.get("decision"):
        raise DefectRefused("Сначала сохраните решение «Подтверждаю дефект» с обоснованием и рекомендацией.")
    if not shown_revision.isdigit() or int(shown_revision) != int(review.get("revision") or 0):
        raise DefectRefused(STALE_REVISION)
    if not review.get("reviewed"):
        raise DefectRefused(NOT_REVIEWED)
    case = db.get_case(pid, f.hub_id)
    assessment = card.sast_assess(request, pid, review, case, source)
    if assessment["state"] != "ok":
        raise DefectRefused(card.sast_state_hint(assessment["state"], review, card.SAST_DEFECT_NOT_READY))
    view = card.sast_defect(db, settings, store_of(request), pid, f, review, None,
                            shown=card.defect_shown_lines(request, pid, f, case), state="ok", source=source)
    if not view["ready"]:
        raise DefectRefused(view["hint"])
    if not shown_hash:
        raise DefectRefused(TEXT_NOT_SHOWN)
    if shown_hash != text_hash(view["body"]):
        raise DefectRefused(TEXT_CHANGED)
    origin = card.comment_origin(db, case, review, review.get("final_comment") or "", project_id=pid, hub_id=f.hub_id)
    if origin and origin != "true_positive":
        raise DefectRefused("Обоснование – текст модели к другому вердикту: поправьте комментарий в карточке, "
                            "сохраните решение и создавайте дефект.")
    targets, left_out = sast_defect_targets(db, settings, pid, f, review, sig, view["body"])
    return {"kind": "SAST", "f": f, "number": int(view["number"]), "summary": view["title"], "body": view["body"],
            "targets": targets, "left_out": left_out, "warnings": list(view.get("warnings") or []),
            "number_keys": [defect.defect_key_sast(str(t["hub_id"])) for t in targets], "require_reviewed": True}


def _prepare_sca(request: Request, project: dict, finding_id: int, shown_revision: str, shown_hash: str) -> dict:
    """Состав и текст дефекта SCA по набору находки (sca_defect): участники набора – цели."""
    from app.routes import sca as sca_card
    db, pid = db_of(request), int(project["id"])
    row = db.get_finding(pid, finding_id)
    if row is None or row["kind"] != "SCA":
        raise LookupError("Находка не найдена.")
    snap = db.sca_snapshot(pid, row["hub_id"])
    if snap.row is None:
        raise DefectRefused("Находки нет в текущей выгрузке: дефект по ней не готовится.")
    f = Finding.from_dict(snap.row["data"])
    review = snap.review
    if not review or not (review.get("decision") or review.get("final_verdict")):
        raise DefectRefused("Сначала сохраните решение «Обновить» по находке набора.")
    if not shown_revision.isdigit() or int(shown_revision) != int(review.get("revision") or 0):
        raise DefectRefused(STALE_REVISION)
    view = sca_card.sca_defect(snap, store_of(request), pid, f, review)
    if not view["ready"]:
        raise DefectRefused(view["hint"] or "Дефект SCA не готов.")
    if view.get("comment_stale"):
        raise DefectRefused("В дефект входят находки, где комментарий – текст агента к другому выводу: "
                            + ", ".join(str(x) for x in view["comment_stale"][:10])
                            + ". Поправьте комментарий в их карточках и сохраните.")
    if not shown_hash:
        raise DefectRefused(TEXT_NOT_SHOWN)
    if shown_hash != str(view.get("text_sig") or ""):
        raise DefectRefused(TEXT_CHANGED)
    targets: list[dict] = []
    for hub_id in view.get("members") or []:
        member_review = review if hub_id == f.hub_id else db.get_review(pid, hub_id)
        member_sig = db.finding_sig(pid, hub_id)
        member = _finding_of(db, pid, hub_id)
        if member is None or not member_review:
            raise DefectRefused(f"Находка {hub_id} набора изменилась: обновите карточку и повторите.")
        targets.append({"hub_id": hub_id, "issue_id": hub_status.issue_id(hub_id),
                        "issue_type": hub_status.issue_type(member.kind),
                        "revision": int(member_review.get("revision") or 0),
                        "decision_hash": str(view["text_sig"]), "entered_hash": "", "entered_parts": "", "sig": member_sig})
    if not any(t["hub_id"] == f.hub_id for t in targets):
        raise DefectRefused("Находки нет в наборе дефекта: обновите карточку.")
    left_out = [{"hub_id": str(x.get("hub_id") or ""), "why": str(x.get("reason") or "")}
                for x in view.get("excluded") or []]
    for t in targets:
        busy = _busy_reason(db, pid, str(t["hub_id"]))
        if busy and t["hub_id"] != f.hub_id:
            raise DefectRefused(f"Находка {t['hub_id']} набора {busy}: сначала закройте тот дефект.")
    return {"kind": "SCA", "f": f, "number": int(view["number"]), "summary": view["title"], "body": view["body"],
            "targets": targets, "left_out": left_out, "warnings": list(view.get("warnings") or []),
            "number_keys": [sca_card.set_key(f, view["set_no"])], "require_reviewed": False,
            "fingerprint": snap.fingerprint, "expect": sca_expect(view, f.package_display_name)}



def _card_url(project_id: int, defect_id: int, params, ok: str = "") -> str:
    """Адрес карточки дефекта с адресом возврата к списку (back из запроса или back_to из формы карточки), если он
    был: отборы списка переживают заготовку, «Создать» и «Отменить» (ревью dev28). Сам адрес
    возврата карточка проверяет через worklists.return_url."""
    from urllib.parse import quote
    back = str(params.get("back_to") or params.get("back") or "")[:2000]
    if back == "defect-card":
        back = ""
    query = [("ok", ok)] if ok else []
    if back:
        query.append(("back", back))
    return f"/projects/{project_id}/defects/{defect_id}" + ("?" + "&".join(f"{k}={quote(v, safe='')}" for k, v in query) if query else "")

async def _blank(request: Request, project_id: int, finding_id: int, kind: str):
    form = await request.form(max_fields=10, max_files=0)
    shown_revision = str(form.get("review_revision") or "")
    shown_hash = str(form.get("text_hash") or "")

    def apply():
        project = project_or_404(request, project_id)
        settings, db = settings_of(request), db_of(request)
        blocker = send_blocker(settings, project) or hub_sync.resync_blocker(db, project_id)
        if blocker:
            raise DefectRefused(blocker)
        db.hub_expire_leases()
        found = db.get_finding(project_id, finding_id)
        if found is None:
            raise LookupError("Находка не найдена.")
        # прежний дефект находки – до сборки состава: открытый предпросмотр не заменяется (отказ раньше подготовки),
        # дефект в работе или созданный – отказ
        current = db.hub_defect_for(project_id, [str(found["hub_id"])])
        if current is not None:
            current = hub_defects.sync(db, current, update_preparer(request))
            if current["state"] == "done":
                raise DefectRefused(f"Дефект по этой находке уже создан в Hub (№{current['hub_defect_id']}): "
                                    "см. вкладку «Дефекты».")
            if current["state"] in hub_defects.OPEN_STATES:
                raise ValueError("Операция по этому дефекту уже идёт: дождитесь её итога.")
            if current["state"] in ("unknown", "mismatch"):
                raise ValueError("У этой находки есть дефект с неясным исходом: сверьте его или проверьте в Hub.")
            if current["state"] == "preview":  # открытый предпросмотр не заменяется
                raise ValueError(PREVIEW_OPEN)
        prepared = (_prepare_sast if kind == "SAST" else _prepare_sca)(request, project, finding_id, shown_revision,
                                                                       shown_hash)
        f = prepared["f"]
        # текст не по требованиям команды в Hub не уходит (ADR-0123 п. 5): отказ до записи операций и ещё раз в
        # транзакции постановки; «Привязать к дефекту» текст не отправляет и не проверяется
        problems = text_problems(db, settings, project_id, kind, prepared["body"], prepared.get("expect"))
        if problems:
            raise DefectRefused(defect_check.refusal(problems))
        text_ok = _text_check(request, db, settings, project_id, kind, prepared["body"], prepared.get("expect"))
        fresh_targets = _fresh_check(project_id, prepared["targets"], prepared["require_reviewed"])
        app_id = int(project["hub_app_id"])
        # строка дефекта запоминает приложение и адрес Hub предпросмотра – те, что прочитаны здесь (KIMI-12)
        hub_target = hub_target_check(request, project_id, settings.hub_url, app_id)
        # сосед группы с тем же текстом уже в дефекте того же Hub и приложения – привязка к нему, второго нет (ADR-0121
        # п. 5): в транзакции
        group = (group_defect_check(db, project_id, f.hub_id, prepared["body"],
                                    [t["hub_id"] for t in prepared["targets"]], hub_url=settings.hub_url,
                                    app_id=app_id) if kind == "SAST" else None)

        def check(c) -> None:
            hub_target(c)
            fresh_targets(c)
            if group is not None:
                group(c)
            text_ok(c)

        issue_type = hub_status.issue_type(f.kind)
        requests = [dict(purpose="defect_blank", request=hub_defects.blank_request(app_id, prepared["targets"], issue_type),
                         hub_url=settings.hub_url, app_id=app_id, project_id=project_id, targets=prepared["targets"],
                         text=prepared["summary"])]
        if not hub_defects.service_info(db, settings.hub_url):  # справочник – один раз, дальше переиспользуется
            requests.append(dict(purpose="read", request=hub_defects.service_info_request(), hub_url=settings.hub_url,
                                 app_id=app_id, project_id=project_id, targets=[]))
        # строка дефекта, проверка занятости целей и номера, заготовка – одной транзакцией (находки 1 и 6)
        row, _ = db.hub_defect_start(project_id, items=requests, check=check,
                                     kind=prepared["kind"], number=prepared["number"], summary=prepared["summary"],
                                     anchor_hub_id=f.hub_id, targets=prepared["targets"],
                                     number_keys=prepared["number_keys"], command_text=prepared["body"],
                                     hub_url=settings.hub_url, app_id=app_id, left_out=prepared["left_out"],
                                     warnings=prepared["warnings"], source_fingerprint=prepared.get("fingerprint", ""))
        return row

    as_json = wants_json(request)
    try:
        row = await run_in_threadpool(apply)
    except HTTPException as e:
        return await _refused(request, as_json, str(e.detail), e.status_code)
    except hub_status.StatusRefused as e:
        return await _refused(request, as_json, str(e), 400)
    except LookupError as e:
        return await _refused(request, as_json, str(e), 404)
    except ValueError as e:  # очередь: такая операция уже есть или у находки есть незакрытая
        return await _refused(request, as_json, str(e), 409)
    # логика оператора: «Создать дефект» сразу открывает карточку дефекта – там заголовок,
    # текст, состав и «Создать»; карточка сама дождётся заготовки Hub (опрос состояния)
    card = _card_url(project_id, row["id"], request.query_params)
    if not as_json:
        return redirect(card)
    count = len(loads(row.get("targets_json"), []))
    return {**_answer(project_id, row, f"Поставлено в очередь исполнителю: заготовка дефекта по находкам – {count}."),
            "redirect": card}


@router.post("/projects/{project_id}/findings/{finding_id}/hub-defect")
async def blank_sast(request: Request, project_id: int, finding_id: int):
    """«Создать дефект в Hub» в карточке SAST: заготовка по находке и её группе."""
    return await _blank(request, project_id, finding_id, "SAST")


@router.post("/projects/{project_id}/sca/findings/{finding_id}/hub-defect")
async def blank_sca(request: Request, project_id: int, finding_id: int):
    """«Создать дефект в Hub» в карточке SCA: заготовка по набору находки."""
    return await _blank(request, project_id, finding_id, "SCA")


@router.post("/projects/{project_id}/findings/{finding_id}/hub-defect-link")
async def link_sast(request: Request, project_id: int, finding_id: int):
    """«Привязать к дефекту №…» в карточке SAST (ADR-0121 п. 5): новая находка группы и её непривязанные соседи с тем
    же текстом решения – строка дефекта сразу «привязываю» (номер ID<n>, заголовок, текст команды, номер и ссылка в
    Hub – как у готового дефекта, цели – новые находки) и операция `POST /defects/{id}/link` одной транзакцией;
    дальше – чтение `GET /defects/{id}`, отметки «Внесено в Hub» и номер ID<n>, как у созданного дефекта. Заготовки Hub
    и предпросмотра нет: дефект уже есть. Поле targets – состав, который видел оператор (shown_targets): состав,
    собранный заново, другой – отказ, как у устаревшей цели. groupId – из заготовки готового дефекта (строка привязки
    хранит заготовку родителя, Database.hub_defect_link_start; назначение поля уточнить)."""
    form = await request.form(max_fields=10, max_files=0)
    shown_revision = str(form.get("review_revision") or "")
    shown_hash = str(form.get("text_hash") or "")
    shown_parent = str(form.get("defect") or "")
    shown_composition = str(form.get("targets") or "")

    def apply():
        project = project_or_404(request, project_id)
        settings, db = settings_of(request), db_of(request)
        blocker = send_blocker(settings, project) or hub_sync.resync_blocker(db, project_id)
        if blocker:
            raise DefectRefused(blocker)
        db.hub_expire_leases()
        found = db.get_finding(project_id, finding_id)
        if found is None or found["kind"] != "SAST":
            raise LookupError("Находка не найдена.")
        current = db.hub_defect_for(project_id, [str(found["hub_id"])])
        if current is not None and hub_defects.sync(db, current, update_preparer(request))["state"] != "failed":
            raise ValueError("У этой находки уже есть дефект из карточки: обновите карточку.")
        prepared = _prepare_sast(request, project, finding_id, shown_revision, shown_hash)
        f = prepared["f"]
        app_id = int(project["hub_app_id"])
        # готовый дефект – только того же Hub и приложения Hub (link_parent)
        parent = link_parent(db, settings, project_id, f, db.get_review(project_id, f.hub_id) or {}, app_id)
        if parent is None or str(parent["id"]) != shown_parent:
            raise StaleTarget("Дефект группы изменился, пока карточка была открыта (решения соседей другие или "
                              "дефект ещё не подтверждён): обновите карточку.")
        defect_id, targets = str(parent["hub_defect_id"]), prepared["targets"]
        # состав – тот, что видел оператор: сосед получил или потерял «Проверено» в другой вкладке – отказ, ничего не
        # ставится (свежесть каждой цели проверяет транзакция)
        if shown_targets(targets) != shown_composition:
            raise StaleTarget("Состав привязки изменился, пока карточка была открыта (у соседа по группе сменились "
                              "решение или отметка «Проверено»): обновите карточку – она покажет, кто привяжется.")
        blank_body = loads(parent.get("blank_json"), {}) or {}
        item = dict(purpose="defect_link",
                    request=hub_defects.link_request(defect_id, targets, blank_body.get("groupId")),
                    hub_url=settings.hub_url, app_id=app_id, project_id=project_id, targets=targets,
                    text=str(parent.get("summary") or ""))
        fresh_targets = _fresh_check(project_id, targets, True)
        in_group = link_group_check(db, project_id, f.hub_id, int(parent["id"]))
        # готовый дефект выбран по приложению и адресу Hub, прочитанным здесь, и операция уходит туда же (KIMI-12)
        hub_target = hub_target_check(request, project_id, settings.hub_url, app_id)

        def check(c) -> None:
            hub_target(c)
            fresh_targets(c)
            in_group(c)

        # строка «привязываю», проверка свежести целей, свободы, текста и состава группы, привязка – одной транзакцией
        return db.hub_defect_link_start(
            project_id, int(parent["id"]), defect_id, item=item, body_hash=text_hash(defect_where.body_of(prepared["body"])),
            hub_link=str(parent.get("hub_link") or ""), check=check, kind="SAST", number=parent.get("number"),
            summary=str(parent.get("summary") or ""), anchor_hub_id=f.hub_id, targets=targets,
            number_keys=prepared["number_keys"], command_text=str(parent.get("command_text") or ""),
            hub_url=settings.hub_url, app_id=app_id,
            left_out=[e for e in prepared["left_out"] if not _in_defect(db, project_id, e["hub_id"], defect_id)],
            warnings=prepared["warnings"])

    as_json = wants_json(request)
    try:
        row = await run_in_threadpool(apply)
    except HTTPException as e:
        return await _refused(request, as_json, str(e.detail), e.status_code)
    except hub_status.StatusRefused as e:
        return await _refused(request, as_json, str(e), 400)
    except LookupError as e:
        return await _refused(request, as_json, str(e), 404)
    except ValueError as e:  # очередь или занятость: такая операция уже есть, находка в другом дефекте
        return await _refused(request, as_json, str(e), 409)
    if not as_json:
        return redirect(_back(request, "/hub-defect-link", "hub_defect_link_queued"))
    count = len(loads(row.get("targets_json"), []))
    return _answer(project_id, row, f"Поставлено в очередь исполнителю: привязка к дефекту "
                                    f"{hub_defects.bound_label(row)} – находок {count}.")


# ============================================================================ создание, состояние, сверка


def _project_row(request: Request, project_id: int, defect_id: int) -> tuple[dict, dict]:
    project = project_or_404(request, project_id)
    db = db_of(request)
    db.hub_expire_leases()
    row = db.hub_defect(defect_id)
    if row is None or int(row["project_id"]) != project_id:
        raise LookupError("Дефект не найден.")
    return project, hub_defects.sync(db, row, update_preparer(request))


def _sca_expect_at_create(request: Request, project_id: int, row: dict) -> dict:
    """Ожидания проверки текста набора SCA при «Создать» (ADR-0123 п. 4): из снимка набора, по которому собран
    предпросмотр. Снимок с другим отпечатком – тот же отказ, что в транзакции постановки (SCA_CHANGED): текст собран
    по другим данным. Отпечаток тот же, а набор по нему уже не готов или без цели (ни целевой версии, ни «Исправленной
    версии нет») или тело по снимку уже другое (например, истёк срок пересмотра решения по компоненту – цель взята из
    исследования, а дата в отпечаток не входит) – тот же отказ до проверки формы: нарушение «строки обновления» ввело
    бы в заблуждение."""
    from app.routes import sca as sca_card
    db = db_of(request)
    snap = db.sca_snapshot(project_id, str(row.get("anchor_hub_id") or ""))
    if snap.row is None or (row.get("source_fingerprint") and snap.fingerprint != row["source_fingerprint"]):
        raise StaleTarget(SCA_CHANGED)
    f = Finding.from_dict(snap.row["data"])
    view = sca_card.sca_defect(snap, store_of(request), project_id, f, snap.review)
    if not view.get("description") or not view.get("ready") or not (view.get("target") or view.get("no_fix")):
        raise StaleTarget(SCA_CHANGED)
    # тело по снимку другое (например, истёк срок пересмотра решения по компоненту и цель взята из исследования):
    # текст предпросмотра собран по другой цели – «набор изменился», а не нарушение строки обновления
    if text_hash(defect_where.body_of(view.get("body"))) != text_hash(defect_where.body_of(row.get("command_text"))):
        raise StaleTarget(SCA_CHANGED)
    return sca_expect(view, f.package_display_name)


def _anchor_url(db: Database, row: dict) -> str:
    return _card_url_of(db, int(row["project_id"]), str(row.get("anchor_hub_id") or "")) or f"/projects/{row['project_id']}/defects"


@router.post("/projects/{project_id}/hub/defects/{defect_id}/create")
async def create_defect(request: Request, project_id: int, defect_id: int):
    """«Создать» из предпросмотра: `POST /defects` с телом заготовки и правками (заголовок, описание – текст команды в
    HTML и блок Hub, приоритет и серьёзность из формы); подтверждение – чтением (hub_defects)."""
    form = await request.form(max_fields=10, max_files=0)
    priority_name = str(form.get("priority") or "")
    severity_name = str(form.get("severity") or "")
    shown_create = str(form.get("create_snapshot") or "")

    def apply():
        project, row = _project_row(request, project_id, defect_id)
        db, settings = db_of(request), settings_of(request)
        blocker = send_blocker(settings, project)
        if blocker:
            raise DefectRefused(blocker)
        if row["state"] != "preview":
            raise ValueError("Предпросмотра нет: дефект уже создаётся, создан или заготовка не получена.")
        from app.routes import defect_selected
        signature = hub_defects.creation_signature(row)
        if (shown_create or defect_selected.attempt(row)) and shown_create != signature:
            raise DefectRefused("Предпросмотр создания изменился: обновите карточку дефекта.")
        # POST уходит по приложению и адресу Hub предпросмотра (строка дефекта): их сменили после предпросмотра – отказ
        # здесь и ещё раз в транзакции постановки (KIMI-12)
        if not _same_hub(row, settings.hub_url, project.get("hub_app_id")):
            raise StaleTarget(PREVIEW_TARGET_CHANGED)
        hub_target = hub_target_check(request, project_id, str(row.get("hub_url") or ""), row.get("app_id"),
                                  PREVIEW_TARGET_CHANGED)
        # сохранённый текст команды, из которого собирается запрос, – по требованиям команды (ADR-0123 п. 5): отказ
        # до постановки и ещё раз в её транзакции (название команды – перечитанное в ней); у SCA ожидания – из того же
        # снимка набора, что и предпросмотр. Отказ советует «Отменить предпросмотр»: заготовка заново – только после него
        command_text = str(row.get("command_text") or "")
        expect = _sca_expect_at_create(request, project_id, row) if row["kind"] == "SCA" else None
        problems = text_problems(db, settings, project_id, row["kind"], command_text, expect)
        if problems:
            raise DefectRefused(defect_check.refusal(problems, at_create=True))
        text_ok = _text_check(request, db, settings, project_id, row["kind"], command_text, expect, at_create=True)
        blank = loads(row.get("blank_json"), {}) or {}
        service = hub_defects.service_info(db, row["hub_url"])
        try:
            priority = hub_defects.pick_level(service.get("priorities"), priority_name, blank.get("priority"))
            severity = hub_defects.pick_level(service.get("severities"), severity_name, blank.get("severity"))
        except ValueError as e:
            raise DefectRefused(str(e)) from None
        # описание – текст приложения и следом блок заготовки Hub как есть (dev30, требование команды:
        # сведения об объекте сканирования остаются; с dev6 по dev29 уходил только текст)
        description = hub_defects.description_html(str(row.get("command_text") or ""), hub_defects.blank_for_send(row).block)
        body = hub_defects.create_body(blank, int(row["app_id"] or 0), str(row["summary"]), description, priority,
                                       severity)
        def level_codes(c) -> dict:  # соответствие уровня коду, данное Hub в прочитанных дефектах (ADR-0126 п. 6)
            return hub_defects.level_codes(loads(r["confirmed_object_json"], None) for r in c.execute(
                "SELECT hub_url, app_id, confirmed_object_json FROM hub_defects WHERE project_id=?"
                " AND confirmed_object_json != ''", (project_id,)) if _same_hub(dict(r), row["hub_url"], row.get("app_id")))

        try:
            used_codes = hub_defects.fill_level_codes(body, db.on_connection(level_codes), blank)
        except ValueError as e:
            raise DefectRefused(str(e)) from None
        targets = loads(row.get("targets_json"), [])
        hub_defects.create_composition_check(body, targets)
        fresh_targets = _fresh_check(project_id, targets, row["kind"] == "SAST")
        group = (group_defect_check(db, project_id, str(row.get("anchor_hub_id") or ""),
                                    str(row.get("command_text") or ""), [t.get("hub_id") for t in targets],
                                    hub_url=row["hub_url"], app_id=row.get("app_id"), in_preview=True)
                 if row["kind"] == "SAST" and not defect_selected.attempt(row) else None)

        def check(c) -> None:
            current = dict(c.execute("SELECT * FROM hub_defects WHERE id=?", (row["id"],)).fetchone())
            if hub_defects.creation_signature(current) != signature:
                raise DefectRefused("Предпросмотр создания изменился: обновите карточку дефекта.")
            hub_defects.create_composition_check(body, loads(current["targets_json"], []))
            if hub_defects.level_codes_changed(used_codes, level_codes(c)):
                raise DefectRefused("Соответствие кодов приоритета и серьёзности в Hub изменилось: обновите карточку.")
            hub_target(c)
            fresh_targets(c)
            defect_selected.create_check(request, c, current)
            if group is not None:  # сосед группы с тем же текстом попал в дефект после предпросмотра (ADR-0121 п. 5)
                group(c)
            # набор SCA: текст набора, исследование, состав – тот же снимок, по которому собран предпросмотр (находка 4)
            if row["kind"] == "SCA" and row.get("source_fingerprint") and db._sca_defect_fingerprint(
                    c, project_id, str(row["anchor_hub_id"])) != row["source_fingerprint"]:
                raise StaleTarget(SCA_CHANGED)
            text_ok(c)

        # проверка строки, постановка POST и переход в «создаётся» – одной транзакцией (находка 1): вторая вкладка
        # со старым предпросмотром второй POST не поставит
        fresh, _ = db.hub_defect_advance(
            int(row["id"]), expect_state="preview", check=check, op_field="create_op_id",
            item=dict(purpose="defect_create", request=hub_defects.create_request(body), hub_url=row["hub_url"],
                      app_id=row.get("app_id"), project_id=project_id, targets=targets, text=str(row["summary"]),
                      key_extra=f"defect-row:{int(row['id'])}"),  # новая строка – новое действие (ADR-0121)
            state="creating", body_html=description, priority=hub_defects.level_name(priority),
            severity=hub_defects.level_name(severity), error="")
        if fresh is None:
            raise ValueError("Состояние дефекта изменилось в другой вкладке: обновите карточку.")
        return fresh

    as_json = wants_json(request)
    try:
        row = await run_in_threadpool(apply)
    except HTTPException as e:
        return await _refused(request, as_json, str(e.detail), e.status_code)
    except hub_status.StatusRefused as e:
        if form.get("back") == "defect-card" and not as_json:
            from app.routes.defect_card_routes import page_context
            context = await run_in_threadpool(page_context, request, project_id, defect_id)
            context["error"] = str(e)
            return render(request, "projects/defect_card.html", context, status_code=400)
        return await _refused(request, as_json, str(e), 400)
    except LookupError as e:
        return await _refused(request, as_json, str(e), 404)
    except ValueError as e:
        return await _refused(request, as_json, str(e), 409)
    if not as_json:
        if form.get("back") == "defect-card":
            return redirect(_card_url(project_id, row["id"], form))
        url = await run_in_threadpool(lambda: _anchor_url(db_of(request), row))
        return redirect(url + "?ok=hub_defect_create_queued#hub-defect")
    return _answer(project_id, row, "Поставлено в очередь исполнителю: создание дефекта.")


@router.post("/projects/{project_id}/hub/defects/{defect_id}/cancel")
async def cancel_preview(request: Request, project_id: int, defect_id: int):
    """«Отменить предпросмотр»: заготовка больше не нужна (состав, текст или номер поменялись) – строка отменена, номер
    ID<n> освобождён, «Создать дефект в Hub» снова доступна. Только из предпросмотра: в Hub ничего не уходило."""
    form = await request.form(max_fields=2, max_files=0)

    def apply():
        _, row = _project_row(request, project_id, defect_id)
        fresh = db_of(request).hub_defect_update(int(row["id"]), expect_state="preview", state="cancelled")
        if fresh is None:
            raise ValueError("Предпросмотра уже нет: дефект создаётся, создан или заготовка отменена – обновите "
                             "карточку.")
        return fresh

    as_json = wants_json(request)
    try:
        row = await run_in_threadpool(apply)
    except HTTPException as e:
        return await _refused(request, as_json, str(e.detail), e.status_code)
    except LookupError as e:
        return await _refused(request, as_json, str(e), 404)
    except ValueError as e:
        return await _refused(request, as_json, str(e), 409)
    if not as_json:
        if form.get("back") == "defect-card":
            return redirect(_card_url(project_id, row["id"], form))
        url = await run_in_threadpool(lambda: _anchor_url(db_of(request), row))
        return redirect(url + "?ok=hub_defect_cancelled#hub-defect")
    return {"ok": True, "defect_id": row["id"], "done": True, "reload": True,
            "message": "Предпросмотр отменён: заготовку можно запросить заново."}


@router.get("/projects/{project_id}/hub/defects/{defect_id}")
def defect_state(request: Request, project_id: int, defect_id: int):
    """Состояние дефекта для опроса из карточки (раз в 2 с); конечное состояние – перезагрузка карточки (предпросмотр,
    итог, отметка)."""
    try:
        _, row = _project_row(request, project_id, defect_id)
    except HTTPException as e:
        return _json_error(str(e.detail), e.status_code)
    except LookupError as e:
        return _json_error(str(e), 404)
    view = hub_defects.view(row)
    return _answer(project_id, row, reload=view["final"])


@router.post("/projects/{project_id}/hub/defects/{defect_id}/verify")
async def verify_defect(request: Request, project_id: int, defect_id: int):
    """«Сверить»: у дефекта с известным номером – чтение `GET /defects/{id}` снова; без номера – постранично
    `GET /defects?appId` → кандидаты с тем же заголовком и автором → чтение каждого → совпадение находок и текста."""
    from app.routes.hub import worker_summary
    form = await request.form(max_fields=5, max_files=0)

    def apply():
        _, row = _project_row(request, project_id, defect_id)
        db = db_of(request)
        if row["state"] not in ("unknown", "unconfirmed") and not hub_defects.link_rereadable(row):
            raise DefectRefused("Сверка нужна только при результате «неизвестен» или неподтверждённом содержимом.")
        if row.get("hub_defect_id"):
            fresh = hub_defects.restart_read(db, row)  # отказ очереди – ValueError с её причиной
            if fresh is None:
                raise ValueError("Состояние дефекта изменилось: обновите карточку.")
            return fresh
        login = str(worker_summary(request).get("hub_login") or "")
        hub_defects.start_verify(db, row, login)  # идущая сверка или отказ очереди – ValueError с причиной
        return db.hub_defect(int(row["id"])) or row

    as_json = wants_json(request)
    try:
        row = await run_in_threadpool(apply)
    except HTTPException as e:
        return await _refused(request, as_json, str(e.detail), e.status_code)
    except hub_status.StatusRefused as e:
        return await _refused(request, as_json, str(e), 400)
    except LookupError as e:
        return await _refused(request, as_json, str(e), 404)
    except ValueError as e:
        return await _refused(request, as_json, str(e), 409)
    if not as_json:
        if form.get("back") == "defect-card":
            owner_id = row.get("draft_owner_id") or row["id"]
            return redirect(_card_url(project_id, owner_id, form, ok="hub_defect_verify_queued"))
        url = await run_in_threadpool(lambda: _anchor_url(db_of(request), row))
        return redirect(url + "?ok=hub_defect_verify_queued#hub-defect")
    return _answer(project_id, row, "Сверка поставлена в очередь исполнителю.")


@router.post("/projects/{project_id}/hub/defects/{defect_id}/recheck")
async def recheck_defect(request: Request, project_id: int, defect_id: int):
    """«Проверить в Hub» у созданного дефекта (ADR-0121 п. 6): чтение `GET /defects/{id}` – только сверка, итог –
    пояснением в строке (404 – «дефект в Hub не найден», состав linkedIssues – о находках, которых в нём нет); состояние
    строки и находки не меняются, снятие привязки – следующая сборка (бэклог 39). Ручного «отвязать» нет: связь живёт
    в Hub. Поле back=defects – ответ без скрипта во вкладку «Дефекты»."""
    form = await request.form(max_fields=5, max_files=0)
    to_tab = str(form.get("back") or "") == "defects"

    def apply():
        project, row = _project_row(request, project_id, defect_id)
        blocker = send_blocker(settings_of(request), project)
        if blocker:
            raise DefectRefused(blocker)
        return hub_defects.start_recheck(db_of(request), row)  # не «создан», идущая проверка, очередь – ValueError

    as_json = wants_json(request)
    try:
        row = await run_in_threadpool(apply)
    except HTTPException as e:
        return await _refused(request, as_json, str(e.detail), e.status_code)
    except hub_status.StatusRefused as e:
        return await _refused(request, as_json, str(e), 400)
    except LookupError as e:
        return await _refused(request, as_json, str(e), 404)
    except ValueError as e:
        return await _refused(request, as_json, str(e), 409)
    if not as_json:
        if to_tab:
            return redirect(f"/projects/{project_id}/defects?ok=hub_defect_recheck_queued")
        url = await run_in_threadpool(lambda: _anchor_url(db_of(request), row))
        return redirect(url + "?ok=hub_defect_recheck_queued#hub-defect")
    return _answer(project_id, row, "Проверка поставлена в очередь исполнителю: чтение дефекта из Hub.")


@router.post("/projects/{project_id}/hub/defects/{defect_id}/template-model")
async def template_model_read(request: Request, project_id: int, defect_id: int):
    """Явно подтверждённый сбор ответа для уточнения контракта, без подготовки Push."""
    from app import hub_template_model
    form = await request.form(max_fields=3, max_files=0)
    if form.get("confirm") != "1":
        raise HTTPException(400, "Подтвердите чтение модели шаблона Hub.")
    issue_id = str(form.get("issue_id") or "")

    def apply():
        project, row = _template_model_row(request, project_id, defect_id)
        settings = settings_of(request)
        blocker = send_blocker(settings, project)
        if blocker:
            raise HTTPException(400, blocker)
        if not _same_hub(row, settings.hub_url, project.get("hub_app_id")):
            raise HTTPException(409, UPDATE_TARGET_CHANGED)
        try:
            op = hub_template_model.enqueue(db_of(request), row, issue_id,
                                             _update_target(request, project_id, row))
        except ValueError as exc:
            raise HTTPException(409, str(exc)) from exc
        return {"ok": True, "op_id": op["id"], "state": op["state"]}

    return await run_in_threadpool(apply)


@router.get("/projects/{project_id}/hub/defects/{defect_id}/template-model/{op_id}")
def template_model_result(request: Request, project_id: int, defect_id: int, op_id: int):
    """Транспортный ответ из PostgreSQL; GET не ставит запросов в Hub."""
    from app import hub_template_model
    _, row = _template_model_row(request, project_id, defect_id)
    try:
        return hub_template_model.saved(db_of(request), row, op_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc


def _template_model_row(request: Request, project_id: int, defect_id: int) -> tuple[dict, dict]:
    # Чтение результата не продвигает цепочки Push и не ставит следующие операции.
    project = project_or_404(request, project_id)
    row = db_of(request).hub_defect(defect_id)
    if row is None or row["project_id"] != project_id:
        raise HTTPException(404, "Дефект не найден.")
    return project, row

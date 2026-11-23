"""«Добавить в дефект» (ADR-0136): находка с другой строки входит в дефект, который оператор выбирает сам, в том числе занесённый из
Hub и обновлённый через Push.

Выбор дефекта, предпросмотр, операция `POST /defects/{id}/link`, сверка чтением – та же цепочка, что у привязки соседа по группе
(`hub_defect_link_start`). Текст дефекта не меняется, решение находки остаётся её. Состав у владельца пополняет «Pull из Hub» и
«Применить»: строка привязки живёт отдельно до этого шага.
"""

import json

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from app import defect, defect_drafts, hub_defects, hub_status, hub_sync, i18n
from app.db import Database, hub_verdict, source_version, text_hash
from app.hub_entity_versions import digest
from app.models import Finding
from app.routes import defect_selected
from app.routes import hub_defect_routes as flow
from app.routes.common import db_of, project_or_404, redirect, register_messages, render, settings_of
from app.routes.hub_status_routes import hub_target_check, send_blocker

router = APIRouter()
STALE = i18n.N_("Дефект, находка или решение изменились после показа: проверьте и подтвердите ещё раз. В Hub ничего не ушло.")
register_messages({"defect_add_queued": "Поставлено в очередь исполнителю: добавление находки в дефект."})


def not_eligible(c, row: dict, hub_id: str) -> str:
    """Почему дефект нельзя выбрать; "" – можно. Причина – для оператора: ограничение видно, а не молча скрыто."""
    if row.get("kind") != "SAST":
        return i18n._("дефект не SAST")
    if row.get("state") != "done" or not row.get("hub_defect_id"):
        return i18n._("состояние «{state}»: нужен созданный дефект, подтверждённый чтением",
                      state=hub_defects.STATE_LABELS.get(row.get('state'), row.get('state')))
    return hub_defects.family_running_problem(c, row) or hub_defects.add_problem(c, row, hub_id)


def defects_of(c, project_id: int, settings, app_id, hub_id: str) -> tuple[list[dict], list[dict]]:
    """Дефекты SAST того же Hub и приложения: (можно выбрать, нельзя – с причиной). Только строки-владельцы: дефект – это семья строк."""
    rows = [dict(r) for r in c.execute(
        "SELECT * FROM hub_defects WHERE project_id = ? AND kind = 'SAST' AND (draft_owner_id IS NULL OR draft_owner_id = id)"
        " AND state NOT IN ('cancelled', 'failed', 'deleted', 'import_reading', 'import_preview') ORDER BY id", (project_id,))]
    ready, closed = [], []
    for row in rows:
        if not flow._same_hub(row, settings.hub_url, app_id):
            continue
        why = not_eligible(c, row, hub_id)
        item = {"id": row["id"], "label": hub_defects.bound_label(row), "summary": row.get("summary") or "", "why": why}
        (closed if why else ready).append(item)
    return ready, closed


def _number_unique(c, project_id: int, hub_id: str) -> None:
    """Номер находки в запросе – числовой и однозначный: как у отмеченных находок (defect_selected)."""
    ident = hub_status.issue_id(hub_id)
    same = 0
    for raw in c.execute("SELECT hub_id FROM findings WHERE project_id = ? AND kind = 'SAST'", (project_id,)):
        try:
            same += hub_status.issue_id(raw["hub_id"]) == ident
        except hub_status.StatusRefused:
            continue
    if same != 1:
        raise hub_defects.DefectRefused(i18n._("Номер находки неоднозначен после нормализации: привязка не выполняется."))


def last_attempt(c, project_id: int, hub_id: str) -> list:
    """Последняя строка дефекта с этой находкой в любом состоянии, в том числе отказ и отмена. Семья их не считает, а форма, показанная до
    завершённой попытки, не должна отправить запрос второй раз: после итога нужен новый предпросмотр."""
    row = c.execute(
        "SELECT id, state FROM hub_defects WHERE project_id = ? AND EXISTS ("
        " SELECT 1 FROM json_array_elements(hub_defects.targets_json::json) AS t(value) WHERE (t.value ->> 'hub_id') = ?)"
        " ORDER BY id DESC LIMIT 1", (project_id, hub_id)).fetchone()
    return [row["id"], row["state"]] if row else []


def assess(request, c, project, hub_id: str, parent_id: int | None) -> dict:
    """Что покажет страница и что проверит запись: находка, дефекты, цель, запрос, отпечаток показанного состояния."""
    from app.routes import findings as card
    db, settings, pid = db_of(request), settings_of(request), int(project["id"])
    app_id = int(project.get("hub_app_id") or 0)
    found = db.get_finding_by_hub_id(pid, hub_id)
    view = {"hub_id": hub_id, "finding": None, "why": "", "ready": [], "closed": [], "parent": None, "target": None, "text": "",
            "snapshot": "", "link": None, "link_body": "", "retry_note": ""}
    if found is None or found.get("missing"):
        view["why"] = i18n._("Находки нет в текущей выгрузке.")
        return view
    if found["kind"] != "SAST":
        view["why"] = i18n._("Добавить в дефект можно находку SAST.")
        return view
    f = Finding.from_dict(found["data"])
    view["finding"] = f
    review = db.get_review(pid, hub_id) or {}
    bound = Database.hub_defect_bound_in(c, pid, hub_id)
    try:
        if bound is not None:
            raise hub_defects.DefectRefused(i18n._("Находка уже входит в {defect}.", defect=hub_defects.bound_name(bound)))
        if hub_verdict(review.get("decision") or "", review.get("final_verdict") or "") != "true_positive" or not review.get("reviewed"):
            raise hub_defects.DefectRefused(i18n._("Сначала сохраните решение «Подтверждаю дефект» с отметкой «Проверено»."))
        _number_unique(c, pid, hub_id)
        busy = defect_selected.busy_reason(db, c, pid, hub_id, hub_status.issue_id(hub_id))
        if busy:
            raise hub_defects.DefectRefused(i18n._("Находка {reason}.", reason=busy))
        source = db.case_input(pid, hub_id)
        case = db.get_case(pid, hub_id)
        state = card.sast_assess(request, pid, review, case, source)["state"]
        if state != "ok":
            raise hub_defects.DefectRefused(card.sast_state_hint(state, review, card.SAST_DEFECT_NOT_READY))
        origin = card.comment_origin(db, case, review, review.get("final_comment") or "", project_id=pid, hub_id=hub_id)
        if origin and origin != "true_positive":  # с такой находкой в составе Push дефекта откажет
            raise hub_defects.DefectRefused(i18n._("Обоснование – текст модели к другому вердикту: поправьте комментарий в карточке и "
                                                    "сохраните решение."))
        snapshot = defect_selected.target_snapshot(request, c, pid, hub_id)
        stored = db.defect_number(pid, defect.defect_key_sast(hub_id))
    except ValueError as e:
        view["why"] = str(e)
        return view
    prior = db.hub_defect_for(pid, [hub_id])
    if prior is not None and prior["state"] == "failed" and prior.get("confirm_op_id"):
        # чтение не показало находку в дефекте, но POST мог выполниться (в составе ответа только открытые находки)
        view["retry_note"] = i18n._("Прошлая попытка: {error}. Запрос мог выполниться: проверьте дефект в Hub до новой "
                                    "попытки.", error=prior.get('error') or i18n._("находки нет в составе ответа Hub"))
    view["ready"], view["closed"] = defects_of(c, pid, settings, app_id, hub_id)
    if parent_id is None:
        return view
    row = c.execute("SELECT * FROM hub_defects WHERE id = ? AND project_id = ?", (int(parent_id), pid)).fetchone()
    parent = dict(row) if row else None
    if parent is None or not any(item["id"] == parent["id"] for item in view["ready"]):
        closed = next((item["why"] for item in view["closed"] if parent and item["id"] == parent["id"]), "")
        view["why"] = (i18n._("Этот дефект сейчас нельзя выбрать: {reason}", reason=closed) if closed
                       else i18n._("Этот дефект сейчас нельзя выбрать: выберите другой."))
        return view
    if stored is not None and stored != parent.get("number"):
        view["why"] = i18n._("У находки уже есть свой номер ID{number}: объединение номеров не выполняется автоматически, "
                             "снимите номер в её карточке.", number=stored)
        return view
    text = card.sast_entered_text(db, settings, pid, f, review)
    try:
        flow.group_defect_check(db, pid, hub_id, text, [hub_id], hub_url=settings.hub_url, app_id=app_id, selected_owner=int(parent["id"]))(c)
    except ValueError as e:
        view["why"] = str(e)
        return view
    target = flow._defect_target(f, review, text, flow.defect_parts(settings, review), db.finding_sig(pid, hub_id))
    blank = hub_defects.loads(parent.get("blank_json"), {}) or {}
    link = hub_defects.link_request(str(parent["hub_defect_id"]), [target], blank.get("groupId"))
    view.update(parent=parent, target=target, text=text, link=link, link_body=json.dumps(link["body"], ensure_ascii=False, indent=2),
                snapshot=digest({
                    # весь показанный запрос: поля нет и поле со значением null – разные тела
                    "request": link, "attempt": last_attempt(c, pid, hub_id), "hub_id": hub_id, "parent": parent["id"], "hub_defect_id": parent["hub_defect_id"], "summary": parent.get("summary"),
                    "number": parent.get("number"), "accepted": text_hash(str(parent.get("confirmed_object_json") or "")),
                    "generation": parent.get("text_generation"), "defect_text": parent.get("command_text"), "draft_revision": parent.get("draft_revision"),
                    "members": defect_drafts.members_in(c, parent), "revision": review.get("revision"), "version": source_version(snapshot["source"]),
                    "code": snapshot["code"]["hash"], "text": text}))
    return view


def apply(request, project_id: int, hub_id: str, parent_id: int | None, shown: str, confirmed: bool) -> dict:
    if parent_id is None:
        raise hub_defects.DefectRefused(i18n._("Выберите дефект."))
    db = db_of(request)
    project = project_or_404(request, project_id)
    settings = settings_of(request)
    blocker = send_blocker(settings, project) or hub_sync.resync_blocker(db, project_id)
    if blocker:
        raise hub_defects.DefectRefused(blocker)
    db.hub_expire_leases()
    view = db.on_connection(lambda c: assess(request, c, project, hub_id, parent_id))
    if view["why"]:
        raise hub_defects.DefectRefused(view["why"])
    if not shown or shown != view["snapshot"]:
        raise hub_defects.DefectRefused(i18n._(STALE))
    if not confirmed:
        raise hub_defects.DefectRefused(i18n._("Подтвердите добавление находки в дефект."))
    parent, target = view["parent"], view["target"]
    defect_id, app_id = str(parent["hub_defect_id"]), int(project["hub_app_id"])
    item = dict(purpose="defect_link", request=view["link"], hub_url=settings.hub_url, app_id=app_id, project_id=project_id,
                targets=[target], text=str(parent.get("summary") or ""))
    fresh = flow._fresh_check(project_id, [target], True)
    hub_target = hub_target_check(request, project_id, settings.hub_url, app_id)

    def check(c) -> None:  # всё показанное – ещё раз в транзакции постановки
        hub_target(c)
        fresh(c)
        again = assess(request, c, project, hub_id, parent_id)
        if again["why"]:
            raise hub_defects.DefectRefused(again["why"])
        if again["snapshot"] != shown:
            raise hub_defects.DefectRefused(i18n._(STALE))

    return db.hub_defect_link_start(
        project_id, int(parent["id"]), defect_id, item=item, body_hash=text_hash(defect.body_key(parent.get("command_text"))),
        hub_link=str(parent.get("hub_link") or ""), check=check, allow_imported=True, kind="SAST", number=parent.get("number"),
        summary=str(parent.get("summary") or ""), anchor_hub_id=hub_id, targets=[target], number_keys=[defect.defect_key_sast(hub_id)],
        command_text=str(parent.get("command_text") or ""), hub_url=settings.hub_url, app_id=app_id, left_out=[], warnings=[])


def page(request, project_id: int, hub_id: str, parent_id: int | None = None, *, confirm=False, error="", status=200):
    project, db = project_or_404(request, project_id), db_of(request)
    view = db.on_connection(lambda c: assess(request, c, project, hub_id, parent_id))
    blocker = send_blocker(settings_of(request), project) or hub_sync.resync_blocker(db, project_id)
    if confirm and not view["parent"]:
        error, confirm, status = (error or view["why"] or i18n._("Выберите дефект.")), False, 400
    return render(request, "findings/defect_add.html", dict(project=project, confirm=confirm, error=error, blocker=blocker,
                  card_url=flow._card_url_of(db, project_id, hub_id), **view), status_code=status)


def _parent_id(value) -> int | None:
    text = str(value or "")
    return int(text) if text.isdigit() else None


@router.get("/projects/{project_id}/hub/add-to-defect")
async def add_page(request: Request, project_id: int):
    return await run_in_threadpool(page, request, project_id, str(request.query_params.get("hub_id") or ""))


@router.post("/projects/{project_id}/hub/add-to-defect")
async def add_submit(request: Request, project_id: int):
    form = await request.form(max_fields=8, max_files=0)
    hub_id, parent_id = str(form.get("hub_id") or ""), _parent_id(form.get("defect"))
    try:
        if form.get("action") == "apply":
            await run_in_threadpool(apply, request, project_id, hub_id, parent_id, str(form.get("snapshot") or ""), form.get("confirm") == "1")
            back = flow._card_url_of(db_of(request), project_id, hub_id)
            return redirect(f"{back}?ok=defect_add_queued#hub-defect")
        return await run_in_threadpool(page, request, project_id, hub_id, parent_id, confirm=form.get("action") == "preview")
    except ValueError as e:
        return await run_in_threadpool(page, request, project_id, hub_id, parent_id, error=str(e), status=409)

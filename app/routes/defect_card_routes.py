"""HTML-карточка логического дефекта; физические операции остаются в hub_defect_routes."""

from difflib import unified_diff
from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app import defect_drafts, defect_fields, defect_form, defect_local_text, defect_references, defect_where, hub_defects
from app.db import dumps, loads
from app.routes.common import register_messages

register_messages({"number_released": "Номер снят с находок вне дефекта: «Push в Hub» больше не считает его занятым."})
from app.routes import hub_defect_routes as flow
from app.routes.common import db_of, project_or_404, redirect, render, settings_of
from app.routes.hub_status_routes import send_blocker
from app.view import DECISION_LABELS, VERDICT_LABELS

router = APIRouter()

# Статусы находок так, как их показывает интерфейс Hub (вкладка «Связанные уязвимости» в Hub, в приложении – «Связанные находки»)
HUB_STATUS_RU = {"To verify": "Не подтверждено", "Open": "Открыто", "Confirmed": "Подтверждено",
                 "False Positive": "Ложное срабатывание", "Accepted risk": "Риск принят", "Fixed": "Исправлено"}


_scan_date = defect_where.scan_date


def linked_rows(db, project_id: int, owner: dict, hub_obj: dict | None, targets: list[dict]) -> list[dict]:
    """Состав дефекта для вкладки «Связанные находки»: связи из объекта Hub; до создания – находки состава."""
    base = str(owner.get("hub_url") or "").rstrip("/")
    app_id = owner.get("app_id")
    rows = []
    issues = (hub_obj or {}).get("linkedIssues") if isinstance(hub_obj, dict) else None
    if isinstance(issues, list) and issues:
        for item in issues:
            if not isinstance(item, dict):
                continue
            hub_id, kind = str(item.get("id") or ""), str(item.get("type") or "")
            scan = item.get("scanObject") if isinstance(item.get("scanObject"), dict) else {}
            rows.append({"hub_id": hub_id, "type": kind, "source": str(item.get("source") or ""),
                         "status": HUB_STATUS_RU.get(str(item.get("status") or ""), str(item.get("status") or "")),
                         "scan_task": str(item.get("lastScanTaskId") or ""), "scan_date": _scan_date(item.get("lastScanTs")),
                         "scan_object": str(scan.get("name") or ""),
                         "url": flow._card_url_of(db, project_id, hub_id),
                         "hub_url": f"{base}/#/appprofile/{app_id}/issues/{kind}/{hub_id}" if base and app_id and kind else ""})
        return rows
    for t in targets:
        rows.append({"hub_id": t["hub_id"], "type": owner.get("kind") or "", "source": "", "status": "",
                     "scan_task": "", "scan_date": "", "scan_object": "", "url": t.get("url") or "", "hub_url": "",
                     "decision": t.get("decision", "")})
    return rows


CATALOG_KEYS = ("page", "q", "sort", "kind", "state", "origin", "page_size")  # отборы вкладки «Дефекты»


def page_context(request, project_id, defect_id):
    project = project_or_404(request, project_id)
    db = db_of(request)
    row = db.hub_defect(defect_id)
    if row is None or row["project_id"] != project_id:
        raise HTTPException(404, "Дефект не найден.")
    family = db.on_connection(lambda c: defect_drafts.family_in(c, row))
    for physical in family or [row]:
        hub_defects.sync(db, physical, flow.update_preparer(request))
    owner = db.on_connection(lambda c: defect_drafts.owner_in(c, row))
    family = db.on_connection(lambda c: defect_drafts.family_in(c, owner))
    defect_references.sync(db, project_id)
    problem = db.on_connection(lambda c: defect_drafts.edit_problem(c, owner))
    targets = {}
    for physical in family:
        for t in loads(physical["targets_json"], []):
            hub_id = str(t.get("hub_id") or "")
            review = db.get_review(project_id, hub_id) or {}
            targets[(hub_id, t.get("issue_type"))] = {
                "hub_id": hub_id, "url": flow._card_url_of(db, project_id, hub_id),
                "decision": review.get("final_verdict") or review.get("decision") or "решение не сохранено",
                "revision": review.get("revision", 0), "sent_revision": t.get("revision", 0),
            }
    settings = settings_of(request)
    single = db.on_connection(lambda c: defect_drafts.family_single_in(c, owner))
    can_read = (not send_blocker(settings, project)
                and flow._same_hub(owner, settings.hub_url, project.get("hub_app_id")) and single)
    sync_preview = bool(loads(owner["sync_json"], {}).get("read"))
    upd = flow.update_context(db, owner, can_read, sync_preview)
    if loads(owner["conflicts_json"], []):
        upd["can_prepare"] = False
        upd["can_put"] = False
    decisions = defect_local_text.generate(request, owner) if single else {}
    confirmed = loads(owner["confirmed_object_json"], None)
    observed = loads(owner["import_json"], {})
    base = hub_defects._read_of(confirmed) if confirmed else None
    basis = defect_fields.basis_of(owner)
    reference_rows = db._all("SELECT * FROM hub_defect_reference_loads WHERE project_id = ? AND hub_url = ?"
                             " AND app_id = ? ORDER BY id DESC", (project_id, owner["hub_url"], owner["app_id"]))
    reference_rows = [r for r in reference_rows if r["state"] != "preview"
                      or loads(r["load_json"], {}).get("defect_id") == owner["id"]]
    latest = next((r for r in reference_rows if r["state"] == "done"), None)
    choices = loads(latest["load_json"], {}).get("projection", {}) if latest else {}
    groups = db.on_connection(lambda c: defect_local_text.groups_in(c, owner)) if owner["kind"] == "SCA" else []
    sync_seen = loads(owner["sync_json"], {}).get("read")
    basis_seen = sync_seen or observed
    draft = {"summary": owner["draft_summary"], "command_text": owner["draft_command_text"]}
    comparisons = []
    for title, before, after in [("Подтверждённая база → черновик", base, draft),
                                  ("Черновик → текущие решения", draft, decisions if not decisions.get("refusals") else None),
                                  ("Подтверждённая база → наблюдение Hub", base, observed)]:
        if before is not None and after and "command_text" in after and not after.get("text_note"):
            left = (before.get("summary", "") + "\n" + before.get("command_text", "")).splitlines()
            right = (after.get("summary", "") + "\n" + after.get("command_text", "")).splitlines()
            comparisons.append({"title": title, "diff": "\n".join(unified_diff(left, right, lineterm=""))})
    catalog_query = {k: request.query_params[k] for k in CATALOG_KEYS if k in request.query_params}
    # действия форм карточки несут и адрес возврата к списку: он переживает сохранение черновика (ревью dev28)
    form_query = {k: request.query_params[k] for k in (*CATALOG_KEYS, "back") if k in request.query_params}
    hub_obj = confirmed if isinstance(confirmed, dict) else (observed.get("object") if isinstance(observed, dict) else None)
    # «Описание в Hub» – текстовая часть; служебный блок Hub показывается отдельно, очищенный до безопасной разметки
    # (dev30): у дефекта в Hub – его блок, у ещё не созданного – блок заготовки
    hub_block_html, hub_block_source = hub_defects.block_for_display(owner, hub_obj if isinstance(hub_obj, dict) else None)
    # блок Hub выделен – «Описание в Hub» показывает текстовую часть; иначе (блок склеен с текстом или его нет) – все
    # строки описания Hub как есть (ревью dev30, круг 2)
    hub_lines = ((hub_defects.split_description(hub_obj.get("description"))[0].splitlines()
                  if hub_block_source == "hub" else hub_defects.description_lines(hub_obj.get("description")))
                 if isinstance(hub_obj, dict) else [])
    # SCA: текст и «Push в Hub» берутся из «Дефекта по шаблону команды» в карточке опорной находки –
    # при отказе карточка дефекта ведёт туда, где ставятся отметки и сохраняется объяснение
    sca_anchor = None
    if owner["kind"] == "SCA":
        hub_ids = [t["hub_id"] for t in targets.values()]
        anchor = str(owner.get("anchor_hub_id") or "")
        anchor = anchor if anchor in hub_ids else (hub_ids[0] if hub_ids else "")
        url = flow._card_url_of(db, project_id, anchor) if anchor else ""
        sca_anchor = {"hub_id": anchor, "url": url + "#sca-set-title"} if url else None
    from app import worklists
    # «К списку» – туда, откуда пришли (back из заготовки: список SCA или общий список находок, по строгому образцу
    # пути, как у карточки SCA), иначе к списку своего вида (ревью dev28)
    back_param = str(request.query_params.get("back") or "")[:2000]
    labels = {f"/projects/{project_id}/findings": "К списку находок"}
    if owner["kind"] == "SCA":
        labels[f"/projects/{project_id}/sca"] = "К списку SCA"
    back_path = back_param.split("?", 1)[0].split("#", 1)[0]
    back_fallback = back_path if back_path in labels else (
        f"/projects/{project_id}/sca" if owner["kind"] == "SCA" else f"/projects/{project_id}/findings")
    back_url = worklists.list_anchor(worklists.return_url(request, back_fallback))
    return {"project": project, "row": owner, "family": family, "targets": list(targets.values()),
            "unmerged": db.on_connection(lambda c: hub_defects.family_unmerged_in(c, owner)),
            "back_url": back_url, "back_label": labels[back_fallback], "back_param": back_param,
            "linked": linked_rows(db, project_id, owner, hub_obj, list(targets.values())),
            "hub_lines": hub_lines, "hub_block_html": hub_block_html, "hub_block_source": hub_block_source,
            "dropped": db.dropped_findings(project_id, int(owner["id"])),
            "foreign_keys": hub_defects.foreign_number_keys(db, owner) if owner.get("hub_defect_id") else [],
            "number_releases": db.on_connection(lambda c: hub_defects.number_releases_in(c, owner)),
            "sca_anchor": sca_anchor,
            "catalog_url": f"/projects/{project_id}/defects" + ("?" + urlencode(catalog_query) if catalog_query else ""),
            "catalog_qs": "?" + urlencode(form_query) if form_query else "",
            "problem": problem, "local_edit_problem": problem,
            # «Push в Hub» – главная кнопка только при неотправленной правке; основа полей неизвестна – Push всё равно откажет
            "push_main": bool(basis["known"] and defect_fields.unsent_edit(owner)),
            "draft_unsent": defect_drafts.local_edit(owner)["edited"],
            "update_problem": db.on_connection(lambda c: hub_defects._update_idle_problem(c, owner)),
            "view": hub_defects.view(owner), "upd": upd, "retry": flow.retry_context(db, project_id, owner),
            "create_preview": hub_defects.preview(db, owner, lambda h: flow._card_url_of(db, project_id, h)),
            "confirmation_rows": [{"row": physical, "view": hub_defects.view(physical)} for physical in family
                                  if hub_defects.view(physical).get("diff") or hub_defects.view(physical).get("verify")],
            "imp": flow.import_context(db, settings, project, owner) or {"hub_update": upd},
            "draft_summary": owner["draft_summary"], "draft_command_text": owner["draft_command_text"],
            "confirmed": confirmed, "comparisons": comparisons,
            "draft_fields": loads(owner["draft_fields_json"], {}),
            "basis": basis, "basis_seen": basis_seen, "basis_source": "sync" if sync_seen else "observation",
            "basis_shown": defect_references.signature(basis_seen),
            "controls": defect_form.controls(loads(owner["draft_fields_json"], {}), basis, choices),
            "form_values": {}, "reference_load": latest["id"] if latest else "", "reference_rows": reference_rows,
            "reference_latest": latest, "can_read": can_read,
            "reference_labels": {"preview": "ожидает подтверждения", "loading": "загружается", "done": "получена",
                                 "failed": "ошибка", "cancelled": "отменена"},
            "conflict_groups": groups, "conflict_explanation": defect_local_text.explanation(groups),
            "observed": loads(owner["import_json"], {}), "attempt": hub_defects.update_state(owner),
            "conflicts": loads(owner["conflicts_json"], []),
            "decisions": decisions,
            "history": db._all("SELECT * FROM hub_defect_history WHERE defect_id = ? ORDER BY id DESC", (owner["id"],)),
            "state_labels": hub_defects.STATE_LABELS,
            "decision_labels": {**VERDICT_LABELS, **DECISION_LABELS},
            "history_labels": {"migration": "обновление схемы", "create": "создание черновика",
                               "edit": "правка черновика", "hub_confirm": "подтверждение в Hub",
                               "hub_sync": "принятие версии Hub"},
            "defect_card": True, "error": ""}


@router.get("/projects/{project_id}/defects/{defect_id}")
def card(request: Request, project_id: int, defect_id: int):
    return render(request, "projects/defect_card.html", page_context(request, project_id, defect_id))


async def save(request: Request, project_id: int, defect_id: int, generate: bool):
    form = await request.form(max_fields=1000, max_files=0)
    values = {"draft_summary": str(form.get("summary") or ""), "draft_command_text": str(form.get("command_text") or "")}

    def apply():
        project_or_404(request, project_id)
        db = db_of(request)
        row = db.hub_defect(defect_id)
        if row is None or row["project_id"] != project_id:
            raise HTTPException(404, "Дефект не найден.")
        owner = db.on_connection(lambda c: defect_drafts.owner_in(c, row))
        ref_id = str(form.get("reference_load") or "")
        if ref_id and not ref_id.isdigit():
            raise defect_fields.FieldError("Неверный идентификатор снимка справочников.")
        choices, _ = db.on_connection(lambda c: defect_references.choices_in(c, owner, int(ref_id) if ref_id else None))
        operations = defect_form.parse(form, loads(owner["draft_fields_json"], {}), choices) if not generate else None
        return defect_drafts.save(db, row, str(form.get("draft_revision") or ""),
                                  summary=values["draft_summary"], command=values["draft_command_text"],
                                  generate=(lambda owner: defect_local_text.generate(request, owner)) if generate else None,
                                  operations=operations, reference_load=int(ref_id) if ref_id else None)

    try:
        owner = await run_in_threadpool(apply)
    except ValueError as exc:
        context = await run_in_threadpool(page_context, request, project_id, defect_id)
        # отказ сборки, который карточка и так показывает с подсказкой, второй раз не выводится
        shown = "; ".join((context.get("decisions") or {}).get("refusals") or [])
        context.update(error="" if generate and str(exc) == shown else str(exc))
        if not generate:
            context.update(values, form_values=dict(form), bug_order=form.getlist("bug_order"))
            # При отказе старой формы показываем варианты именно её загрузки, а не более новой из другой вкладки.
            selected = next((r for r in context["reference_rows"] if str(r["id"]) == str(form.get("reference_load"))
                             and r["state"] == "done"), None)
            if selected:
                choices = loads(selected["load_json"], {}).get("projection", {})
                context.update(reference_latest=selected,
                               controls=defect_form.controls(context["draft_fields"], context["basis"], choices))
        return render(request, "projects/defect_card.html", context,
                      status_code=422 if isinstance(exc, defect_fields.FieldError) else 409)
    # отборы каталога (page, q, sort, kind, state, origin, page_size) – дальше в карточку, для «Дефекты» в цепочке
    keep = {k: request.query_params[k] for k in (*CATALOG_KEYS, "back") if k in request.query_params}
    return redirect(f"/projects/{project_id}/defects/{owner['id']}" + ("?" + urlencode(keep) if keep else ""))


@router.post("/projects/{project_id}/defects/{defect_id}/fields")
async def fields(request: Request, project_id: int, defect_id: int):
    return await save(request, project_id, defect_id, False)


@router.post("/projects/{project_id}/defects/{defect_id}/text-from-decisions")
async def from_decisions(request: Request, project_id: int, defect_id: int):
    return await save(request, project_id, defect_id, True)


@router.post("/projects/{project_id}/defects/{defect_id}/basis")
async def use_basis(request: Request, project_id: int, defect_id: int):
    form = await request.form(max_fields=4, max_files=0)
    context = await run_in_threadpool(page_context, request, project_id, defect_id)
    try:
        await run_in_threadpool(defect_drafts.use_basis, db_of(request), context["row"], form.get("draft_revision"),
                                form.get("source"), form.get("shown"))
    except ValueError as exc:
        context["error"] = str(exc)
        return render(request, "projects/defect_card.html", context, status_code=409)
    keep = {k: request.query_params[k] for k in (*CATALOG_KEYS, "back") if k in request.query_params}
    return redirect(f"/projects/{project_id}/defects/{context['row']['id']}" + ("?" + urlencode(keep) if keep else ""))


@router.post("/projects/{project_id}/defects/{defect_id}/release-number")
async def release_number(request: Request, project_id: int, defect_id: int):
    """«Снять номер ID<n> с находок вне дефекта»: номер дефекта остался за ключами находок,
    которых в его составе больше нет. Снимается только показанное (keys), в одной транзакции и с теми же проверками:
    номер тот же, ключ не свой, не числится за другой записью, тот же номер не резервирует другая запись."""
    form = await request.form(max_fields=40, max_files=0)
    context = await run_in_threadpool(page_context, request, project_id, defect_id)
    row = context["row"]
    keys, stamps = [str(k) for k in form.getlist("key")], [str(a) for a in form.getlist("assigned_at")]
    if len(keys) != len(stamps):
        raise HTTPException(400, "Форма снятия номера неполная: обновите страницу.")
    shown = dict(zip(keys, stamps, strict=True))

    def apply():
        db = db_of(request)
        with db._tx() as c:
            current = dict(c.execute("SELECT * FROM hub_defects WHERE id = ?", (int(row["id"]),)).fetchone())
            if str(current.get("number")) != str(form.get("number") or "") or not shown:
                raise ValueError("Номер дефекта изменился: обновите страницу.")
            if str(hub_defects.number_releases_in(c, current)) != str(form.get("releases") or ""):
                raise ValueError("Номер уже снимали с этой страницы: обновите страницу.")
            for key, stamp in shown.items():  # то же назначение, что показано: повтор старой формы новый номер не снимет
                have = c.execute("SELECT assigned_at FROM defects WHERE project_id = ? AND defect_key = ?",
                                 (project_id, key)).fetchone()
                if have is None or str(have["assigned_at"]) != stamp:
                    raise ValueError("Номер у этих находок выдан заново или уже снят: обновите страницу.")
            own = hub_defects.own_number_keys_in(c, current, hub_defects.family_targets_in(c, current))
            released = hub_defects.release_number_in(c, current, current["number"], shown, own)
            if sorted(released) != sorted(set(shown)):
                raise ValueError("Часть номеров снять нельзя: ключ стал своим, его держит другая запись или номер "
                                 "сменился. Обновите страницу.")
            # снятый ключ уходит и из ключей номера семьи: отложенное последствие подтверждения не вернёт номер
            owner_id = int(current.get("draft_owner_id") or current["id"])
            for member in c.execute("SELECT id, number_keys_json FROM hub_defects WHERE COALESCE(draft_owner_id, id) = ?",
                                    (owner_id,)).fetchall():
                keys = loads(member["number_keys_json"], [])
                if set(keys) & set(released):
                    c.execute("UPDATE hub_defects SET number_keys_json = ? WHERE id = ?",
                              (dumps([k for k in keys if k not in released]), member["id"]))
            defect_drafts.history(c, defect_drafts.owner_in(c, current), "edit",
                                  details={"released_number": current["number"], "keys": released})

    try:
        await run_in_threadpool(apply)
    except ValueError as exc:
        context = await run_in_threadpool(page_context, request, project_id, defect_id)
        context["error"] = str(exc)
        return render(request, "projects/defect_card.html", context, status_code=409)
    return redirect(flow._card_url(project_id, row["id"], await request.form(), ok="number_released"))


@router.post("/projects/{project_id}/defects/{defect_id}/references/prepare")
def references_prepare(request: Request, project_id: int, defect_id: int):
    context = page_context(request, project_id, defect_id)
    if not context["can_read"]:
        raise HTTPException(409, "Загрузка для текущего Hub и приложения недоступна.")
    row, settings = context["row"], settings_of(request)
    try:
        load_id = defect_references.prepare(db_of(request), row, settings.hub_url, context["project"]["hub_app_id"],
                                            flow._update_target(request, project_id, row))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return redirect(f"/projects/{project_id}/defects/{row['id']}/references/{load_id}")


@router.get("/projects/{project_id}/defects/{defect_id}/references/{load_id}")
def references_state(request: Request, project_id: int, defect_id: int, load_id: int):
    context = page_context(request, project_id, defect_id)
    row = db_of(request)._one("SELECT * FROM hub_defect_reference_loads WHERE id = ? AND project_id = ?",
                              (load_id, project_id))
    if (row is None or row["hub_url"] != context["row"]["hub_url"] or row["app_id"] != context["row"]["app_id"]
            or row["state"] == "preview" and loads(row["load_json"], {}).get("defect_id") != context["row"]["id"]):
        raise HTTPException(404, "Загрузка не найдена.")
    context.update(reference=row, plan=loads(row["load_json"], {}), shown=defect_references.signature(loads(row["load_json"], {})))
    return render(request, "projects/defect_references.html", context)


@router.post("/projects/{project_id}/defects/{defect_id}/references/load")
async def references_load(request: Request, project_id: int, defect_id: int):
    form = await request.form(max_fields=4, max_files=0)
    context = await run_in_threadpool(page_context, request, project_id, defect_id)
    row, db = context["row"], db_of(request)
    try:
        load_id = int(str(form.get("load_id") or ""))
        if form.get("action") == "cancel":
            with db._tx() as c:
                found = c.execute("SELECT * FROM hub_defect_reference_loads WHERE id = ? AND project_id = ?",
                                  (load_id, project_id)).fetchone()
                plan = loads(found["load_json"], {}) if found else {}
                if (not found or found["state"] != "preview" or plan.get("defect_id") != row["id"]
                        or defect_references.signature(plan) != form.get("shown")):
                    raise ValueError("Предпросмотр изменился.")
                c.execute("UPDATE hub_defect_reference_loads SET state = 'cancelled' WHERE id = ?", (load_id,))
        else:
            if not context["can_read"] or form.get("action") != "confirm":
                raise ValueError("Подтверждение загрузки недоступно.")
            await run_in_threadpool(defect_references.load, db, row, load_id, form.get("shown"),
                                    settings_of(request).hub_url, context["project"]["hub_app_id"],
                                    flow._update_target(request, project_id, row))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return redirect(f"/projects/{project_id}/defects/{row['id']}/references/{load_id}")

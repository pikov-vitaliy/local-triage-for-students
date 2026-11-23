"""Одно решение на отмеченные находки SAST (план dev7, раздел 7), по образцу пакетного решения SCA: один вывод, текст и рекомендация
сразу на отмеченные находки, с предпросмотром состава и отказом при устаревшей версии находки или вердикта. В Hub ничего не уходит."""

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from app import defect, hub_defects, hub_status, i18n
from app.db import source_version
from app.hub_entity_versions import digest
from app.models import Finding
from app.routes import defect_selected, hub_defect_routes as flow
from app.routes.common import db_of, project_or_404, redirect, register_messages, render
from app.routes.hub_bulk import MAX_SELECTED

router = APIRouter()
OUTCOMES = i18n.Labels({"false_positive": "Ложное срабатывание", "true_positive": "Подтверждаю дефект"})
STALE = i18n.N_("Состав, данные или решения изменились после показа: проверьте состав и подтвердите ещё раз. Ничего не "
                "сохранено.")
register_messages({"decide_selected": "Решение сохранено на всех находках показанного состава."})


def assess(request, c, project, selected, outcome, comment, fix):
    """Состав: кто войдёт, кто исключён и почему, чьи решения будут заменены. snapshot – отпечаток показанного состояния."""
    db, pid = db_of(request), project["id"]
    ready, excluded, replacements = [], [], []
    for hub_id in selected:
        row = db.get_finding_by_hub_id(pid, hub_id)
        url = flow._card_url_of(db, pid, hub_id) if row else ""
        try:
            if row is None or row.get("missing"):
                raise hub_defects.DefectRefused(i18n._("находки нет в текущей выгрузке"))
            if row["kind"] != "SAST":
                raise hub_defects.DefectRefused(i18n._("не SAST: решение по SCA – в карточке версии компонента"))
            bound = db.hub_defect_bound_in(c, pid, hub_id)
            if bound is not None:  # решение находки в дефекте – через дефект
                raise hub_defects.DefectRefused(i18n._("входит в {defect}: решение меняется в карточке находки",
                                                        defect=hub_defects.bound_name(bound)))
            ident = hub_status.issue_id(hub_id)
            why = defect_selected.busy_reason(db, c, pid, hub_id, ident)
            if why:
                raise hub_defects.DefectRefused(why)
            snap = defect_selected.target_snapshot(request, c, pid, hub_id)
        except ValueError as e:
            excluded.append({"hub_id": hub_id, "why": str(e), "url": url})
            continue
        old = snap["review"]
        case = snap["case"] or {}
        ready.append({"hub_id": hub_id, "url": url, "finding": Finding.from_dict(row["data"]), "snapshot": snap,
                      "version": source_version(snap["source"]), "revision": old.get("revision", 0),
                      "verdict_id": case.get("verdict_id"), "code_hash": snap["code"]["hash"], "code_chars": snap["code"]["chars"]})
        if (old.get("decision") or old.get("final_comment")) and hub_defects.decision_changes(
                old, "disagree", outcome, comment, fix if outcome == "true_positive" else ""):
            replacements.append({"hub_id": hub_id, "revision": old.get("revision", 0),
                                 # «Отложено» и «Риск принят» – сам вид решения, вердикт при них прежний
                                 "outcome": (old.get("decision") if old.get("decision") in ("later", "risk_accepted")
                                             else old.get("final_verdict") or old.get("decision")),
                                 "comment": old.get("final_comment"), "fix": old.get("final_fix")})
    state = {"selected": selected, "outcome": outcome, "comment": comment, "fix": fix,
             "ready": [{k: r[k] for k in ("hub_id", "version", "revision", "verdict_id", "code_hash", "code_chars")} for r in ready],
             "excluded": excluded}
    return {"ready": ready, "excluded": excluded, "replacements": replacements, "snapshot": digest(state)}


def text_refusal(request, project_id, view, outcome, comment, fix) -> str:
    """Что мешает сохранить: те же требования, что в карточке находки."""
    from app.routes import findings as card
    if outcome not in OUTCOMES:
        return i18n._("Выберите решение: «Ложное срабатывание» или «Подтверждаю дефект».")
    if not defect.reason_text(comment):
        return card.SAST_NEED_REASON[outcome]
    if outcome == "true_positive" and not defect.has_recommendation(fix):
        return i18n._(card.SAST_NEED_FIX)
    if len(comment) > card.MAX_COMMENT or len(fix) > card.MAX_FIX:
        return i18n._("Текст решения слишком длинный: сократите его.")
    if not view["ready"]:
        return i18n._("Нет находок, на которые можно сохранить решение.")
    db = db_of(request)
    for r in view["ready"]:
        origin = card.comment_origin(db, r["snapshot"]["case"], r["snapshot"]["review"], comment, project_id=project_id, hub_id=r["hub_id"])
        if origin and origin != outcome:
            return i18n._("{id}: текст написан моделью к другому исходу, поправьте его.", id=r['hub_id'])
    return ""


def apply(request, project_id, selected, outcome, comment, fix, shown, confirmed, overwrite) -> int:
    from app.routes import findings as card
    db = db_of(request)
    project = project_or_404(request, project_id)
    view = db.on_connection(lambda c: assess(request, c, project, selected, outcome, comment, fix))
    refusal = text_refusal(request, project_id, view, outcome, comment, fix)
    if refusal:
        raise hub_defects.DefectRefused(refusal)
    if not shown or shown != view["snapshot"]:
        raise hub_defects.DefectRefused(i18n._(STALE))
    if not confirmed:
        raise hub_defects.DefectRefused(i18n._("Подтвердите состав и общее решение."))
    if view["replacements"] and not overwrite:
        raise hub_defects.DefectRefused(i18n._("Подтвердите замену перечисленных решений."))
    items = []
    for r in view["ready"]:
        snap, old = r["snapshot"], r["snapshot"]["review"]
        case = snap["case"] or {}
        decision, chosen = card.sast_choice(outcome, "", case.get("verdict"), snap["code"]["stale_verdict"], old,
                                            case.get("verdict_id"))
        items.append(dict(hub_id=r["hub_id"], decision=decision, final_verdict=chosen, final_comment=comment,
                          final_fix=fix if outcome == "true_positive" else "", reviewed=True, verdict_id=case.get("verdict_id"),
                          expect={"version": r["version"], "revision": r["revision"], "verdict_id": case.get("verdict_id")},
                          code_hash=r["code_hash"], code_chars=r["code_chars"], require_present=True, recheck=True))

    def check(c) -> None:  # всё или ничего: состав перечитывается в транзакции записи
        if assess(request, c, project, selected, outcome, comment, fix)["snapshot"] != shown:
            raise hub_defects.DefectRefused(i18n._(STALE))

    db.save_reviews(project_id, items, check=check)
    return len(items)


def page(request, project_id, selected, outcome="", comment="", fix="", *, confirm=False, error="", status=200):
    project, db = project_or_404(request, project_id), db_of(request)
    view = db.on_connection(lambda c: assess(request, c, project, selected, outcome, comment, fix))
    if confirm:
        refusal = text_refusal(request, project_id, view, outcome, comment, fix)
        if refusal:
            error, confirm, status = refusal, False, 400
    return render(request, "findings/decision_selected.html", dict(project=project, selected=selected, outcome=outcome, outcomes=OUTCOMES,
                  comment=comment, fix=fix, confirm=confirm, error=error, **view), status_code=status)


@router.get("/projects/{project_id}/hub/decide-selected")
async def selected_page(request: Request, project_id: int):
    try:
        selected = defect_selected.selection(request.query_params.getlist("hub_id"))
    except ValueError as e:
        return await run_in_threadpool(page, request, project_id, [], error=str(e), status=400)
    return await run_in_threadpool(page, request, project_id, selected)


@router.post("/projects/{project_id}/hub/decide-selected")
async def selected_submit(request: Request, project_id: int):
    form = await request.form(max_fields=MAX_SELECTED + 20, max_files=0)
    selected = form.getlist("hub_id")
    outcome = str(form.get("outcome") or "")
    comment = str(form.get("comment") or "").replace("\r\n", "\n")
    fix = str(form.get("fix") or "").replace("\r\n", "\n")
    try:
        selected = defect_selected.selection(selected)
        if form.get("action") == "apply":
            await run_in_threadpool(apply, request, project_id, selected, outcome, comment, fix, str(form.get("snapshot") or ""),
                                    form.get("confirm") == "1", form.get("overwrite") == "1")
            return redirect(f"/projects/{project_id}/findings?kind=SAST&ok=decide_selected")
        return await run_in_threadpool(page, request, project_id, selected, outcome, comment, fix, confirm=form.get("action") == "preview")
    except ValueError as e:
        if len(set(selected)) > MAX_SELECTED:
            selected = []
        return await run_in_threadpool(page, request, project_id, selected, outcome, comment, fix, error=str(e), status=409)

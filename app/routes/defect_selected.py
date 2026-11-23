"""ADR-0122, 7а: выбранный состав SAST, одно решение и одна строка создания."""

from fastapi import APIRouter, Request
from starlette.concurrency import run_in_threadpool

from app import defect, hub_defects, hub_ops, hub_status, hub_sync, i18n
from app.db import dumps, loads, source_signature, source_version
from app.hub_entity_versions import digest
from app.hub_import import _cwe2
from app.models import Finding
from app.routes import hub_defect_routes as flow
from app.routes.common import db_of, project_or_404, redirect, render, settings_of
from app.routes.hub_bulk import MAX_SELECTED
from app.routes.hub_status_routes import hub_target_check, send_blocker

router = APIRouter()
CONTRACT = "selected-defect/1"
STALE = i18n.N_("Состав, данные или решение изменились после показа: проверьте состав и подтвердите подготовку заново.")


def selection(values):
    """Сохраняет порядок и уникальность; непригодные ID показываются среди исключений."""
    result = list(dict.fromkeys(str(value).strip() for value in values))
    if len(result) > MAX_SELECTED:
        raise hub_defects.DefectRefused(i18n._("Выбрано {count} находок; допускается не более {limit}.", count=len(result),
                                               limit=MAX_SELECTED))
    return result


def attempt(row):
    saved = loads(row.get("source_fingerprint"), {})
    return saved if isinstance(saved, dict) and saved.get("contract") == CONTRACT else None


def bases(c, project_id, hub_url, app_id):
    """Принятые версии назначения: изменение состава Hub делает подтверждение устаревшим."""
    return [dict(r) for r in c.execute(
        "SELECT entity_kind, entity_key, accepted_epoch, accepted_hash FROM hub_entity_versions"
        " WHERE project_id=? AND hub_url=? AND app_id=? ORDER BY entity_kind, entity_key",
        (project_id, hub_ops.hub_base(hub_url), app_id))]


def target_snapshot(request, c, project_id, hub_id):
    from app.routes import findings as card
    db = db_of(request)
    source = db.case_input(project_id, hub_id)
    if source is None or source.get("missing"):
        raise hub_defects.DefectRefused(i18n._("Находка отсутствует: подтвердите состав заново."))
    case = db.get_case(project_id, hub_id)
    raw = c.execute("SELECT * FROM reviews WHERE project_id=? AND hub_id=?", (project_id, hub_id)).fetchone()
    review = dict(raw) if raw else {}
    f = Finding.from_dict(source["data"])
    # срез разбора модели не совпадает с текущим – предупреждение в составе, а не исключение (ADR-0147); исход
    # сохраняется «Не согласен» со своим вердиктом (sast_choice получает stale_verdict)
    code = card.check_code(request, project_id, f, case, "", None)
    if review.get("finding_sig") and review["finding_sig"] != source_signature(source):
        raise hub_defects.DefectRefused(i18n._("источник изменился после решения: проверьте находку в карточке"))
    return {"hub_id": hub_id, "source": source, "review": review,
            "case": case, "code": code,
            "number": db.defect_number(project_id, defect.defect_key_sast(hub_id))}


def group_check(db, c, project_id, hub_id, body, targets, hub_url, app_id, own_id=None):
    """Каждая исходная группа; сосед не добавляется в состав даже при одинаковом тексте."""
    flow.group_defect_check(db, project_id, hub_id, body, targets, hub_url=hub_url,
                            app_id=app_id, in_preview=own_id is not None)(c)
    for neighbor in db._group_neighbor_ids(c, project_id, hub_id):
        if neighbor in targets:
            continue
        row = db.hub_defect_for(project_id, [neighbor])
        if (row and row["id"] != own_id and row["state"] in ("blank", "preview")
                and flow._same_hub(row, hub_url, app_id) and defect.body_key(row["command_text"]) == defect.body_key(body)):
            raise hub_defects.DefectRefused(i18n._("в группе уже готовится дефект с тем же текстом: завершите его подготовку"))


def busy_reason(db, c, project_id, hub_id, issue_id, own_id=None):
    """Причина занятости называет первую подходящую строку, а её текст входит в подпись предпросмотра: порядок – по номеру,
    иначе перестановка строк в таблице сделала бы показанную форму устаревшей без единой правки."""
    for row in c.execute(f"SELECT * FROM hub_defects WHERE project_id=? AND {db.HUB_DEFECT_RESERVING} ORDER BY id", (project_id,)):
        if row["id"] == own_id:
            continue
        if any(str(t.get("hub_id")) == hub_id or (t.get("issue_id") == issue_id and t.get("issue_type") == "SAST")
               for t in loads(row["targets_json"], [])):
            return i18n._("занята другим дефектом или подготовкой №{id} ({state})", id=row['id'],
                          state=hub_defects.STATE_LABELS.get(row['state'], row['state']))
    for op in c.execute("SELECT id, targets_json FROM hub_ops WHERE project_id=? AND purpose='status'"
                         " AND state IN ('queued','taken','unknown') ORDER BY id", (project_id,)):
        if any(t.get("issue_id") == issue_id and t.get("issue_type") == "SAST" for t in loads(op["targets_json"], [])):
            return i18n._("незавершённая операция статуса №{id}: дождитесь итога или сверьте результат", id=op['id'])
    return ""


def assess(request, c, project, selected, anchor, comment, fix):
    """Локальный снимок для показа и повторной проверки на том же соединении."""
    db, settings, pid = db_of(request), settings_of(request), project["id"]
    selected = selection(selected)
    anchor = anchor or (selected[0] if selected else "")
    anchor_row = db.get_finding_by_hub_id(pid, anchor) if anchor in selected else None
    f0 = Finding.from_dict(anchor_row["data"]) if anchor_row else None
    ready, excluded, snapshots = [], [], []
    app_id = int(project.get("hub_app_id") or 0)
    body = defect.sast_body(f0, "true_positive", comment, fix, settings.team_name) if defect.has_recommendation(fix) else ""
    aliases = {}
    for raw in c.execute("SELECT hub_id FROM findings WHERE project_id=? AND kind='SAST'", (pid,)):
        try:
            ident = hub_status.issue_id(raw["hub_id"])
        except hub_status.StatusRefused:
            continue
        aliases.setdefault(ident, []).append(raw["hub_id"])
    for hub_id in selected:
        row = db.get_finding_by_hub_id(pid, hub_id)
        why, snap = "", None
        f = Finding.from_dict(row["data"]) if row else None
        url = flow._card_url_of(db, pid, hub_id) if row else ""
        try:
            if f is None or row.get("missing"):
                raise hub_defects.DefectRefused(i18n._("находка отсутствует по принятому состоянию Hub или выгрузке"))
            if f.kind != "SAST":
                raise hub_defects.DefectRefused(i18n._("не SAST: для SCA откройте карточку соответствующего набора"))
            if not f0 or f0.kind != "SAST":
                raise hub_defects.DefectRefused(i18n._("выберите опорную находку SAST из исходного выбора"))
            if f.codebase != f0.codebase:
                raise hub_defects.DefectRefused(i18n._("другая кодовая база"))
            if f.rule != f0.rule:
                raise hub_defects.DefectRefused(i18n._("другая категория"))
            if _cwe2(f.cwe) != _cwe2(f0.cwe):
                raise hub_defects.DefectRefused(i18n._("другой набор CWE"))
            ident = hub_status.issue_id(hub_id)
            if len(aliases.get(ident, [])) != 1:
                raise hub_defects.DefectRefused(i18n._("неоднозначное сопоставление номера Hub после нормализации"))
            why = busy_reason(db, c, pid, hub_id, ident)
            if why:
                raise hub_defects.DefectRefused(why)
            snap = target_snapshot(request, c, pid, hub_id)
            if body:
                # Невыбранные соседи, в том числе у второй и последней цели.
                group_check(db, c, pid, hub_id, body, [], settings.hub_url, app_id)
        except ValueError as e:
            why = str(e)
        snapshots.append({"hub_id": hub_id, "row": row, "snapshot": snap, "why": why})
        if why:
            excluded.append({"hub_id": hub_id, "why": why, "url": url})
        else:
            ready.append({"hub_id": hub_id, "url": url, "finding": f, "snapshot": snap,
                          "issue_id": ident, "issue_type": "SAST"})
    numbers = {r["snapshot"]["number"] for r in ready if r["snapshot"]["number"] is not None}
    problems = []
    if len(numbers) > 1:
        problems.append(i18n._("У выбранных находок разные номера ID: автоматическое объединение номеров не выполняется."))
    number = next(iter(numbers)) if len(numbers) == 1 else db.next_defect_number(pid)
    keys = [defect.defect_key_sast(r["hub_id"]) for r in ready]
    if db.hub_defects_with_number(pid, number) or set(db.defect_keys_with_number(pid, number)) - set(keys):
        problems.append(i18n._("Номер ID{number} удерживают другие находки или подготовка: нужен новый предпросмотр.",
                               number=number))
    if not ready:
        problems.append(i18n._("Нет находок, пригодных для подготовки дефекта."))
    elif len(",".join(str(r["issue_id"]) for r in ready)) > hub_defects.ISSUE_IDS_MAX:
        size = len(",".join(str(r["issue_id"]) for r in ready))
        problems.append(i18n._("Состав из {count} находок: issueIds занимает {size} знаков при пределе {limit}. Выберите "
                               "меньше находок; решения не сохранены.", count=len(ready), size=size,
                               limit=hub_defects.ISSUE_IDS_MAX))
    from app.routes import findings as card
    anchor_ready = next((r for r in ready if r["hub_id"] == anchor), None)
    model = card.model_suggestion(f0, anchor_ready["snapshot"]["case"]) if anchor_ready else {}
    warnings = [i18n._("Выбраны разные файлы одной кодовой базы: проверьте применимость общего решения.")] \
        if len({r["finding"].file for r in ready}) > 1 else []
    replacements = []
    for r in ready:
        old = r["snapshot"]["review"]
        if (old.get("decision") or old.get("final_comment") or old.get("final_fix")) and hub_defects.decision_changes(
                old, "disagree", "true_positive", comment, fix):
            replacements.append({"hub_id": r["hub_id"], "revision": old["revision"],
                                 "outcome": old.get("final_verdict") or old.get("decision"),
                                 "comment": old.get("final_comment"), "fix": old.get("final_fix")})
    state = {"contract": CONTRACT, "project_id": pid, "hub_url": hub_ops.hub_base(settings.hub_url),
             "app_id": app_id, "selected": selected, "anchor": anchor, "snapshots": snapshots,
             "comment": comment, "fix": fix, "body": body, "number": number, "keys": keys,
             "bases": bases(c, pid, settings.hub_url, app_id), "problems": problems,
             "replacements": replacements, "service": bool(hub_defects.service_info(db, settings.hub_url))}
    return {"ready": ready, "excluded": excluded, "warnings": warnings, "problems": problems,
            "replacements": replacements, "number": number, "body": body, "anchor_finding": f0,
            "anchor": anchor, "snapshot": digest(state), "state": state, "model": model,
            "anchor_ready": anchor_ready is not None}


def text_check(request, project_id, view, comment, fix):
    from app.routes import findings as card
    if not defect.reason_text(comment):
        raise hub_defects.DefectRefused(card.SAST_NEED_REASON["true_positive"])
    if not defect.has_recommendation(fix):
        raise hub_defects.DefectRefused(i18n._(card.SAST_NEED_FIX))
    if len(comment) > card.MAX_COMMENT or len(fix) > card.MAX_FIX:
        raise hub_defects.DefectRefused(i18n._("Обоснование или рекомендация слишком длинные: сократите текст."))
    db = db_of(request)
    for r in view["ready"]:
        snap = r["snapshot"]
        origin = card.comment_origin(db, snap["case"], snap["review"], comment,
                                     project_id=project_id, hub_id=r["hub_id"])
        if origin and origin != "true_positive":
            raise hub_defects.DefectRefused(i18n._("{id}: обоснование написано моделью к другому исходу; поправьте текст.",
                                                   id=r['hub_id']))
    problems = flow.sast_text_problems(db, settings_of(request), project_id, view["body"])
    if problems:
        from app import defect_check
        raise hub_defects.DefectRefused(defect_check.refusal(problems))


def prepare(request, project_id, selected, anchor, comment, fix, shown, confirmed, overwrite):
    from app.routes import findings as card
    db = db_of(request)
    prepared = {}

    def check(c):
        project = project_or_404(request, project_id)
        settings = settings_of(request)
        view = assess(request, c, project, selected, anchor, comment, fix)
        if not shown or shown != view["snapshot"]:
            raise hub_defects.DefectRefused(i18n._(STALE))
        if not confirmed:
            raise hub_defects.DefectRefused(i18n._("Подтвердите показанное решение и запросы подготовки."))
        if view["replacements"] and not overwrite:
            raise hub_defects.DefectRefused(i18n._("Подтвердите перезапись перечисленных решений."))
        blocker = send_blocker(settings, project) or hub_sync.resync_blocker(db_of(request), project_id)
        if blocker or view["problems"]:
            raise hub_defects.DefectRefused(blocker or " ".join(view["problems"]))
        text_check(request, project_id, view, comment, fix)
        hub_target_check(request, project_id, settings.hub_url, project["hub_app_id"])(c)
        # Даже отказ длины запроса обязан произойти до первого сохранения.
        hub_defects.blank_request(project["hub_app_id"], view["ready"], "SAST")
        prepared.update(view=view, project=project, settings=settings)
        reviews = []
        for r in view["ready"]:
            snap = r["snapshot"]
            case, old, code = snap["case"] or {}, snap["review"], snap["code"]
            decision, outcome = card.sast_choice("true_positive", "", case.get("verdict"), code["stale_verdict"], old,
                                                  case.get("verdict_id"))
            reviews.append(dict(hub_id=r["hub_id"], decision=decision, final_verdict=outcome,
                                final_comment=comment, final_fix=fix, reviewed=True, verdict_id=case.get("verdict_id"),
                                expect={"version": source_version(snap["source"]), "revision": old.get("revision", 0),
                                        "verdict_id": case.get("verdict_id")},
                                code_hash=code["hash"], code_chars=code["chars"], require_present=True))
        return reviews

    def build(c, saved):
        view, settings, project = prepared["view"], prepared["settings"], prepared["project"]
        targets = [flow._defect_target(r["finding"], review, view["body"], flow.defect_parts(settings, review),
                                      db.finding_sig(project_id, r["hub_id"]))
                   for r, review in zip(view["ready"], saved, strict=True)]
        snapshots = []
        for r in view["ready"]:
            current = target_snapshot(request, c, project_id, r["hub_id"])
            confirmed_code = r["snapshot"]["code"]
            if any(current["code"][key] != confirmed_code[key] for key in ("hash", "chars")):
                raise hub_defects.DefectRefused(i18n._(STALE))
            snapshots.append({"hub_id": r["hub_id"], "fingerprint": digest(current)})
        saved_attempt = {"contract": CONTRACT, "selected": selected, "anchor": view["anchor"],
                         "confirmation": shown, "bases": view["state"]["bases"],
                         "snapshots": snapshots}
        summary = defect.sast_title(view["number"], view["anchor_finding"])
        row = dict(kind="SAST", number=view["number"], summary=summary, anchor_hub_id=view["anchor"],
                   targets=targets, number_keys=view["state"]["keys"], command_text=view["body"],
                   hub_url=settings.hub_url, app_id=project["hub_app_id"], left_out=view["excluded"],
                   warnings=view["warnings"], source_fingerprint=dumps(saved_attempt))
        items = [dict(purpose="defect_blank", request=hub_defects.blank_request(project["hub_app_id"], targets, "SAST"),
                      hub_url=settings.hub_url, app_id=project["hub_app_id"], project_id=project_id,
                      targets=targets, text=summary)]
        if not view["state"]["service"]:
            items.append(dict(purpose="read", request=hub_defects.service_info_request(), hub_url=settings.hub_url,
                              app_id=project["hub_app_id"], project_id=project_id, targets=[]))
        return row, items

    return db.hub_defect_selected_start(project_id, check=check, build=build)


def create_check(request, c, row):
    """Состав не сокращается при позднем конфликте: вся постановка отклоняется."""
    saved = attempt(row)
    if saved is None:
        return
    db, pid = db_of(request), row["project_id"]
    targets = loads(row["targets_json"], [])
    ids = [t["hub_id"] for t in targets]
    if ids != [s["hub_id"] for s in saved["snapshots"]]:
        raise hub_defects.DefectRefused(i18n._(STALE))
    if saved["bases"] != bases(c, pid, row["hub_url"], row["app_id"]):
        raise hub_defects.DefectRefused(i18n._("Принятая база Hub изменилась: отмените предпросмотр и подготовьте заново."))
    if (db.hub_defects_with_number(pid, row["number"], exclude_id=row["id"])
            or set(db.defect_keys_with_number(pid, row["number"])) - set(loads(row["number_keys_json"], []))):
        raise hub_defects.DefectRefused(i18n._("Номер дефекта занят другой находкой: отмените предпросмотр и подготовьте заново."))
    for target, snapshot in zip(targets, saved["snapshots"], strict=True):
        if digest(target_snapshot(request, c, pid, target["hub_id"])) != snapshot["fingerprint"]:
            raise hub_defects.DefectRefused(i18n._(STALE))
        why = busy_reason(db, c, pid, target["hub_id"], target["issue_id"], row["id"])
        if why:
            raise hub_defects.DefectRefused(why)
        group_check(db, c, pid, target["hub_id"], row["command_text"], ids,
                    row["hub_url"], row["app_id"], row["id"])


def page(request, project_id, selected, anchor="", comment=None, fix=None, *, confirm=False, error="", status=200):
    project, db = project_or_404(request, project_id), db_of(request)
    selected = selection(selected)
    view = db.on_connection(lambda c: assess(request, c, project, selected, anchor, comment or "", fix or ""))
    if comment is None and fix is None:
        texts = {(r["snapshot"]["review"].get("final_comment", ""), r["snapshot"]["review"].get("final_fix", ""))
                 for r in view["ready"]}
        comment, fix = next(iter(texts)) if len(texts) == 1 else ("", "")
        view = db.on_connection(lambda c: assess(request, c, project, selected, anchor, comment, fix))
    if confirm:
        try:
            text_check(request, project_id, view, comment, fix)
        except ValueError as e:
            error, confirm, status = str(e), False, 400
    return render(request, "findings/defect_selected.html", dict(project=project, selected=selected,
                  comment=comment or "", fix=fix or "", confirm=confirm, error=error,
                  blocker=send_blocker(settings_of(request), project) or hub_sync.resync_blocker(db_of(request), project_id), **view), status_code=status)


@router.get("/projects/{project_id}/hub/defect-selected")
async def selected_page(request: Request, project_id: int):
    try:
        return await run_in_threadpool(page, request, project_id, request.query_params.getlist("hub_id"))
    except ValueError as e:
        return await run_in_threadpool(page, request, project_id, [], error=str(e), status=400)


@router.post("/projects/{project_id}/hub/defect-selected")
async def selected_submit(request: Request, project_id: int):
    form = await request.form(max_fields=MAX_SELECTED + 20, max_files=0)
    selected = form.getlist("hub_id")
    anchor = str(form.get("anchor") or "")
    comment = str(form.get("comment") or "").replace("\r\n", "\n")
    fix = str(form.get("fix") or "").replace("\r\n", "\n")
    try:
        selected = selection(selected)
        if form.get("action") == "prepare":
            row = await run_in_threadpool(prepare, request, project_id, selected, anchor, comment, fix,
                                          str(form.get("snapshot") or ""), form.get("confirm") == "1",
                                          form.get("overwrite") == "1")
            return redirect(f"/projects/{project_id}/defects/{row['id']}")
        return await run_in_threadpool(page, request, project_id, selected, anchor, comment, fix,
                                       confirm=form.get("action") == "preview")
    except ValueError as e:
        if len(set(selected)) > MAX_SELECTED:
            selected = []
        return await run_in_threadpool(page, request, project_id, selected, anchor, comment, fix,
                                       error=str(e), status=409)

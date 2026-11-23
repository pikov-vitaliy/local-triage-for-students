"""«Отправить выбранные в Hub» (этап 3, ADR-0119): несколько находок SAST, отмеченных галочками в списке, – один
статус «Ложное срабатывание», общий комментарий оператора и срок одним запросом (`POST /issue/status/change`;
одна находка – `/issue/status/update`). Запрос выполняет исполнитель (ADR-0114), отметку ставит ответ Hub
(hub_effects) – с отпечатком общего текста и признаком «общий комментарий» в частях отметки.

  GET  /projects/{id}/hub/send-selected?hub_id=…  – предпросмотр: кто уйдёт, кто исключён и почему, общий текст, срок;
                                                    с ?op= – состояние поставленной операции (опрос как у карточки)
  POST /projects/{id}/hub/send-selected           – постановка операции status; ответ – 303 на предпросмотр с ?op=
                                                    (форма без скрипта; JSON – только при Accept: application/json)
"""

from __future__ import annotations

import json
from datetime import timedelta

from fastapi import APIRouter, HTTPException, Request
from starlette.concurrency import run_in_threadpool

from app import hub_defects, hub_effects, hub_ops, hub_status, hub_sync, i18n
from app.db import Database, hub_verdict, loads, text_hash
from app.models import Finding
from app.routes.common import db_of, form_int, project_or_404, redirect, register_messages, render, settings_of
from app.routes.hub_status_routes import (
    StaleTarget,
    _answer,
    _finding_of,
    _project_op,
    _refused,
    _revisions_check,
    _target,
    checking_of,
    hub_target_check,
    is_fixed,
    op_view,
    same_target,
    send_blocker,
    shown_target,
    status_now_in,
    status_already_in,
    today,
    wants_json,
)
from app.sca_research import review_presets

router = APIRouter()

MAX_SELECTED = 50  # находок за одну отправку: больше – выберите часть
OUTCOME = "false_positive"
# форма предпросмотра несёт назначение, которое он показал (KIMI-12)
FORM_OUTDATED = i18n.N_("Страница открыта до обновления приложения: обновите предпросмотр и отправьте ещё раз – "
                        "ничего не отправлено.")
TARGET_CHANGED = i18n.N_("Приложение Hub или адрес Hub изменились, пока открыт предпросмотр (в другой вкладке – "
                         "«Параметры проекта» или «Настройки»): ничего не отправлено – обновите предпросмотр и отправьте "
                         "ещё раз.")

register_messages({
    "hub_bulk_queued": "Поставлено в очередь исполнителю: состояние – ниже, под перечнем находок.",
})


def bulk_parts(settings, review: dict, text: str) -> str:
    """Части отметки «Внесено в Hub» у массовой отправки: как у карточки (entered_parts), но отпечаток текста – общего
    комментария, и признак bulk: карточка не называет такую отметку «текст изменился» (ADR-0119)."""
    from app.routes import findings as card
    parts = json.loads(card.entered_parts(settings, review))
    parts.update(comment=text_hash(text), bulk=1)
    return json.dumps(parts, sort_keys=True)


def _unique_ids(values, limit: int | None = None) -> list[str]:
    """Безопасные номера (цифры, буквы, дефис, подчёркивание) без повторов, в порядке выбора; limit – достаточно
    первых limit (один проход, множество для повторов)."""
    seen: set[str] = set()
    result: list[str] = []
    for raw in values or []:
        hub_id = str(raw or "").strip()
        if hub_id and len(hub_id) <= 40 and all(ch.isalnum() or ch in "-_" for ch in hub_id) and hub_id not in seen:
            seen.add(hub_id)
            result.append(hub_id)
            if limit is not None and len(result) >= limit:
                break
    return result


def selected_ids(values) -> list[str]:
    """Номера находок из формы или адреса: без повторов, в порядке выбора, не больше MAX_SELECTED; только
    безопасные значения (цифры, буквы, дефис и подчёркивание)."""
    return _unique_ids(values, MAX_SELECTED)


def assess(db: Database, settings, project: dict, hub_ids: list[str]) -> tuple[list[dict], list[dict]]:
    """Состав отправки: ready – находки, которые уйдут (с редакцией, отпечатком данных и текстом сохранённого решения),
    excluded – исключённые с причиной. Правила – как у отправки из карточки (ADR-0115, ADR-0116): SAST, есть в
    выгрузке, сохранённое «Ложное срабатывание» с «Проверено», статуса в Hub ещё нет. Находка в дефекте, созданном в
    Hub, исключается с его номером – её статус противоречил бы дефекту (ADR-0121 п. 3)."""
    from app.routes import findings as card
    pid, status = int(project["id"]), hub_status.api_status(OUTCOME)
    app_id = int(project["hub_app_id"]) if project.get("hub_app_id") else None
    # незакрытые операции статуса – одним чтением на партию; ключи – как у постановки (lock_keys)
    open_ops = [(row, set(loads(row["lock_keys"], []))) for row in db.hub_open_ops(settings.hub_url, "status")]
    ready, excluded = [], []
    for hub_id in hub_ids:
        row = db.get_finding_by_hub_id(pid, hub_id)
        if row is None or row.get("missing"):
            excluded.append({"hub_id": hub_id, "why": i18n._("нет в текущей выгрузке")})
            continue
        if row["kind"] != "SAST":
            excluded.append({"hub_id": hub_id, "why": i18n._("не находка SAST – из списка уходят только SAST")})
            continue
        review = db.get_review(pid, hub_id)
        if not review or not review.get("decision"):
            excluded.append({"hub_id": hub_id, "why": i18n._("решения нет")})
            continue
        if hub_verdict(review["decision"], review.get("final_verdict") or "") != OUTCOME:
            excluded.append({"hub_id": hub_id, "why": i18n._("решение – не «Ложное срабатывание»")})
            continue
        if not review.get("reviewed"):
            excluded.append({"hub_id": hub_id, "why": i18n._("нет отметки «Проверено»")})
            continue
        bound = db.hub_defect_bound(pid, hub_id)
        if bound is not None:
            excluded.append({"hub_id": hub_id, "why": i18n._("входит в {defect} – статус противоречил бы дефекту в Hub",
                                                             defect=hub_defects.bound_name(bound))})
            continue
        found = Finding.from_dict(row["data"])
        if is_fixed(db.on_connection(lambda c, n=found: status_now_in(c, pid, n.hub_id, n.kind, n.status, settings.hub_url, app_id))):
            excluded.append({"hub_id": hub_id, "why": i18n._("статус в Hub – «Fixed»: Hub отклонил бы смену статуса")})
            continue
        # тот же предикат, что в транзакции постановки (status_already_in: версия или отказ Hub, назвавший находку)
        if db.status_in_hub(pid, hub_id, status, status_already_in, settings.hub_url, app_id):
            excluded.append({"hub_id": hub_id, "why": i18n._("статус уже внесён в Hub")})
            continue
        try:
            issue = hub_status.issue_id(hub_id)  # номер в Hub – только число (как у отправки из карточки)
        except hub_status.StatusRefused as e:
            excluded.append({"hub_id": hub_id, "why": str(e)})
            continue
        # та же область ключей, по которой очередь отказывает в постановке (lock_keys: адрес Hub, приложение, тип и
        # номер находки) – иначе очередь отказала бы всей партии; транзакция постановки проверяет ключи ещё раз
        locks = set(hub_ops.lock_keys(settings.hub_url, app_id, "status",
                                      [{"issue_type": hub_status.issue_type(row["kind"]), "issue_id": issue}]))
        busy = next((op for op, keys in open_ops if keys & locks), None)
        if busy is not None:
            excluded.append({"hub_id": hub_id, "why": i18n._("есть незакрытая операция №{op_id} («{state}») – "
                                                             "дождитесь её итога или сверьте результат",
                                                             op_id=busy['id'], state=busy['state'])})
            continue
        sig = db.finding_sig(pid, hub_id)  # до чтения данных: обновление выгрузки поймает транзакция
        f = _finding_of(db, pid, hub_id)
        if f is None:
            excluded.append({"hub_id": hub_id, "why": i18n._("нет в текущей выгрузке")})
            continue
        ready.append({"hub_id": hub_id, "id": int(row["id"]), "where": f"{f.file}:{f.line or '–'}", "rule": f.rule,
                      "revision": int(review.get("revision") or 0), "sig": sig,
                      "text": card.saved_hub_text(f, review, settings.hub_status_map), "finding": f, "review": review})
    return ready, excluded


def common_text(ready: list[dict]) -> str:
    """Общий комментарий по умолчанию: у всех один текст – он; иначе текст первой (оператор правит в предпросмотре)."""
    texts = [r["text"] for r in ready if r["text"]]
    return texts[0] if texts else ""


def _page(request: Request, project_id: int, hub_ids: list[str], op_id: int | None, error: str = "",
          comment: str | None = None, status_code: int = 200, too_many: bool = False):
    project = project_or_404(request, project_id)
    settings, db = settings_of(request), db_of(request)
    db.hub_expire_leases()
    blocker = send_blocker(settings, project) or hub_sync.resync_blocker(db, project_id)
    ready, excluded = assess(db, settings, project, hub_ids) if not blocker else ([], [])
    op = _project_op(request, project_id, op_id) if op_id is not None else None
    view = op_view(op, checking_of(db, op), hub_effects.effects_pending(db, op))
    now = today()
    return render(request, "findings/send_selected.html", {
        "project": project, "blocker": blocker, "ready": ready, "excluded": excluded,
        # назначение, по которому собран состав: форма отправляет его с запросом (shown_target, KIMI-12)
        "hub_base": hub_ops.hub_base(settings.hub_url), "hub_app_id": project.get("hub_app_id") or "",
        "comment": common_text(ready) if comment is None else comment,
        "hub_ids": hub_ids, "max_selected": MAX_SELECTED, "too_many": too_many,
        "presets": review_presets(now), "min": (now + timedelta(days=1)).isoformat(),
        "max": (now + timedelta(days=hub_status.EXPIRY_MAX_DAYS)).isoformat(),
        "op": op, "last": view, "poll_url": f"/projects/{project_id}/hub/ops/{op['id']}" if op and not view["final"] else "",
        "error": error, "reason_max": hub_status.REASON_MAX,
    }, status_code)


def _back_url(project_id: int, hub_ids: list[str], op_id: int | None = None, ok: str = "") -> str:
    query = "&".join(f"hub_id={h}" for h in hub_ids)
    if op_id is not None:
        query += f"&op={op_id}"
    if ok:
        query += f"&ok={ok}"
    return f"/projects/{project_id}/hub/send-selected?{query}"


@router.get("/projects/{project_id}/hub/send-selected")
def send_selected_page(request: Request, project_id: int):
    """Предпросмотр массовой отправки: состав, общий комментарий, срок; с ?op= – состояние операции."""
    raw = request.query_params.getlist("hub_id")
    # предупреждение о партии – только если отброшены настоящие номера сверх предела, а не повторы и мусор: одного
    # прохода до (MAX_SELECTED + 1)-го уникального номера достаточно
    unique = _unique_ids(raw, MAX_SELECTED + 1)
    hub_ids, too_many = unique[:MAX_SELECTED], len(unique) > MAX_SELECTED
    return _page(request, project_id, hub_ids, form_int(request.query_params.get("op")), too_many=too_many)


@router.post("/projects/{project_id}/hub/send-selected")
async def send_selected(request: Request, project_id: int):
    """Постановка операции status по выбранным находкам: общий комментарий и срок из формы; цели – ровно те, что
    показаны в предпросмотре (номер, редакция, отпечаток данных), состав сверяется ещё раз здесь и в транзакции."""
    form = await request.form(max_fields=MAX_SELECTED + 10, max_files=0)
    shown = [str(v) for v in form.getlist("target")]
    # края текста – в hub_status.clean_reason (ADR-0149 п. 5: отступ первой строки остаётся)
    comment = str(form.get("comment") or "").replace("\r\n", "\n")
    expires = str(form.get("expires") or "")
    hub_ids = selected_ids(t.split("|", 1)[0] for t in shown)
    target_shown = shown_target(form)  # адрес Hub и приложение, по которым собран показанный предпросмотр (KIMI-12)

    def apply():
        project = project_or_404(request, project_id)
        settings, db = settings_of(request), db_of(request)
        blocker = send_blocker(settings, project) or hub_sync.resync_blocker(db, project_id)
        if blocker:
            raise hub_status.StatusRefused(blocker)
        if not hub_ids:
            raise hub_status.StatusRefused(i18n._("Не выбрано ни одной находки."))
        # назначение сменили после показа предпросмотра – отказ сразу и ещё раз в транзакции (hub_target_check)
        if not same_target(settings.hub_url, project.get("hub_app_id"), target_shown):
            raise StaleTarget(i18n._(FORM_OUTDATED if not (target_shown[0] and target_shown[1]) else TARGET_CHANGED))
        shown_by_id = {}
        for item in shown:
            parts = item.split("|")
            if len(parts) == 3 and parts[0] in hub_ids:
                shown_by_id[parts[0]] = (parts[1], parts[2])
        ready, excluded = assess(db, settings, project, hub_ids)
        if excluded:
            raise StaleTarget(i18n._("Состав изменился, пока открыт предпросмотр – не отправляются: {items}. Обновите "
                                     "предпросмотр и отправьте ещё раз.",
                                     items="; ".join(f"{e['hub_id']} ({e['why']})" for e in excluded)))
        for r in ready:
            rev, sig = shown_by_id.get(r["hub_id"], ("", ""))
            if not rev.isdigit() or int(rev) != r["revision"] or sig != r["sig"]:
                raise StaleTarget(i18n._("Решение или данные находки {hub_id} изменились, пока открыт предпросмотр: "
                                         "обновите его и отправьте ещё раз.", hub_id=r['hub_id']))
        reason = hub_status.clean_reason(comment)
        expired = hub_status.expired_at(expires, today())
        status = hub_status.api_status(OUTCOME)
        targets = [_target(r["finding"], r["review"], reason, bulk_parts(settings, r["review"], reason), r["sig"])
                   for r in ready]
        app_id = int(project["hub_app_id"])
        # приложение и адрес Hub – показанные предпросмотром (поля формы) и те же, по которым собраны состав (assess) и
        # запрос (KIMI-12)
        hub_target = hub_target_check(request, project_id, settings.hub_url, app_id, TARGET_CHANGED, target_shown)
        revisions = _revisions_check(project_id, targets, status, [], settings.hub_url, app_id, check_all=True)

        def check(c) -> None:
            hub_target(c)
            revisions(c)
            for target in targets:  # находка попала в дефект после предпросмотра – партия не ставится (ADR-0121 п. 3)
                bound = Database.hub_defect_bound_in(c, project_id, target["hub_id"])
                if bound is not None:
                    raise StaleTarget(i18n._("Находка {hub_id} входит в {defect}: статус противоречил бы дефекту в "
                                             "Hub. Обновите предпросмотр и отправьте ещё раз.",
                                             hub_id=target['hub_id'], defect=hub_defects.bound_name(bound)))

        op = db.hub_enqueue(purpose="status", request=hub_status.status_request(targets, status, reason, expired),
                            hub_url=settings.hub_url, app_id=app_id, project_id=project_id, targets=targets,
                            text=reason, check=check)
        return op

    as_json = wants_json(request)
    try:
        op = await run_in_threadpool(apply)
    except HTTPException as e:
        return await _refused(request, as_json, str(e.detail), e.status_code)
    except hub_status.StatusRefused as e:
        if as_json:
            return await _refused(request, True, str(e), 400)
        return await run_in_threadpool(_page, request, project_id, hub_ids, None, str(e), comment, 400)
    except LookupError as e:
        return await _refused(request, as_json, str(e), 404)
    except ValueError as e:  # очередь: такая операция уже есть или у находки есть незакрытая
        if as_json:
            return await _refused(request, True, str(e), 409)
        return await run_in_threadpool(_page, request, project_id, hub_ids, None, str(e), comment, 409)
    if not as_json:
        return redirect(_back_url(project_id, hub_ids, int(op["id"]), "hub_bulk_queued"))
    count = len(loads(op.get("targets_json"), []))
    return _answer(project_id, op, i18n._("Поставлено в очередь исполнителю: находок – {count}.", count=count))

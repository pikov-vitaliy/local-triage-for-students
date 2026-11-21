"""Подтверждение, ход и сохранённые расхождения общего чтения Hub."""

from urllib.parse import urlencode

from fastapi import APIRouter, HTTPException, Request
from fastapi.responses import JSONResponse
from starlette.concurrency import run_in_threadpool

from app import hub_pull, hub_sync, hub_sync_api, hub_sync_compare
from app.db import loads
from app.hub_entity_versions import digest
from app.hub_ops import hub_base
from app.hub_status import HUB_ISSUE_TYPE
from app.routes.common import db_of, project_or_404, redirect, register_messages, render, settings_of
from app.routes.hub import worker_summary
from app.routes.hub_status_routes import hub_target_check

router = APIRouter()
register_messages({"pending_kept": "В редакторе уже другое решение – оно не изменено; отброшена только сохранённая правка."})
GROUP_PAGE_SIZE = 50
GROUP_ORDER = hub_sync_compare.GROUP_ORDER
STATES = {"running": "Чтение Hub", "waiting": "Ожидание исполнителя", "stopped": "Остановлено",
          "interrupted": "Прервано перезапуском", "failed": "Чтение завершилось ошибкой",
          "comparing": "Локальное сравнение", "ready": "Чтение завершено", "closed": "Запуск закрыт"}


def target(request, project):
    return {"project_id": project["id"], "hub_url": hub_base(settings_of(request).hub_url),
            "app_id": project.get("hub_app_id")}


def get_run(request, project_id, run_id):
    project_or_404(request, project_id)
    row = db_of(request)._one("SELECT * FROM hub_defect_sync_runs WHERE id=? AND project_id=?", (run_id, project_id))
    if not row:
        raise HTTPException(404, "Запуск синхронизации не найден.")
    return row


def context(request, project, row=None, app_confirmed=False):
    to = target(request, project)
    existing = None if row else db_of(request)._one(
        "SELECT * FROM hub_defect_sync_runs WHERE project_id=? AND closed_at IS NULL", (project["id"],))
    token = digest({**to, "adapter": hub_sync_api.ADAPTER.passport(),
                    "run": row["id"] if row else None, "revision": row["revision"] if row else None,
                    "previous": [existing["id"], existing["revision"]] if existing else None,
                    # подтверждённый оператором номер – часть показанного режима чтения (ревью dev13)
                    "app_confirmed": bool(app_confirmed) and not row})
    worker = worker_summary(request)
    return {"project": project, "target": to, "confirmation": token, "run": row,
            "worker": worker, "sync_protocol": hub_sync_api.SYNC_PROTOCOL,
            "worker_label": worker_label(worker, row["hub_url"] if row else to["hub_url"]),
            "existing": existing, "previous_data": hub_sync.passport(existing) if existing else {},
            "can_start": not existing or existing["state"] not in (*hub_sync.ACTIVE, "comparing"),
            "labels": hub_sync_compare.LABELS, "states": STATES}


def worker_label(worker, hub_url):
    if not worker["online"]:
        return "Ожидание исполнителя: связи нет."
    if worker.get("hub_url") != hub_url:
        return "Ожидание исполнителя для указанного Hub."
    if worker.get("sync_protocol") != hub_sync_api.SYNC_PROTOCOL:
        return "Исполнитель на связи, но протокол устарел: обновите исполнитель."
    return "Исполнитель на связи."


@router.post("/projects/{project_id}/hub-sync/preview")
async def preview(request: Request, project_id: int):
    form = await request.form()
    project = project_or_404(request, project_id)
    # «Номер верный, продолжить» со страницы остановленного прогона: оператор подтвердил номер приложения,
    # сверка с выгрузкой в новом прогоне не останавливает чтение (решает оператор)
    confirmed = form.get("app_confirmed") == "yes"
    return render(request, "projects/hub_sync_confirm.html",
                  {**context(request, project, app_confirmed=confirmed), "app_confirmed": confirmed})


@router.post("/projects/{project_id}/hub-sync/start")
async def start(request: Request, project_id: int):
    form = await request.form()
    project = project_or_404(request, project_id)
    confirmed = form.get("app_confirmed") == "yes"
    ctx = context(request, project, app_confirmed=confirmed)
    if form.get("confirm") != "yes" or form.get("confirmation") != ctx["confirmation"]:
        raise HTTPException(409, "Область чтения изменилась или не подтверждена.")
    db = db_of(request)
    to = ctx["target"]
    check = hub_target_check(request, project_id, to["hub_url"], to["app_id"])
    try:
        previous = (ctx["existing"]["id"], ctx["existing"]["revision"]) if ctx["existing"] else None
        run_id = await run_in_threadpool(lambda: hub_sync.start(db, **to, check=check, previous=previous,
                                                                app_confirmed=confirmed))
    except ValueError as exc:
        return render(request, "projects/hub_sync_confirm.html",
                      {**ctx, "error": str(exc), "app_confirmed": confirmed}, status_code=409)
    return redirect(f"/projects/{project_id}/hub-sync/{run_id}")


def progress(db, row):
    data = hub_sync.passport(row)
    cached = data.get("progress_counts") if row["state"] == "ready" else None
    if cached:
        return progress_view(row, data, **cached)
    steps = db._all("SELECT entity_kind,request_key,state FROM hub_sync_requests WHERE run_id=? ORDER BY id", (row["id"],))
    latest = {s["request_key"]: s for s in steps}
    items = db._all("SELECT entity_kind,hub_json FROM hub_sync_items WHERE run_id=?", (row["id"],))
    counts = {"issue": 0, "defect": 0, "issue_detail": 0, "defect_detail": 0, "basis": 0}
    for item in items:
        hub = loads(item["hub_json"], {})
        if "brief" in hub:
            counts[item["entity_kind"]] += 1
        counts[item["entity_kind"] + "_detail"] += int("detail" in hub)
        counts["basis"] += int("manual" in hub) + int("risk" in hub)
    needed = {"issue": 0, "defect": 0, "basis": 0}
    for s in latest.values():
        part = loads(s["request_key"], ["", "", ""])[2]
        if part == "detail":
            needed[s["entity_kind"]] += 1
        elif part in ("manual", "risk"):
            needed["basis"] += 1
    exceptions = sum(len(loads(i["coverage_json"], {}).get("exceptions", {})) for i in db._all(
        "SELECT coverage_json FROM hub_sync_items WHERE run_id=?", (row["id"],)))
    return progress_view(row, data, counts, needed, exceptions,
                         sum(s["state"] == "done" for s in latest.values()), len(latest))


def progress_view(row, data, counts, needed, exceptions, complete, total):
    totals = data["totals"]
    text = (f"Находки в списке: {counts['issue']} / {totals.get('issue', '?')}. "
            f"Подробности находок: {counts['issue_detail']} / {needed['issue']}. "
            f"Основания и риски: {counts['basis']} / {needed['basis']}. "
            f"Дефекты в списке: {counts['defect']} / {totals.get('defect', '?')}; "
            f"подробности: {counts['defect_detail']} / {needed['defect']}. "
            f"Сохранено запросов: {data['saved_requests']}.")
    done = row["state"] not in hub_sync.ACTIVE
    percent = None
    if data["inventory_complete"]:
        percent = 100 if done and data["details_complete"] else int(100 * complete / max(1, total))
    checks = data.get("page_checks", [])
    checked = sum(p["state"] == "checked" for p in checks)
    restarts = sum(p["state"] == "restart" for p in checks)
    verification = (f"Проверка на ходу: страницы {checked}, перечитывания с меньшим шагом {restarts}; "
                    f"уникальные ID / total: находки {counts['issue']} / {totals.get('issue', '?')}, "
                    f"дефекты {counts['defect']} / {totals.get('defect', '?')}; исключения ответов: {exceptions}.")
    scope = "запрошено отключение фильтра веток" if data["adapter"]["all_branches"] else "как в Hub по умолчанию"
    branches = f"Ветки: {scope}. Фактически встретились: {', '.join(data.get('branches', [])) or 'не встретились'}."
    return {"text": text, "percent": percent, "done": done, "needed": needed, "counts": counts,
            "verification": verification, "exceptions": exceptions, "branches": branches}


def item_card(project_id, item):
    local = loads(item["local_json"], {})
    if item["entity_kind"] == "issue":
        finding = local.get("finding")
        if (finding and finding["kind"] in HUB_ISSUE_TYPE
                and item["entity_key"] == f"{HUB_ISSUE_TYPE[finding['kind']]}:{finding['hub_id']}"):
            section = "sca/findings" if finding["kind"] == "SCA" else "findings"
            return f"/projects/{project_id}/{section}/{finding['id']}"
    else:
        owner = local.get("owner") or (local if item["entity_key"].startswith("local:") else None)
        if owner:
            return f"/projects/{project_id}/defects/{owner['id']}"
    return ""


# после «у»: родительный падеж – «у 1 находки», «у 3 находок»
KIND_WORDS = {"issue": ("находки", "находок"), "defect": ("дефекта", "дефектов")}


def _plural(n: int, forms: tuple[str, str]) -> str:
    return forms[0] if n % 10 == 1 and n % 100 != 11 else forms[1]


def incomplete_causes(db, run_id: int) -> list[dict]:
    """Общие причины неполных сведений чтения (бэклог 97): исключения объектов запуска (coverage_json.exceptions[часть] =
    {op_id, reason}) по части чтения, виду объекта, причине и коду ответа Hub (hub_ops.result_json.status по op_id);
    число – уникальные объекты. Пример: «у 40 находок Hub не отдал сведения riskAcceptance: ошибка 500»."""
    rows = db._all("SELECT entity_kind, entity_key, coverage_json FROM hub_sync_items WHERE run_id = ?"
                   " AND coverage_json::json -> 'exceptions' IS NOT NULL", (run_id,))
    found: dict[tuple, set] = {}
    ops: set[int] = set()
    for row in rows:
        for part, exc in (loads(row["coverage_json"], {}).get("exceptions") or {}).items():
            if not isinstance(exc, dict):
                continue
            op_id = exc.get("op_id")
            reason = " ".join(str(exc.get("reason") or "").split())[:200]
            key = (row["entity_kind"], str(part or ""), reason, op_id if isinstance(op_id, int) else None,
                   bool(exc.get("missing_raw")))
            found.setdefault(key, set()).add(row["entity_key"])
            if isinstance(op_id, int):
                ops.add(op_id)
    codes: dict[int, str] = {}
    if ops:
        marks = ",".join("?" * len(ops))
        for op in db._all(f"SELECT id, result_json FROM hub_ops WHERE id IN ({marks})", tuple(sorted(ops))):
            status = (loads(op["result_json"], {}) or {}).get("status")
            codes[int(op["id"])] = str(status) if status not in (None, "", 0) else ""
    merged: dict[tuple, set] = {}
    for (kind, part, reason, op_id, missing_raw), keys in found.items():
        code = codes.get(op_id, "") if op_id is not None else ""
        merged.setdefault((kind, part, reason, code, missing_raw), set()).update(keys)
    causes = []
    for (kind, part, reason, code, missing_raw), keys in sorted(merged.items(), key=lambda kv: (-len(kv[1]), kv[0])):
        words = KIND_WORDS.get(kind, ("объекта", "объектов"))
        who = f"у {len(keys)} {_plural(len(keys), words)}"
        what = part_words(part, kind)
        # только код ответа не 2xx – отказ Hub; остальное – приложение не смогло прочитать или обработать ответ
        if missing_raw:
            text = f"{who} ответ Hub на чтение {what} не сохранён в приложении" + (f": {reason}" if reason else "")
        elif code and not code.startswith("2"):
            text = f"{who} Hub ответил ошибкой {code} на чтение {what}"
        else:
            text = (f"{who} не удалось прочитать или обработать {what}" + (f" (ответ Hub {code})" if code else "")
                    + f": {reason or 'причина не записана'}")
        causes.append({"count": len(keys), "part": part, "code": code, "reason": reason, "missing_raw": missing_raw,
                       "text": text})
    return causes


PART_WORDS = {"detail": "карточки находки", "manual": "статуса находки", "risk": "принятия риска"}


def part_words(part: str, kind: str = "issue") -> str:
    """Часть чтения словами (hub_sync.plan: detail, manual, risk, branch:<имя>) – с названием в кавычках; detail у
    дефекта – карточка дефекта (GET /defects/{id})."""
    if part == "detail" and kind == "defect":
        return "карточки дефекта («detail»)"
    if part.startswith("branch:"):
        return f"ветки «{part[len('branch:'):]}»"
    if part in PART_WORDS:
        return f"{PART_WORDS[part]} («{part}»)"
    return f"«{part}»" if part else "сведений"


@router.get("/projects/{project_id}/hub-sync/{run_id}")
def view(request: Request, project_id: int, run_id: int, group: str = "", page: int = 1, q: str = ""):
    row = get_run(request, project_id, run_id)
    db = db_of(request)
    if hub_pull.reconcile_pending(db, row):
        row = get_run(request, project_id, run_id)
    data = hub_sync.passport(row)
    if data["comparison_complete"] and not hub_sync_compare.snapshot_current(db, row):
        data = {**data, "matches_snapshot": False, "local_changed": True}
    items = db._all("SELECT entity_kind,entity_key,diff_json,observed_from,observed_to FROM hub_sync_items"
                    " WHERE run_id=? ORDER BY entity_kind,entity_key", (run_id,))
    groups = {}
    for item in items:
        if q.strip().casefold() not in item["entity_key"].casefold():
            continue
        diff = loads(item["diff_json"], {})
        tags = diff.get("groups") or ["incomplete"]
        name = hub_sync_compare.primary_group(tags)
        groups.setdefault(name, []).append(item)
    pages = {}
    base_url = f"/projects/{project_id}/hub-sync/{run_id}"
    for name, members in groups.items():
        total = len(members)
        last = max(1, (total + GROUP_PAGE_SIZE - 1) // GROUP_PAGE_SIZE)
        current = min(max(1, page), last) if name == group else 1
        offset = (current - 1) * GROUP_PAGE_SIZE
        # поиск по ключу без выбранной группы открывает группы с найденными объектами (ссылки значков, dev15)
        pages[name] = {"total": total, "page": current, "last": last, "open": name == group or (bool(q.strip()) and not group),
                       "previous": base_url + "?" + urlencode({"group": name, "page": current - 1, "q": q}),
                       "next": base_url + "?" + urlencode({"group": name, "page": current + 1, "q": q})}
        visible = members[offset:offset + GROUP_PAGE_SIZE]
        keys = [item["entity_key"] for item in visible]
        local_rows = db._all("SELECT entity_kind,entity_key,local_json FROM hub_sync_items WHERE run_id=?"
                             f" AND entity_key IN ({','.join('?' for _ in keys)})", (run_id, *keys))
        local_index = {(r["entity_kind"], r["entity_key"]): r for r in local_rows}
        groups[name] = [{**item, "diff": loads(item["diff_json"], {}),
                         "card_url": item_card(project_id, local_index[(item["entity_kind"], item["entity_key"])]),
                         "raw_url": base_url + "/raw?" + urlencode({"kind": item["entity_kind"], "key": item["entity_key"]})}
                        for item in visible]
    prog = progress(db, row)
    from app.package_transition import TABLE_LABELS, entity_rows
    pull = hub_pull.preview(db, row)
    return render(request, "projects/hub_sync.html", {
        **context(request, project_or_404(request, project_id), row), "data": data,
        "progress": prog, "groups": groups, "pages": pages, "labels": hub_sync_compare.LABELS,
        "delivery_labels": hub_sync_compare.DELIVERY_LABELS,
        # «Идентичность пакетов» – до принятия (предпросмотр) и после него (итог), план dev17 п. 4.5
        "identity_rows": entity_rows(pull.get("identity") or {}), "table_labels": TABLE_LABELS,
        "pull": pull, "query": q, "result_count": sum(p["total"] for p in pages.values()),
        "state_label": STATES.get(row["state"], row["state"]),
        "incomplete_causes": incomplete_causes(db, run_id) if prog.get("exceptions") else []})


@router.post("/projects/{project_id}/hub-sync/{run_id}/apply")
async def apply(request: Request, project_id: int, run_id: int):
    row = get_run(request, project_id, run_id)
    form = await request.form()
    if form.get("confirm") != "yes":
        raise HTTPException(409, "Принятие состояния Hub не подтверждено.")
    check = hub_target_check(request, project_id, row["hub_url"], row["app_id"])
    try:
        await run_in_threadpool(lambda: hub_pull.apply(db_of(request), run_id, str(form.get("confirmation") or ""), check=check))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return redirect(f"/projects/{project_id}/hub-sync/{run_id}")


PENDING_STATES = {"pending": "ждёт отправки в Hub", "saved": "сохранено до принятия состояния Hub",
                  "restored": "возвращено в редактор", "delivered": "принято Hub", "discarded": "отброшено"}


PENDING_PAGE = 200  # действующих правок на странице списка; закрытые – последние CLOSED_SHOWN


CLOSED_SHOWN = 100


@router.get("/projects/{project_id}/hub-pending")
def pending_list(request: Request, project_id: int, page: int = 1):
    """История сохранённых правок текущего назначения (dev15, план п. 1.4): решения, заменённые состоянием Hub при
    принятии, и прежние ожидания – со ссылками на каждую. Действующие – все, постранично (после массового принятия их
    может быть больше тысячи, ревью кода dev15, круг 1), закрытые – последние, с полным числом."""
    project = project_or_404(request, project_id)
    to = target(request, project)
    db = db_of(request)
    scope_args = (project_id, to["hub_url"], to["app_id"])
    counts = {r["state"]: int(r["n"]) for r in db._all(
        "SELECT state,COUNT(*) AS n FROM hub_sync_pending WHERE project_id=? AND hub_url=? AND app_id=? GROUP BY state",
        scope_args)}
    open_total = sum(counts.get(s, 0) for s in ("pending", "saved", "restored"))
    last = max(1, (open_total + PENDING_PAGE - 1) // PENDING_PAGE)
    page = min(max(1, page), last)
    open_rows = db._all("SELECT id,entity_kind,entity_key,state,created_at,resolved_at FROM hub_sync_pending"
                        " WHERE project_id=? AND hub_url=? AND app_id=? AND state IN ('pending','saved','restored')"
                        " ORDER BY id DESC LIMIT ? OFFSET ?", (*scope_args, PENDING_PAGE, (page - 1) * PENDING_PAGE))
    closed_rows = db._all("SELECT id,entity_kind,entity_key,state,created_at,resolved_at FROM hub_sync_pending"
                          " WHERE project_id=? AND hub_url=? AND app_id=? AND state NOT IN ('pending','saved','restored')"
                          " ORDER BY id DESC LIMIT ?", (*scope_args, CLOSED_SHOWN))
    base_url = f"/projects/{project_id}/hub-pending"
    return render(request, "projects/hub_pending_list.html", {
        "project": project, "open_rows": open_rows, "closed_rows": closed_rows, "labels": PENDING_STATES,
        "open_total": open_total, "closed_total": sum(counts.values()) - open_total, "counts": counts,
        "page": page, "pages": last,
        "previous": f"{base_url}?page={page - 1}" if page > 1 else "",
        "next": f"{base_url}?page={page + 1}" if page < last else ""})


@router.get("/projects/{project_id}/hub-pending/{pending_id}")
def pending(request: Request, project_id: int, pending_id: int):
    project = project_or_404(request, project_id)
    try:
        ctx = hub_pull.pending_context(db_of(request), target(request, project), pending_id)
    except ValueError as exc:
        raise HTTPException(404, str(exc)) from exc
    p = ctx["pending"]
    card = item_card(project_id, {"entity_kind": p["entity_kind"], "entity_key": p["entity_key"],
                                  "local_json": hub_sync_compare.dumps(ctx["current"])})
    return render(request, "projects/hub_pending.html", {"project": project, "card_url": card, **ctx})


@router.post("/projects/{project_id}/hub-pending/{pending_id}")
async def pending_action(request: Request, project_id: int, pending_id: int):
    project = project_or_404(request, project_id)
    form = await request.form()
    to = target(request, project)
    if form.get("confirm") != "yes" or form.get("action") not in ("restore", "discard"):
        raise HTTPException(409, "Действие с неотправленной правкой не подтверждено.")
    try:
        note = await run_in_threadpool(lambda: hub_pull.restore(db_of(request), to, pending_id,
            str(form.get("confirmation") or ""), discard=form.get("action") == "discard",
            check=hub_target_check(request, project_id, to["hub_url"], to["app_id"])))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    # более новая работа оператора в редакторе не тронута – страница говорит об этом (ревью Kimi dev15, круг 3)
    return redirect(f"/projects/{project_id}/hub-pending/{pending_id}" + ("?ok=pending_kept" if note else ""))


@router.get("/projects/{project_id}/hub-sync/{run_id}/raw")
def raw_item(request: Request, project_id: int, run_id: int, kind: str, key: str):
    """Сохранённые данные одного объекта; чтений Hub и постановки операций нет."""
    get_run(request, project_id, run_id)
    db = db_of(request)
    item = db._one("SELECT * FROM hub_sync_items WHERE run_id=? AND entity_kind=? AND entity_key=?",
                   (run_id, kind, key))
    if not item:
        raise HTTPException(404, "Объект синхронизации не найден.")
    operations = db._all("SELECT s.request_key,s.generation,s.state,s.processed_at,o.id,o.request_json,o.result_json"
                         " FROM hub_sync_requests s JOIN hub_ops o ON o.id=s.op_id"
                         " WHERE s.run_id=? AND s.entity_kind=? AND s.entity_key=? ORDER BY s.id", (run_id, kind, key))
    return JSONResponse({"B: принятая база": loads(item["base_json"], {}),
                         "L: локальные данные": loads(item["local_json"], {}),
                         "H: отдельные ответы Hub": loads(item["hub_json"], {}),
                         "Источники": loads(item["source_ops_json"], {}),
                         "Расхождения полей": loads(item["diff_json"], {}),
                         "Полнота и исключения": loads(item["coverage_json"], {}),
                         "Сохранённые операции": operations})


@router.get("/projects/{project_id}/hub-sync/{run_id}/state")
def state(request: Request, project_id: int, run_id: int):
    db = db_of(request)
    get_run(request, project_id, run_id)
    db.hub_expire_leases()
    row = get_run(request, project_id, run_id)
    p = progress(db, row)
    worker = worker_summary(request)
    label = STATES.get(row["state"], row["state"])
    worker_text = worker_label(worker, row["hub_url"])
    if row["state"] in hub_sync.ACTIVE and worker_text != "Исполнитель на связи.":
        label = worker_text
    return JSONResponse({"ok": True, "done": p["done"], "reload": p["done"],
                         "text": {"hub-sync-progress-label": p["text"], "hub-sync-state": label,
                                  "hub-sync-worker": worker_text, "hub-sync-verification": p["verification"],
                                  "hub-sync-branches": p["branches"]},
                         **({"value": {"hub-sync-progress": p["percent"]}} if p["percent"] is not None else {})})


@router.post("/projects/{project_id}/hub-sync/{run_id}/stop")
def stop(request: Request, project_id: int, run_id: int):
    get_run(request, project_id, run_id)
    hub_sync.stop(db_of(request), run_id)
    return redirect(f"/projects/{project_id}/hub-sync/{run_id}")


@router.post("/projects/{project_id}/hub-sync/{run_id}/continue-preview")
def continue_preview(request: Request, project_id: int, run_id: int):
    row = get_run(request, project_id, run_id)
    if row["closed_at"]:
        raise HTTPException(409, "Запуск закрыт. Подтвердите новое чтение на вкладке «Дефекты».")
    remaining = db_of(request)._all("SELECT request_json,state FROM hub_sync_requests WHERE run_id=?"
                                   " AND generation=? AND state!='done' ORDER BY id", (run_id, row["generation"]))
    return render(request, "projects/hub_sync_confirm.html", {
        **context(request, project_or_404(request, project_id), row),
        "remaining": [loads(s["request_json"], {})["path"] for s in remaining]})


@router.post("/projects/{project_id}/hub-sync/{run_id}/continue")
async def continue_run(request: Request, project_id: int, run_id: int):
    form = await request.form()
    row = get_run(request, project_id, run_id)
    ctx = context(request, project_or_404(request, project_id), row)
    if form.get("confirm") != "yes" or form.get("confirmation") != ctx["confirmation"]:
        raise HTTPException(409, "Продолжение не подтверждено или состояние изменилось.")
    db = db_of(request)
    check = hub_target_check(request, project_id, row["hub_url"], row["app_id"])
    try:
        await run_in_threadpool(lambda: hub_sync.continue_run(db, run_id, row["revision"], check=check))
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return redirect(f"/projects/{project_id}/hub-sync/{run_id}")


@router.post("/projects/{project_id}/hub-sync/{run_id}/recompare")
def recompare(request: Request, project_id: int, run_id: int):
    get_run(request, project_id, run_id)
    try:
        hub_sync_compare.recompare(db_of(request), run_id)
    except ValueError as exc:
        raise HTTPException(409, str(exc)) from exc
    return redirect(f"/projects/{project_id}/hub-sync/{run_id}")


@router.post("/projects/{project_id}/hub-sync/{run_id}/close")
def close(request: Request, project_id: int, run_id: int):
    get_run(request, project_id, run_id)
    hub_sync.close(db_of(request), run_id)
    return redirect(f"/projects/{project_id}/defects")

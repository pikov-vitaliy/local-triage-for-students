"""Сохранённый последовательный обход Hub через очередь, без собственного HTTP-клиента."""

import json
from dataclasses import replace

from app import hub_entity_versions as versions, hub_sync_api as api, i18n
from app.db import dumps, loads, now_iso
from app.hub_ops import hub_base
from app.hub_status import HUB_ISSUE_TYPE

ACTIVE = ("running", "waiting")


RESYNC_KEY = "hub_resync_required"
RESYNC_REFUSAL = i18n.N_("База восстановлена из копии: сначала «Синхронизировать» на вкладке «Дефекты» и «Принять состояние Hub». "
                  "Сделанное в Hub после копии база не знает: новая запись могла бы его повторить.")


def require_resync_in(c, ts):
    """После восстановления копии: источник сведений о потерянном – Hub. Пока состояние Hub не принято в базу по проекту, новый дефект, статус и `PUT`
    не ставятся, и пауза записи не снимается (ADR-0128, п. 9)."""
    projects = [row["id"] for row in c.execute("SELECT id FROM projects WHERE COALESCE(hub_app_id, 0) <> 0 ORDER BY id").fetchall()]
    if projects:
        c.execute("INSERT INTO settings(key, value_json, updated_at) VALUES (?, ?, ?)"
                  " ON CONFLICT(key) DO UPDATE SET value_json = excluded.value_json, updated_at = excluded.updated_at",
                  (RESYNC_KEY, dumps({"since": ts, "projects": projects}), ts))
    else:
        clear_resync_in(c)


def _resync_state_in(c):
    row = c.execute("SELECT value_json FROM settings WHERE key = ?", (RESYNC_KEY,)).fetchone()
    return loads(row[0], {}) if row is not None else {}


def resync_pending_in(c):
    """Проекты, по которым после восстановления состояние Hub ещё не принято; удалённый проект и проект без приложения Hub ждать нечего."""
    waiting = list(_resync_state_in(c).get("projects") or [])
    if not waiting:
        return []
    live = {row["id"] for row in c.execute("SELECT id FROM projects WHERE COALESCE(hub_app_id, 0) <> 0").fetchall()}
    return [project for project in waiting if project in live]


def clear_resync_in(c):
    c.execute("DELETE FROM settings WHERE key = ?", (RESYNC_KEY,))


def resync_done_in(c, row, skipped=()):
    """Состояние Hub из прохода, начатого после восстановления, принято в базу (или принимать нечего): запись по проекту снова можно ставить."""
    state = _resync_state_in(c)
    projects = list(state.get("projects") or [])
    if row["project_id"] not in projects or str(row["created_at"]) < str(state.get("since") or ""):
        return
    data = passport(run_in(c, row["id"]))
    if not (data.get("inventory_complete") and data.get("details_complete")):
        return
    # пропущенный объект в базу не занесён: это может быть тот самый дефект; записи без соответствия в API Hub занести нельзя никогда,
    # а занесённый дефект база уже знает, если весь его состав в Hub закреплён за его строками: второй дефект по этим находкам не начать
    if any(not str(item.get("key") or "").startswith("UNMAPPED:") and not _known_defect_in(c, row, item) for item in skipped):
        return
    projects.remove(row["project_id"])
    if not projects:
        clear_resync_in(c)
        return
    c.execute("UPDATE settings SET value_json = ? WHERE key = ?", (dumps({**state, "projects": projects}), RESYNC_KEY))


def _known_defect_in(c, row, item):
    if item.get("kind") != "defect":
        return False
    from app.hub_defects import linked_pairs
    rows = c.execute("SELECT targets_json FROM hub_defects WHERE project_id=? AND hub_url=? AND COALESCE(app_id, 0)=? AND hub_defect_id=?"
                     " AND state IN ('done', 'mismatch')",
                     (row["project_id"], row["hub_url"], int(row["app_id"] or 0), str(item.get("key") or ""))).fetchall()
    read = c.execute("SELECT hub_json FROM hub_sync_items WHERE run_id=? AND entity_kind='defect' AND entity_key=?",
                     (row["id"], str(item.get("key") or ""))).fetchone()
    detail = (loads(read["hub_json"], {}) or {}).get("detail") if read is not None else None
    if not rows or not isinstance(detail, dict):
        return False
    held = {(str(target.get("hub_id") or ""), str(target.get("issue_type") or "")) for line in rows for target in loads(line["targets_json"], []) or []}
    return all((str(ident), kind) in held for ident, kind in linked_pairs(detail))


def resync_blocker(db, project_id):
    """Почему запись по проекту сейчас не поставить: «» – можно."""
    return i18n._(RESYNC_REFUSAL) if db.on_connection(lambda c: int(project_id) in resync_pending_in(c)) else ""


def run_in(c, run_id):
    row = c.execute("SELECT * FROM hub_defect_sync_runs WHERE id=?", (run_id,)).fetchone()
    if row is None:
        raise ValueError(i18n._("Запуск синхронизации не найден."))
    return dict(row)


def passport(row):
    return loads(row["run_json"], {})


def save_run(c, row, data, state=None):
    c.execute("UPDATE hub_defect_sync_runs SET run_json=?,state=?,revision=revision+1 WHERE id=?",
              (dumps(data), state or row["state"], row["id"]))


def plan(c, row, kind, key, part, req):
    logical = dumps([kind, key, part])
    latest = c.execute("SELECT state FROM hub_sync_requests WHERE run_id=? AND request_key=? ORDER BY id DESC LIMIT 1",
                        (row["id"], logical)).fetchone()
    if latest and latest[0] == "done":
        return
    c.execute("INSERT INTO hub_sync_requests(run_id,generation,request_key,entity_kind,"
              "entity_key,request_json) VALUES (?,?,?,?,?,?)"
              " ON CONFLICT(run_id,generation,request_key) DO NOTHING",
              (row["id"], row["generation"], logical, kind, key, dumps(req)))


def add_item(c, row, kind, key, brief=None, missing=False):
    c.execute("INSERT INTO hub_sync_items(run_id,entity_kind,entity_key,hub_json,coverage_json)"
              " VALUES (?,?,?,?,?) ON CONFLICT(run_id,entity_kind,entity_key) DO NOTHING",
              (row["id"], kind, key, dumps({"brief": brief} if brief else {}),
                                       dumps({"absent_from_list": missing})))


def start(db, project_id, hub_url, app_id, *, adapter=None, check=None, previous=None, app_confirmed=False):
    if getattr(db, "hub_disabled", False):  # учебный стенд npm (ADR-0155): сверка с Hub не запускается
        from app.db import HUB_DISABLED_TEXT, HubDisabledInStand
        raise HubDisabledInStand(HUB_DISABLED_TEXT)
    adapter = adapter or api.ADAPTER
    adapter.require()
    with db._tx() as c:
        if check:
            check(c)
        existing = c.execute("SELECT * FROM hub_defect_sync_runs WHERE project_id=? AND closed_at IS NULL",
                             (project_id,)).fetchone()
        actual = (existing["id"], existing["revision"]) if existing else None
        if actual != previous:
            raise ValueError(i18n._("Список запусков изменился: откройте подтверждение нового чтения заново."))
        if existing:
            if existing["state"] in (*ACTIVE, "comparing"):
                raise ValueError(i18n._("Чтение уже идёт. Откройте его результат или остановите запуск."))
            cancel_queued(c, existing)
            c.execute("UPDATE hub_defect_sync_runs SET closed_at=?,state='closed',revision=revision+1 WHERE id=?",
                      (now_iso(), existing["id"]))
        now = now_iso()
        data = {"version": 1, "adapter": adapter.passport(), "confirmed_at": now, "started_at": now,
                "finished_at": None, "phase": "issue_list", "totals": {}, "lists_done": [],
                "inventory_complete": False, "details_complete": False, "comparison_complete": False,
                "matches_snapshot": False, "error": "", "saved_requests": 0}
        data.update(page_sizes={"issue": adapter.issue_size, "defect": adapter.defect_size},
                    page_checks=[], restart_keys={}, branches=[], exceptions=0, app_confirmed=bool(app_confirmed))
        cur = c.execute("INSERT INTO hub_defect_sync_runs(project_id,hub_url,app_id,state,run_json,created_at)"
                        " VALUES (?,?,?,'running',?,?) RETURNING id", (project_id, hub_base(hub_url), app_id, dumps(data), now))
        row = run_in(c, cur.fetchone()[0])
        plan(c, row, "issue", "", f"page:{adapter.first_page}", api.page(adapter, "issue", app_id, adapter.first_page))
        advance(db, c, row)
        return row["id"]


def advance(db, c, row):
    if row["state"] not in ACTIVE:
        return
    pending = c.execute("SELECT 1 FROM hub_sync_requests WHERE run_id=? AND state='queued'", (row["id"],)).fetchone()
    if pending:
        return
    step = c.execute("SELECT * FROM hub_sync_requests WHERE run_id=? AND generation=? AND state='planned'"
                     " ORDER BY entity_kind DESC,id LIMIT 1", (row["id"], row["generation"])).fetchone()
    if step is None:
        data = passport(row)
        if data["inventory_complete"]:
            from app.hub_sync_compare import compare_in
            exceptions = [e for r in c.execute("SELECT coverage_json FROM hub_sync_items WHERE run_id=?", (row["id"],))
                          for e in loads(r[0], {}).get("exceptions", {}).values()]
            data["exceptions"] = len(exceptions)
            data["reparse_missing"] = sum(bool(e.get("missing_raw")) for e in exceptions)
            data["details_complete"] = data["exceptions"] == 0
            data["finished_at"] = now_iso()
            save_run(c, row, data, "comparing")
            compare_in(c, run_in(c, row["id"]))
        return
    op = db._hub_insert(c, purpose="sync_read", request=loads(step["request_json"], {}),
                        project_id=row["project_id"], hub_url=row["hub_url"], app_id=row["app_id"],
                        targets=[{"issue_type": "HUB_SYNC", "issue_id": row["id"]}],
                        key_extra=f"sync:{row['id']}:{row['generation']}:{step['id']}")
    c.execute("UPDATE hub_sync_requests SET state='queued',op_id=? WHERE id=?", (op["id"], step["id"]))
    data = passport(row)
    part = loads(step["request_key"], [None, None, ""])[2]
    data["phase"] = step["entity_kind"] + ("_list" if part.startswith("page:") else "_details")
    save_run(c, row, data, "running")


def claimable(c, op, protocol):
    if protocol != api.SYNC_PROTOCOL:
        return False
    step = c.execute("SELECT s.*,r.state AS run_state,r.generation AS run_generation FROM hub_sync_requests s"
                     " JOIN hub_defect_sync_runs r ON r.id=s.run_id WHERE s.op_id=?", (op["id"],)).fetchone()
    return bool(step and step["state"] == "queued" and step["run_state"] in ACTIVE
                and step["generation"] == step["run_generation"])


def capture(c, op):
    """Вызывается в транзакции выдачи, а не в момент постановки в очередь."""
    step = c.execute("SELECT * FROM hub_sync_requests WHERE op_id=?", (op["id"],)).fetchone()
    if not step or not step["entity_key"]:
        return
    base = versions.current(c, op["project_id"], op["hub_url"], op["app_id"], step["entity_kind"], step["entity_key"])
    c.execute("UPDATE hub_sync_requests SET base_epoch=?,base_hash=? WHERE id=?",
              (base["accepted_epoch"], base["accepted_hash"], step["id"]))


def fail_in(c, row, message):
    data = passport(row)
    data.update(error=message, matches_snapshot=False, finished_at=now_iso())
    save_run(c, row, data, "failed")


def response_body(c, row, adapter, step, op):
    """Одинаковый разбор при доставке и локальном пересчёте сохранённого ответа."""
    result = loads(op["result_json"], {})
    part = loads(step["request_key"], [None, None, ""])[2]
    documented_empty = adapter.absent_response(part, result)
    item = c.execute("SELECT coverage_json FROM hub_sync_items WHERE run_id=? AND entity_kind=? AND entity_key=?",
                     (row["id"], step["entity_kind"], step["entity_key"])).fetchone()
    missing_404 = (part == "detail" and result.get("status") == 404 and item
                   and loads(item[0], {}).get("absent_from_list"))
    if result.get("truncated") or result.get("error") or result.get("not_sent"):
        raise ValueError("Обязательный ответ не получен полностью. " + str(result.get("error") or ""))
    if op["state"] != "done" and not documented_empty and not missing_404:
        raise ValueError(op.get("error") or i18n.N_("Чтение Hub не завершено."))
    body = None if documented_empty or missing_404 else json.loads(result["body_text"])
    if body is None and not (documented_empty or missing_404):
        raise ValueError(i18n.N_("Ответ null не подтверждает отсутствие объекта по установленному контракту."))
    return body


def delivery_in(db, c, op):
    step_row = c.execute("SELECT * FROM hub_sync_requests WHERE op_id=?", (op["id"],)).fetchone()
    if step_row is None or step_row["processed_at"]:
        return
    step = dict(step_row)
    row = run_in(c, step["run_id"])
    if step["generation"] != row["generation"] or row["closed_at"]:
        return
    data, result = passport(row), loads(op["result_json"], {})
    part = loads(step["request_key"], [None, None, ""])[2]
    adapter = api.Adapter(**data["adapter"])
    try:
        body = response_body(c, row, adapter, step, op)
        if part.startswith("page:"):
            consume_page(c, row, data, adapter, step, body)
        else:
            consume_object(c, row, adapter, step, body, op)
            collect_branches(data, [body])
        c.execute("UPDATE hub_sync_requests SET state='done',result_hash=?,processed_at=? WHERE id=?",
                  (versions.digest(result), now_iso(), step["id"]))
        data["saved_requests"] += 1
        save_run(c, row, data)
        if data.get("app_check", {}).get("stop"):
            save_run(c, run_in(c, row["id"]), data, "stopped")
            return
        advance(db, c, run_in(c, row["id"]))
    except (ValueError, KeyError, TypeError) as exc:
        c.execute("UPDATE hub_sync_requests SET state='failed',result_hash=?,processed_at=? WHERE id=?",
                  (versions.digest(result), now_iso(), step["id"]))
        if part.startswith("page:"):
            save_run(c, row, data)
            fail_in(c, run_in(c, row["id"]), "Чтение неполное: " + str(exc))
        else:
            object_exception(c, row, step, op, str(exc))
            data["saved_requests"] += 1
            save_run(c, row, data)
            advance(db, c, run_in(c, row["id"]))


def object_exception(c, row, step, op, reason, *, missing_raw=False):
    """Ответ остаётся в hub_ops; исключение связано с объектом и частью чтения."""
    part = loads(step["request_key"], [None, None, ""])[2]
    item = c.execute("SELECT coverage_json FROM hub_sync_items WHERE run_id=? AND entity_kind=? AND entity_key=?",
                     (row["id"], step["entity_kind"], step["entity_key"])).fetchone()
    coverage = loads(item[0], {})
    coverage.setdefault("exceptions", {})[part] = {"op_id": op["id"], "reason": reason,
                                                  **({"missing_raw": True} if missing_raw else {})}
    c.execute("UPDATE hub_sync_items SET coverage_json=? WHERE run_id=? AND entity_kind=? AND entity_key=?",
              (dumps(coverage), row["id"], step["entity_kind"], step["entity_key"]))


def collect_branches(data, objects):
    names = set(data.get("branches", []))
    for obj in objects:
        if isinstance(obj, dict):
            for field in ("branch", "currentBranch"):
                if isinstance(obj.get(field), str) and obj[field]:
                    names.add(obj[field])
    data["branches"] = sorted(names)


def consume_page(c, row, data, adapter, step, body):
    kind = step["entity_kind"]
    seen = {r[0] for r in c.execute("SELECT entity_key FROM hub_sync_items WHERE run_id=? AND entity_kind=?",
                                   (row["id"], kind))}
    size = data.setdefault("page_sizes", {"issue": adapter.issue_size, "defect": adapter.defect_size})[kind]
    index = int(loads(step["request_key"], [None, None, ""])[2].split(":")[1])
    audit = {"kind": kind, "index": index, "size": size, "state": "invalid", "op_id": step["op_id"],
             "received": len(body["filteredEntities"]) if isinstance(body, dict) and isinstance(body.get("filteredEntities"), list) else None,
             "total": body.get("totalEntitiesCount") if isinstance(body, dict) else None}
    data.setdefault("page_checks", []).append(audit)
    try:
        total, entries = api.read_page(body, row["app_id"], kind, data["totals"].get(kind), seen, size)
    except api.ShortPage as exc:
        audit["state"] = "restart"
        for previous in data["page_checks"]:
            if previous["kind"] == kind and previous["state"] == "checked":
                previous["state"] = "superseded"
        data["totals"][kind] = body["totalEntitiesCount"]
        keys = {api.identifier(obj, row["app_id"], kind) for obj in body["filteredEntities"]}
        restarts = data.setdefault("restart_keys", {})
        restarts[kind] = sorted(set(restarts.get(kind, [])) | seen | keys)
        collect_branches(data, body["filteredEntities"])
        c.execute("DELETE FROM hub_sync_items WHERE run_id=? AND entity_kind=?", (row["id"], kind))
        data["page_sizes"][kind] = exc.size
        plan(c, row, kind, "", f"page:0:size:{exc.size}", api.page(adapter, kind, row["app_id"], 0, exc.size))
        return
    audit["state"] = "checked"
    data["totals"][kind] = total
    collect_branches(data, [obj for _, obj in entries])
    for key, obj in entries:
        add_item(c, row, kind, key, obj)
    if len(seen) + len(entries) < total:
        plan(c, row, kind, "", f"page:{index+1}:size:{size}", api.page(adapter, kind, row["app_id"], index+1, size))
    else:
        if not set(data.get("restart_keys", {}).get(kind, [])) <= seen | {key for key, _ in entries}:
            audit["state"] = "invalid"
            raise ValueError(i18n.N_("После изменения шага пропали ранее прочитанные ID. Нужен новый обход."))
        data["lists_done"].append(kind)
        if kind == "issue":
            app_check_in(c, row, data)
            if data["app_check"].get("stop"):
                return  # прогон остановит delivery_in: дефекты и подробности не читаются, решает оператор
            plan(c, row, "defect", "", "page:0", api.page(adapter, "defect", row["app_id"], 0))
        else:
            data["inventory_complete"] = True
            plan_details(c, row)


def _app_name(brief):
    """Название приложения в кратком объекте находки Hub: `appName` или `application.name`; нет – пусто."""
    if not isinstance(brief, dict):
        return ""
    app = brief.get("application") if isinstance(brief.get("application"), dict) else {}
    name = brief.get("appName") if isinstance(brief.get("appName"), str) else app.get("name")
    return " ".join(name.split()) if isinstance(name, str) else ""


def app_check_in(c, row, data):
    """Сверка номера приложения с выгрузкой проекта (неверный номер приложение должно
    отработать). Идёт после полного списка находок Hub, до дефектов и подробностей: номера находок Hub против
    номеров выгрузки, название приложения Hub против столбца «application» выгрузки. Ни одной общей находки при
    непустых списках – остановка, пока оператор не подтвердит номер; иначе только сведения. Запросов к Hub нет."""
    hub = {}
    for key, raw in c.execute("SELECT entity_key,hub_json FROM hub_sync_items WHERE run_id=? AND entity_kind='issue'",
                              (row["id"],)):
        hub[key] = loads(raw, {}).get("brief") or {}
    # только строки последней файловой выгрузки: находки, занесённые синхронизацией, и строки прежних выгрузок
    # принадлежность выгрузки номеру не доказывают (ревью плана dev13, круг 2)
    latest = c.execute("SELECT id FROM imports WHERE project_id=? AND source_kind='file' ORDER BY id DESC LIMIT 1",
                       (row["project_id"],)).fetchone()
    local, export_names = set(), set()
    rows = c.execute("SELECT hub_id,kind,file_data_json FROM findings WHERE project_id=? AND file_checked_import_id=?"
                     " AND file_presence='present'", (row["project_id"], latest[0])).fetchall() if latest else []
    for f in rows:
        typ = HUB_ISSUE_TYPE.get(f["kind"])
        if typ and f["hub_id"].isascii() and f["hub_id"].isdigit():
            local.add(f"{typ}:{f['hub_id']}")
        name = loads(f["file_data_json"], {}).get("application")
        if isinstance(name, str) and name.strip():
            export_names.add(" ".join(name.split()))
    hub_names = {name for name in map(_app_name, hub.values()) if name}
    common = len(local & set(hub))
    check = {"export": len(local), "hub": len(hub), "common": common, "confirmed": bool(data.get("app_confirmed")),
             "hub_names": sorted(hub_names)[:3], "export_names": sorted(export_names)[:3],
             "names_differ": bool(hub_names and export_names
                                  and not {n.casefold() for n in hub_names} & {n.casefold() for n in export_names}),
             "status": "match", "reason": "", "stop": False}
    if not local:
        check.update(status="skipped", reason=i18n.N_("В последней выгрузке проекта нет номеров находок Hub: сверять не с чем."))
    elif not common:
        # в том числе пустой список Hub при непустой выгрузке: соответствие не установлено, решает оператор
        check.update(status="mismatch", stop=not check["confirmed"])
    data["app_check"] = check
    return check


def local_keys(c, row):
    keys = set()
    for f in c.execute("SELECT hub_id,kind FROM findings WHERE project_id=?", (row["project_id"],)):
        typ = HUB_ISSUE_TYPE.get(f["kind"])
        if typ and f["hub_id"].isascii() and f["hub_id"].isdigit():
            keys.add(("issue", typ + ":" + f["hub_id"]))
        else:
            keys.add(("issue", "UNMAPPED:" + f["hub_id"]))
    for d in c.execute("SELECT hub_defect_id FROM hub_defects WHERE project_id=? AND hub_url=? AND app_id=?"
                       " AND hub_defect_id!='' AND state NOT IN ('deleted','cancelled','failed')",
                       (row["project_id"], row["hub_url"], row["app_id"])):
        keys.add(("defect", str(d[0])))
    for s in c.execute("SELECT issue_type,issue_id FROM hub_issue_states WHERE project_id=? AND hub_url=? AND app_id=?",
                       (row["project_id"], row["hub_url"], row["app_id"])):
        keys.add(("issue", f"{s[0]}:{s[1]}"))
    for d in c.execute("SELECT id FROM hub_defects WHERE project_id=? AND hub_defect_id=''"
                       " AND state NOT IN ('deleted','cancelled','failed')", (row["project_id"],)):
        keys.add(("defect", f"local:{d[0]}"))
    return keys


def plan_details(c, row):
    seen = {(r[0], r[1]) for r in c.execute("SELECT entity_kind,entity_key FROM hub_sync_items WHERE run_id=?", (row["id"],))}
    for kind, key in sorted(local_keys(c, row) - seen):
        add_item(c, row, kind, key, missing=True)
    for item in c.execute("SELECT * FROM hub_sync_items WHERE run_id=? ORDER BY entity_kind DESC,entity_key", (row["id"],)).fetchall():
        kind, key = item["entity_kind"], item["entity_key"]
        if kind == "defect" and key.startswith("local:"):
            continue
        if kind == "issue" and key.split(":")[0] not in api.DETAIL_PATHS:
            c.execute("UPDATE hub_sync_items SET stale_reason=? WHERE run_id=? AND entity_kind=? AND entity_key=?",
                      (i18n.N_("Неподдержанный тип находки."), row["id"], kind, key))
            continue
        brief = loads(item["hub_json"], {}).get("brief", {})
        branch = brief.get("currentBranch") if kind == "issue" else None
        plan(c, row, kind, key, "detail", api.detail(kind, key, branch))


def consume_object(c, row, adapter, step, body, op, *, replay=False):
    kind, key, part = loads(step["request_key"], [])
    item = dict(c.execute("SELECT * FROM hub_sync_items WHERE run_id=? AND entity_kind=? AND entity_key=?",
                          (row["id"], kind, key)).fetchone())
    hub, sources = loads(item["hub_json"], {}), loads(item["source_ops_json"], {})
    coverage = loads(item["coverage_json"], {})
    coverage.get("exceptions", {}).pop(part, None)
    if part in ("manual", "risk") and body is not None and not isinstance(body, dict):
        raise ValueError(i18n.N_("Ручная запись или риск имеет неверный формат: требуется объект либо подтверждённое отсутствие."))
    if part in ("manual", "risk") and isinstance(body, dict):
        if type(body.get("issueId")) is not int or not isinstance(body.get("issueType"), str):
            raise ValueError(i18n.N_("Ручная запись или риск имеет неверный формат: отсутствуют issueId или issueType."))
        if part == "manual" and not isinstance(body.get("status"), str):
            raise ValueError(i18n.N_("Ручная запись имеет неверный формат: отсутствует status."))
    if part == "detail" and body is None and coverage.get("absent_from_list"):
        coverage["id_response"] = {"status": 404, "op_id": op["id"], "at": step["processed_at"] if replay else now_iso()}
    elif part == "detail" or part.startswith("branch:"):
        expected_id = int(key.split(":")[-1])
        if not isinstance(body, dict) or type(body.get("id")) is not int or body["id"] != expected_id:
            raise ValueError(i18n.N_("ID подробного ответа не совпадает с запросом."))
        actual_app = api.application_id(body, kind)
        if type(actual_app) is not int or actual_app != row["app_id"]:
            raise ValueError(i18n.N_("Подробный объект другого приложения."))
        if kind == "issue" and not isinstance(body.get("status"), str):
            raise ValueError(i18n.N_("В подробном ответе отсутствует текущий статус."))
        if part.startswith("branch:") and body.get("currentBranch") != part.removeprefix("branch:"):
            raise ValueError(i18n.N_("Подробный ответ относится к другой ветке."))
        selected = (hub.get("brief") or {}).get("currentBranch")
        if kind == "issue" and part == "detail" and selected is not None and body.get("currentBranch") != selected:
            raise ValueError(i18n.N_("Ветка основного подробного ответа не совпала с currentBranch списка."))
        if kind == "defect" and (problems := api.composition_problems(body)):
            raise ValueError(problems[0])
        if coverage.get("absent_from_list"):
            coverage["inventory_contradiction"] = i18n.N_("Объект найден по ID, но отсутствует в полном списке.")
        if kind == "issue" and part == "detail":
            typ, ident = key.split(":")
            if not replay:
                plan(c, row, kind, key, "manual", api.request("/issue/status", issueId=ident, issueType=typ))
            branches = body.get("issueBranchBriefData", [])
            if not isinstance(branches, list):
                raise ValueError(i18n.N_("Неверный список веток находки."))
            for branch in branches:
                if not isinstance(branch, dict) or not isinstance(branch.get("branch"), str):
                    raise ValueError(i18n.N_("У ветки отсутствует имя."))
                if not replay and branch["branch"] != body.get("currentBranch"):
                    plan(c, row, kind, key, "branch:" + branch["branch"], api.detail(kind, key, branch["branch"]))
    if not replay and kind == "issue" and (part in ("detail", "manual") or part.startswith("branch:")):
        old = c.execute("SELECT confirmed_json FROM hub_issue_states WHERE project_id=? AND hub_url=? AND app_id=?"
                        " AND issue_type=? AND issue_id=?", (row["project_id"], row["hub_url"], row["app_id"], *key.split(":"))).fetchone()
        was_risk = old and "Accepted risk" in old[0]
        if (isinstance(body, dict) and body.get("status") == "Accepted risk") or was_risk:
            typ, ident = key.split(":")
            plan(c, row, kind, key, "risk", api.request(f"/issue/{typ}/{ident}/riskAcceptance"))
    base = versions.current(c, row["project_id"], row["hub_url"], row["app_id"], kind, key)
    stale = item["stale_reason"]
    if replay:
        from app.hub_pull import applied_version
        accepted = applied_version(c, row, kind, key)
        if accepted and accepted == base:
            base = {"accepted_epoch": step["base_epoch"], "accepted_hash": step["base_hash"]}
    if (step["base_epoch"] != base["accepted_epoch"] or step["base_hash"] != base["accepted_hash"]
            or (sources and item["base_epoch"] != step["base_epoch"])):
        stale = i18n.N_("Принятая база изменилась между чтениями. Требуется новое подтверждённое чтение.")
    hub[part] = body
    attempt = c.execute("SELECT taken_at FROM hub_attempts WHERE op_id=? ORDER BY id DESC LIMIT 1", (op["id"],)).fetchone()
    observed_from = attempt[0] if attempt else op["created_at"]
    observed_to = step["processed_at"] if replay else now_iso()
    sources[part] = {"op_id": op["id"], "base_epoch": step["base_epoch"], "base_hash": step["base_hash"],
                     "from": observed_from, "to": observed_to}
    c.execute("UPDATE hub_sync_items SET hub_json=?,source_ops_json=?,coverage_json=?,base_epoch=?,"
              " observed_from=COALESCE(observed_from,?),observed_to=?,stale_reason=?"
              " WHERE run_id=? AND entity_kind=? AND entity_key=?",
              (dumps(hub), dumps(sources), dumps(coverage), item["base_epoch"] if len(sources) > 1 else step["base_epoch"],
               observed_from, max(item["observed_to"] or "", observed_to), stale, row["id"], kind, key))


def reparse_saved(c, row):
    """Переразбор последних сохранённых ответов без выдачи и планирования запросов."""
    data = passport(row)
    adapter = api.Adapter(**data["adapter"])
    if adapter.version in ("hub-sync/2-measured-2026-10-27", "hub-sync/3-measured-2026-10-30"):
        data.setdefault("read_adapter", data["adapter"])
        adapter = replace(adapter, version=api.ADAPTER.version, manual_empty=True, manual_scope=True,
                          evidence=api.ADAPTER.evidence)
        data["adapter"] = adapter.passport()
    steps = c.execute("SELECT s.* FROM hub_sync_requests s WHERE s.run_id=?"
                      " AND NOT EXISTS (SELECT 1 FROM hub_sync_requests newer WHERE newer.run_id=s.run_id"
                      " AND newer.request_key=s.request_key AND newer.id>s.id)", (row["id"],)).fetchall()
    missing = 0
    for raw in steps:
        step = dict(raw)
        part = loads(step["request_key"], [None, None, ""])[2]
        if part.startswith("page:") or not step["processed_at"]:
            continue
        op_row = c.execute("SELECT * FROM hub_ops WHERE id=?", (step["op_id"],)).fetchone()
        op = dict(op_row) if op_row else {"id": step["op_id"], "result_json": ""}
        result = loads(op["result_json"], {})
        try:
            if not isinstance(result.get("body_text"), str):
                missing += 1
                raise ValueError(i18n.N_("Сырой ответ не сохранён. Требуется подтверждённое продолжение для недостающего чтения."))
            body = response_body(c, row, adapter, step, op)
            consume_object(c, row, adapter, step, body, op, replay=True)
            c.execute("UPDATE hub_sync_requests SET state='done' WHERE id=?", (step["id"],))
        except (ValueError, KeyError, TypeError) as exc:
            object_exception(c, row, step, op, str(exc), missing_raw=not isinstance(result.get("body_text"), str))
            c.execute("UPDATE hub_sync_requests SET state='failed' WHERE id=?", (step["id"],))
    data["reparse_missing"] = missing
    data["exceptions"] = sum(len(loads(r[0], {}).get("exceptions", {})) for r in c.execute(
        "SELECT coverage_json FROM hub_sync_items WHERE run_id=?", (row["id"],)))
    unfinished = c.execute("SELECT 1 FROM hub_sync_requests s WHERE run_id=? AND state!='done'"
                           " AND NOT EXISTS (SELECT 1 FROM hub_sync_requests n WHERE n.run_id=s.run_id"
                           " AND n.request_key=s.request_key AND n.id>s.id) LIMIT 1", (row["id"],)).fetchone()
    data["details_complete"] = data["inventory_complete"] and not data["exceptions"] and not unfinished
    save_run(c, row, data)


def stop(db, run_id):
    with db._tx() as c:
        row = run_in(c, run_id)
        if row["closed_at"] or row["state"] not in ACTIVE:
            return
        cancel_queued(c, row)
        save_run(c, row, passport(row), "stopped")


def cancel_queued(c, row):
    c.execute("UPDATE hub_ops SET state='cancelled',closed_at=?,updated_at=? WHERE state='queued' AND id IN"
              " (SELECT op_id FROM hub_sync_requests WHERE run_id=?)", (now_iso(), now_iso(), row["id"]))
    c.execute("UPDATE hub_sync_requests SET state='planned',op_id=NULL WHERE run_id=? AND state='queued'"
              " AND op_id IN (SELECT id FROM hub_ops WHERE state='cancelled')", (row["id"],))


def recover(db):
    with db._tx() as c:
        for raw in c.execute("SELECT * FROM hub_defect_sync_runs WHERE closed_at IS NULL").fetchall():
            row = dict(raw)
            if row["state"] in ACTIVE:
                cancel_queued(c, row)
                save_run(c, row, passport(row), "interrupted")
            elif row["state"] == "comparing":
                from app.hub_sync_compare import compare_in
                compare_in(c, row)


def continue_run(db, run_id, revision, *, check=None):
    with db._tx() as c:
        if check:
            check(c)
        row = run_in(c, run_id)
        data = passport(row)
        if row["closed_at"] or row["revision"] != revision or row["state"] in ACTIVE:
            raise ValueError(i18n._("Состояние запуска изменилось: обновите страницу подтверждения."))
        if not data["inventory_complete"]:
            raise ValueError(i18n._("Списки прочитаны не полностью. Закройте запуск и подтвердите новый полный обход."))
        if c.execute("SELECT 1 FROM hub_ops WHERE state='taken' AND id IN"
                     " (SELECT op_id FROM hub_sync_requests WHERE run_id=?)", (run_id,)).fetchone():
            raise ValueError(i18n._("Дождитесь ответа уже выданного чтения или истечения его аренды."))
        reparse_saved(c, row)
        row = run_in(c, run_id)
        data = passport(row)
        steps = c.execute("SELECT s.* FROM hub_sync_requests s WHERE run_id=? AND state!='done'"
                          " AND NOT EXISTS (SELECT 1 FROM hub_sync_requests n WHERE n.run_id=s.run_id"
                          " AND n.request_key=s.request_key AND n.id>s.id) ORDER BY id", (run_id,)).fetchall()
        c.execute("UPDATE hub_defect_sync_runs SET generation=generation+1 WHERE id=?", (run_id,))
        row = run_in(c, run_id)
        for step in steps:
            kind, key, part = loads(step["request_key"], [])
            plan(c, row, kind, key, part, loads(step["request_json"], {}))
        data.update(error="", finished_at=None)
        save_run(c, row, data, "running")
        advance(db, c, run_in(c, run_id))


def close(db, run_id):
    with db._tx() as c:
        row = run_in(c, run_id)
        cancel_queued(c, row)
        c.execute("UPDATE hub_defect_sync_runs SET closed_at=?,state='closed',revision=revision+1 WHERE id=?",
                  (now_iso(), run_id))


def expire_in(c, op_id, message):
    step = c.execute("SELECT * FROM hub_sync_requests WHERE op_id=?", (op_id,)).fetchone()
    if step:
        c.execute("UPDATE hub_sync_requests SET state='failed',processed_at=? WHERE id=?", (now_iso(), step["id"]))
        row = run_in(c, step["run_id"])
        if step["generation"] == row["generation"] and not row["closed_at"]:
            fail_in(c, row, message)

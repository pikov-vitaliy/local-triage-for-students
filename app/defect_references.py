"""Явные загрузки справочников дефекта; показ и восстановление читают только сохранённые ответы."""

import hashlib
import json

from app import defect_fields, hub_ops, i18n
from app.db import dumps, loads, now_iso
from app.defect_dto import ID_NAME, is_int64, validate_value
from app.defect_fields import FieldError


def signature(value):
    return hashlib.sha256(dumps(value).encode("utf-8")).hexdigest()


def requests(app_id):
    return [{"method": "GET", "path": path, "body": None} for path in (
        "/defects/serviceInfo", f"/application/{app_id}/structureUnits", f"/releaseObject/filters?appId={app_id}")]


def _target(c, row, hub_url, app_id):
    project = c.execute("SELECT hub_app_id FROM projects WHERE id = ?", (row["project_id"],)).fetchone()
    if (project is None or not is_int64(app_id) or project["hub_app_id"] != app_id
            or row["app_id"] != app_id or row["hub_url"] != hub_ops.hub_base(hub_url)):
        raise ValueError(i18n._("Hub или приложение проекта изменились: подготовьте загрузку заново."))


def prepare(db, row, hub_url, app_id, check):
    with db._tx() as c:
        check(c)
        _target(c, row, hub_url, app_id)
        plan = {"version": 1, "defect_id": row["id"], "requests": requests(app_id), "results": {}}
        cur = c.execute("INSERT INTO hub_defect_reference_loads(project_id, hub_url, app_id, state, load_json, created_at)"
                        " VALUES (?, ?, ?, 'preview', ?, ?)" " RETURNING id",
                        (row["project_id"], hub_ops.hub_base(hub_url), app_id, dumps(plan), now_iso()))
        return int(cur.fetchone()[0])


def load(db, row, load_id, shown, hub_url, app_id, check):
    with db._tx() as c:
        check(c)
        _target(c, row, hub_url, app_id)
        found = c.execute("SELECT * FROM hub_defect_reference_loads WHERE id = ?", (load_id,)).fetchone()
        if (found is None or found["project_id"] != row["project_id"] or found["hub_url"] != row["hub_url"]
                or found["app_id"] != app_id or found["state"] != "preview"):
            raise ValueError(i18n._("Предпросмотр справочников изменился или уже использован."))
        plan = loads(found["load_json"], {})
        if signature(plan) != shown or plan.get("defect_id") != row["id"] or plan["requests"] != requests(app_id):
            raise ValueError(i18n._("Показанная загрузка изменилась."))
        ops = [db._hub_insert(c, purpose="defect_reference", request=req, hub_url=hub_url, app_id=app_id,
                             project_id=row["project_id"], targets=[{"reference_load": load_id,
                                 "issue_type": "DEFECT_REFERENCE", "issue_id": f"{load_id}:{index}"}],
                             key_extra=f"defect-reference:{load_id}:{index}")
               for index, req in enumerate(plan["requests"])]
        plan["ops"] = [op["id"] for op in ops]
        c.execute("UPDATE hub_defect_reference_loads SET state = 'loading', load_json = ? WHERE id = ?",
                  (dumps(plan), load_id))


def projection(bodies):
    service, units, filters = bodies
    validate_value(service, {"priorities": ["string"], "statuses": ["string"]})
    validate_value(units, [{"id": "integer", "name": "string"}])
    validate_value(filters, {"releaseObjects": [ID_NAME], "structureUnits": [ID_NAME]})
    pairs = []
    for unit in units:
        if not is_int64(unit.get("id")) or not isinstance(unit.get("name"), str):
            continue
        matches = [x for x in filters.get("structureUnits", []) if x.get("id") == str(unit["id"])
                   and x.get("name") == unit["name"]]
        same_id = [x for x in units if x.get("id") == unit["id"]]
        filter_ids = [x for x in filters.get("structureUnits", []) if x.get("id") == str(unit["id"])]
        if len(matches) == len(same_id) == len(filter_ids) == 1:
            pairs.append({"structureUnitId": unit["id"], "appStructureUnit": matches[0]})
    return {"version": 1, "priorities": service.get("priorities", []), "structureUnits": pairs,
            "releaseObjects": filters.get("releaseObjects", [])}


def sync(db, project_id):
    """Идемпотентное принятие уже доставленных результатов. Ни одной операции здесь не создаётся."""
    if db.read_only:  # режим обслуживания: только показ сохранённого
        return
    with db._tx() as c:
        for row in c.execute("SELECT * FROM hub_defect_reference_loads WHERE project_id = ? AND state = 'loading'",
                             (project_id,)).fetchall():
            plan = loads(row["load_json"], {})
            results = plan["results"]
            for op_id in plan["ops"]:
                if str(op_id) in results:
                    continue
                op = c.execute("SELECT * FROM hub_ops WHERE id = ?", (op_id,)).fetchone()
                if op is None or op["state"] in ("queued", "taken"):
                    continue
                result = loads(op["result_json"], {})
                item = {"op_id": op_id, "request": loads(op["request_json"], {}), "received_at": op["closed_at"],
                        "hub_url": op["hub_url"], "app_id": op["app_id"], "raw": result,
                        "error": op["error"] if op["state"] != "done" else ""}
                if result.get("truncated"):
                    item["error"] = i18n._("Ответ усечён: загрузка неполна.")
                if not item["error"]:
                    try:
                        item["body"] = json.loads(result.get("body_text", ""))
                    except (ValueError, TypeError):
                        item["error"] = i18n._("Ответ не является JSON.")
                results[str(op_id)] = item
            state, closed = "loading", None
            if len(results) == 3:
                closed = now_iso()
                if any(x["error"] for x in results.values()):
                    state = "failed"
                else:
                    try:
                        plan["projection"] = projection([results[str(i)]["body"] for i in plan["ops"]])
                        state = "done"
                    except ValueError as exc:
                        plan["error"] = str(exc)
                        state = "incompatible"
            c.execute("UPDATE hub_defect_reference_loads SET load_json = ?, state = ?, closed_at = ? WHERE id = ?",
                      (dumps(plan), state, closed, row["id"]))


def choices_in(c, row, load_id):
    if not load_id:
        return {}, None
    found = c.execute("SELECT * FROM hub_defect_reference_loads WHERE id = ?", (load_id,)).fetchone()
    if (found is None or found["state"] != "done" or found["project_id"] != row["project_id"]
            or found["hub_url"] != row["hub_url"] or found["app_id"] != row["app_id"]):
        raise FieldError(i18n._("Снимок справочников недоступен для этого Hub и приложения."))
    plan = loads(found["load_json"], {})
    return plan["projection"], {"load_id": found["id"], "signature": signature(plan), "at": found["closed_at"]}


def check_selected(c, row, references):
    for reference in references.values():
        _, actual = choices_in(c, row, reference["load_id"])
        if actual != reference:
            raise ValueError(i18n._("Источник выбранных полей изменился: обновите предпросмотр."))


def check_candidate(c, row, body):
    """Проверка готового PUT по выбранному варианту и его сохранённому источнику."""
    changed = set(defect_fields.changed_roots(defect_fields.local_changes(row)))
    draft = loads(row["draft_fields_json"], {})
    references = defect_fields.basis_of(row)["references"]
    for name, group in defect_fields.REFERENCE_GROUPS.items():
        roots = changed.intersection(group)
        if not roots:
            continue
        selected = {k: draft[k] for k in group if k in draft}
        candidate = {k: body[k] for k in group if k in body}
        if not defect_fields.equal(candidate, selected):
            raise FieldError(i18n._("/{field}: кандидат PUT не совпадает с выбранным справочным вариантом.", field=group[0]))
        if not selected:  # Явное удаление всей необязательной группы не требует справочника.
            continue
        value = candidate if name == "structureUnits" else candidate["releaseObject"]
        for root in sorted(roots):
            reference = references.get(root)
            if not reference:
                raise FieldError(i18n._("/{field}: нет сохранённого источника выбранного справочного варианта.", field=group[0]))
            choices, actual = choices_in(c, row, reference["load_id"])
            if actual != reference:
                raise FieldError(i18n._("/{field}: источник выбранного справочного варианта изменился.", field=group[0]))
            if not any(defect_fields.equal(value, option) for option in choices.get(name, [])):
                raise FieldError(i18n._("/{field}: кандидат PUT не соответствует варианту сохранённого справочника.", field=group[0]))

"""Порядок подтверждений Hub; время сервера не является номером редакции."""

import hashlib
import json


class StaleObservation(ValueError):
    """Ответ получен для уже заменённой принятой версии."""


def digest(value):
    return hashlib.sha256(json.dumps(value, ensure_ascii=False, sort_keys=True,
                                     separators=(",", ":")).encode("utf-8")).hexdigest()


def current(c, project_id, hub_url, app_id, kind, key):
    row = c.execute("SELECT accepted_epoch, accepted_hash FROM hub_entity_versions WHERE project_id=?"
                    " AND hub_url=? AND app_id=? AND entity_kind=? AND entity_key=?",
                    (project_id, hub_url, app_id, kind, str(key))).fetchone()
    return dict(row) if row else {"accepted_epoch": 0, "accepted_hash": ""}


def accept(c, row, raw, source):
    from app.db import dumps, loads
    from app.hub_ops import hub_base
    obj = loads(raw, None)
    if not isinstance(obj, dict) or not obj or not row.get("hub_defect_id"):
        return
    c.execute("INSERT INTO hub_entity_versions(project_id,hub_url,app_id,entity_kind,entity_key,"
              "accepted_epoch,accepted_hash,accepted_source_json) VALUES (?,?,?,'defect',?,1,?,?)"
              " ON CONFLICT(project_id,hub_url,app_id,entity_kind,entity_key) DO UPDATE SET"
              " accepted_epoch=hub_entity_versions.accepted_epoch+1, accepted_hash=excluded.accepted_hash,"
              " accepted_source_json=excluded.accepted_source_json",
              (row["project_id"], hub_base(row["hub_url"]), row["app_id"], str(row["hub_defect_id"]),
               digest(obj), dumps(source)))


def require_current(c, row, op_id):
    """Старые операции без сохранённой версии требуют нового чтения."""
    from app.db import loads
    from app.hub_ops import hub_base
    op = c.execute("SELECT request_json FROM hub_ops WHERE id=?", (op_id,)).fetchone()
    expected = loads(op[0], {}).get("accepted_base") if op else None
    actual = current(c, row["project_id"], hub_base(row["hub_url"]), row["app_id"],
                     "defect", row["hub_defect_id"])
    if expected != actual:
        raise StaleObservation("Принятая база изменилась или версия чтения неизвестна: повторите чтение Hub.")


def capture_issues(c, op, request):
    from app.db import loads
    if op["purpose"] not in ("status", "read") or op["project_id"] is None:
        return request
    bases = {}
    for target in loads(op["targets_json"], []):
        typ, ident = target.get("issue_type"), target.get("issue_id")
        if typ in ("SAST", "SCA_S", "SCA_L", "DAST") and ident:
            key = f"{typ}:{ident}"
            bases[key] = current(c, op["project_id"], op["hub_url"], op["app_id"], "issue", key)
    return {**request, "accepted_issue_bases": bases}


def confirm_targets(c, op):
    """Версии всех целей операции статуса, ставшей done, – в той же транзакции, что переход (ревью dev16, A1): между
    записью результата и доставкой отметок (mark_targets) предикат «статус уже стоит в Hub» уже видит запись, а
    принятие снимка Pull, прочитанного до записи, отвергается (база изменилась). Отметки «Внесено в Hub» ставятся
    по-прежнему отдельно и повторно; confirm_status идемпотентна."""
    from app.db import loads
    if not op or op.get("purpose") != "status" or op.get("state") != "done" or op.get("project_id") is None:
        return
    for target in loads(op.get("targets_json"), []):
        if isinstance(target, dict):
            confirm_status(c, int(op["project_id"]), {**target, "entered_op_id": op["id"]})


def confirmable(c, project_id, target):
    """Подтверждение цели операцией ещё возможно (только чтение): версия цели – от этой операции (уже подтверждена)
    или ожидаемая при постановке база цели не менялась. (можно, подтверждена, op, args)."""
    from app.db import loads
    op = c.execute("SELECT * FROM hub_ops WHERE id=?", (target.get("entered_op_id"),)).fetchone()
    if op is None:
        return False, False, None, ()
    key = f"{target.get('issue_type')}:{target.get('issue_id')}"
    args = (project_id, op["hub_url"], op["app_id"], "issue", key)
    existing = c.execute("SELECT * FROM hub_entity_versions WHERE project_id=? AND hub_url=? AND app_id=?"
                         " AND entity_kind=? AND entity_key=?", args).fetchone()
    if existing and loads(existing["accepted_source_json"], {}).get("op_id") == op["id"]:
        return True, True, op, args
    expected = loads(op["request_json"], {}).get("accepted_issue_bases", {}).get(key)
    return expected == current(c, *args), False, op, args


def confirm_status(c, project_id, target):
    """Старая доставленная операция не восстанавливает отметку поверх новой базы."""
    from app.db import dumps, loads
    allowed, confirmed, op, args = confirmable(c, project_id, target)
    if not allowed:
        return False
    if confirmed:
        return True
    request = loads(op["request_json"], {})
    c.execute("INSERT INTO hub_entity_versions(project_id,hub_url,app_id,entity_kind,entity_key,accepted_epoch,"
              "accepted_hash,accepted_source_json) VALUES (?,?,?,?,?,1,?,?)"
              " ON CONFLICT(project_id,hub_url,app_id,entity_kind,entity_key) DO UPDATE SET"
              " accepted_epoch=hub_entity_versions.accepted_epoch+1,accepted_hash=excluded.accepted_hash,"
              " accepted_source_json=excluded.accepted_source_json",
              (*args, digest(request.get("body")), dumps({"op_id": op["id"], "origin": "status_confirmation"})))
    return True

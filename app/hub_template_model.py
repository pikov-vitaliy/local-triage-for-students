"""Сохранение неизвестного ответа модели шаблона Hub без сборки блока (ADR-0139)."""
from __future__ import annotations

import re
from urllib.parse import urlencode

from app import hub_ops, i18n
from app.db import loads

PATH = "/templates/defects/model"
OLD_WORKER = i18n.N_("Исполнитель не отправил GET /templates/defects/model: обновите файл исполнителя в ВМ "
                     "до 0.10.0.dev10 и повторите чтение по подтверждению оператора.")


def request_for(row: dict, issue_id: str) -> dict:
    if not re.fullmatch(r"[0-9]{1,12}", issue_id) or int(issue_id) <= 0:
        raise ValueError(i18n._("Укажите номер находки Hub из состава дефекта."))
    targets = loads(row.get("targets_json"), [])
    found = [t for t in targets if str(t.get("issue_id")) == str(int(issue_id))]
    types = {t.get("issue_type") for t in found}
    if len(types) != 1 or not types <= {"SAST", "SCA_S", "SCA_L", "DAST"}:
        raise ValueError(i18n._("Находка отсутствует в составе дефекта или её тип не определён."))
    app_id = row.get("app_id")
    if type(app_id) is not int or app_id <= 0:
        raise ValueError(i18n._("У дефекта нет номера приложения Hub."))
    request = {"method": "GET", "path": PATH + "?" + urlencode({
        "issueType": next(iter(types)), "issueId": int(issue_id), "appId": app_id})}
    hub_ops.check_operation("read", request, app_id)
    return request


def model_of(answer, issue_id: int) -> dict | None:
    """Ответ модели шаблона на находку issue_id: одна находка с этим номером; иначе None."""
    issues = answer.get("issues") if isinstance(answer, dict) else None
    if not isinstance(issues, list) or len(issues) != 1 or not isinstance(issues[0], dict):
        return None
    ident = issues[0].get("id")
    return answer if not isinstance(ident, bool) and str(ident) == str(issue_id) else None


def enqueue(db, row: dict, issue_id: str, target_check) -> dict:
    request = request_for(row, issue_id)

    def check(c):
        target_check(c)
        current = c.execute("SELECT * FROM hub_defects WHERE id = ?", (row["id"],)).fetchone()
        if current is None or any(current[k] != row[k] for k in
                                  ("project_id", "hub_url", "app_id", "targets_json")):
            raise ValueError(i18n._("Состав или назначение дефекта изменились: подготовьте чтение заново."))

    return db.hub_enqueue(purpose="read", request=request, hub_url=row["hub_url"], app_id=row["app_id"],
                          project_id=row["project_id"], targets=[{"issue_type": "DEFECT_TEMPLATE_MODEL",
                          "issue_id": int(issue_id), "defect_id": row["id"]}], check=check)


def saved(db, row: dict, op_id: int) -> dict:
    op = db.hub_op(op_id)
    targets = loads((op or {}).get("targets_json"), [])
    if (op is None or op["project_id"] != row["project_id"] or op["purpose"] != "read"
            or not any(t.get("defect_id") == row["id"] and t.get("issue_type") == "DEFECT_TEMPLATE_MODEL"
                       for t in targets)
            or loads(op["request_json"], {}).get("path", "").partition("?")[0] != PATH):
        raise ValueError(i18n._("Чтение модели шаблона этого дефекта не найдено."))
    result = loads(op.get("result_json"), {})
    old_worker = result.get("not_sent") and "белый список" in str(result.get("error") or "")
    if op["state"] in ("queued", "taken"):
        note = i18n._("Ожидается ответ исполнителя; служебный блок не собран.")
    elif op["state"] != "done":
        note = i18n._("Чтение не завершено успешно; исходный результат сохранён, служебный блок не собран.")
    else:
        note = i18n._("Ответ сохранён без разбора; служебный блок не собран.")
    return {"op_id": op_id, "state": op["state"], "request": loads(op["request_json"], {}),
            "result": result, "received_at": op.get("closed_at"), "error": op.get("error") or "",
            "note": i18n._(OLD_WORKER) if old_worker else note}
